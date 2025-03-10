use pgmq::PGMQueueExt;
use statig::awaitable::IntoStateMachineExt;

use crate::{
    builder::transaction::{DepositData, OperatorData},
    database::{Database, DatabaseTransaction},
    errors::BridgeError,
    rpc::clementine::KickoffId,
};

use super::{kickoff::KickoffStateMachine, round::RoundStateMachine, Owner, StateManager};

#[derive(Debug, serde::Serialize, Clone, serde::Deserialize)]
pub enum SystemEvent {
    NewBlock {
        block: bitcoin::Block,
        height: u32,
    },
    NewOperator {
        operator_data: OperatorData,
        operator_idx: u32,
    },
    NewKickoff {
        kickoff_id: KickoffId,
        kickoff_height: u32,
        deposit_data: DepositData,
    },
}

impl<T: Owner + std::fmt::Debug + 'static> StateManager<T> {
    pub async fn dispatch_new_round_machine(
        db: Database,
        tx: DatabaseTransaction<'_, '_>,
        operator_data: OperatorData,
        operator_idx: u32,
    ) -> Result<(), eyre::Report> {
        let queue_name = StateManager::<T>::queue_name();
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        let message = SystemEvent::NewOperator {
            operator_data,
            operator_idx,
        };
        queue
            .send_with_cxn(&queue_name, &message, &mut *(*tx))
            .await
            .map_err(|e| BridgeError::Error(format!("Error sending NewOperator event: {:?}", e)))?;
        Ok(())
    }

    pub async fn dispatch_new_kickoff_machine(
        db: Database,
        tx: DatabaseTransaction<'_, '_>,
        kickoff_id: KickoffId,
        kickoff_height: u32,
        deposit_data: DepositData,
    ) -> Result<(), eyre::Report> {
        let queue_name = StateManager::<T>::queue_name();
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        let message = SystemEvent::NewKickoff {
            kickoff_id,
            kickoff_height,
            deposit_data,
        };
        queue
            .send_with_cxn(&queue_name, &message, &mut *(*tx))
            .await
            .map_err(|e| BridgeError::Error(format!("Error sending NewKickoff event: {:?}", e)))?;
        Ok(())
    }

    pub async fn handle_event(
        &mut self,
        event: SystemEvent,
        dbtx: DatabaseTransaction<'_, '_>,
    ) -> Result<(), BridgeError> {
        match event {
            SystemEvent::NewBlock { block, height } => {
                self.process_block_parallel(&block, height).await?;
            }
            SystemEvent::NewOperator {
                operator_data,
                operator_idx,
            } => {
                let operator_machine = RoundStateMachine::new(operator_data, operator_idx)
                    .uninitialized_state_machine()
                    .init_with_context(&mut self.context)
                    .await;
                self.process_and_add_new_states_from_height(
                    vec![operator_machine],
                    vec![],
                    self.paramset.start_height,
                )
                .await?;
            }
            SystemEvent::NewKickoff {
                kickoff_id,
                kickoff_height,
                deposit_data,
            } => {
                let kickoff_machine =
                    KickoffStateMachine::new(kickoff_id, kickoff_height, deposit_data)
                        .uninitialized_state_machine()
                        .init_with_context(&mut self.context)
                        .await;
                self.process_and_add_new_states_from_height(
                    vec![],
                    vec![kickoff_machine],
                    kickoff_height,
                )
                .await?;
            }
        }
        // Save the state machines to the database with the current block height
        self.save_state_to_db(self.last_processed_block_height, Some(dbtx))
            .await?;
        Ok(())
    }
}
