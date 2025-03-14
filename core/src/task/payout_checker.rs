use tokio::time::Duration;
use tonic::async_trait;

use crate::{database::Database, errors::BridgeError};

use super::Task;

pub const PAYOUT_CHECKER_POLL_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct PayoutCheckerTask {
    db: Database,
    operator: crate::operator::Operator,
}

impl PayoutCheckerTask {
    pub fn new(db: Database, operator: crate::operator::Operator) -> Self {
        Self { db, operator }
    }
}

#[async_trait]
impl Task for PayoutCheckerTask {
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let unhandled_payout = self
            .db
            .get_first_unhandled_payout_by_operator_id(None, self.operator.idx as u32)
            .await?;
        if unhandled_payout.is_none() {
            return Ok(false);
        }
        let mut dbtx = self.db.begin_transaction().await?;
        let unhandled_payout = self
            .db
            .get_first_unhandled_payout_by_operator_id(Some(&mut dbtx), self.operator.idx as u32)
            .await?;

        if unhandled_payout.is_none() {
            return Ok(false);
        }

        let (citrea_idx, move_to_vault_txid, payout_tx_blockhash) =
            unhandled_payout.expect("Must be Some");

        let deposit_data = self
            .db
            .get_deposit_data_with_move_tx(Some(&mut dbtx), move_to_vault_txid)
            .await?;
        if deposit_data.is_none() {
            return Err(BridgeError::Error("Deposit data not found".to_string()));
        }

        let deposit_data = deposit_data.expect("Must be Some");

        let kickoff_txid = self
            .operator
            .handle_finalized_payout(
                &mut dbtx,
                deposit_data.deposit_outpoint,
                payout_tx_blockhash,
            )
            .await?;

        // TODO: Remove this, for now, we can end round after handling a single payout
        self.operator.end_round(&mut dbtx).await?;

        self.db
            .set_payout_handled(Some(&mut dbtx), citrea_idx, kickoff_txid)
            .await?;

        dbtx.commit().await?;

        Ok(false)
    }
}
