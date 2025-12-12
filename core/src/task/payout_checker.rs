use eyre::OptionExt;
use tokio::time::Duration;
use tonic::async_trait;

use crate::{citrea::CitreaClientT, database::Database, operator::Operator};
use clementine_errors::BridgeError;

use super::{Task, TaskVariant};

pub const PAYOUT_CHECKER_POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(250)
} else {
    Duration::from_secs(60)
};

#[derive(Debug, Clone)]
pub struct PayoutCheckerTask<C: CitreaClientT> {
    db: Database,
    operator: Operator<C>,
}

impl<C> PayoutCheckerTask<C>
where
    C: CitreaClientT,
{
    pub fn new(db: Database, operator: Operator<C>) -> Self {
        Self { db, operator }
    }
}

#[async_trait]
impl<C> Task for PayoutCheckerTask<C>
where
    C: CitreaClientT,
{
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::PayoutChecker;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let mut dbtx = self.db.begin_transaction().await?;
        let unhandled_payout = self
            .db
            .get_first_unhandled_payout_by_operator_xonly_pk(
                Some(&mut dbtx),
                self.operator.signer.xonly_public_key,
            )
            .await?;

        if unhandled_payout.is_none() {
            return Ok(false);
        }

        let (citrea_idx, move_to_vault_txid, payout_tx_blockhash) =
            unhandled_payout.expect("Must be Some");

        tracing::info!(
            "Unhandled payout found for withdrawal {}, move_txid: {}",
            citrea_idx,
            move_to_vault_txid
        );

        let deposit_data = self
            .db
            .get_deposit_data_with_move_tx(Some(&mut dbtx), move_to_vault_txid)
            .await?;
        if deposit_data.is_none() {
            return Err(eyre::eyre!("Deposit data not found").into());
        }

        let deposit_data = deposit_data.expect("Must be Some");

        let kickoff_txid = self
            .operator
            .handle_finalized_payout(
                &mut dbtx,
                deposit_data.get_deposit_outpoint(),
                payout_tx_blockhash,
            )
            .await?;

        // fetch and save the LCP for if we get challenged and need to provide proof of payout later
        let (_, payout_block_height) = self
            .operator
            .db
            .get_block_info_from_hash(Some(&mut dbtx), payout_tx_blockhash)
            .await?
            .ok_or_eyre("Couldn't find payout blockhash in bitcoin sync")?;

        let _ = self
            .operator
            .citrea_client
            .fetch_validate_and_store_lcp(
                payout_block_height as u64,
                citrea_idx,
                &self.operator.db,
                Some(&mut dbtx),
                self.operator.config.protocol_paramset(),
            )
            .await?;

        #[cfg(feature = "automation")]
        self.operator.end_round(&mut dbtx).await?;

        self.db
            .mark_payout_handled(Some(&mut dbtx), citrea_idx, kickoff_txid)
            .await?;

        dbtx.commit().await?;

        Ok(true)
    }
}
