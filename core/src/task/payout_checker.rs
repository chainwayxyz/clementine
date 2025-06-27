use tokio::time::Duration;
use tonic::async_trait;

use crate::{citrea::CitreaClientT, database::Database, errors::BridgeError, operator::Operator};

use super::Task;

pub const PAYOUT_CHECKER_POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(200)
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

        // TODO: Remove this, for now, we can end round after handling a single payout
        #[cfg(feature = "automation")]
        self.operator.end_round(&mut dbtx).await?;

        self.db
            .set_payout_handled(Some(&mut dbtx), citrea_idx, kickoff_txid)
            .await?;

        dbtx.commit().await?;

        Ok(true)
    }
}
