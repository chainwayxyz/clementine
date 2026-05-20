use crate::database::DatabaseTransaction;
use crate::utils::TxMetadata;
use crate::{
    database::{wrapper::TxidDB, Database},
    execute_query_with_tx,
};
use bitcoin::{Amount, Txid};
use clementine_errors::BridgeError;
use clementine_primitives::FeeRateKvb;
use eyre::Context;

impl Database {
    pub async fn get_fee_payer_utxos_for_tx(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        tx_id: u32,
    ) -> Result<Vec<(Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64)>(
            r#"
            SELECT fee_payer_txid, vout, amount
            FROM tx_sender_fee_payer_utxos
            WHERE bumped_id = $1
            "#,
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?);

        let results: Vec<(TxidDB, i32, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        results
            .iter()
            .map(|(fee_payer_txid, vout, amount)| {
                Ok((
                    fee_payer_txid.0,
                    u32::try_from(*vout).wrap_err("Failed to convert vout to u32")?,
                    Amount::from_sat(
                        u64::try_from(*amount).wrap_err("Failed to convert amount to u64")?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    pub async fn get_id_from_txid(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        txid: Txid,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_scalar::<_, i32>(
            "SELECT id FROM tx_sender_try_to_send_txs WHERE txid = $1",
        )
        .bind(TxidDB(txid));

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        match result {
            Some(id) => Ok(Some(
                u32::try_from(id).wrap_err("Failed to convert id to u32")?,
            )),
            None => Ok(None),
        }
    }

    pub async fn debug_inactive_txs(&self, fee_rate: FeeRateKvb, current_tip_height: u32) {
        tracing::info!("TXSENDER_DBG_INACTIVE_TXS: Checking inactive transactions");

        // Query all transactions that aren't confirmed yet
        let unconfirmed_txs = match sqlx::query_as::<_, (i32, TxidDB, Option<String>)>(
            "SELECT id, txid, tx_metadata FROM tx_sender_try_to_send_txs WHERE seen_at_height IS NULL",
        )
        .fetch_all(&self.connection)
        .await
        {
            Ok(txs) => txs,
            Err(e) => {
                tracing::error!(
                    "TXSENDER_DBG_INACTIVE_TXS: Failed to query unconfirmed txs: {}",
                    e
                );
                return;
            }
        };

        let txsender_db = clementine_tx_sender::TxSenderDb::from_pool(self.get_pool());
        let sendable_txs = match txsender_db
            .get_sendable_txs(None, fee_rate, current_tip_height)
            .await
        {
            Ok(txs) => txs,
            Err(e) => {
                tracing::error!(
                    "TXSENDER_DBG_INACTIVE_TXS: Failed to get sendable txs: {}",
                    e
                );
                return;
            }
        };

        for (tx_id, txid, tx_metadata) in unconfirmed_txs {
            let tx_metadata: Option<TxMetadata> =
                serde_json::from_str(tx_metadata.as_deref().unwrap_or("null")).ok();

            let id = match u32::try_from(tx_id) {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("TXSENDER_DBG_INACTIVE_TXS: Failed to convert id: {}", e);
                    continue;
                }
            };

            if sendable_txs.contains(&id) {
                tracing::info!(
                    "TXSENDER_DBG_INACTIVE_TXS: TX {} (txid: {}) is ACTIVE",
                    id,
                    txid.0
                );
                continue;
            }

            tracing::info!(
                "TXSENDER_DBG_INACTIVE_TXS: TX {} (txid: {}, type: {:?}) is inactive, reasons:",
                id,
                txid.0,
                tx_metadata.map(|metadata| metadata.tx_type)
            );

            // Check for txid activations that aren't active yet
            let txid_activations = match sqlx::query_as::<_, (Option<i32>, i64, TxidDB)>(
                "SELECT seen_at_height, timelock, txid
                FROM tx_sender_activate_try_to_send_txids
                WHERE activated_id = $1",
            )
            .bind(tx_id)
            .fetch_all(&self.connection)
            .await
            {
                Ok(activations) => activations,
                Err(e) => {
                    tracing::error!(
                        "TXSENDER_DBG_INACTIVE_TXS: Failed to query txid activations: {}",
                        e
                    );
                    continue;
                }
            };

            for (seen_at_height, timelock, txid) in txid_activations {
                if seen_at_height.is_none() {
                    tracing::info!("TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its txid activation {} has not been seen", id, txid.0);
                    continue;
                }

                let seen_at_height = seen_at_height.expect("checked above");
                if (seen_at_height as i64) + timelock > current_tip_height as i64 {
                    tracing::info!(
                        "TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its txid activation timelock hasn't expired (seen_at_height: {}, timelock: {}, current_tip_height: {})",
                        id, seen_at_height, timelock, current_tip_height
                    );
                }
            }

            // Check fee rate
            let effective_fee_rate = match sqlx::query_scalar::<_, Option<i64>>(
                "SELECT effective_fee_rate FROM tx_sender_try_to_send_txs WHERE id = $1",
            )
            .bind(tx_id)
            .fetch_one(&self.connection)
            .await
            {
                Ok(rate) => rate,
                Err(e) => {
                    tracing::error!(
                        "TXSENDER_DBG_INACTIVE_TXS: Failed to query effective fee rate: {}",
                        e
                    );
                    continue;
                }
            };

            if let Some(rate) = effective_fee_rate {
                if rate >= fee_rate.to_sat_per_kvb() as i64 {
                    tracing::info!(
                        "TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its effective fee rate ({} sat/kvB) is >= the current fee rate ({} sat/kvB)",
                        id, rate, fee_rate.to_sat_per_kvb()
                    );
                }
            }
        }
    }
}
