use crate::maraslipstream::MaraSlipstreamConfig;
use crate::maraslipstream_client::{MaraSlipstreamClient, SlipstreamRateInfo};
use crate::{
    log_error_for_tx, Result, TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder,
};
use bitcoin::{consensus::encode::serialize, FeeRate, Transaction, Txid};

const DISCOUNTED_MULTIPLIER_CAP: f64 = 3.0;
const F64_EXACT_INT_LIMIT: u64 = 1u64 << 53;

impl<S, D, B> TxSender<S, D, B>
where
    S: TxSenderSigner,
    D: TxSenderDatabase,
    B: TxSenderTxBuilder,
{
    pub(crate) fn slipstream_supported_network(&self) -> bool {
        matches!(
            self.protocol_paramset.network,
            bitcoin::Network::Bitcoin | bitcoin::Network::Testnet4
        )
    }

    pub(crate) fn slipstream_cfg_if_enabled(&self) -> Option<&MaraSlipstreamConfig> {
        if !self.slipstream_supported_network() {
            return None;
        }
        self.maraslipstream_config.as_ref()
    }

    /// Returns Slipstream config only when the tx is nonstandard, the current
    /// network supports Slipstream, and the config is present.
    pub(crate) fn maybe_slipstream_cfg_for_nonstandard_tx(
        &self,
        tx: &Transaction,
    ) -> Option<&MaraSlipstreamConfig> {
        if !self.is_bridge_tx_nonstandard(tx) {
            return None;
        }

        if !self.slipstream_supported_network() {
            return None;
        }

        let cfg = self.slipstream_cfg_if_enabled();
        if cfg.is_none() {
            tracing::warn!(
                network = ?self.protocol_paramset.network,
                "Nonstandard tx on Slipstream-supported network but Slipstream config is not set; falling back to RPC submission"
            );
        }

        cfg
    }

    pub(crate) fn slipstream_client(
        &self,
        cfg: &MaraSlipstreamConfig,
    ) -> Result<MaraSlipstreamClient> {
        // Clone operation should be cheap since HttpClient is Arc-based internally.
        MaraSlipstreamClient::new(self.http_client.clone(), cfg)
    }

    pub(crate) async fn slipstream_client_or_mark_failed(
        &self,
        cfg: &MaraSlipstreamConfig,
        try_to_send_id: u32,
        failed_state: &str,
    ) -> Result<MaraSlipstreamClient> {
        match self.slipstream_client(cfg) {
            Ok(client) => Ok(client),
            Err(e) => {
                log_error_for_tx!(
                    self.db,
                    try_to_send_id,
                    format!("Failed to build Slipstream client: {e:?}")
                );
                let _ = self
                    .db
                    .update_tx_debug_sending_state(try_to_send_id, failed_state, true)
                    .await;
                Err(e)
            }
        }
    }

    pub(crate) fn tx_to_hex(tx: &Transaction) -> String {
        hex::encode(serialize(tx))
    }

    /// Attempts to submit a transaction to Slipstream when enabled for this tx.
    ///
    /// Returns:
    /// - `Ok(Some(expected_txid))` when submitted (and txid check passed)
    /// - `Ok(None)` when Slipstream is not applicable
    /// - `Err(_)` when submission fails or txid mismatches
    pub(crate) async fn maybe_submit_tx_via_slipstream(
        &self,
        tx: &Transaction,
        expected_txid: Txid,
        try_to_send_id: u32,
        state_prefix: &str,
    ) -> Result<Option<Txid>> {
        let Some(cfg) = self.maybe_slipstream_cfg_for_nonstandard_tx(tx) else {
            return Ok(None);
        };

        let txid_mismatch_state = format!("{state_prefix}_txid_mismatch");
        let sent_state = format!("{state_prefix}_sent");
        let send_failed_state = format!("{state_prefix}_send_failed");

        let client = self
            .slipstream_client_or_mark_failed(cfg, try_to_send_id, &send_failed_state)
            .await?;
        let tx_hex = Self::tx_to_hex(tx);

        match client.submit_tx(&tx_hex, cfg.client_code.as_ref()).await {
            Ok(returned_txid) => {
                if returned_txid != expected_txid {
                    let err_msg = format!(
                        "Slipstream returned unexpected txid {returned_txid} (expected {expected_txid})"
                    );
                    log_error_for_tx!(self.db, try_to_send_id, err_msg);
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(try_to_send_id, &txid_mismatch_state, true)
                        .await;
                    return Err(eyre::eyre!("Slipstream returned unexpected txid").into());
                }

                tracing::debug!(
                    try_to_send_id,
                    "Successfully submitted tx to Slipstream: {}",
                    returned_txid
                );
                let _ = self
                    .db
                    .update_tx_debug_sending_state(try_to_send_id, &sent_state, true)
                    .await;

                Ok(Some(expected_txid))
            }
            Err(e) => {
                log_error_for_tx!(
                    self.db,
                    try_to_send_id,
                    format!("Slipstream submit-tx failed: {e:?}")
                );
                let _ = self
                    .db
                    .update_tx_debug_sending_state(try_to_send_id, &send_failed_state, true)
                    .await;
                Err(e)
            }
        }
    }

    pub(crate) async fn slipstream_get_rate_info_for_cfg(
        &self,
        cfg: &MaraSlipstreamConfig,
    ) -> Option<SlipstreamRateInfo> {
        let client = match self.slipstream_client(cfg) {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(
                    "Failed to build Slipstream client; falling back to normal fee logic: {e:?}"
                );
                return None;
            }
        };

        match client.get_rate(cfg.client_code.as_ref()).await {
            Ok(info) => Some(info),
            Err(e) => {
                tracing::warn!(
                    "Slipstream getrate failed; falling back to normal fee logic: {e:?}"
                );
                None
            }
        }
    }

    pub(crate) async fn maybe_slipstream_adjust_fee_rate(
        &self,
        fee_rate: FeeRate,
        cfg: Option<&MaraSlipstreamConfig>,
    ) -> FeeRate {
        let Some(cfg) = cfg else {
            return fee_rate;
        };

        let Some(info) = self.slipstream_get_rate_info_for_cfg(cfg).await else {
            return fee_rate;
        };

        let mut mult = info.discounted_multiplier;
        if !mult.is_finite() || mult < 1.0 {
            tracing::warn!(
                "Slipstream returned invalid discounted_multiplier={mult}; using original fee rate"
            );
            return fee_rate;
        }
        if mult > DISCOUNTED_MULTIPLIER_CAP {
            tracing::warn!(
                "Slipstream returned discounted_multiplier={mult} above cap; capping to {DISCOUNTED_MULTIPLIER_CAP}"
            );
            mult = DISCOUNTED_MULTIPLIER_CAP;
        }

        let base_sat_kwu = fee_rate.to_sat_per_kwu();
        // Very unlikely, but warn if we cross the f64 exact-integer boundary for safety.
        if base_sat_kwu >= F64_EXACT_INT_LIMIT {
            tracing::warn!(
                base_sat_kwu,
                "Fee rate is at or above 2^53 sat/kwu; f64 conversion may lose precision"
            );
        }

        // It should be safe to do the multiplication in f64 since fee rates are small.
        let target_sat_kwu = (base_sat_kwu as f64) * mult;

        if !target_sat_kwu.is_finite() || target_sat_kwu > (u64::MAX as f64) {
            tracing::warn!(
                base_sat_kwu,
                mult,
                "Slipstream fee rate multiplication overflowed; using original fee rate"
            );
            return fee_rate;
        }

        let min_sat_kwu_u64 = FeeRate::BROADCAST_MIN.to_sat_per_kwu();

        let target_sat_kwu_u64 = (target_sat_kwu.ceil() as u64).max(min_sat_kwu_u64);
        FeeRate::from_sat_per_kwu(target_sat_kwu_u64)
    }

    pub(crate) async fn slipstream_fee_rate_and_cfg(
        &self,
        tx: &Transaction,
        base_fee_rate: FeeRate,
    ) -> (FeeRate, Option<&MaraSlipstreamConfig>) {
        let cfg = self.maybe_slipstream_cfg_for_nonstandard_tx(tx);
        let fee_rate = self
            .maybe_slipstream_adjust_fee_rate(base_fee_rate, cfg)
            .await;
        (fee_rate, cfg)
    }
}
