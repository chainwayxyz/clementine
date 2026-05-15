use crate::maraslipstream::MaraSlipstreamConfig;
use crate::maraslipstream_client::{MaraSlipstreamClient, SlipstreamRateInfo};
use crate::{log_error_for_tx, Result, TxSender};
use crate::{SlipstreamSubmitTxLabel, TxDebugState};
use bitcoin::{consensus::encode::serialize, Transaction, Txid};
use clementine_primitives::FeeRateKvb;

const SLIPSTREAM_FEE_RATE_CAP_MULTIPLIER: u64 = 3;
const DISCOUNTED_MULTIPLIER_CAP: f64 = SLIPSTREAM_FEE_RATE_CAP_MULTIPLIER as f64;

impl TxSender {
    pub(crate) fn slipstream_supported_network(&self) -> bool {
        matches!(
            self.network,
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
                network = ?self.network,
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
        failed_state: TxDebugState,
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
                    .update_tx_debug_sending_state(try_to_send_id, failed_state.as_str(), true)
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
        label: SlipstreamSubmitTxLabel,
        cfg: Option<&MaraSlipstreamConfig>,
    ) -> Result<Option<Txid>> {
        let Some(cfg) = cfg.or_else(|| self.maybe_slipstream_cfg_for_nonstandard_tx(tx)) else {
            return Ok(None);
        };

        let client = self
            .slipstream_client_or_mark_failed(cfg, try_to_send_id, label.client_failed_state())
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
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            label.txid_mismatch_state().as_str(),
                            true,
                        )
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
                    .update_tx_debug_sending_state(
                        try_to_send_id,
                        label.sent_state().as_str(),
                        true,
                    )
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
                    .update_tx_debug_sending_state(
                        try_to_send_id,
                        label.failed_state().as_str(),
                        true,
                    )
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

    pub(crate) async fn maybe_adjust_fee_rate_for_slipstream_cfg(
        &self,
        fee_rate: FeeRateKvb,
        cfg: Option<&MaraSlipstreamConfig>,
    ) -> FeeRateKvb {
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

        let max_slipstream_fee_rate = self.max_slipstream_fee_rate();

        // It should be safe to do the multiplication in f64 since fee rates are small.
        let base_sat_kvb = fee_rate.to_sat_per_kvb();
        let target_sat_kvb = (base_sat_kvb as f64) * mult;
        if !target_sat_kvb.is_finite() || target_sat_kvb < 0.0 {
            tracing::warn!(
                base_sat_kvb,
                mult,
                "Slipstream fee rate multiplication overflowed; using original fee rate"
            );
            return fee_rate;
        }

        let max_sat_kvb = max_slipstream_fee_rate.to_sat_per_kvb() as f64;
        let target_fee_rate =
            FeeRateKvb::from_sat_per_kvb(target_sat_kvb.min(max_sat_kvb).ceil() as u64);

        target_fee_rate
    }

    pub(crate) fn max_slipstream_fee_rate(&self) -> FeeRateKvb {
        self.fee_rate_hard_cap()
            .checked_mul(SLIPSTREAM_FEE_RATE_CAP_MULTIPLIER)
            .unwrap_or_else(|| self.fee_rate_hard_cap())
    }
}
