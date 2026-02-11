use crate::maraslipstream::MaraSlipstreamConfig;
use crate::maraslipstream_client::{MaraSlipstreamClient, SlipstreamRateInfo};
use crate::{TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder};
use bitcoin::{consensus::encode::serialize, FeeRate, Transaction};

const DISCOUNTED_MULTIPLIER_CAP: f64 = 3.0;

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

    pub(crate) fn slipstream_client(&self, cfg: &MaraSlipstreamConfig) -> MaraSlipstreamClient {
        // Clone operation should be cheap since HttpClient is Arc-based internally.
        MaraSlipstreamClient::new(self.http_client.clone(), cfg)
    }

    pub(crate) fn tx_to_hex(tx: &Transaction) -> String {
        hex::encode(serialize(tx))
    }

    pub(crate) async fn slipstream_get_rate_info_for_cfg(
        &self,
        cfg: &MaraSlipstreamConfig,
    ) -> Option<SlipstreamRateInfo> {
        let client = self.slipstream_client(cfg);

        match client
            .get_rate_with_fallback(cfg.client_code.as_ref())
            .await
        {
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

        // It should be safe to do the multiplication in f64 since fee rates are smaller than 2**53.
        let target_sat_kwu = (fee_rate.to_sat_per_kwu() as f64) * mult;

        let min_sat_kwu_u64 = FeeRate::BROADCAST_MIN.to_sat_per_kwu();

        let target_sat_kwu_u64 = (target_sat_kwu.ceil() as u64).max(min_sat_kwu_u64);
        FeeRate::from_sat_per_kwu(target_sat_kwu_u64)
    }
}
