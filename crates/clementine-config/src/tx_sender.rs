//! Transaction sender configuration.

use serde::Deserialize;

/// Transaction sender limits and fee configuration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TxSenderLimits {
    /// Hard cap on fee rate in sat/vB.
    pub fee_rate_hard_cap: u64,
    /// Multiplier applied to mempool fee rate.
    pub mempool_fee_rate_multiplier: u64,
    /// Offset added to mempool fee rate in sat/kvB.
    pub mempool_fee_rate_offset_sat_kvb: u64,
    /// Time to wait before bumping the fee of a fee payer UTXO in seconds.
    /// We wait a bit because after bumping the fee, the unconfirmed change utxo that is in the bumped tx will not be able to be spent (so won't be used to create new fee payer utxos) until that fee payer tx confirms.
    pub cpfp_fee_payer_bump_wait_time_seconds: u64,
    /// The number of blocks after which to bump the fee a tx in tx sender queue if it's still not confirmed
    pub fee_bump_after_blocks: u32,
}

impl Default for TxSenderLimits {
    fn default() -> Self {
        Self {
            fee_rate_hard_cap: 100,
            mempool_fee_rate_multiplier: 1,
            mempool_fee_rate_offset_sat_kvb: 0,
            cpfp_fee_payer_bump_wait_time_seconds: 60 * 60, // 1 hour in seconds
            fee_bump_after_blocks: 10,
        }
    }
}
