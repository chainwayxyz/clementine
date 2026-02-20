//! Transaction sender configuration.

use serde::Deserialize;

/// 10 minutes in milliseconds.
pub const BITCOIN_TARGET_BLOCK_TIME_MS: u64 = 10 * 60 * 1000;
/// Keep retrying for 2 * finality depth worth of expected block time.
pub const INPUT_UNSPENT_TIMEOUT_FINALITY_MULTIPLIER: u64 = 2;

/// Derive default maximum retries for input-unspent checks:
/// `(finality_depth * 2 * 10 minutes) / poll_delay_ms`.
///
/// Uses ceil division and always returns at least 1.
pub fn derive_input_unspent_max_retries(finality_depth: u32, poll_delay_ms: u64) -> u32 {
    let poll_delay_ms = poll_delay_ms.max(1);
    let timeout_window_ms = u64::from(finality_depth)
        .saturating_mul(INPUT_UNSPENT_TIMEOUT_FINALITY_MULTIPLIER)
        .saturating_mul(BITCOIN_TARGET_BLOCK_TIME_MS);
    let retries = timeout_window_ms.div_ceil(poll_delay_ms).max(1);
    u32::try_from(retries).unwrap_or(i32::MAX as u32)
}

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
    /// Minimum fee bump increment in sat/kvB. If current fee rate is smaller than previously sent fee rate + min_bump_kvb, we do not bump at all. This is so that we do not do tiny fee bumps constantly.
    pub min_bump_kvb: u64,
}

impl Default for TxSenderLimits {
    fn default() -> Self {
        Self {
            fee_rate_hard_cap: 100,
            mempool_fee_rate_multiplier: 1,
            mempool_fee_rate_offset_sat_kvb: 0,
            cpfp_fee_payer_bump_wait_time_seconds: 60 * 60, // 1 hour in seconds
            fee_bump_after_blocks: 10,
            // 0.2 sat/vB ~= 200 sat/kvB
            min_bump_kvb: 200,
        }
    }
}
