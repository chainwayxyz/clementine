use std::time::Duration;

use bitcoin::{Address, Amount, ScriptBuf};

/// The amount of the non-ephemeral P2A anchor output.
pub const NON_EPHEMERAL_ANCHOR_AMOUNT: Amount = Amount::from_sat(240);

/// The minimum possible amount that a UTXO can have when created into a Taproot address.
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330);

pub const TEN_MINUTES_IN_SECS: u32 = 600;

pub const DEFAULT_CHANNEL_SIZE: usize = 1280;

/// The maximum number of nonces that can be generated in a single nonce generation session.
/// A single nonce takes 132 (musig2 secret nonce) bytes. We calculate NUM_NONCES so that a nonce
/// session takes at maximum 150MB.
pub const NUM_NONCES_LIMIT: u32 = 150 * 1_000_000 / MUSIG_SECNONCE_LEN as u32;

/// The maximum number of bytes that can be used by all nonce sessions.
/// If it exceeds this limit, the verifier will delete the oldest nonce sessions.
pub const MAX_ALL_SESSIONS_BYTES: u64 = 1_000_000_000;

use secp256k1::ffi::MUSIG_SECNONCE_LEN;
pub use timeout::*;

mod timeout {
    use std::time::Duration;

    pub const OVERALL_DEPOSIT_TIMEOUT: Duration = Duration::from_secs(7200); // 2 hours

    pub const KEY_DISTRIBUTION_TIMEOUT: Duration = Duration::from_secs(1200); // 20 minutes
    pub const OPERATOR_GET_KEYS_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes
    pub const VERIFIER_SEND_KEYS_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes

    pub const NONCE_STREAM_CREATION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
    pub const PARTIAL_SIG_STREAM_CREATION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
    pub const OPERATOR_SIGS_STREAM_CREATION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
    pub const DEPOSIT_FINALIZE_STREAM_CREATION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

    pub const PIPELINE_COMPLETION_TIMEOUT: Duration = Duration::from_secs(3600); // 60 minutes
    pub const OPERATOR_SIGS_TIMEOUT: Duration = Duration::from_secs(1200); // 20 minutes
    pub const SEND_OPERATOR_SIGS_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes
    pub const DEPOSIT_FINALIZATION_TIMEOUT: Duration = Duration::from_secs(2400);
    // 40 minutes
}

lazy_static::lazy_static! {
  pub static ref BURN_SCRIPT: ScriptBuf = ("1111111111111111111114oLvT2")
          .parse::<Address<_>>()
          .expect("valid burn address")
          .assume_checked()
          .script_pubkey();
}
