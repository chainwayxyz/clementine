use bitcoin::{transaction::Version, Address, Amount, ScriptBuf};

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
/// This limit is approximate, because it doesn't take into account the internal extra bytes used in
/// HashMap and VecDeque used in the AllSessions. It only takes into account bytes used for the secnonces.
pub const MAX_ALL_SESSIONS_BYTES: usize = 2_000_000_000;

/// The maximum number of nonce sessions that can be stored in the verifier.
/// It is used so that the allsessions do not store too many small (1 nonce) sessions.
pub const MAX_NUM_SESSIONS: usize = 2000;

use secp256k1::ffi::MUSIG_SECNONCE_LEN;
/// The maximum number of Winternitz digits per key.
/// This is used to limit the size of the Winternitz public keys in the protocol
/// to prevent excessive memory usage and ensure efficient processing.
/// This value is achieved when signing a 32-byte message with a Winternitz key,
/// resulting in a maximum of 64 + 4 digits per key, where the last 4 digits are used for
/// the sum-check operation.
pub const MAX_WINTERNITZ_DIGITS_PER_KEY: usize = 68;

/// The maximum number of script replacement operations allowed in a single BitVM operation.
/// This is a safeguard to prevent excessive resource usage and ensure that the BitVM protocol
/// remains efficient and manageable.
/// The limit is set to 100,000 operations, which is a reasonable upper bound for
/// script replacement operations in the context of BitVM, which is normally a constant
/// equal to 47544.
pub const MAX_SCRIPT_REPLACEMENT_OPERATIONS: usize = 100_000;

/// The maximum number of bytes per Winternitz key.
pub const MAX_BYTES_PER_WINTERNITZ_KEY: usize = MAX_WINTERNITZ_DIGITS_PER_KEY * 20;

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
    pub const DEPOSIT_FINALIZATION_TIMEOUT: Duration = Duration::from_secs(2400); // 40 minutes

    pub const RESTART_BACKGROUND_TASKS_TIMEOUT: Duration = Duration::from_secs(60);

    pub const ENTITY_STATUS_POLL_TIMEOUT: Duration = Duration::from_secs(120);

    pub const ENTITY_COMP_DATA_POLL_TIMEOUT: Duration = Duration::from_secs(120); // 2 minutes

    pub const PUBLIC_KEY_COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);

    pub const WITHDRAWAL_TIMEOUT: Duration = Duration::from_secs(120); // 2 minutes
}

pub const NON_STANDARD_V3: Version = Version(3);

lazy_static::lazy_static! {
  pub static ref BURN_SCRIPT: ScriptBuf = ("1111111111111111111114oLvT2")
          .parse::<Address<_>>()
          .expect("valid burn address")
          .assume_checked()
          .script_pubkey();

}
