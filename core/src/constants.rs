use bitcoin::{Address, Amount, ScriptBuf};

/// The amount of the P2A anchor output.
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(240); // TODO: This will change to 0 in the future after Bitcoin v0.29.0

/// The minimum possible amount that a UTXO can have when created into a Taproot address.
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330); // TODO: Maybe this could be 294, check

pub const TEN_MINUTES_IN_SECS: u32 = 600;

pub const CITREA_LCP_START_HEIGHT: u64 = 60;

lazy_static::lazy_static! {
  pub static ref BURN_SCRIPT: ScriptBuf = ("1111111111111111111114oLvT2")
          .parse::<Address<_>>()
          .expect("valid burn address")
          .assume_checked()
          .script_pubkey();
}
