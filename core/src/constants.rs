use bitcoin::{Address, Amount, ScriptBuf};

/// The amount of the P2A anchor output.
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(0);

pub const NON_EPHEMERAL_ANCHOR_AMOUNT: Amount = Amount::from_sat(240);

pub const DEFAULT_UTXO_AMOUNT: Amount = Amount::from_sat(0);

/// The minimum possible amount that a UTXO can have when created into a Taproot address.
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330); // TODO: Maybe this could be 294, check

pub const TEN_MINUTES_IN_SECS: u32 = 600;

lazy_static::lazy_static! {
  pub static ref BURN_SCRIPT: ScriptBuf = ("1111111111111111111114oLvT2")
          .parse::<Address<_>>()
          .expect("valid burn address")
          .assume_checked()
          .script_pubkey();
}
