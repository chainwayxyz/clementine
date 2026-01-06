//! Utility traits for clementine.

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use clementine_errors::BridgeError;
use eyre::Context;

/// A trait for entities that have a name, operator, verifier, etc.
/// Used to distinguish between state machines with different owners in the database,
/// and to provide a human-readable name for the entity for task names.
pub trait NamedEntity: Sync + Send + 'static {
    /// A string identifier for this owner type used to distinguish between
    /// state machines with different owners in the database.
    ///
    /// ## Example
    /// "operator", "verifier", "user"
    const ENTITY_NAME: &'static str;

    /// Consumer ID for the tx sender task.
    const TX_SENDER_CONSUMER_ID: &'static str;

    /// Consumer ID for the finalized block task with no automation.
    const FINALIZED_BLOCK_CONSUMER_ID_NO_AUTOMATION: &'static str;

    /// Consumer ID for the finalized block task with automation.
    const FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION: &'static str;
}

/// Trait to extract last 20 bytes (for address derivation).
pub trait Last20Bytes {
    /// Extract the last 20 bytes.
    fn last_20_bytes(&self) -> [u8; 20];
}

/// Fallible version of [`Last20Bytes`].
pub trait TryLast20Bytes {
    /// Extract the last 20 bytes, or return an error.
    fn try_last_20_bytes(self) -> Result<[u8; 20], BridgeError>;
}

impl Last20Bytes for [u8; 32] {
    fn last_20_bytes(&self) -> [u8; 20] {
        self.as_slice()
            .try_last_20_bytes()
            .expect("will not happen")
    }
}

impl TryLast20Bytes for &[u8] {
    fn try_last_20_bytes(self) -> Result<[u8; 20], BridgeError> {
        if self.len() < 20 {
            return Err(eyre::eyre!("Input is too short to contain 20 bytes").into());
        }
        let mut result = [0u8; 20];
        result.copy_from_slice(&self[self.len() - 20..]);
        Ok(result)
    }
}

/// Extension trait for [`ScriptBuf`].
pub trait ScriptBufExt {
    /// Try to extract the taproot public key from a P2TR script.
    fn try_get_taproot_pk(&self) -> Result<XOnlyPublicKey, BridgeError>;
}

impl ScriptBufExt for ScriptBuf {
    fn try_get_taproot_pk(&self) -> Result<XOnlyPublicKey, BridgeError> {
        if !self.is_p2tr() {
            return Err(eyre::eyre!("Script is not a valid P2TR script (not 34 bytes)").into());
        }

        Ok(XOnlyPublicKey::from_slice(&self.as_bytes()[2..34])
            .wrap_err("Failed to parse XOnlyPublicKey from script")?)
    }
}
