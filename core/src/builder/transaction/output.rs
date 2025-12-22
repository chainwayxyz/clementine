//! # Transaction Output Types and Utilities
//!
//! This module defines types and utilities for representing and handling transaction outputs used in [`super::TxHandler`].
//! Main purpose of it is to store the scripts used in the taproot outputs.
//!

use crate::builder::address::create_taproot_address;
use crate::builder::script::SpendableScript;
use bitcoin::{taproot::TaprootSpendInfo, Amount, ScriptBuf, TxOut, XOnlyPublicKey};
use std::sync::Arc;

#[derive(Debug, Clone)]
/// Represents a spendable transaction output, including scripts and optional Taproot spend info.
pub struct UnspentTxOut {
    txout: TxOut,
    scripts: Vec<Arc<dyn SpendableScript>>,
    spendinfo: Option<TaprootSpendInfo>,
}

impl UnspentTxOut {
    /// Constructs an [`UnspentTxOut`] from a partial [`TxOut`] (no scripts or spend info).
    ///
    /// # Arguments
    /// * `txout` - The Bitcoin transaction output.
    ///
    /// # Returns
    /// An [`UnspentTxOut`] with no scripts or spend info.
    pub fn from_partial(txout: TxOut) -> UnspentTxOut {
        UnspentTxOut {
            txout,
            scripts: vec![],
            spendinfo: None,
        }
    }
    /// Constructs an [`UnspentTxOut`] from all fields.
    ///
    /// # Arguments
    /// * `txout` - The Bitcoin transaction output.
    /// * `scripts` - Scripts associated with this output (for script path spends).
    /// * `spendinfo` - Optional Taproot spend info for this output.
    ///
    /// # Returns
    /// An [`UnspentTxOut`] with the specified parameters.
    pub fn new(
        txout: TxOut,
        scripts: Vec<Arc<dyn SpendableScript>>,
        spendinfo: Option<TaprootSpendInfo>,
    ) -> UnspentTxOut {
        UnspentTxOut {
            txout,
            scripts,
            spendinfo,
        }
    }

    /// Constructs an [`UnspentTxOut`] from value, scripts, and key path.
    ///
    /// # Arguments
    /// * `value` - The output value.
    /// * `scripts` - Scripts for script path spends.
    /// * `key_path` - The internal key for key path spends.
    /// * `network` - Bitcoin network.
    ///
    /// # Returns
    /// An [`UnspentTxOut`] with the specified parameters and Taproot spend info if applicable.
    pub fn from_scripts(
        value: Amount,
        scripts: Vec<Arc<dyn SpendableScript>>,
        key_path: Option<XOnlyPublicKey>,
        network: bitcoin::Network,
    ) -> UnspentTxOut {
        let script_bufs: Vec<ScriptBuf> = scripts
            .iter()
            .map(|script| script.clone().to_script_buf())
            .collect();
        let (addr, spend_info) = create_taproot_address(&script_bufs, key_path, network);
        Self::new(
            TxOut {
                value,
                script_pubkey: addr.script_pubkey(),
            },
            scripts,
            Some(spend_info),
        )
    }

    /// Returns a reference to the underlying [`TxOut`].
    pub fn txout(&self) -> &TxOut {
        &self.txout
    }

    /// Returns a reference to the scripts for this output.
    pub fn scripts(&self) -> &Vec<Arc<dyn SpendableScript>> {
        &self.scripts
    }

    /// Returns a reference to the Taproot spend info for this output, if any.
    pub fn spendinfo(&self) -> &Option<TaprootSpendInfo> {
        &self.spendinfo
    }
}
