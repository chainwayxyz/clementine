//! # Transaction Input Types and Utilities
//!
//! This module defines types and utilities for representing and handling transaction inputs used in [`super::TxHandler`].
//! It provides abstractions for spendable inputs, input errors, correctness checks, supporting Taproot and script path spends.
//!

use crate::bitvm_client;
use crate::builder::script::SpendableScript;
use crate::builder::sighash::TapTweakData;
use crate::builder::{address::create_taproot_address, script::SpendPath};
use crate::config::protocol::ProtocolParamset;
use crate::rpc::clementine::tagged_signature::SignatureId;
use bitcoin::{
    taproot::{LeafVersion, TaprootSpendInfo},
    Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, WitnessProgram, XOnlyPublicKey,
};
use std::sync::Arc;
use thiserror::Error;

pub type BlockHeight = u16;

#[derive(Debug, Clone)]
/// Represents a spendable transaction input, including previous output, scripts, and Taproot spend info.
pub struct SpendableTxIn {
    /// The reference to the previous output that is being used as an input.
    previous_outpoint: OutPoint,
    prevout: TxOut, // locking script (taproot => op_1 op_pushbytes_32 tweaked pk)
    /// Scripts associated with this input (for script path spends).
    scripts: Vec<Arc<dyn SpendableScript>>,
    /// Optional Taproot spend info for this input.
    spendinfo: Option<TaprootSpendInfo>,
}

#[derive(Clone, Debug, Error, PartialEq)]
/// Error type for spendable input construction and validation.
pub enum SpendableTxInError {
    #[error(
        "The taproot spend info contains an incomplete merkle proof map. Some scripts are missing."
    )]
    IncompleteMerkleProofMap,

    #[error("The script_pubkey of the previous output does not match the expected script_pubkey for the taproot spending information.")]
    IncorrectScriptPubkey,

    #[error("Error creating a spendable txin: {0}")]
    Error(String),
}

#[derive(Debug, Clone, Copy)]
/// Enumerates protocol-specific UTXO output indices for transaction construction.
/// Used to identify the vout of specific UTXOs in protocol transactions.
pub enum UtxoVout {
    /// The vout of the assert utxo in KickoffTx
    Assert(usize),
    /// The vout of the watchtower challenge utxo in KickoffTx
    WatchtowerChallenge(usize),
    /// The vout of the watchtower challenge ack utxo in KickoffTx
    WatchtowerChallengeAck(usize),
    /// The vout of the challenge utxo in KickoffTx
    Challenge,
    /// The vout of the kickoff finalizer utxo in KickoffTx
    KickoffFinalizer,
    /// The vout of the reimburse utxo in KickoffTx
    ReimburseInKickoff,
    /// The vout of the disprove utxo in KickoffTx
    Disprove,
    /// The vout of the latest blockhash utxo in KickoffTx
    LatestBlockhash,
    /// The vout of the deposited btc utxo in MoveTx
    DepositInMove,
    /// The vout of the reimburse connector utxo in RoundTx
    ReimburseInRound(usize, &'static ProtocolParamset),
    /// The vout of the kickoff utxo in RoundTx
    Kickoff(usize),
    /// The vout of the collateral utxo in RoundTx
    CollateralInRound,
    /// The vout of the collateral utxo in ReadyToReimburseTx
    CollateralInReadyToReimburse,
}

impl UtxoVout {
    /// Returns the vout index for this UTXO in the corresponding transaction.
    pub fn get_vout(self) -> u32 {
        match self {
            UtxoVout::Assert(idx) => idx as u32 + 5,
            UtxoVout::WatchtowerChallenge(idx) => {
                (2 * idx + 5 + bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs())
                    as u32
            }
            UtxoVout::WatchtowerChallengeAck(idx) => {
                (2 * idx + 6 + bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs())
                    as u32
            }
            UtxoVout::Challenge => 0,
            UtxoVout::KickoffFinalizer => 1,
            UtxoVout::ReimburseInKickoff => 2,
            UtxoVout::Disprove => 3,
            UtxoVout::LatestBlockhash => 4,
            UtxoVout::ReimburseInRound(idx, paramset) => {
                (paramset.num_kickoffs_per_round + idx + 1) as u32
            }
            UtxoVout::Kickoff(idx) => idx as u32 + 1,
            UtxoVout::DepositInMove => 0,
            UtxoVout::CollateralInRound => 0,
            UtxoVout::CollateralInReadyToReimburse => 0,
        }
    }
}

impl SpendableTxIn {
    /// Returns a reference to the previous output (TxOut) for this input.
    pub fn get_prevout(&self) -> &TxOut {
        &self.prevout
    }

    /// Returns a reference to the previous outpoint (OutPoint) for this input.
    pub fn get_prev_outpoint(&self) -> &OutPoint {
        &self.previous_outpoint
    }

    /// Creates a new [`SpendableTxIn`] with only a previous output and TxOut (no scripts or spend info).
    pub fn new_partial(previous_output: OutPoint, prevout: TxOut) -> SpendableTxIn {
        Self::new(previous_output, prevout, vec![], None)
    }

    /// Constructs a [`SpendableTxIn`] from scripts, value, and the internal key. Giving None for the internal key will create the tx
    /// with an unspendable internal key.
    ///
    /// # Arguments
    /// * `previous_output` - The outpoint being spent.
    /// * `value` - The value of the previous output.
    /// * `scripts` - Scripts for script path spends.
    /// * `key_path` - The internal key for key path spends.
    /// * `network` - Bitcoin network.
    ///
    /// # Returns
    ///
    /// A new [`SpendableTxIn`] with the specified parameters.
    pub fn from_scripts(
        previous_output: OutPoint,
        value: Amount,
        scripts: Vec<Arc<dyn SpendableScript>>,
        key_path: Option<XOnlyPublicKey>,
        network: bitcoin::Network,
    ) -> SpendableTxIn {
        let script_bufs: Vec<ScriptBuf> = scripts
            .iter()
            .map(|script| script.clone().to_script_buf())
            .collect();
        let (addr, spend_info) = create_taproot_address(&script_bufs, key_path, network);
        Self::new(
            previous_output,
            TxOut {
                value,
                script_pubkey: addr.script_pubkey(),
            },
            scripts,
            Some(spend_info),
        )
    }

    /// Creates a new [`SpendableTxIn`] from all fields.
    #[inline(always)]
    pub fn new(
        previous_output: OutPoint,
        prevout: TxOut,
        scripts: Vec<Arc<dyn SpendableScript>>,
        spendinfo: Option<TaprootSpendInfo>,
    ) -> SpendableTxIn {
        if cfg!(debug_assertions) {
            return Self::from_checked(previous_output, prevout, scripts, spendinfo)
                .expect("failed to construct a spendabletxin in debug mode");
        }

        Self::from_unchecked(previous_output, prevout, scripts, spendinfo)
    }

    /// Returns a reference to the scripts for this input.
    pub fn get_scripts(&self) -> &Vec<Arc<dyn SpendableScript>> {
        &self.scripts
    }

    /// Returns a reference to the Taproot spend info for this input, if any.
    pub fn get_spend_info(&self) -> &Option<TaprootSpendInfo> {
        &self.spendinfo
    }

    /// Sets the Taproot spend info for this input.
    pub fn set_spend_info(&mut self, spendinfo: Option<TaprootSpendInfo>) {
        self.spendinfo = spendinfo;
        #[cfg(debug_assertions)]
        self.check().expect("spendinfo is invalid in debug mode");
    }

    /// Checks the validity of the spendable input, ensuring script pubkey and merkle proof map are correct.
    fn check(&self) -> Result<(), SpendableTxInError> {
        use SpendableTxInError::*;
        let Some(spendinfo) = self.spendinfo.as_ref() else {
            return Ok(());
        };

        let (prevout, scripts) = (&self.prevout, &self.scripts);

        if ScriptBuf::new_witness_program(&WitnessProgram::p2tr_tweaked(spendinfo.output_key()))
            != prevout.script_pubkey
        {
            return Err(IncorrectScriptPubkey);
        }
        let script_bufs: Vec<ScriptBuf> = scripts
            .iter()
            .map(|script| script.to_script_buf())
            .collect();
        if script_bufs.into_iter().any(|script| {
            spendinfo
                .script_map()
                .get(&(script, LeafVersion::TapScript))
                .is_none()
        }) {
            return Err(IncompleteMerkleProofMap);
        }
        Ok(())
    }

    /// Creates a [`SpendableTxIn`] with validation if the given input is valid (used in debug mode for testing).
    fn from_checked(
        previous_output: OutPoint,
        prevout: TxOut,
        scripts: Vec<Arc<dyn SpendableScript>>,
        spendinfo: Option<TaprootSpendInfo>,
    ) -> Result<SpendableTxIn, SpendableTxInError> {
        let this = Self::from_unchecked(previous_output, prevout, scripts, spendinfo);
        this.check()?;
        Ok(this)
    }

    /// Creates a [`SpendableTxIn`] without validation (used in release mode).
    fn from_unchecked(
        previous_outpoint: OutPoint,
        prevout: TxOut,
        scripts: Vec<Arc<dyn SpendableScript>>,
        spendinfo: Option<TaprootSpendInfo>,
    ) -> SpendableTxIn {
        SpendableTxIn {
            previous_outpoint,
            prevout,
            scripts,
            spendinfo,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
/// Represents a fully specified transaction input, including sequence, witness, spend path, and signature ID.
pub struct SpentTxIn {
    spendable: SpendableTxIn,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behavior cannot be enforced.
    sequence: Sequence,
    /// Witness data used to spend this TxIn. Can be None if the
    /// transaction that this TxIn is in has not been signed yet.
    ///
    /// Has to be Some(_) when the transaction is signed.
    witness: Option<Witness>,
    /// Spend path for this input (key or script path).
    spend_path: SpendPath,
    /// Signature ID for this input, which signature in the protocol this input needs.
    input_id: SignatureId,
}

impl SpentTxIn {
    /// Constructs a [`SpentTxIn`] from a spendable input and associated metadata.
    pub fn from_spendable(
        input_id: SignatureId,
        spendable: SpendableTxIn,
        spend_path: SpendPath,
        sequence: Sequence,
        witness: Option<Witness>,
    ) -> SpentTxIn {
        SpentTxIn {
            spendable,
            sequence,
            witness,
            spend_path,
            input_id,
        }
    }

    /// Returns a reference to the underlying [`SpendableTxIn`].
    pub fn get_spendable(&self) -> &SpendableTxIn {
        &self.spendable
    }

    /// Returns the spend path for this input.
    pub fn get_spend_path(&self) -> SpendPath {
        self.spend_path
    }

    /// Returns the Taproot tweak data for this input, based on the spend path and spend info.
    pub fn get_tweak_data(&self) -> TapTweakData {
        match self.spend_path {
            SpendPath::ScriptSpend(_) => TapTweakData::ScriptPath,
            SpendPath::KeySpend => {
                let spendinfo = self.spendable.get_spend_info();
                match spendinfo {
                    Some(spendinfo) => TapTweakData::KeyPath(spendinfo.merkle_root()),
                    None => TapTweakData::Unknown,
                }
            }
            SpendPath::Unknown => TapTweakData::Unknown,
        }
    }

    /// Returns a reference to the witness data for this input, if any.
    pub fn get_witness(&self) -> &Option<Witness> {
        &self.witness
    }

    /// Returns the signature ID for this input.
    pub fn get_signature_id(&self) -> SignatureId {
        self.input_id
    }

    /// Sets the witness data for this input.
    pub fn set_witness(&mut self, witness: Witness) {
        self.witness = Some(witness);
    }

    // pub fn get_sequence(&self) -> Sequence {
    //     self.sequence
    // }

    // pub fn set_sequence(&mut self, sequence: Sequence) {
    //     self.sequence = sequence;
    // }

    /// Converts this [`SpentTxIn`] into a Bitcoin [`TxIn`] for inclusion in a Bitcoin transaction.
    pub fn to_txin(&self) -> TxIn {
        TxIn {
            previous_output: self.spendable.previous_outpoint,
            sequence: self.sequence,
            script_sig: ScriptBuf::default(),
            witness: self.witness.clone().unwrap_or_default(),
        }
    }
}
