//! # Transaction Handler Module
//!
//! This module defines the [`TxHandler`] abstraction, which wraps a protocol transaction and its metadata.
//! Metadata includes taproot scripts and protocol specific data to enable signing of the transactions.
//! [`TxHandlerBuilder`] is used to create [`TxHandler`]s.
//!

use super::input::{SpendableTxIn, SpentTxIn, UtxoVout};
use super::output::UnspentTxOut;
use crate::builder::script::SpendPath;
use crate::builder::sighash::{PartialSignatureInfo, SignatureInfo};
use crate::builder::transaction::deposit_signature_owner::{DepositSigKeyOwner, EntityType};
use crate::builder::transaction::TransactionType;
use crate::errors::{BridgeError, TxError};
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::{NormalSignatureKind, RawSignedTx};
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, LeafVersion};
use bitcoin::transaction::Version;
use bitcoin::{absolute, OutPoint, Script, Sequence, TapNodeHash, Transaction, Witness};
use bitcoin::{TapLeafHash, TapSighash, TapSighashType, TxOut, Txid};
use eyre::{Context, OptionExt};
use std::collections::BTreeMap;
use std::marker::PhantomData;

pub const DEFAULT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

#[derive(Debug, Clone)]
/// Handler for protocol transactions, wrapping inputs, outputs, and cached transaction data.
pub struct TxHandler<T: State = Unsigned> {
    transaction_type: TransactionType,
    txins: Vec<SpentTxIn>,
    txouts: Vec<UnspentTxOut>,

    /// Cached and immutable, same as other fields
    cached_tx: bitcoin::Transaction,
    cached_txid: bitcoin::Txid,

    phantom: PhantomData<T>,
}

pub trait State: Clone + std::fmt::Debug {}

// #[derive(Debug, Clone)]
// pub struct PartialInputs;
#[derive(Debug, Clone)]
/// Marker type for signed transactions.
pub struct Signed;
#[derive(Debug, Clone)]
/// Marker type for unsigned transactions.
pub struct Unsigned;

// impl State for PartialInputs {}
impl State for Unsigned {}
impl State for Signed {}
pub type SighashCalculator<'a> =
    Box<dyn Fn(TapSighashType) -> Result<TapSighash, BridgeError> + 'a>;

impl<T: State> TxHandler<T> {
    /// Returns a spendable input for the specified output index in this transaction.
    ///
    /// # Arguments
    /// * `vout` - The protocol-specific output index.
    ///
    /// # Returns
    /// A [`SpendableTxIn`] for the specified output, or a [`BridgeError`] if not found.
    pub fn get_spendable_output(&self, vout: UtxoVout) -> Result<SpendableTxIn, BridgeError> {
        let idx = vout.get_vout();
        let txout = self
            .txouts
            .get(idx as usize)
            .ok_or_else(|| eyre::eyre!("Could not find output {idx} in transaction"))?;
        Ok(SpendableTxIn::new(
            OutPoint {
                txid: self.cached_txid,
                vout: idx,
            },
            txout.txout().clone(),
            txout.scripts().clone(),
            txout.spendinfo().clone(),
        ))
    }

    /// Returns the Taproot merkle root of the specified input, if available.
    ///
    /// # Arguments
    /// * `idx` - The input index.
    ///
    /// # Returns
    /// The Taproot merkle root, or a [`BridgeError`] if not found.
    pub fn get_merkle_root_of_txin(&self, idx: usize) -> Result<Option<TapNodeHash>, BridgeError> {
        let txin = self
            .txins
            .get(idx)
            .ok_or(TxError::TxInputNotFound)?
            .get_spendable();
        let merkle_root = txin
            .get_spend_info()
            .as_ref()
            .ok_or(eyre::eyre!(
                "Spend info not found for requested txin in get_merkle_root_of_txin"
            ))?
            .merkle_root();
        Ok(merkle_root)
    }

    /// Returns the signature ID for the specified input.
    ///
    /// # Arguments
    /// * `idx` - The input index.
    ///
    /// # Returns
    /// The signature ID, or a [`BridgeError`] if not found.
    pub fn get_signature_id(&self, idx: usize) -> Result<SignatureId, BridgeError> {
        let txin = self.txins.get(idx).ok_or(TxError::TxInputNotFound)?;
        Ok(txin.get_signature_id())
    }

    /// Returns the protocol transaction type for this handler.
    pub fn get_transaction_type(&self) -> TransactionType {
        self.transaction_type
    }

    /// Returns a reference to the cached Bitcoin transaction.
    pub fn get_cached_tx(&self) -> &Transaction {
        &self.cached_tx
    }

    /// Returns a reference to the cached transaction ID.
    pub fn get_txid(&self) -> &Txid {
        // Not sure if this should be public
        &self.cached_txid
    }

    /// Returns a lambda function that calculates the sighash for the specified input, given the sighash type.
    ///
    /// # Arguments
    /// * `idx` - The input index.
    ///
    /// # Returns
    /// A lambda function that calculates the sighash for the specified input, given the sighash type.
    fn get_sighash_calculator(
        &self,
        idx: usize,
    ) -> impl Fn(TapSighashType) -> Result<TapSighash, BridgeError> + '_ {
        move |sighash_type: TapSighashType| -> Result<TapSighash, BridgeError> {
            match self.txins[idx].get_spend_path() {
                SpendPath::KeySpend => self.calculate_pubkey_spend_sighash(idx, sighash_type),
                SpendPath::ScriptSpend(script_idx) => {
                    self.calculate_script_spend_sighash_indexed(idx, script_idx, sighash_type)
                }
                SpendPath::Unknown => Err(TxError::SpendPathNotSpecified.into()),
            }
        }
    }

    /// Signs all **unsigned** transaction inputs using the provided signer function.
    ///
    /// This function will skip all transaction inputs that already have a witness.
    ///
    /// # Arguments
    /// * `signer` - A function that returns an optional witness for transaction inputs or returns an error
    ///   if the signing fails. The function takes the input idx, input object, and a sighash calculator closure.
    ///
    /// # Returns
    /// * `Ok(())` if signing is successful
    /// * `Err(BridgeError)` if signing fails
    pub fn sign_txins(
        &mut self,
        mut signer: impl for<'a> FnMut(
            usize,
            &'a SpentTxIn,
            SighashCalculator<'a>,
        ) -> Result<Option<Witness>, BridgeError>,
    ) -> Result<(), BridgeError> {
        for idx in 0..self.txins.len() {
            let calc_sighash = Box::new(self.get_sighash_calculator(idx));
            if self.txins[idx].get_witness().is_some() {
                continue;
            }

            if let Some(witness) = signer(idx, &self.txins[idx], calc_sighash)
                .wrap_err_with(|| format!("Failed to sign input {idx}"))?
            {
                self.cached_tx.input[idx].witness = witness.clone();
                self.txins[idx].set_witness(witness);
            }
        }
        Ok(())
    }

    /// Calculates the Taproot sighash for a key spend input for the given input and sighash type.
    ///
    /// # Arguments
    /// * `txin_index` - The input index.
    /// * `sighash_type` - The Taproot sighash type.
    ///
    /// # Returns
    /// The calculated Taproot sighash, or a [`BridgeError`] if calculation fails.
    pub fn calculate_pubkey_spend_sighash(
        &self,
        txin_index: usize,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, BridgeError> {
        let prevouts_vec: Vec<&TxOut> = self
            .txins
            .iter()
            .map(|s| s.get_spendable().get_prevout())
            .collect();
        let mut sighash_cache: SighashCache<&bitcoin::Transaction> =
            SighashCache::new(&self.cached_tx);
        let prevouts = match sighash_type {
            TapSighashType::SinglePlusAnyoneCanPay
            | TapSighashType::AllPlusAnyoneCanPay
            | TapSighashType::NonePlusAnyoneCanPay => {
                bitcoin::sighash::Prevouts::One(txin_index, prevouts_vec[txin_index])
            }
            _ => bitcoin::sighash::Prevouts::All(&prevouts_vec),
        };

        let sig_hash = sighash_cache
            .taproot_key_spend_signature_hash(txin_index, &prevouts, sighash_type)
            .wrap_err("Failed to calculate taproot sighash for key spend")?;

        Ok(sig_hash)
    }

    /// Calculates the Taproot sighash for a script spend input by script index.
    ///
    /// # Arguments
    /// * `txin_index` - The input index.
    /// * `spend_script_idx` - The script index in the input's script list.
    /// * `sighash_type` - The Taproot sighash type.
    ///
    /// # Returns
    /// The calculated Taproot sighash, or a [`BridgeError`] if calculation fails.
    pub fn calculate_script_spend_sighash_indexed(
        &self,
        txin_index: usize,
        spend_script_idx: usize,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, BridgeError> {
        let script = self
            .txins
            .get(txin_index)
            .ok_or(TxError::TxInputNotFound)?
            .get_spendable()
            .get_scripts()
            .get(spend_script_idx)
            .ok_or(TxError::ScriptNotFound(spend_script_idx))?
            .to_script_buf();

        self.calculate_script_spend_sighash(txin_index, &script, sighash_type)
    }

    /// Calculates the Taproot sighash for a script spend input by script.
    ///
    /// # Arguments
    /// * `txin_index` - The input index.
    /// * `spend_script` - The script being spent.
    /// * `sighash_type` - The Taproot sighash type.
    ///
    /// # Returns
    /// The calculated Taproot sighash, or a [`BridgeError`] if calculation fails.
    pub fn calculate_script_spend_sighash(
        &self,
        txin_index: usize,
        spend_script: &Script,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, BridgeError> {
        let prevouts_vec: Vec<&TxOut> = self
            .txins
            .iter()
            .map(|s| s.get_spendable().get_prevout())
            .collect();
        let mut sighash_cache: SighashCache<&bitcoin::Transaction> =
            SighashCache::new(&self.cached_tx);

        let prevouts = &match sighash_type {
            TapSighashType::SinglePlusAnyoneCanPay
            | TapSighashType::AllPlusAnyoneCanPay
            | TapSighashType::NonePlusAnyoneCanPay => {
                bitcoin::sighash::Prevouts::One(txin_index, prevouts_vec[txin_index])
            }
            _ => bitcoin::sighash::Prevouts::All(&prevouts_vec),
        };
        let leaf_hash = TapLeafHash::from_script(spend_script, LeafVersion::TapScript);
        let sig_hash = sighash_cache
            .taproot_script_spend_signature_hash(txin_index, prevouts, leaf_hash, sighash_type)
            .wrap_err("Failed to calculate taproot sighash for script spend")?;

        Ok(sig_hash)
    }

    /// Calculates the sighash for the specified input, based on its spend path stored inside [`SpentTxIn`].
    ///
    /// # Arguments
    /// * `txin_index` - The input index.
    /// * `sighash_type` - The Taproot sighash type.
    ///
    /// # Returns
    /// The calculated Taproot sighash, or a [`BridgeError`] if calculation fails.
    pub fn calculate_sighash_txin(
        &self,
        txin_index: usize,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, BridgeError> {
        match self.txins[txin_index].get_spend_path() {
            SpendPath::ScriptSpend(idx) => {
                self.calculate_script_spend_sighash_indexed(txin_index, idx, sighash_type)
            }
            SpendPath::KeySpend => self.calculate_pubkey_spend_sighash(txin_index, sighash_type),
            SpendPath::Unknown => Err(TxError::MissingSpendInfo.into()),
        }
    }

    /// Calculates sighashes for all shared inputs for a given entity type.
    ///
    /// # Arguments
    /// * `needed_entity` - The entity type (operator, verifier, etc.).
    /// * `partial_signature_info` - Partial signature info for the entity.
    ///
    /// # Returns
    /// A vector of (sighash, signature info) pairs, or a [`BridgeError`] if calculation fails.
    pub fn calculate_shared_txins_sighash(
        &self,
        needed_entity: EntityType,
        partial_signature_info: PartialSignatureInfo,
    ) -> Result<Vec<(TapSighash, SignatureInfo)>, BridgeError> {
        let mut sighashes = Vec::with_capacity(self.txins.len());
        for idx in 0..self.txins.len() {
            let sig_id = self.txins[idx].get_signature_id();
            let spend_data = self.txins[idx].get_tweak_data();
            let sig_owner = sig_id.get_deposit_sig_owner()?;
            match (sig_owner, needed_entity) {
                (
                    DepositSigKeyOwner::OperatorSharedDeposit(sighash_type),
                    EntityType::OperatorDeposit,
                )
                | (
                    DepositSigKeyOwner::NofnSharedDeposit(sighash_type),
                    EntityType::VerifierDeposit,
                )
                | (
                    DepositSigKeyOwner::OperatorSharedSetup(sighash_type),
                    EntityType::OperatorSetup,
                ) => {
                    sighashes.push((
                        self.calculate_sighash_txin(idx, sighash_type)?,
                        partial_signature_info.complete(sig_id, spend_data),
                    ));
                }
                _ => {}
            }
        }
        Ok(sighashes)
    }

    #[cfg(test)]
    /// Returns the previous output (TxOut) for the specified input
    pub fn get_input_txout(&self, input_idx: usize) -> &TxOut {
        self.txins[input_idx].get_spendable().get_prevout()
    }
}

impl TxHandler<Signed> {
    /// Encodes the signed transaction as a raw byte vector.
    pub fn encode_tx(&self) -> RawSignedTx {
        RawSignedTx {
            raw_tx: bitcoin::consensus::encode::serialize(self.get_cached_tx()),
        }
    }
}

impl TxHandler<Unsigned> {
    /// Promotes an unsigned handler to a signed handler, checking that all witnesses are present.
    ///
    /// # Returns
    /// A [`TxHandler<Signed>`] if all witnesses are present, or a [`BridgeError`] if not.
    pub fn promote(self) -> Result<TxHandler<Signed>, BridgeError> {
        if self.txins.iter().any(|s| s.get_witness().is_none()) {
            return Err(eyre::eyre!("Missing witness data").into());
        }

        Ok(TxHandler {
            transaction_type: self.transaction_type,
            txins: self.txins,
            txouts: self.txouts,
            cached_tx: self.cached_tx,
            cached_txid: self.cached_txid,
            phantom: PhantomData::<Signed>,
        })
    }

    /// Sets the witness for a script path spend input.
    ///
    /// # Arguments
    /// * `script_inputs` - The inputs to the tapscript.
    /// * `txin_index` - The input index.
    /// * `script_index` - The script index in the input's script list.
    ///
    /// # Returns
    /// Ok(()) if successful, or a [`BridgeError`] if not.
    pub fn set_p2tr_script_spend_witness<T: AsRef<[u8]>>(
        &mut self,
        script_inputs: &[T],
        txin_index: usize,
        script_index: usize,
    ) -> Result<(), BridgeError> {
        let txin = self
            .txins
            .get_mut(txin_index)
            .ok_or(TxError::TxInputNotFound)?;

        if txin.get_witness().is_some() {
            return Err(TxError::WitnessAlreadySet.into());
        }

        let script = txin
            .get_spendable()
            .get_scripts()
            .get(script_index)
            .ok_or_else(|| {
                eyre::eyre!("Could not find script {script_index} in input {txin_index}")
            })?
            .to_script_buf();

        let spend_control_block = txin
            .get_spendable()
            .get_spend_info()
            .as_ref()
            .ok_or(TxError::MissingSpendInfo)?
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or_eyre("Failed to find control block for script")?;

        let mut witness = Witness::new();
        script_inputs
            .iter()
            .for_each(|element| witness.push(element));
        witness.push(script.clone());
        witness.push(spend_control_block.serialize());

        self.cached_tx.input[txin_index].witness = witness.clone();
        txin.set_witness(witness);

        Ok(())
    }

    /// Sets the witness for a key path spend input.
    ///
    /// # Arguments
    /// * `signature` - The Taproot signature.
    /// * `txin_index` - The input index.
    ///
    /// # Returns
    /// Ok(()) if successful, or a [`BridgeError`] if not.
    pub fn set_p2tr_key_spend_witness(
        &mut self,
        signature: &taproot::Signature,
        txin_index: usize,
    ) -> Result<(), BridgeError> {
        let txin = self
            .txins
            .get_mut(txin_index)
            .ok_or(TxError::TxInputNotFound)?;

        if txin.get_witness().is_none() {
            let witness = Witness::p2tr_key_spend(signature);
            txin.set_witness(witness.clone());
            self.cached_tx.input[txin_index].witness = witness;

            Ok(())
        } else {
            Err(TxError::WitnessAlreadySet.into())
        }
    }
}

#[derive(Debug, Clone)]
/// Builder for [`TxHandler`], allowing stepwise construction of inputs and outputs.
pub struct TxHandlerBuilder {
    transaction_type: TransactionType,
    version: Version,
    lock_time: absolute::LockTime,
    txins: Vec<SpentTxIn>,
    txouts: Vec<UnspentTxOut>,
}

impl TxHandlerBuilder {
    /// Creates a new [`TxHandlerBuilder`] for the specified transaction type.
    pub fn new(transaction_type: TransactionType) -> TxHandlerBuilder {
        TxHandlerBuilder {
            transaction_type,
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            txins: vec![],
            txouts: vec![],
        }
    }

    /// Sets the version for the transaction being built.
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Adds an input to the transaction being built.
    pub fn add_input(
        mut self,
        input_id: impl Into<SignatureId>,
        spendable: SpendableTxIn,
        spend_path: SpendPath,
        sequence: Sequence,
    ) -> Self {
        self.txins.push(SpentTxIn::from_spendable(
            input_id.into(),
            spendable,
            spend_path,
            sequence,
            None,
        ));

        self
    }

    /// Adds an input with a pre-specified witness to the transaction being built.
    pub fn add_input_with_witness(
        mut self,
        spendable: SpendableTxIn,
        sequence: Sequence,
        witness: Witness,
    ) -> Self {
        self.txins.push(SpentTxIn::from_spendable(
            NormalSignatureKind::NormalSignatureUnknown.into(),
            spendable,
            SpendPath::Unknown,
            sequence,
            Some(witness),
        ));

        self
    }

    /// Adds an output to the transaction being built.
    pub fn add_output(mut self, output: UnspentTxOut) -> Self {
        self.txouts.push(output);

        self
    }

    /// Finalizes the transaction, returning an unsigned [`TxHandler`].
    pub fn finalize(self) -> TxHandler<Unsigned> {
        // construct cached Transaction
        let tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self.txins.iter().map(|s| s.to_txin()).collect(),
            output: self.txouts.iter().map(|s| s.txout().clone()).collect(),
        };
        let txid = tx.compute_txid();

        // #[cfg(debug_assertions)]
        // {
        //     // txins >= txouts
        //     assert!(
        //         self.txins
        //             .iter()
        //             .map(|s| s.get_spendable().get_prevout().value)
        //             .sum::<bitcoin::Amount>()
        //             >= self
        //                 .txouts
        //                 .iter()
        //                 .map(|s| s.txout().value)
        //                 .sum::<bitcoin::Amount>(),
        //                 "Txins should be bigger than txouts"
        //     );
        // }
        TxHandler::<Unsigned> {
            transaction_type: self.transaction_type,
            txins: self.txins,
            txouts: self.txouts,
            cached_tx: tx,
            cached_txid: txid,
            phantom: PhantomData,
        }
    }

    /// Finalizes the transaction and promotes it to signed, checking all witnesses.
    pub fn finalize_signed(self) -> Result<TxHandler<Signed>, BridgeError> {
        self.finalize().promote()
    }
}

/// Removes a [`TxHandler`] from a map by transaction type, returning an error if not found.
///
/// # Arguments
/// * `txhandlers` - The map of transaction handlers.
/// * `tx_type` - The transaction type to remove.
///
/// # Returns
/// The removed [`TxHandler`], or a [`BridgeError`] if not found.
pub fn remove_txhandler_from_map<T: State>(
    txhandlers: &mut BTreeMap<TransactionType, TxHandler<T>>,
    tx_type: TransactionType,
) -> Result<TxHandler<T>, BridgeError> {
    txhandlers
        .remove(&tx_type)
        .ok_or(TxError::TxHandlerNotFound(tx_type).into())
}
