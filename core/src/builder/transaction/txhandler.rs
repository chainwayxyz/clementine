use crate::errors::BridgeError;
use crate::utils::{self, SECP};
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, LeafVersion};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute, Amount, OutPoint, Script, Sequence, TapNodeHash, Transaction, TxIn, Witness,
};
use bitcoin::{
    taproot::TaprootSpendInfo, ScriptBuf, TapLeafHash, TapSighash, TapSighashType, TxOut, Txid,
};
use std::marker::PhantomData;

use super::input::{SpendableTxIn, SpentTxIn};
use super::output::UnspentTxOut;

pub const DEFAULT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

#[derive(Debug, Clone)]
pub struct TxHandler<T: State = Unsigned> {
    txins: Vec<SpentTxIn>,
    txouts: Vec<UnspentTxOut>,

    /// Cached and immutable, same as other fields
    cached_tx: bitcoin::Transaction,
    cached_txid: bitcoin::Txid,

    phantom: PhantomData<T>,
}

trait State: Clone + std::fmt::Debug {}

// #[derive(Debug, Clone)]
// pub struct PartialInputs;
#[derive(Debug, Clone)]
pub struct Signed;
#[derive(Debug, Clone)]
pub struct Unsigned;

// impl State for PartialInputs {}
impl State for Unsigned {}
impl State for Signed {}

impl<T: State> TxHandler<T> {
    pub fn get_spendable_output(&self, idx: usize) -> Option<SpendableTxIn> {
        let txout = self.txouts.get(idx)?;
        Some(
            SpendableTxIn::from_checked(
                OutPoint {
                    txid: self.cached_txid,
                    vout: idx as u32,
                },
                txout.txout.clone(),
                txout.scripts.clone(),
                txout.spendinfo.clone(),
            )
            .unwrap(),
        ) // TODO: Can we get rid of clones?
    }
}

impl TxHandler<Unsigned> {
    pub fn get_txid(&self) -> &Txid {
        // Not sure if this should be public
        &self.cached_txid
    }

    pub fn calculate_pubkey_spend_sighash(
        &self,
        txin_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<TapSighash, BridgeError> {
        let prevouts_vec: Vec<&TxOut> = self
            .txins
            .iter()
            .map(|s| s.get_spendable().get_prevout())
            .collect(); // TODO: Maybe there is a better way to do this
        let mut sighash_cache: SighashCache<&bitcoin::Transaction> =
            SighashCache::new(&self.cached_tx);
        let prevouts = &match sighash_type {
            Some(TapSighashType::SinglePlusAnyoneCanPay)
            | Some(TapSighashType::AllPlusAnyoneCanPay)
            | Some(TapSighashType::NonePlusAnyoneCanPay) => {
                bitcoin::sighash::Prevouts::One(txin_index, prevouts_vec[txin_index])
            }
            _ => bitcoin::sighash::Prevouts::All(&prevouts_vec),
        };

        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            txin_index,
            prevouts,
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        Ok(sig_hash)
    }

    pub fn calculate_script_spend_sighash_indexed(
        &mut self,
        txin_index: usize,
        spend_script_idx: usize,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, BridgeError> {
        let script = self
            .txins
            .get(txin_index)
            .ok_or(BridgeError::TxInputNotFound)?
            .get_spendable()
            .get_scripts()
            .get(spend_script_idx)
            .ok_or(BridgeError::ScriptNotFound(spend_script_idx))?;

        // TODO: remove copy here
        self.calculate_script_spend_sighash(txin_index, &script.clone(), sighash_type)
    }

    pub fn calculate_script_spend_sighash(
        &mut self,
        txin_index: usize,
        spend_script: &Script,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, BridgeError> {
        let prevouts_vec: Vec<&TxOut> = self
            .txins
            .iter()
            .map(|s| s.get_spendable().get_prevout())
            .collect(); // TODO: Maybe there is a better way to do this
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
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            prevouts,
            leaf_hash,
            sighash_type,
        )?;

        Ok(sig_hash)
    }

    pub fn promote(self) -> Result<TxHandler<Signed>, BridgeError> {
        if self.txins.iter().any(|s| s.get_witness().is_none()) {
            return Err(BridgeError::MissingWitnessData);
        }

        Ok(TxHandler {
            txins: self.txins,
            txouts: self.txouts,
            cached_tx: self.cached_tx,
            cached_txid: self.cached_txid,
            phantom: PhantomData::<Signed>,
        })
    }
}

impl TxHandler<Unsigned> {
    pub fn get_output_as_spendable(&self, idx: usize) -> SpendableTxIn {
        SpendableTxIn::from(
            OutPoint {
                txid: self.cached_txid,
                vout: idx as u32,
            },
            self.txouts[idx].txout.clone(),
            self.txouts[idx].scripts.clone(),
            self.txouts[idx].spendinfo.clone(),
        )
    }
    /// Constructs the witness for a script path spend of a transaction input.
    ///
    /// # Arguments
    ///
    /// - `tx`: The transaction to add the witness to.
    /// - `script_inputs`: The inputs to the tapscript
    /// - `txin_index`: The index of the transaction input to add the witness to.
    /// - `script_index`: The script index in the input UTXO's Taproot script tree. This is used to get the control block and script contents of the script being spent.
    pub fn set_p2tr_script_spend_witness<T: AsRef<[u8]>>(
        &mut self,
        script_inputs: &[T],
        txin_index: usize,
        script_index: usize,
    ) -> Result<(), BridgeError> {
        let txin = self
            .txins
            .get_mut(txin_index)
            .ok_or(BridgeError::TxInputNotFound)?;

        if txin.get_witness().is_some() {
            return Err(BridgeError::WitnessAlreadySet);
        }

        let script = txin
            .get_spendable()
            .get_scripts()
            .get(script_index)
            .ok_or(BridgeError::TaprootScriptError)?;

        let spend_control_block = txin
            .get_spendable()
            .get_spend_info()
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(BridgeError::ControlBlockError)?;

        let mut witness = Witness::new();
        script_inputs
            .iter()
            .for_each(|element| witness.push(element));
        witness.push(script.clone());
        witness.push(spend_control_block.serialize());

        txin.set_witness(witness);

        Ok(())
    }

    // Candidate refactoring
    // pub fn set_p2tr_script_spend_witness_find<T: AsRef<[u8]>>(
    //     &mut self,
    //     txin_index: usize,
    //     script_finder: impl Fn(&&Scripts) -> bool,
    //     script_spender: impl FnOnce(&Scripts) -> Witness,
    // ) -> Result<(), BridgeError> {
    //     let txin = self
    //         .txins
    //         .get_mut(txin_index)
    //         .ok_or(BridgeError::TxInputNotFound)?;

    //     if txin.get_witness().is_some() {
    //         return Err(BridgeError::WitnessAlreadySet);
    //     }

    //     let script = txin
    //         .get_witness()
    //         .get_scripts()
    //         .iter()
    //         .find(script_finder)
    //         .ok_or(BridgeError::TaprootScriptError)?;

    //     let spend_control_block = txin
    //         .get_spendable()
    //         .get_spend_info()
    //         .control_block(&((*script).to_script_buf(), LeafVersion::TapScript))
    //         .ok_or(BridgeError::ControlBlockError)?;

    //     let witness = script_spender(script);

    //     txin.set_witness(witness);

    //     Ok(())
    // }

    pub fn set_p2tr_key_spend_witness(
        tx: &mut TxHandler<Unsigned>,
        signature: &taproot::Signature,
        txin_index: usize,
    ) -> Result<(), BridgeError> {
        let txin = tx
            .txins
            .get_mut(txin_index)
            .ok_or(BridgeError::TxInputNotFound)?;

        if txin.get_witness().is_none() {
            txin.set_witness(Witness::p2tr_key_spend(signature));

            Ok(())
        } else {
            Err(BridgeError::WitnessAlreadySet)
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxHandlerBuilder {
    /// TODO: Document
    version: Version,
    lock_time: absolute::LockTime,
    txins: Vec<SpentTxIn>,
    txouts: Vec<UnspentTxOut>,
}

impl TxHandlerBuilder {
    pub fn new() -> TxHandlerBuilder {
        TxHandlerBuilder {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            txins: vec![],
            txouts: vec![],
        }
    }

    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    pub fn add_input_with_witness(
        mut self,
        spendable: SpendableTxIn,
        sequence: Sequence,
        witness: Witness,
    ) -> Self {
        self.txins.push(SpentTxIn::from_spendable(
            spendable,
            sequence,
            Some(witness),
        ));

        self
    }

    pub fn add_input(mut self, spendable: SpendableTxIn, sequence: Sequence) -> Self {
        self.txins
            .push(SpentTxIn::from_spendable(spendable, sequence, None));

        self
    }

    pub fn add_output(mut self, output: UnspentTxOut) -> Self {
        self.txouts.push(output);

        self
    }

    /// TODO: output likely fallible
    pub fn finalize(self) -> TxHandler<Unsigned> {
        // construct cached Transaction
        let tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self.txins.iter().map(|s| s.to_txin()).collect(),
            output: self.txouts.iter().map(|s| s.txout.clone()).collect(), // TODO: Get rid of .clone()
        };
        let txid = tx.compute_txid();
        TxHandler::<Unsigned> {
            txins: self.txins,
            txouts: self.txouts,
            cached_tx: tx,
            cached_txid: txid,
            phantom: PhantomData,
        }
    }

    fn finalize_signed(self) -> Result<TxHandler<Signed>, BridgeError> {
        self.finalize().promote()
    }
}
