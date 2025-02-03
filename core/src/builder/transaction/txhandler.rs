use crate::errors::BridgeError;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, LeafVersion};
use bitcoin::transaction::Version;
use bitcoin::{absolute, OutPoint, Script, Sequence, Transaction, TxIn, Witness};
use bitcoin::{
    taproot::TaprootSpendInfo, ScriptBuf, TapLeafHash, TapSighash, TapSighashType, TxOut, Txid,
};
use std::marker::PhantomData;

use super::input::{SpendableTxIn, SpentTxIn};
use super::output::UnspentTxOut;

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

#[derive(Debug, Clone)]
pub enum Signed {}
#[derive(Debug, Clone)]
pub enum Unsigned {}

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
    /// Constructs the witness for a script path spend of a transaction input.
    ///
    /// # Arguments
    ///
    /// - `self`: The transaction to add the witness to.
    /// - `script_inputs`: The inputs to the tapscript
    /// - `txin_index`: The index of the transaction input to add the witness to.
    /// - `script_index`: The script index in the input UTXO's Taproot script tree. This is used to get the control block and script contents of the script being spent.
    pub fn set_p2tr_script_spend_witness<U: AsRef<[u8]>>(
        &mut self,
        txin_index: usize,
        script_index: usize,
        script_inputs: &[U],
    ) -> Result<(), BridgeError> {
        let txin = self
            .txins
            .get_mut(txin_index)
            .ok_or(BridgeError::TxInputNotFound)?;

        if txin.get_witness().is_some() {
            return Err(BridgeError::WitnessAlreadySet);
        }

        let spendable = txin.get_spendable();
        let script = spendable
            .get_scripts()
            .get(script_index)
            .ok_or(BridgeError::TaprootScriptError)?;

        let spend_control_block = spendable
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

    pub fn set_p2tr_key_spend_witness(
        &mut self,
        signature: &taproot::Signature,
        txin_index: usize,
    ) -> Result<(), BridgeError> {
        let txin = self
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

    pub fn calculate_script_spend_sighash(
        &mut self,
        txin_index: usize,
        spend_script: &Script,
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
        let leaf_hash = TapLeafHash::from_script(spend_script, LeafVersion::TapScript);
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            prevouts,
            leaf_hash,
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        Ok(sig_hash)
    }

    fn promote(self) -> Result<TxHandler<Signed>, BridgeError> {
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

impl TxHandler<Signed> {
    // ...
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

    pub fn add_input(
        mut self,
        spendable: SpendableTxIn,
        sequence: Sequence,
        witness: Option<Witness>,
    ) -> Self {
        self.txins
            .push(SpentTxIn::from_spendable(spendable, sequence, witness));

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
}

// fn test() {
//     let op_collat = SpendableTxIn::new();
//     let out1_amt = Amount::from_sat(10);
//     let (out1_addr, out1_spend) = create_taproot_address(scripts, internal_key, network)

//     let txhandler = TxHandlerBuilder::new()
//         .add_input(op_collat)
//         .define_output(UnspentTxOut::new(out1_amt, &out1_addr, out1_spend))
//         .finalize();

//     txhandler
// }

// fn in_the_chain(txhanlder: TxHandler<impl State>) {
//     let our_tx = TxHandlerBuilder::new().add_input(txhanlder.get_spendable_output(0), Sequence::ENABLE_RBF_NO_LOCKTIME).define_output(UnspentTxOut::new(amount, taproot_spend_info))

// }

// enum ScriptType {
//     ChecksigNofN,
//     ComplicatedScript,
// }

// struct TaggedScript(ScriptBuf, ScriptType);

// TxHandler + UTXO => SpendableTxIn

// createtxhandler -> pass it around -> another tx handler constructor uses output of previous one

// struct ChecksigNofN(XOnlyPublicKey);

// struct ComplicatedScript();

// struct RelativeTimeLock {
//     block_count: u16,
// }
// trait IntoScriptBuf<T>: Any {
//     fn into_script_buf(self: Box<Self>, params: T) -> ScriptBuf;
// }

// impl IntoScriptBuf<u8> for ChecksigNofN {
//     fn into_script_buf(self: Box<Self>, params: u8) -> ScriptBuf {
//         todo!()
//     }
// }

// impl IntoScriptBuf<u8> for RelativeTimeLock {
//     fn into_script_buf(self: Box<Self>, params: u8) -> ScriptBuf {
//         todo!()
//     }
// }
// fn test() {
//     let mut prev_scripts: Vec<Box<dyn IntoScriptBuf<u8>>> = Vec::new();

//     // let id = TypeId::<ChecksigNofN>::type_id();
//     prev_scripts.push(Box::new(RelativeTimeLock { block_count: 1 }));
//     prev_scripts.push(Box::new(ChecksigNofN(
//         XOnlyPublicKey::from_slice(&[]).expect("."),
//     )));

//     let k = prev_scripts
//         .iter()
//         .find(|s| (s as &dyn Any).downcast_ref::<ComplicatedScript>().is_some());

//     let script_buf_arr: Vec<ScriptBuf> = prev_scripts
//         .into_iter()
//         .map(|s| s.into_script_buf(0))
//         .collect::<Vec<_>>();

//     ()
// }
