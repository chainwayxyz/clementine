use crate::errors::BridgeError;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, LeafVersion};
use bitcoin::transaction::Version;
use bitcoin::{absolute, OutPoint, Script, Sequence, Transaction, TxIn, Witness};
use bitcoin::{
    taproot::TaprootSpendInfo, ScriptBuf, TapLeafHash, TapSighash, TapSighashType, TxOut, Txid,
};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct TxHandler<T: State> {
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

impl TxHandler<Unsigned> {
    fn get_txid(&self) -> &Txid {
        &self.cached_txid
    }

    pub fn calculate_pubkey_spend_sighash(
        &self,
        txin_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<TapSighash, BridgeError> {
        let prevouts_vec: Vec<_> = self.txins.iter().map(|s| &s.spendable.prevout).collect(); // TODO: Maybe there is a better way to do this
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
        let prevouts_vec: Vec<_> = self.txins.iter().map(|s| &s.spendable.prevout).collect(); // TODO: Maybe there is a better way to do this
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
        if self.txins.iter().any(|s| s.witness.is_none()) {
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
    fn new() -> TxHandlerBuilder {
        TxHandlerBuilder {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            txins: vec![],
            txouts: vec![],
        }
    }

    fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    fn add_input(mut self, spendable: SpendableTxIn, sequence: Sequence) -> Self {
        self.txins.push(SpentTxIn {
            spendable,
            sequence,
            witness: None,
        });

        self
    }

    fn add_output(mut self, output: UnspentTxOut) -> Self {
        self.txouts.push(output);

        self
    }

    /// TODO: output likely fallible
    fn finalize(self) -> TxHandler<Unsigned> {
        // construct cached Transaction
        let tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self
                .txins
                .iter()
                .map(|s| TxIn {
                    previous_output: s.spendable.previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                })
                .collect(),
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

impl SpendableTxIn {
    // TODO: Find out what is needed here
}

#[derive(Debug, Clone)]
struct SpendableTxIn {
    /// The reference to the previous output that is being used as an input.
    previous_output: OutPoint,
    prevout: TxOut, // locking script (taproot => op_1 op_pushbytes_32 tweaked pk)

    /// TODO: refactor later
    scripts: Vec<ScriptBuf>,
    spendinfo: TaprootSpendInfo,
}

impl SpendableTxIn {
    fn new() -> SpendableTxIn {
        todo!()
    }
}

#[derive(Debug, Clone)]
struct SpentTxIn {
    spendable: SpendableTxIn,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behavior cannot be enforced.
    sequence: Sequence,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other
    /// (de)serialization routines.
    witness: Option<Witness>,
}

#[derive(Debug, Clone)]
struct UnspentTxOut {
    txout: TxOut,
    scripts: Vec<ScriptBuf>, // TODO: Remove either scripts or spendinfo
    spendinfo: TaprootSpendInfo,
}

impl UnspentTxOut {
    fn new(txout: TxOut, scripts: Vec<ScriptBuf>, spendinfo: TaprootSpendInfo) -> UnspentTxOut {
        UnspentTxOut {
            txout,
            scripts,
            spendinfo,
        }
    }
}

impl TxHandler<Unsigned> {
    fn get_output_as_spendable(&self, idx: usize) -> SpendableTxIn {
        SpendableTxIn {
            previous_output: OutPoint {
                txid: self.cached_txid,
                vout: idx as u32,
            },
            prevout: self.txouts[idx].txout.clone(),
            scripts: self.txouts[idx].scripts.clone(),
            spendinfo: self.txouts[idx].spendinfo.clone(),
        }
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
        tx: &mut TxHandler<Unsigned>,
        script_inputs: &[T],
        txin_index: usize,
        script_index: usize,
    ) -> Result<(), BridgeError> {
        let txin = tx
            .txins
            .get_mut(txin_index)
            .ok_or(BridgeError::TxInputNotFound)?;

        if txin.witness.is_some() {
            return Err(BridgeError::WitnessAlreadySet);
        }

        let script = txin
            .spendable
            .scripts
            .get(script_index)
            .ok_or(BridgeError::TaprootScriptError)?;

        let spend_control_block = txin
            .spendable
            .spendinfo
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(BridgeError::ControlBlockError)?;

        let mut witness = Witness::new();
        script_inputs
            .iter()
            .for_each(|element| witness.push(element));
        witness.push(script.clone());
        witness.push(spend_control_block.serialize());

        txin.witness = Some(witness);

        Ok(())
    }

    pub fn set_p2tr_key_spend_witness(
        tx: &mut TxHandler<Unsigned>,
        signature: &taproot::Signature,
        txin_index: usize,
    ) -> Result<(), BridgeError> {
        let witness = &mut tx
            .txins
            .get_mut(txin_index)
            .ok_or(BridgeError::TxInputNotFound)?
            .witness;

        witness
            .is_none()
            .then(|| *witness = Some(Witness::p2tr_key_spend(signature)))
            .ok_or(BridgeError::WitnessAlreadySet)
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
//     let our_tx = TxHandlerBuilder::new().add_input(txhanlder.get_output_as_spendable(0), Sequence::ENABLE_RBF_NO_LOCKTIME).define_output(UnspentTxOut::new(amount, taproot_spend_info))

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

// use crate::errors::BridgeError;
// use bitcoin::sighash::SighashCache;
// use bitcoin::taproot::LeafVersion;
// use bitcoin::{
//     taproot::TaprootSpendInfo, ScriptBuf, TapLeafHash, TapSighash, TapSighashType, TxOut, Txid,
// };

// /// Verbose information about a transaction.
// #[derive(Debug, Clone)]
// pub struct TxHandler {
//     /// Transaction itself.
//     pub tx: bitcoin::Transaction,
//     /// Txid of the transaction, saved here to not repeatedly calculate it.
//     pub txid: Txid,
//     /// Previous outputs in [`TxOut`] format.
//     pub prevouts: Vec<TxOut>,
//     /// Taproot scripts for each previous output.
//     pub prev_scripts: Vec<Vec<ScriptBuf>>,
//     /// Taproot spend information for each previous output.
//     pub prev_taproot_spend_infos: Vec<Option<TaprootSpendInfo>>,
//     /// Taproot scripts for each tx output.
//     pub out_scripts: Vec<Vec<ScriptBuf>>,
//     /// Taproot spend information for each tx output.
//     pub out_taproot_spend_infos: Vec<Option<TaprootSpendInfo>>,
// }

// impl TxHandler {
//     /// Calculates the sighash for a given transaction input for key spend path.
//     /// See [`bitcoin::sighash::SighashCache::taproot_key_spend_signature_hash`] for more details.
//     #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
//     pub fn calculate_pubkey_spend_sighash(
//         &mut self,
//         txin_index: usize,
//         sighash_type: Option<TapSighashType>,
//     ) -> Result<TapSighash, BridgeError> {
//         let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
//             SighashCache::new(&mut self.tx);
//         let prevouts = &match sighash_type {
//             Some(TapSighashType::SinglePlusAnyoneCanPay)
//             | Some(TapSighashType::AllPlusAnyoneCanPay)
//             | Some(TapSighashType::NonePlusAnyoneCanPay) => {
//                 bitcoin::sighash::Prevouts::One(txin_index, self.prevouts[txin_index].clone())
//             }
//             _ => bitcoin::sighash::Prevouts::All(&self.prevouts),
//         };

//         let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
//             txin_index,
//             prevouts,
//             sighash_type.unwrap_or(TapSighashType::Default),
//         )?;

//         Ok(sig_hash)
//     }

//     /// Calculates the sighash for a given transaction input for script spend path.
//     /// See [`bitcoin::sighash::SighashCache::taproot_script_spend_signature_hash`] for more details.
//     #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
//     pub fn calculate_script_spend_sighash(
//         &mut self,
//         txin_index: usize,
//         script_index: usize,
//         sighash_type: Option<TapSighashType>,
//     ) -> Result<TapSighash, BridgeError> {
//         let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
//             SighashCache::new(&mut self.tx);

//         let prevouts = &match sighash_type {
//             Some(TapSighashType::SinglePlusAnyoneCanPay)
//             | Some(TapSighashType::AllPlusAnyoneCanPay)
//             | Some(TapSighashType::NonePlusAnyoneCanPay) => {
//                 bitcoin::sighash::Prevouts::One(txin_index, self.prevouts[txin_index].clone())
//             }
//             _ => bitcoin::sighash::Prevouts::All(&self.prevouts),
//         };
//         let leaf_hash = TapLeafHash::from_script(
//             self.prev_scripts
//                 .get(txin_index)
//                 .ok_or(BridgeError::NoScriptsForTxIn(txin_index))?
//                 .get(script_index)
//                 .ok_or(BridgeError::NoScriptAtIndex(script_index))?,
//             LeafVersion::TapScript,
//         );
//         let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
//             txin_index,
//             prevouts,
//             leaf_hash,
//             sighash_type.unwrap_or(TapSighashType::Default),
//         )?;

//         Ok(sig_hash)
//     }
// }
