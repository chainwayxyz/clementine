use std::any::Any;
use std::marker::PhantomData;

use crate::builder::address::create_taproot_address;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::rpc::clementine::Outpoint;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{absolute, Address, Amount, OutPoint, Script, Sequence, Transaction, TxIn, Witness, XOnlyPublicKey};
use bitcoin::{
    taproot::TaprootSpendInfo, ScriptBuf, TapLeafHash, TapSighash, TapSighashType, TxOut, Txid,
};
use sqlx::Postgres;

/// Verbose information about a transaction.
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
struct Signed;
#[derive(Debug, Clone)]
struct Unsigned;

impl State for Unsigned {}
impl State for Signed {}

impl TxHandler<Unsigned> {
    fn get_txid(&self) -> &Txid {
        &self.cached_txid
    }

    fn calculate_sighash(&self, input_idx: usize, sighash_type: TapSighashType) -> Option<()> {
        let sighash_cache = SighashCache::new(&self.cached_tx);

        let prevouts = &match sighash_type {
            Some(TapSighashType::SinglePlusAnyoneCanPay)
            | Some(TapSighashType::AllPlusAnyoneCanPay)
            | Some(TapSighashType::NonePlusAnyoneCanPay) => {
                bitcoin::sighash::Prevouts::One(txin_index, self.prevouts[txin_index].clone())
            }
            _ => bitcoin::sighash::Prevouts::All(&self.prevouts),
        };

        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            txin_index,
            prevouts,
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        Ok(sig_hash)
    }

    fn promote(self) -> Result<TxHandler<Signed>, ()> {
        if self.txins.iter().any(|s| s.witness.is_none()) {
            return Err(());
        }

        todo!()
        // TxHandler<Signed> {
        //     ..self
        // }
    }
}

impl TxHandler<Signed> {
    // ...
}

#[derive(Debug, Clone)]
pub struct TxHandlerBuilder {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    version: Version,
    lock_time: absolute::LockTime,
    txins: Vec<SpentTxIn>,
    txouts: Vec<UnspentTxOut>,
}
fn test() {
    TxHandlerBuilder::new()
        .with_version(Version(3))
        .add_input(s)
        .add_output()
        .add_output()
        .finalize()()
}

impl TxHandlerBuilder {
    fn new() -> TxHandlerBuilder {
        TxHandlerBuilder {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
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
    fn finalize(self) -> TxHandler {
        // construct cached Transaction

        todo!()
    }
}

impl SpendableTxIn {
    fn spend_to_witness(
        &self,
        taproot_script_index: usize,
        script_input: &[u8],
        script_contents: &Script,
    ) -> Witness {
    }
}

#[derive(Debug, Clone)]
struct SpendableTxIn {
    /// The reference to the previous output that is being used as an input.
    previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to be accepted.
    script_sig: ScriptBuf,
    prevout: TxOut, // locking script (taproot => op_2 op_pushbytes_32 tweaked pk)

    /// TODO: refactor later
    scripts: Vec<ScriptBuf>,
    spendinfo: TaprootSpendInfo,
}

impl SpendableTxIn {
    fn new() -> SpendableTxIn {}
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
    spendinfo: TaprootSpendInfo,
}

impl UnspentTxOut {
    fn new(amount: Amount, address: &Address, spendinfo: TaprootSpendInfo) -> UnspentTxOut {
        UnspentTxOut {
            txout: TxOut { value: amount, script_pubkey: address.script_pubkey()},
            spendinfo
        }
    }
}

impl<T> TxHandler<T> {
    fn get_output_as_spendable(&self, idx: usize) -> SpendableTxIn {
        todo!()
    }
}

fn test() {
    let op_collat = SpendableTxIn::new();
    let out1_amt = Amount::from_sat(10);
    let (out1_addr, out1_spend) = create_taproot_address(scripts, internal_key, network)

    let txhandler = TxHandlerBuilder::new()
        .add_input(op_collat)
        .define_output(UnspentTxOut::new(out1_amt, &out1_addr, out1_spend))
        .finalize();

    txhandler
}

fn in_the_chain(txhanlder: TxHandler<impl State>) {
    let our_tx = TxHandlerBuilder::new().add_input(txhanlder.get_output_as_spendable(0), Sequence::ENABLE_RBF_NO_LOCKTIME).define_output(UnspentTxOut::new(amount, taproot_spend_info))


}

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

impl TxHandler {
    /// Calculates the sighash for a given transaction input for key spend path.
    /// See [`bitcoin::sighash::SighashCache::taproot_key_spend_signature_hash`] for more details.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn calculate_pubkey_spend_sighash(
        &mut self,
        txin_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<TapSighash, BridgeError> {
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&self.tx);
        let prevouts = &match sighash_type {
            Some(TapSighashType::SinglePlusAnyoneCanPay)
            | Some(TapSighashType::AllPlusAnyoneCanPay)
            | Some(TapSighashType::NonePlusAnyoneCanPay) => {
                bitcoin::sighash::Prevouts::One(txin_index, self.prevouts[txin_index].clone())
            }
            _ => bitcoin::sighash::Prevouts::All(&self.prevouts),
        };

        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            txin_index,
            prevouts,
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        Ok(sig_hash)
    }

    /// Calculates the sighash for a given transaction input for script spend path.
    /// See [`bitcoin::sighash::SighashCache::taproot_script_spend_signature_hash`] for more details.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn calculate_script_spend_sighash(
        &mut self,
        txin_index: usize,
        script_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<TapSighash, BridgeError> {
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut self.tx);

        let prevouts = &match sighash_type {
            Some(TapSighashType::SinglePlusAnyoneCanPay)
            | Some(TapSighashType::AllPlusAnyoneCanPay)
            | Some(TapSighashType::NonePlusAnyoneCanPay) => {
                bitcoin::sighash::Prevouts::One(txin_index, self.prevouts[txin_index].clone())
            }
            _ => bitcoin::sighash::Prevouts::All(&self.prevouts),
        };
        let leaf_hash = TapLeafHash::from_script(
            self.prev_scripts
                .get(txin_index)
                .ok_or(BridgeError::NoScriptsForTxIn(txin_index))?
                .get(script_index)
                .ok_or(BridgeError::NoScriptAtIndex(script_index))?,
            LeafVersion::TapScript,
        );
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            prevouts,
            leaf_hash,
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        Ok(sig_hash)
    }
}
