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
pub struct Signed;
#[derive(Debug, Clone)]
pub struct Unsigned;

// impl State for PartialInputs {}
impl State for Unsigned {}
impl State for Signed {}
pub type SighashCalculator<'a> =
    Box<dyn FnOnce(TapSighashType) -> Result<TapSighash, BridgeError> + 'a>;

impl<T: State> TxHandler<T> {
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
        )) // TODO: Can we get rid of clones?
    }

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

    pub fn get_signature_id(&self, idx: usize) -> Result<SignatureId, BridgeError> {
        let txin = self.txins.get(idx).ok_or(TxError::TxInputNotFound)?;
        Ok(txin.get_signature_id())
    }

    pub fn get_transaction_type(&self) -> TransactionType {
        self.transaction_type
    }

    pub fn get_cached_tx(&self) -> &Transaction {
        &self.cached_tx
    }

    pub fn get_txid(&self) -> &Txid {
        // Not sure if this should be public
        &self.cached_txid
    }

    fn get_sighash_calculator(
        &self,
        idx: usize,
    ) -> impl FnOnce(TapSighashType) -> Result<TapSighash, BridgeError> + '_ {
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
    /// # Parameters
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

    pub fn calculate_pubkey_spend_sighash(
        &self,
        txin_index: usize,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, BridgeError> {
        let prevouts_vec: Vec<&TxOut> = self
            .txins
            .iter()
            .map(|s| s.get_spendable().get_prevout())
            .collect(); // TODO: Maybe there is a better way to do this
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

        // TODO: remove copy here
        self.calculate_script_spend_sighash(txin_index, &script, sighash_type)
    }

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
        let sig_hash = sighash_cache
            .taproot_script_spend_signature_hash(txin_index, prevouts, leaf_hash, sighash_type)
            .wrap_err("Failed to calculate taproot sighash for script spend")?;

        Ok(sig_hash)
    }

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
    pub fn get_input_txout(&self, input_idx: usize) -> &TxOut {
        self.txins[input_idx].get_spendable().get_prevout()
    }
}

impl TxHandler<Signed> {
    pub fn encode_tx(&self) -> RawSignedTx {
        RawSignedTx {
            raw_tx: bitcoin::consensus::encode::serialize(self.get_cached_tx()),
        }
    }
}

impl TxHandler<Unsigned> {
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
pub struct TxHandlerBuilder {
    /// TODO: Document
    transaction_type: TransactionType,
    version: Version,
    lock_time: absolute::LockTime,
    txins: Vec<SpentTxIn>,
    txouts: Vec<UnspentTxOut>,
}

impl TxHandlerBuilder {
    pub fn new(transaction_type: TransactionType) -> TxHandlerBuilder {
        TxHandlerBuilder {
            transaction_type,
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

    pub fn finalize_signed(self) -> Result<TxHandler<Signed>, BridgeError> {
        self.finalize().promote()
    }
}

pub fn remove_txhandler_from_map<T: State>(
    txhandlers: &mut BTreeMap<TransactionType, TxHandler<T>>,
    tx_type: TransactionType,
) -> Result<TxHandler<T>, BridgeError> {
    txhandlers
        .remove(&tx_type)
        .ok_or(TxError::TxHandlerNotFound(tx_type).into())
}
