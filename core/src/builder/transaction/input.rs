use crate::bitvm_client;
use crate::builder::script::SpendableScript;
use crate::builder::sighash::SpendData;
use crate::builder::{address::create_taproot_address, script::SpendPath};
use crate::rpc::clementine::tagged_signature::SignatureId;
use bitcoin::{
    taproot::{LeafVersion, TaprootSpendInfo},
    Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, WitnessProgram, XOnlyPublicKey,
};
use std::sync::Arc;
use thiserror::Error;

pub type BlockHeight = u16;

#[derive(Debug, Clone)]
pub struct SpendableTxIn {
    /// The reference to the previous output that is being used as an input.
    previous_outpoint: OutPoint,
    prevout: TxOut, // locking script (taproot => op_1 op_pushbytes_32 tweaked pk)

    /// TODO: refactor later, decide on what's needed and what's redundant
    scripts: Vec<Arc<dyn SpendableScript>>,
    spendinfo: Option<TaprootSpendInfo>,
}

#[derive(Clone, Debug, Error, PartialEq)]
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

pub fn get_assert_utxo_vout(kickoff_idx: usize) -> usize {
    kickoff_idx + 4
}

pub fn get_watchtower_challenge_utxo_vout(watchtower_idx: usize) -> usize {
    2 * watchtower_idx + 4 + bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs()
}

pub fn get_challenge_ack_vout(watchtower_idx: usize) -> usize {
    get_watchtower_challenge_utxo_vout(watchtower_idx) + 1
}

impl SpendableTxIn {
    pub fn get_prevout(&self) -> &TxOut {
        &self.prevout
    }

    pub fn get_prev_outpoint(&self) -> &OutPoint {
        &self.previous_outpoint
    }

    #[inline(always)]
    pub fn new_partial(previous_output: OutPoint, prevout: TxOut) -> SpendableTxIn {
        Self::new(previous_output, prevout, vec![], None)
    }

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

    pub fn get_scripts(&self) -> &Vec<Arc<dyn SpendableScript>> {
        &self.scripts
    }

    pub fn get_spend_info(&self) -> &Option<TaprootSpendInfo> {
        &self.spendinfo
    }
    pub fn set_spend_info(&mut self, spendinfo: Option<TaprootSpendInfo>) {
        self.spendinfo = spendinfo;
        #[cfg(debug_assertions)]
        self.check().expect("spendinfo is invalid in debug mode");
    }

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
    spend_path: SpendPath,
    input_id: SignatureId,
}

impl SpentTxIn {
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

    pub fn get_spendable(&self) -> &SpendableTxIn {
        &self.spendable
    }

    pub fn get_spend_path(&self) -> SpendPath {
        self.spend_path
    }

    pub fn get_spend_data(&self) -> SpendData {
        match self.spend_path {
            SpendPath::ScriptSpend(_) => SpendData::ScriptPath,
            SpendPath::KeySpend => {
                let spendinfo = self.spendable.get_spend_info();
                match spendinfo {
                    Some(spendinfo) => SpendData::KeyPath(spendinfo.merkle_root()),
                    None => SpendData::Unknown,
                }
            }
            SpendPath::Unknown => SpendData::Unknown,
        }
    }

    pub fn get_witness(&self) -> &Option<Witness> {
        &self.witness
    }

    pub fn get_signature_id(&self) -> SignatureId {
        self.input_id
    }

    pub fn set_witness(&mut self, witness: Witness) {
        self.witness = Some(witness);
    }

    // pub fn get_sequence(&self) -> Sequence {
    //     self.sequence
    // }

    // pub fn set_sequence(&mut self, sequence: Sequence) {
    //     self.sequence = sequence;
    // }

    pub fn to_txin(&self) -> TxIn {
        TxIn {
            previous_output: self.spendable.previous_outpoint,
            sequence: self.sequence,
            script_sig: ScriptBuf::default(),
            witness: self.witness.clone().unwrap_or_default(),
        }
    }
}
