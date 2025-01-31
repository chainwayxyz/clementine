use bitcoin::{taproot::{LeafVersion, TaprootSpendInfo}, witness, Address, Network, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, WitnessProgram};
use thiserror::{Error};
use std::fmt::Display;
pub type BlockHeight = u16;

pub struct TxInArgs(pub Vec<(OutPoint, Option<BlockHeight>)>);

impl From<Vec<OutPoint>> for TxInArgs {
    fn from(outpoints: Vec<OutPoint>) -> TxInArgs {
        TxInArgs(
            outpoints
                .into_iter()
                .map(|outpoint| (outpoint, None))
                .collect(),
        )
    }
}

impl From<Vec<(OutPoint, Option<BlockHeight>)>> for TxInArgs {
    fn from(value: Vec<(OutPoint, Option<BlockHeight>)>) -> TxInArgs {
        TxInArgs(value)
    }
}

/// Creates a Vec of TxIn from a TxInArgs (helper struct to represent args)
/// If only a Vec of OutPoints are provided there are no relative locktimes
/// If at least one TxIn requires a locktime, a Vec of (OutPoint, Option<u16>) is required
/// Option represents Some(locktime) or None if there is no locktime for that TxIn
pub fn create_tx_ins(tx_in_args: TxInArgs) -> Vec<TxIn> {
    tx_in_args
        .0
        .into_iter()
        .map(|(outpoint, height)| TxIn {
            previous_output: outpoint,
            sequence: height
                .map(Sequence::from_height)
                .unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME),
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct SpendableTxIn {
    /// The reference to the previous output that is being used as an input.
    previous_outpoint: OutPoint,
    prevout: TxOut, // locking script (taproot => op_1 op_pushbytes_32 tweaked pk)

    /// TODO: refactor later, decide on what's needed and what's redundant
    scripts: Vec<ScriptBuf>,
    spendinfo: TaprootSpendInfo,
}

#[derive(Clone,Debug,Error,PartialEq) ]
pub enum SpendableTxInError {
    #[error("The taproot spend info contains an incomplete merkle proof map. Some scripts are missing.")]
    IncompleteMerkleProofMap,

    #[error("The script_pubkey of the previous output does not match the expected script_pubkey for the taproot spending information.")]
    IncorrectScriptPubkey,

    #[error("Error creating a spendable txin: {0}")]
    Error(String)
}

impl SpendableTxIn {
    pub fn get_prevout(&self) -> &TxOut {
        &self.prevout
    }

    pub fn get_prev_outpoint(&self) -> &OutPoint {
        &self.previous_outpoint
    }

    pub fn from(previous_output: OutPoint, prevout: TxOut, scripts: Vec<ScriptBuf>, spendinfo: TaprootSpendInfo) -> SpendableTxIn {
        if cfg!(debug_assertions) {
            return Self::from_checked(previous_output, prevout, scripts, spendinfo).unwrap();
        }
        
        Self::from_unchecked(previous_output, prevout, scripts, spendinfo)
        
    }

    pub fn get_scripts(&self) -> &Vec<ScriptBuf> {
        &self.scripts
    }

    pub fn get_spend_info(&self) -> &TaprootSpendInfo {
        &self.spendinfo
    }

    pub fn from_checked(previous_output: OutPoint, prevout: TxOut, scripts: Vec<ScriptBuf>, spendinfo: TaprootSpendInfo) -> Result<SpendableTxIn, SpendableTxInError> {
        use SpendableTxInError::*;
        
        if  ScriptBuf::new_witness_program(&WitnessProgram::p2tr_tweaked(spendinfo.output_key())) != prevout.script_pubkey {
            return Err(IncorrectScriptPubkey);
        }

        if scripts.iter().any(|script| spendinfo.script_map().get(&(script.clone(), LeafVersion::TapScript)).is_none()) {
            return Err(IncompleteMerkleProofMap);
        }

        Ok(Self::from_unchecked(previous_output, prevout, scripts, spendinfo))
    }

    pub fn from_unchecked(previous_outpoint: OutPoint, prevout: TxOut, scripts: Vec<ScriptBuf>, spendinfo: TaprootSpendInfo) -> SpendableTxIn {
        SpendableTxIn {
            previous_outpoint: previous_outpoint,
            prevout,
            scripts,
            spendinfo,
        }
    }
}

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
}

impl SpentTxIn {
    pub fn from_spendable(spendable: SpendableTxIn, sequence: Sequence, witness: Option<Witness>) -> SpentTxIn {
        SpentTxIn {
            spendable,
            sequence,
            witness,
        }
    }

    pub fn get_spendable(&self) -> &SpendableTxIn {
        &self.spendable
    }

    pub fn get_witness(&self) -> Option<&Witness> {
        self.witness.as_ref()
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
            witness: self.witness.clone().unwrap_or(Witness::new()),
        }
    }
}
