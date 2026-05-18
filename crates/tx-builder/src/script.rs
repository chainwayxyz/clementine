use bitcoin::taproot::TapNodeHash;
use bitcoin::{ScriptBuf, Witness, XOnlyPublicKey};

use crate::witness::{WitnessCodec, WitnessData, WitnessInput};
use clementine_errors::WitnessError;

/// A concrete leaf script that can be serialized into a tapscript leaf.
pub trait SpendableScript {
    fn to_script_buf(&self) -> ScriptBuf;
}

/// A concrete heterogeneous tapscript leaf used at runtime.
#[derive(Debug, Clone)]
pub enum ScriptLeaf {
    CheckSig(crate::scripts::CheckSig),
    Timelock(crate::scripts::TimelockScript),
    Multisig(crate::scripts::Multisig),

    WinternitzCommit(crate::scripts::WinternitzCommit),
    PreimageReveal(crate::scripts::PreimageRevealScript),
    BaseDeposit(crate::scripts::BaseDepositScript),
    ReplacementDeposit(crate::scripts::ReplacementDepositScript),
    Other(crate::scripts::OtherSpendable),
}

impl ScriptLeaf {
    pub fn kind_name(&self) -> &'static str {
        match self {
            ScriptLeaf::CheckSig(_) => "CheckSig",
            ScriptLeaf::Timelock(_) => "Timelock",
            ScriptLeaf::Multisig(_) => "Multisig",

            ScriptLeaf::WinternitzCommit(_) => "WinternitzCommit",
            ScriptLeaf::PreimageReveal(_) => "PreimageReveal",
            ScriptLeaf::BaseDeposit(_) => "BaseDeposit",
            ScriptLeaf::ReplacementDeposit(_) => "ReplacementDeposit",
            ScriptLeaf::Other(_) => "Other",
        }
    }

    pub fn encode_witness(&self, input: &WitnessInput) -> Result<Witness, WitnessError> {
        match (self, input) {
            (_, WitnessInput::RawWitness(items)) => {
                let mut witness = Witness::new();
                for item in items {
                    witness.push(item);
                }
                Ok(witness)
            }
            (ScriptLeaf::CheckSig(script), WitnessInput::CheckSig(input)) => {
                script.encode_witness(input)
            }
            (ScriptLeaf::Timelock(script), WitnessInput::Timelock(input)) => {
                script.encode_witness(input)
            }
            (ScriptLeaf::Multisig(script), WitnessInput::Multisig(input)) => {
                script.encode_witness(input)
            }

            (ScriptLeaf::WinternitzCommit(script), WitnessInput::WinternitzCommit(input)) => {
                script.encode_witness(input)
            }
            (ScriptLeaf::PreimageReveal(script), WitnessInput::PreimageReveal(input)) => {
                script.encode_witness(input)
            }
            (ScriptLeaf::BaseDeposit(script), WitnessInput::BaseDeposit(input)) => {
                script.encode_witness(input)
            }
            (ScriptLeaf::ReplacementDeposit(script), WitnessInput::ReplacementDeposit(input)) => {
                script.encode_witness(input)
            }
            (ScriptLeaf::Other(_), _) => Err(WitnessError::Message(
                "witness encode unsupported for Other script leaf".to_string(),
            )),
            (script, input) => Err(WitnessError::Message(format!(
                "witness input does not match script type: expected {}, got {}",
                script.kind_name(),
                input.kind_name()
            ))),
        }
    }

    pub fn decode_witness(&self, witness: &Witness) -> Result<WitnessData, WitnessError> {
        match self {
            ScriptLeaf::CheckSig(script) => {
                script.decode_witness(witness).map(WitnessData::CheckSig)
            }
            ScriptLeaf::Timelock(script) => {
                script.decode_witness(witness).map(WitnessData::Timelock)
            }
            ScriptLeaf::Multisig(script) => {
                script.decode_witness(witness).map(WitnessData::Multisig)
            }

            ScriptLeaf::WinternitzCommit(script) => script
                .decode_witness(witness)
                .map(WitnessData::WinternitzCommit),
            ScriptLeaf::PreimageReveal(script) => script
                .decode_witness(witness)
                .map(WitnessData::PreimageReveal),
            ScriptLeaf::BaseDeposit(script) => {
                script.decode_witness(witness).map(WitnessData::BaseDeposit)
            }
            ScriptLeaf::ReplacementDeposit(script) => script
                .decode_witness(witness)
                .map(WitnessData::ReplacementDeposit),
            ScriptLeaf::Other(_) => Err(WitnessError::Message(
                "witness decode unsupported for Other script leaf".to_string(),
            )),
        }
    }

    pub fn to_script_buf(&self) -> ScriptBuf {
        SpendableScript::to_script_buf(self)
    }

    pub fn sig_owner_key(&self) -> Option<XOnlyPublicKey> {
        match self {
            ScriptLeaf::CheckSig(script) => Some(script.pk),
            ScriptLeaf::Timelock(script) => script.pk,
            ScriptLeaf::WinternitzCommit(script) => Some(script.checksig_pubkey),
            ScriptLeaf::PreimageReveal(script) => Some(script.pk),
            ScriptLeaf::BaseDeposit(script) => Some(script.nofn_xonly_pk),
            ScriptLeaf::ReplacementDeposit(script) => Some(script.nofn_xonly_pk),
            ScriptLeaf::Multisig(_) | ScriptLeaf::Other(_) => None,
        }
    }
}

impl SpendableScript for ScriptLeaf {
    fn to_script_buf(&self) -> ScriptBuf {
        match self {
            ScriptLeaf::CheckSig(script) => script.to_script_buf(),
            ScriptLeaf::Timelock(script) => script.to_script_buf(),
            ScriptLeaf::Multisig(script) => script.to_script_buf(),

            ScriptLeaf::WinternitzCommit(script) => script.to_script_buf(),
            ScriptLeaf::PreimageReveal(script) => script.to_script_buf(),
            ScriptLeaf::BaseDeposit(script) => script.to_script_buf(),
            ScriptLeaf::ReplacementDeposit(script) => script.to_script_buf(),
            ScriptLeaf::Other(script) => script.to_script_buf(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScriptNode {
    Leaf(ScriptLeaf),
    Scripts(Vec<ScriptNode>),
    TapNodeHash(TapNodeHash),
}

pub type BatchScripts = ScriptNode;

impl From<ScriptLeaf> for ScriptNode {
    fn from(value: ScriptLeaf) -> Self {
        ScriptNode::Leaf(value)
    }
}

pub(crate) fn flatten_script_bufs(scripts: &[ScriptNode]) -> Vec<ScriptBuf> {
    let mut flattened = Vec::new();
    for script in scripts {
        flatten_script_buf(script, &mut flattened);
    }
    flattened
}

fn flatten_script_buf(script: &ScriptNode, out: &mut Vec<ScriptBuf>) {
    match script {
        ScriptNode::Leaf(leaf) => out.push(leaf.to_script_buf()),
        ScriptNode::Scripts(scripts) => {
            for script in scripts {
                flatten_script_buf(script, out);
            }
        }
        ScriptNode::TapNodeHash(_) => {}
    }
}
