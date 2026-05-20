use bitcoin::taproot;
use bitcoin::Witness;

use clementine_errors::WitnessError;

pub trait WitnessCodec {
    type EncodeInput;
    type Decoded;

    fn encode_witness(&self, input: &Self::EncodeInput) -> Result<Witness, WitnessError>;
    fn decode_witness(&self, witness: &Witness) -> Result<Self::Decoded, WitnessError>;
}

pub type CheckSigInput = taproot::Signature;
pub type CheckSigDecoded = taproot::Signature;
pub type KeySpendInput = taproot::Signature;
pub type RawWitnessInput = Vec<Vec<u8>>;
pub type TimelockInput = Option<taproot::Signature>;
pub type TimelockDecoded = Option<taproot::Signature>;
pub type MultisigInput = Vec<Option<taproot::Signature>>;
pub type MultisigDecoded = Vec<Option<taproot::Signature>>;
pub type BaseDepositInput = taproot::Signature;
pub type BaseDepositDecoded = taproot::Signature;
pub type ReplacementDepositInput = taproot::Signature;
pub type ReplacementDepositDecoded = taproot::Signature;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreimageRevealInput {
    pub signature: taproot::Signature,
    pub preimage: Vec<u8>,
}

pub type PreimageRevealDecoded = PreimageRevealInput;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinternitzCommitInput {
    pub signature: taproot::Signature,
    pub stack_items: Vec<Vec<u8>>,
}

pub type WinternitzCommitDecoded = WinternitzCommitInput;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessInput {
    KeySpend(KeySpendInput),
    RawWitness(RawWitnessInput),
    CheckSig(CheckSigInput),
    Timelock(TimelockInput),
    Multisig(MultisigInput),
    WinternitzCommit(WinternitzCommitInput),
    PreimageReveal(PreimageRevealInput),
    BaseDeposit(BaseDepositInput),
    ReplacementDeposit(ReplacementDepositInput),
}

impl WitnessInput {
    pub fn kind_name(&self) -> &'static str {
        match self {
            WitnessInput::KeySpend(_) => "KeySpend",
            WitnessInput::RawWitness(_) => "RawWitness",
            WitnessInput::CheckSig(_) => "CheckSig",
            WitnessInput::Timelock(_) => "Timelock",
            WitnessInput::Multisig(_) => "Multisig",
            WitnessInput::WinternitzCommit(_) => "WinternitzCommit",
            WitnessInput::PreimageReveal(_) => "PreimageReveal",
            WitnessInput::BaseDeposit(_) => "BaseDeposit",
            WitnessInput::ReplacementDeposit(_) => "ReplacementDeposit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessData {
    CheckSig(CheckSigDecoded),
    Timelock(TimelockDecoded),
    Multisig(MultisigDecoded),
    WinternitzCommit(WinternitzCommitDecoded),
    PreimageReveal(PreimageRevealDecoded),
    BaseDeposit(BaseDepositDecoded),
    ReplacementDeposit(ReplacementDepositDecoded),
}
