use crate::errors::BridgeError;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
use bitcoin::TapSighashType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    OperatorDeposit,
    Watchtower,
    VerifierDeposit,
    OperatorSetup,
}

/// Entity whose signature is needed to unlock the input utxo
#[derive(Debug, Clone, Copy)]
pub enum DepositSigKeyOwner {
    NotOwned,
    /// this type is for operator's signatures that need to be saved during deposit
    OperatorSharedDeposit(TapSighashType),
    NofnSharedDeposit(TapSighashType),
    /// this type is for signatures that is needed for Operator themselves to spend the utxo
    /// So verifiers do not need this signature info, thus it is not saved to DB.
    /// Added to help define different sighash types for operator's own signatures.
    Operator(TapSighashType),
    /// For operator signatures that are needed to be saved during aggregator setups
    OperatorSharedSetup(TapSighashType),
}

impl SignatureId {
    pub fn get_deposit_sig_owner(&self) -> Result<DepositSigKeyOwner, BridgeError> {
        use DepositSigKeyOwner::*;
        use TapSighashType::{
            Default as SighashDefault, None as SighashNone, SinglePlusAnyoneCanPay,
        };
        match *self {
            SignatureId::NormalSignature(normal_sig) => {
                let normal_sig_type = NormalSignatureKind::try_from(normal_sig.signature_kind)
                    .map_err(|_| {
                        BridgeError::Error(
                            "Couldn't convert SignatureId::NormalSignature to DepositSigKey"
                                .to_string(),
                        )
                    })?;
                use NormalSignatureKind::*;
                match normal_sig_type {
                    OperatorSighashDefault => Ok(Operator(SighashDefault)),
                    NormalSignatureUnknown => Ok(NotOwned),
                    Challenge => Ok(NofnSharedDeposit(SinglePlusAnyoneCanPay)),
                    DisproveTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                    Disprove2 => Ok(OperatorSharedDeposit(SighashNone)),
                    Reimburse1 => Ok(NofnSharedDeposit(SighashDefault)),
                    KickoffNotFinalized1 => Ok(NofnSharedDeposit(SighashDefault)),
                    KickoffNotFinalized2 => Ok(OperatorSharedDeposit(SighashDefault)),
                    Reimburse2 => Ok(NofnSharedDeposit(SighashDefault)),
                    NoSignature => Ok(NotOwned),
                    ChallengeTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                    MiniAssert1 => Ok(Operator(SinglePlusAnyoneCanPay)),
                    OperatorChallengeAck1 => Ok(Operator(SinglePlusAnyoneCanPay)),
                    NotStored => Ok(NotOwned),
                }
            }
            SignatureId::NumberedSignature(numbered_sig) => {
                let numbered_sig_type =
                    NumberedSignatureKind::try_from(numbered_sig.signature_kind).map_err(|_| {
                        BridgeError::Error(
                            "Couldn't convert SignatureId::NumberedSignature to DepositSigKey"
                                .to_string(),
                        )
                    })?;
                use NumberedSignatureKind::*;
                match numbered_sig_type {
                    OperatorChallengeNack1 => Ok(NofnSharedDeposit(SighashDefault)),
                    OperatorChallengeNack2 => Ok(NofnSharedDeposit(SighashDefault)),
                    NumberedSignatureUnknown => Ok(NotOwned),
                    NumberedNotStored => Ok(Operator(SighashDefault)),
                    OperatorChallengeNack3 => Ok(OperatorSharedDeposit(SighashDefault)),
                    AssertTimeout1 => Ok(NofnSharedDeposit(SighashDefault)),
                    AssertTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                    AssertTimeout3 => Ok(OperatorSharedDeposit(SighashDefault)),
                    UnspentKickoff1 => Ok(OperatorSharedSetup(SighashDefault)),
                    UnspentKickoff2 => Ok(OperatorSharedSetup(SighashDefault)),
                    WatchtowerChallengeTimeout1 => Ok(NofnSharedDeposit(SighashDefault)),
                    WatchtowerChallengeTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                }
            }
        }
    }
}
