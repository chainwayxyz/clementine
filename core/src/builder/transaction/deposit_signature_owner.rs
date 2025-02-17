use crate::errors::BridgeError;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::{NormalSignatureKind, WatchtowerSignatureKind};
use bitcoin::TapSighashType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    Operator,
    Watchtower,
    Verifier,
}

#[derive(Debug, Clone, Copy)]
pub enum DepositSigKeyOwner {
    NotOwned,
    Operator(TapSighashType),
    NofN(TapSighashType),
}

impl DepositSigKeyOwner {
    pub fn sighash_type(&self) -> Option<TapSighashType> {
        match self {
            DepositSigKeyOwner::NotOwned => None,
            DepositSigKeyOwner::Operator(t) | DepositSigKeyOwner::NofN(t) => Some(*t),
        }
    }
}

impl SignatureId {
    pub fn get_deposit_sig_owner(&self) -> Result<DepositSigKeyOwner, BridgeError> {
        use DepositSigKeyOwner::*;
        use TapSighashType::{
            Default as SighashDefault, None as SighashNone, SinglePlusAnyoneCanPay,
        };
        match *self {
            SignatureId::NormalSignature(normal_sig) => {
                let normal_sig_type = (normal_sig.signature_kind).try_into().map_err(|_| {
                    BridgeError::Error(
                        "Couldn't convert SignatureId::NormalSignature to DepositSigKey"
                            .to_string(),
                    )
                })?;
                use NormalSignatureKind::*;
                match normal_sig_type {
                    NotStored => Ok(NotOwned),
                    NormalSignatureUnknown => Ok(NotOwned),
                    WatchtowerChallengeKickoff => Ok(NofN(SighashDefault)),
                    Challenge => Ok(NofN(SinglePlusAnyoneCanPay)),
                    AssertTimeout1 => Ok(NofN(SighashDefault)),
                    AssertTimeout2 => Ok(Operator(SighashDefault)),
                    StartHappyReimburse2 => Ok(NofN(SighashDefault)),
                    HappyReimburse1 => Ok(NofN(SighashDefault)),
                    AssertEndLast => Ok(NofN(SighashDefault)),
                    DisproveTimeout1 => Ok(NofN(SighashDefault)),
                    DisproveTimeout2 => Ok(NofN(SighashDefault)),
                    AlreadyDisproved1 => Ok(NofN(SighashDefault)),
                    AlreadyDisproved2 => Ok(Operator(SighashDefault)),
                    Disprove2 => Ok(Operator(SighashNone)),
                    Reimburse1 => Ok(NofN(SighashDefault)),
                    StartHappyReimburse3 => Ok(NofN(SighashDefault)),
                    DisproveTimeout3 => Ok(NofN(SighashDefault)),
                    KickoffNotFinalized1 => Ok(NofN(SighashDefault)),
                    KickoffNotFinalized2 => Ok(Operator(SighashDefault)),
                }
            }
            SignatureId::WatchtowerSignature(watchtower_sig) => {
                let watchtower_sig_type = WatchtowerSignatureKind::try_from(
                    watchtower_sig.signature_kind,
                )
                .map_err(|_| {
                    BridgeError::Error(
                        "Couldn't convert SignatureId::WatchtowerSignature to DepositSigKey"
                            .to_string(),
                    )
                })?;
                use WatchtowerSignatureKind::*;
                match watchtower_sig_type {
                    WatchtowerSignatureUnknown => Ok(NotOwned),
                    WatchtowerNotStored => Ok(NotOwned),
                    OperatorChallengeAck => Ok(Operator(SinglePlusAnyoneCanPay)),
                    OperatorChallengeNack1 => Ok(NofN(SighashDefault)),
                    OperatorChallengeNack2 => Ok(NofN(SighashDefault)),
                }
            }
        }
    }
}
