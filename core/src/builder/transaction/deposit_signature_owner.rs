use crate::errors::BridgeError;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
use bitcoin::TapSighashType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    Operator,
    Watchtower,
    Verifier,
}

/// Entity whose signature is needed to unlock the input utxo
#[derive(Debug, Clone, Copy)]
pub enum DepositSigKeyOwner {
    NotOwned,
    /// this type is for operator's signatures that need to be saved during deposit
    OperatorDB(TapSighashType),
    NofnDB(TapSighashType),
    /// this type is for signatures that is needed for Operator themselves to spend the utxo
    /// So verifiers do not need this signature info, thus it is not saved to DB.
    Operator(TapSighashType),
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
                    OperatorSighashDefault => Ok(NotOwned),
                    NormalSignatureUnknown => Ok(NotOwned),
                    WatchtowerChallengeKickoff => Ok(NofnDB(SighashDefault)),
                    Challenge => Ok(NofnDB(SinglePlusAnyoneCanPay)),
                    AssertTimeout1 => Ok(NofnDB(SighashDefault)),
                    AssertTimeout2 => Ok(OperatorDB(SighashDefault)),
                    StartHappyReimburse2 => Ok(NofnDB(SighashDefault)),
                    HappyReimburse1 => Ok(NofnDB(SighashDefault)),
                    AssertEndLast => Ok(NofnDB(SighashDefault)),
                    DisproveTimeout1 => Ok(NofnDB(SighashDefault)),
                    DisproveTimeout2 => Ok(NofnDB(SighashDefault)),
                    AlreadyDisproved1 => Ok(NofnDB(SighashDefault)),
                    AlreadyDisproved2 => Ok(OperatorDB(SighashDefault)),
                    Disprove2 => Ok(OperatorDB(SighashNone)),
                    Reimburse1 => Ok(NofnDB(SighashDefault)),
                    StartHappyReimburse3 => Ok(NofnDB(SighashDefault)),
                    DisproveTimeout3 => Ok(NofnDB(SighashDefault)),
                    KickoffNotFinalized1 => Ok(NofnDB(SighashDefault)),
                    KickoffNotFinalized2 => Ok(OperatorDB(SighashDefault)),
                }
            }
            SignatureId::NumberedSignature(watchtower_sig) => {
                let watchtower_sig_type = NumberedSignatureKind::try_from(
                    watchtower_sig.signature_kind,
                )
                .map_err(|_| {
                    BridgeError::Error(
                        "Couldn't convert SignatureId::WatchtowerSignature to DepositSigKey"
                            .to_string(),
                    )
                })?;
                use NumberedSignatureKind::*;
                match watchtower_sig_type {
                    WatchtowerSignatureUnknown => Ok(NotOwned),
                    WatchtowerNotStored => Ok(NotOwned),
                    OperatorChallengeNack1 => Ok(NofnDB(SighashDefault)),
                    OperatorChallengeNack2 => Ok(NofnDB(SighashDefault)),
                    AssertPart1 => Ok(NofnDB(SighashDefault)),
                }
            }
        }
    }
}
