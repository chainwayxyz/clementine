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
    /// Added to help define different sighash types for operator's own signatures.
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
                    WatchtowerChallengeKickoff => Ok(NofnDB(SighashDefault)),
                    Challenge => Ok(NofnDB(SinglePlusAnyoneCanPay)),
                    DisproveTimeout2 => Ok(NofnDB(SighashDefault)),
                    Disprove2 => Ok(OperatorDB(SighashNone)),
                    Reimburse1 => Ok(NofnDB(SighashDefault)),
                    KickoffNotFinalized1 => Ok(NofnDB(SighashDefault)),
                    KickoffNotFinalized2 => Ok(OperatorDB(SighashDefault)),
                    Reimburse2 => Ok(NofnDB(SighashDefault)),
                    NoSignature => Ok(NotOwned),
                    ChallengeTimeout2 => Ok(NofnDB(SighashDefault)),
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
                    OperatorChallengeNack1 => Ok(NofnDB(SighashDefault)),
                    OperatorChallengeNack2 => Ok(NofnDB(SighashDefault)),
                    NumberedSignatureUnknown => Ok(NotOwned),
                    NumberedNotStored => Ok(Operator(SighashDefault)),
                    OperatorChallengeNack3 => Ok(OperatorDB(SighashDefault)),
                    AssertTimeout1 => Ok(NofnDB(SighashDefault)),
                    AssertTimeout2 => Ok(NofnDB(SighashDefault)),
                    AssertTimeout3 => Ok(OperatorDB(SighashDefault)),
                    UnspentKickoff1 => Ok(OperatorDB(SighashDefault)),
                    UnspentKickoff2 => Ok(OperatorDB(SighashDefault)),
                }
            }
        }
    }
}
