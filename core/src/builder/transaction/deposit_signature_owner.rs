//! # Deposit Signature Ownership Mapping
//!
//! This module provides types and logic for mapping transaction signature requirements to protocol entities in the Clementine bridge.
//! It is used to determine which entity (operator, verifier, N-of-N, etc.) is responsible for providing a signature for a given transaction input,
//! and what sighash type is required for that signature. Additionally it encodes when this signature is given to other entities.
//!

use crate::errors::BridgeError;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
use bitcoin::TapSighashType;
use eyre::Context;

/// Enumerates the protocol entities that may own a required signature for a transaction input.
/// Additionally it encodes when this signature is given to other entities. For example signatures with OperatorDeposit are operator's
/// signatures that are shared with verifiers during a new deposit, while OperatorSetup is operator's signature that is given to the
/// verifiers when Operator is  being newly setup and added to verifiers databases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    OperatorDeposit,
    VerifierDeposit,
    OperatorSetup,
}

/// Describes the ownership and sighash type for a required signature.
///
/// - `NotOwned`: No signature required or not owned by any protocol entity.
/// - `OperatorSharedDeposit`: Operator's signature required for deposit, with the given sighash type.
/// - `NofnSharedDeposit`: N-of-N signature required for deposit, with the given sighash type.
/// - `Own`: Signature required for the entity running the program, with the given sighash type.
/// - `OperatorSharedSetup`: Operator's signature required during aggregator setup, with the given sighash type.
#[derive(Debug, Clone, Copy)]
pub enum DepositSigKeyOwner {
    NotOwned,
    /// Operator's signature required for deposit (shared with verifiers), with the given sighash type.
    OperatorSharedDeposit(TapSighashType),
    /// N-of-N signature required for deposit, with the given sighash type.
    NofnSharedDeposit(TapSighashType),
    /// Signature required for the entity itself, with the given sighash type.
    /// Verifiers do not need this signature info, thus it is not saved to DB.
    /// Added to help define different sighash types for operator's own signatures.
    Own(TapSighashType),
    /// Operator's signature required during first setup, with the given sighash type.
    OperatorSharedSetup(TapSighashType),
}

impl DepositSigKeyOwner {
    /// Returns the sighash type for this signature owner, if any.
    pub fn sighash_type(&self) -> Option<TapSighashType> {
        match self {
            DepositSigKeyOwner::NotOwned => None,
            DepositSigKeyOwner::Own(t)
            | DepositSigKeyOwner::NofnSharedDeposit(t)
            | DepositSigKeyOwner::OperatorSharedDeposit(t)
            | DepositSigKeyOwner::OperatorSharedSetup(t) => Some(*t),
        }
    }
}

impl SignatureId {
    /// Maps a [`SignatureId`] to its required signature owner and sighash type.
    ///
    /// # Returns
    ///
    /// A [`DepositSigKeyOwner`] describing the required signature owner and sighash type for this signature ID, or a [`BridgeError`] if the mapping fails.
    pub fn get_deposit_sig_owner(&self) -> Result<DepositSigKeyOwner, BridgeError> {
        use DepositSigKeyOwner::*;
        use TapSighashType::{Default as SighashDefault, SinglePlusAnyoneCanPay};
        match *self {
            SignatureId::NormalSignature(normal_sig) => {
                let normal_sig_type = NormalSignatureKind::try_from(normal_sig.signature_kind)
                    .wrap_err("Couldn't convert SignatureId::NormalSignature to DepositSigKey")?;
                use NormalSignatureKind::*;
                match normal_sig_type {
                    OperatorSighashDefault => Ok(Own(SighashDefault)),
                    NormalSignatureUnknown => {
                        Err(eyre::eyre!("Signature type is unknown, possible bad data").into())
                    }
                    Challenge => Ok(OperatorSharedDeposit(SinglePlusAnyoneCanPay)),
                    DisproveTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                    Disprove2 => Ok(OperatorSharedDeposit(SighashDefault)),
                    Reimburse1 => Ok(NofnSharedDeposit(SighashDefault)),
                    KickoffNotFinalized1 => Ok(NofnSharedDeposit(SighashDefault)),
                    KickoffNotFinalized2 => Ok(OperatorSharedDeposit(SighashDefault)),
                    Reimburse2 => Ok(NofnSharedDeposit(SighashDefault)),
                    NoSignature => Ok(NotOwned),
                    ChallengeTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                    MiniAssert1 => Ok(Own(SighashDefault)),
                    OperatorChallengeAck1 => Ok(Own(SighashDefault)),
                    NotStored => Ok(NotOwned),
                    YieldKickoffTxid => Ok(NotOwned),
                    LatestBlockhashTimeout1 => Ok(NofnSharedDeposit(SighashDefault)),
                    LatestBlockhashTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                    LatestBlockhashTimeout3 => Ok(OperatorSharedDeposit(SighashDefault)),
                    LatestBlockhash => Ok(Own(SighashDefault)),
                }
            }
            SignatureId::NumberedSignature(numbered_sig) => {
                let numbered_sig_type = NumberedSignatureKind::try_from(
                    numbered_sig.signature_kind,
                )
                .wrap_err("Couldn't convert SignatureId::NumberedSignature to DepositSigKey")?;
                use NumberedSignatureKind::*;
                match numbered_sig_type {
                    OperatorChallengeNack1 => Ok(NofnSharedDeposit(SighashDefault)),
                    OperatorChallengeNack2 => Ok(NofnSharedDeposit(SighashDefault)),
                    NumberedSignatureUnknown => Err(eyre::eyre!(
                        "Numbered signature type is unknown, possible bad data"
                    )
                    .into()),
                    NumberedNotStored => Ok(Own(SighashDefault)),
                    OperatorChallengeNack3 => Ok(OperatorSharedDeposit(SighashDefault)),
                    AssertTimeout1 => Ok(NofnSharedDeposit(SighashDefault)),
                    AssertTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                    AssertTimeout3 => Ok(OperatorSharedDeposit(SighashDefault)),
                    UnspentKickoff1 => Ok(OperatorSharedSetup(SighashDefault)),
                    UnspentKickoff2 => Ok(OperatorSharedSetup(SighashDefault)),
                    WatchtowerChallengeTimeout1 => Ok(NofnSharedDeposit(SighashDefault)),
                    WatchtowerChallengeTimeout2 => Ok(NofnSharedDeposit(SighashDefault)),
                    WatchtowerChallenge => Ok(Own(SighashDefault)),
                }
            }
        }
    }
}
