//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use super::script::{BaseDepositScript, CheckSig, TimelockScript};
use super::script::{ReplacementDepositScript, SpendPath};
use crate::builder::transaction::challenge::*;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::operator_assert::*;
use crate::builder::transaction::operator_collateral::*;
use crate::builder::transaction::operator_reimburse::*;
use crate::builder::transaction::output::UnspentTxOut;
use crate::config::protocol::ProtocolParamset;
use crate::constants::ANCHOR_AMOUNT;
use crate::errors::BridgeError;
use crate::rpc::clementine::grpc_transaction_id;
use crate::rpc::clementine::GrpcTransactionId;
use crate::rpc::clementine::{
    NormalSignatureKind, NormalTransactionId, NumberedTransactionId, NumberedTransactionType,
};
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_RETURN};
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey};
use eyre::Context;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

// Exports to the outside
pub use crate::builder::transaction::txhandler::*;
pub use creator::{
    create_round_txhandlers, create_txhandlers, ContractContext, KickoffWinternitzKeys,
    ReimburseDbCache, TxHandlerCache,
};
pub use operator_collateral::{
    create_burn_unused_kickoff_connectors_txhandler, create_round_nth_txhandler,
};
pub use operator_reimburse::create_payout_txhandler;
pub use txhandler::Unsigned;

mod challenge;
mod creator;
pub mod deposit_signature_owner;
pub mod input;
mod operator_assert;
mod operator_collateral;
mod operator_reimburse;
pub mod output;
pub mod sign;
mod txhandler;

#[derive(Debug, Error)]
pub enum TxError {
    /// TxInputNotFound is returned when the input is not found in the transaction
    #[error("Could not find input of transaction")]
    TxInputNotFound,
    #[error("Could not find output of transaction")]
    TxOutputNotFound,
    #[error("Attempted to set witness when it's already set")]
    WitnessAlreadySet,
    #[error("Script with index {0} not found for transaction")]
    ScriptNotFound(usize),
    #[error("Insufficient Context data for the requested TxHandler")]
    InsufficientContext,
    #[error("No scripts in TxHandler for the TxIn with index {0}")]
    NoScriptsForTxIn(usize),
    #[error("No script in TxHandler for the index {0}")]
    NoScriptAtIndex(usize),
    #[error("Spend Path in SpentTxIn in TxHandler not specified")]
    SpendPathNotSpecified,
    #[error("Actor does not own the key needed in P2TR keypath")]
    NotOwnKeyPath,
    #[error("public key of Checksig in script is not owned by Actor")]
    NotOwnedScriptPath,
    #[error("Couldn't find needed signature from database for tx: {:?}", _0)]
    SignatureNotFound(TransactionType),
    #[error("Couldn't find needed txhandler during creation for tx: {:?}", _0)]
    TxHandlerNotFound(TransactionType),
    #[error("BitvmSetupNotFound for operator {0}, deposit_txid {1}")]
    BitvmSetupNotFound(i32, Txid),
    #[error("Transaction input is missing spend info")]
    MissingSpendInfo,
    #[error("Incorrect watchtower challenge data length")]
    IncorrectWatchtowerChallengeDataLength,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DepositData {
    BaseDeposit(BaseDepositData),
    ReplacementDeposit(ReplacementDepositData),
}

impl DepositData {
    pub fn get_deposit_outpoint(&self) -> OutPoint {
        match self {
            DepositData::BaseDeposit(data) => data.deposit_outpoint,
            DepositData::ReplacementDeposit(data) => data.deposit_outpoint,
        }
    }
    pub fn get_nofn_xonly_pk(&self) -> XOnlyPublicKey {
        match self {
            DepositData::BaseDeposit(data) => data.nofn_xonly_pk,
            DepositData::ReplacementDeposit(data) => data.nofn_xonly_pk,
        }
    }
    fn get_num_verifiers(&self) -> usize {
        match self {
            DepositData::BaseDeposit(data) => data.verifiers.len(),
            DepositData::ReplacementDeposit(data) => data.verifiers.len(),
        }
    }
    pub fn get_num_watchtowers(&self) -> usize {
        self.get_num_verifiers()
            + match self {
                DepositData::BaseDeposit(data) => data.watchtowers.len(),
                DepositData::ReplacementDeposit(data) => data.watchtowers.len(),
            }
    }
    pub fn get_verifier_index(&self, xonly_pk: &XOnlyPublicKey) -> Result<usize, eyre::Report> {
        self.get_verifiers()
            .iter()
            .position(|pk| pk == xonly_pk)
            .ok_or_else(|| eyre::eyre!("Verifier with public key {} not found", xonly_pk))
    }
    pub fn get_watchtower_index(&self, xonly_pk: &XOnlyPublicKey) -> Result<usize, eyre::Report> {
        self.get_watchtowers()
            .iter()
            .position(|pk| pk == xonly_pk)
            .ok_or_else(|| eyre::eyre!("Watchtower with public key {} not found", xonly_pk))
    }
    /// Returns sorted verifiers, they are sorted so that their order is deterministic.
    pub fn get_verifiers(&self) -> Vec<XOnlyPublicKey> {
        let mut verifiers = match self {
            DepositData::BaseDeposit(data) => data.verifiers.clone(),
            DepositData::ReplacementDeposit(data) => data.verifiers.clone(),
        };
        verifiers.sort();
        verifiers
    }
    /// Returns sorted watchtowers, they are sorted so that their order is deterministic.
    pub fn get_watchtowers(&self) -> Vec<XOnlyPublicKey> {
        let mut watchtowers = self.get_verifiers().to_vec();
        match self {
            DepositData::BaseDeposit(data) => watchtowers.extend(data.watchtowers.iter()),
            DepositData::ReplacementDeposit(data) => watchtowers.extend(data.watchtowers.iter()),
        }
        watchtowers.sort();
        watchtowers
    }
    // pub fn get_num_verifiers(&self) -> usize {
    //     match self {
    //         DepositData::BaseDeposit(data) => data.num_verifiers,
    //         DepositData::ReplacementDeposit(data) => data.num_verifiers,
    //     }
    // }
}

/// Type to uniquely identify a deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BaseDepositData {
    /// User's deposit UTXO.
    pub deposit_outpoint: bitcoin::OutPoint,
    /// User's EVM address.
    pub evm_address: EVMAddress,
    /// User's recovery taproot address.
    pub recovery_taproot_address: bitcoin::Address<NetworkUnchecked>,
    /// nofn xonly public key used for deposit.
    pub nofn_xonly_pk: XOnlyPublicKey,
    /// X-only public keys of verifiers that will participate in the deposit.
    pub verifiers: Vec<XOnlyPublicKey>,
    /// X-only public keys of watchtowers that will participate in the deposit.
    /// NOTE: verifiers are automatically considered watchtowers. This field is only for additional watchtowers.
    pub watchtowers: Vec<XOnlyPublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ReplacementDepositData {
    /// deposit UTXO.
    pub deposit_outpoint: bitcoin::OutPoint,
    /// old move_to_vault txid that was replaced
    pub old_move_txid: Txid,
    /// nofn xonly public key used for deposit.
    pub nofn_xonly_pk: XOnlyPublicKey,
    /// X-only public keys of verifiers that will participate in the deposit.
    pub verifiers: Vec<XOnlyPublicKey>,
    /// X-only public keys of watchtowers that will participate in the deposit.
    /// NOTE: verifiers are automatically considered watchtowers. This field is only for additional watchtowers.
    pub watchtowers: Vec<XOnlyPublicKey>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct OperatorData {
    pub xonly_pk: XOnlyPublicKey,
    pub reimburse_addr: Address,
    pub collateral_funding_outpoint: OutPoint,
}

// TODO: remove this impl, this is done to avoid checking the address, instead
// we should be checking address against a paramset
impl<'de> serde::Deserialize<'de> for OperatorData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct OperatorDataHelper {
            xonly_pk: XOnlyPublicKey,
            reimburse_addr: Address<NetworkUnchecked>,
            collateral_funding_outpoint: OutPoint,
        }

        let helper = OperatorDataHelper::deserialize(deserializer)?;

        Ok(OperatorData {
            xonly_pk: helper.xonly_pk,
            reimburse_addr: helper.reimburse_addr.assume_checked(),
            collateral_funding_outpoint: helper.collateral_funding_outpoint,
        })
    }
}

/// Types of all transactions that can be created. Some transactions have an (usize) to as they are created
/// multiple times per kickoff.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TransactionType {
    Round,
    Kickoff,
    MoveToVault,
    Payout,
    Challenge,
    UnspentKickoff(usize),
    WatchtowerChallengeTimeout(usize),
    WatchtowerChallenge(usize),
    OperatorChallengeNack(usize),
    OperatorChallengeAck(usize),
    AssertTimeout(usize),
    MiniAssert(usize),
    Disprove,
    DisproveTimeout,
    Reimburse,
    AllNeededForDeposit, // this will include all tx's that is to be signed for a deposit for verifiers
    Dummy,               // for tests
    ReadyToReimburse,
    KickoffNotFinalized,
    ChallengeTimeout,
    BurnUnusedKickoffConnectors,
    YieldKickoffTxid, // This is just to yield kickoff txid from the sighash stream, not used for anything else, sorry
    BaseDeposit,
    ReplacementDeposit,
}

// converter from proto type to rust enum
impl TryFrom<GrpcTransactionId> for TransactionType {
    type Error = ::prost::UnknownEnumValue;
    fn try_from(value: GrpcTransactionId) -> Result<Self, Self::Error> {
        use NormalTransactionId as Normal;
        use NumberedTransactionType as Numbered;
        // return err if id is None
        let inner_id = value.id.ok_or(::prost::UnknownEnumValue(0))?;
        match inner_id {
            grpc_transaction_id::Id::NormalTransaction(idx) => {
                let tx_type = NormalTransactionId::try_from(idx)?;
                match tx_type {
                    Normal::Round => Ok(Self::Round),
                    Normal::Kickoff => Ok(Self::Kickoff),
                    Normal::MoveToVault => Ok(Self::MoveToVault),
                    Normal::Payout => Ok(Self::Payout),
                    Normal::Challenge => Ok(Self::Challenge),
                    Normal::Disprove => Ok(Self::Disprove),
                    Normal::DisproveTimeout => Ok(Self::DisproveTimeout),
                    Normal::Reimburse => Ok(Self::Reimburse),
                    Normal::AllNeededForDeposit => Ok(Self::AllNeededForDeposit),
                    Normal::Dummy => Ok(Self::Dummy),
                    Normal::ReadyToReimburse => Ok(Self::ReadyToReimburse),
                    Normal::KickoffNotFinalized => Ok(Self::KickoffNotFinalized),
                    Normal::ChallengeTimeout => Ok(Self::ChallengeTimeout),
                    Normal::UnspecifiedTransactionType => Err(::prost::UnknownEnumValue(idx)),
                    Normal::BurnUnusedKickoffConnectors => Ok(Self::BurnUnusedKickoffConnectors),
                    Normal::YieldKickoffTxid => Ok(Self::YieldKickoffTxid),
                    Normal::BaseDeposit => Ok(Self::BaseDeposit),
                    Normal::ReplacementDeposit => Ok(Self::ReplacementDeposit),
                }
            }
            grpc_transaction_id::Id::NumberedTransaction(transaction_id) => {
                let tx_type = NumberedTransactionType::try_from(transaction_id.transaction_type)?;
                match tx_type {
                    Numbered::WatchtowerChallenge => {
                        Ok(Self::WatchtowerChallenge(transaction_id.index as usize))
                    }
                    Numbered::OperatorChallengeNack => {
                        Ok(Self::OperatorChallengeNack(transaction_id.index as usize))
                    }
                    Numbered::OperatorChallengeAck => {
                        Ok(Self::OperatorChallengeAck(transaction_id.index as usize))
                    }
                    Numbered::AssertTimeout => {
                        Ok(Self::AssertTimeout(transaction_id.index as usize))
                    }
                    Numbered::UnspentKickoff => {
                        Ok(Self::UnspentKickoff(transaction_id.index as usize))
                    }
                    Numbered::MiniAssert => Ok(Self::MiniAssert(transaction_id.index as usize)),
                    Numbered::WatchtowerChallengeTimeout => Ok(Self::WatchtowerChallengeTimeout(
                        transaction_id.index as usize,
                    )),
                    Numbered::UnspecifiedIndexedTransactionType => {
                        Err(::prost::UnknownEnumValue(transaction_id.transaction_type))
                    }
                }
            }
        }
    }
}

impl From<TransactionType> for GrpcTransactionId {
    fn from(value: TransactionType) -> Self {
        use grpc_transaction_id::Id::*;
        use NormalTransactionId as Normal;
        use NumberedTransactionType as Numbered;
        GrpcTransactionId {
            id: Some(match value {
                TransactionType::Round => NormalTransaction(Normal::Round as i32),
                TransactionType::Kickoff => NormalTransaction(Normal::Kickoff as i32),
                TransactionType::MoveToVault => NormalTransaction(Normal::MoveToVault as i32),
                TransactionType::Payout => NormalTransaction(Normal::Payout as i32),
                TransactionType::Challenge => NormalTransaction(Normal::Challenge as i32),
                TransactionType::Disprove => NormalTransaction(Normal::Disprove as i32),
                TransactionType::DisproveTimeout => {
                    NormalTransaction(Normal::DisproveTimeout as i32)
                }
                TransactionType::Reimburse => NormalTransaction(Normal::Reimburse as i32),
                TransactionType::AllNeededForDeposit => {
                    NormalTransaction(Normal::AllNeededForDeposit as i32)
                }
                TransactionType::Dummy => NormalTransaction(Normal::Dummy as i32),
                TransactionType::ReadyToReimburse => {
                    NormalTransaction(Normal::ReadyToReimburse as i32)
                }
                TransactionType::KickoffNotFinalized => {
                    NormalTransaction(Normal::KickoffNotFinalized as i32)
                }
                TransactionType::ChallengeTimeout => {
                    NormalTransaction(Normal::ChallengeTimeout as i32)
                }
                TransactionType::BaseDeposit => NormalTransaction(Normal::BaseDeposit as i32),
                TransactionType::ReplacementDeposit => {
                    NormalTransaction(Normal::ReplacementDeposit as i32)
                }
                TransactionType::WatchtowerChallenge(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::WatchtowerChallenge as i32,
                        index: index as i32,
                    })
                }
                TransactionType::OperatorChallengeNack(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::OperatorChallengeNack as i32,
                        index: index as i32,
                    })
                }
                TransactionType::OperatorChallengeAck(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::OperatorChallengeAck as i32,
                        index: index as i32,
                    })
                }
                TransactionType::AssertTimeout(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::AssertTimeout as i32,
                        index: index as i32,
                    })
                }
                TransactionType::UnspentKickoff(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::UnspentKickoff as i32,
                        index: index as i32,
                    })
                }
                TransactionType::MiniAssert(index) => NumberedTransaction(NumberedTransactionId {
                    transaction_type: Numbered::MiniAssert as i32,
                    index: index as i32,
                }),
                TransactionType::WatchtowerChallengeTimeout(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::WatchtowerChallengeTimeout as i32,
                        index: index as i32,
                    })
                }
                TransactionType::BurnUnusedKickoffConnectors => {
                    NormalTransaction(Normal::BurnUnusedKickoffConnectors as i32)
                }
                TransactionType::YieldKickoffTxid => {
                    NormalTransaction(Normal::YieldKickoffTxid as i32)
                }
            }),
        }
    }
}

/// Creates a P2WSH output that anyone can spend. TODO: We will not need this in the future.
pub fn anyone_can_spend_txout() -> TxOut {
    let script = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
    let script_pubkey = script.to_p2wsh();
    let value = script_pubkey.minimal_non_dust();

    TxOut {
        script_pubkey,
        value,
    }
}

/// Creates a P2A output for CPFP.
pub fn anchor_output() -> TxOut {
    TxOut {
        value: ANCHOR_AMOUNT,
        script_pubkey: ScriptBuf::from_hex("51024e73").expect("statically valid script"),
    }
}

/// Creates a OP_RETURN output.
pub fn op_return_txout<S: AsRef<bitcoin::script::PushBytes>>(slice: S) -> TxOut {
    let script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(slice)
        .into_script();

    TxOut {
        value: Amount::from_sat(0),
        script_pubkey: script,
    }
}

/// Creates a [`TxHandler`] for the `move_to_vault_tx`. This transaction will move
/// the funds to a NofN address from the deposit intent address, after all the signature
/// collection operations are done.
pub fn create_move_to_vault_txhandler(
    deposit_data: DepositData,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    let nofn_script = Arc::new(CheckSig::new(deposit_data.get_nofn_xonly_pk()));

    let builder = match deposit_data {
        DepositData::BaseDeposit(original_deposit_data) => {
            let deposit_script = Arc::new(BaseDepositScript::new(
                original_deposit_data.nofn_xonly_pk,
                original_deposit_data.evm_address,
                paramset.bridge_amount,
            ));

            let recovery_script_pubkey = original_deposit_data
                .recovery_taproot_address
                .clone()
                .assume_checked()
                .script_pubkey();

            let recovery_extracted_xonly_pk =
                XOnlyPublicKey::from_slice(&recovery_script_pubkey.as_bytes()[2..34])
                    .wrap_err("Failed to extract xonly public key from recovery script pubkey")?;

            let script_timelock = Arc::new(TimelockScript::new(
                Some(recovery_extracted_xonly_pk),
                paramset.user_takes_after,
            ));

            TxHandlerBuilder::new(TransactionType::MoveToVault)
                .with_version(Version::non_standard(3))
                .add_input(
                    NormalSignatureKind::NotStored,
                    SpendableTxIn::from_scripts(
                        original_deposit_data.deposit_outpoint,
                        paramset.bridge_amount,
                        vec![deposit_script, script_timelock],
                        None,
                        paramset.network,
                    ),
                    SpendPath::ScriptSpend(0),
                    DEFAULT_SEQUENCE,
                )
        }
        DepositData::ReplacementDeposit(replacement_deposit_data) => {
            let deposit_script = Arc::new(ReplacementDepositScript::new(
                replacement_deposit_data.nofn_xonly_pk,
                replacement_deposit_data.old_move_txid,
                paramset.bridge_amount,
            ));

            TxHandlerBuilder::new(TransactionType::MoveToVault)
                .with_version(Version::non_standard(3))
                .add_input(
                    NormalSignatureKind::NotStored,
                    SpendableTxIn::from_scripts(
                        replacement_deposit_data.deposit_outpoint,
                        paramset.bridge_amount,
                        vec![deposit_script],
                        None,
                        paramset.network,
                    ),
                    SpendPath::ScriptSpend(0),
                    DEFAULT_SEQUENCE,
                )
        }
    };

    Ok(builder
        .add_output(UnspentTxOut::from_scripts(
            paramset.bridge_amount - ANCHOR_AMOUNT,
            vec![nofn_script],
            None,
            paramset.network,
        ))
        .add_output(UnspentTxOut::from_partial(anchor_output()))
        .finalize())
}

/// Creates a [`TxHandler`] for the `move_to_vault_tx`. This transaction will move
/// the funds to a NofN address from the deposit intent address, after all the signature
/// collection operations are done.
pub fn create_replacement_deposit_txhandler(
    old_move_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::ReplacementDeposit)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::from_scripts(
                bitcoin::OutPoint {
                    txid: old_move_txid,
                    vout: 0,
                },
                paramset.bridge_amount - ANCHOR_AMOUNT,
                vec![Arc::new(CheckSig::new(nofn_xonly_pk))],
                None,
                paramset.network,
            ),
            crate::builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            paramset.bridge_amount,
            vec![Arc::new(ReplacementDepositScript::new(
                nofn_xonly_pk,
                old_move_txid,
                paramset.bridge_amount,
            ))],
            None,
            paramset.network,
        ))
        .add_output(UnspentTxOut::from_partial(anchor_output()))
        .finalize())
}

#[cfg(test)]
mod tests {
    // #[test]
    // fn create_watchtower_challenge_page_txhandler() {
    //     let network = bitcoin::Network::Regtest;
    //     let secret_key = SecretKey::new(&mut rand::thread_rng());
    //     let nofn_xonly_pk =
    //         XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &secret_key)).0;
    //     let (nofn_musig2_address, _) =
    //         builder::address::create_musig2_address(nofn_xonly_pk, network);

    //     let kickoff_outpoint = OutPoint {
    //         txid: Txid::all_zeros(),
    //         vout: 0x45,
    //     };
    //     let kickoff_utxo = UTXO {
    //         outpoint: kickoff_outpoint,
    //         txout: TxOut {
    //             value: Amount::from_int_btc(2),
    //             script_pubkey: nofn_musig2_address.script_pubkey(),
    //         },
    //     };

    //     let bridge_amount_sats = Amount::from_sat(0x1F45);
    //     let num_watchtowers = 3;

    //     let wcp_txhandler = super::create_watchtower_challenge_page_txhandler(
    //         &kickoff_utxo,
    //         nofn_xonly_pk,
    //         bridge_amount_sats,
    //         num_watchtowers,
    //         network,
    //     );
    //     assert_eq!(wcp_txhandler.tx.output.len(), num_watchtowers as usize);
    // }

    // #[test]
    // fn create_challenge_tx() {
    //     let operator_secret_key = SecretKey::new(&mut rand::thread_rng());
    //     let operator_xonly_pk =
    //         XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &operator_secret_key)).0;

    //     let kickoff_outpoint = OutPoint {
    //         txid: Txid::all_zeros(),
    //         vout: 0x45,
    //     };

    //     let challenge_tx = super::create_challenge_tx(kickoff_outpoint, operator_xonly_pk);
    //     assert_eq!(
    //         challenge_tx.tx_out(0).unwrap().value,
    //         Amount::from_int_btc(2)
    //     );
    //     assert_eq!(
    //         challenge_tx.tx_out(0).unwrap().script_pubkey,
    //         ScriptBuf::new_p2tr(&SECP, operator_xonly_pk, None)
    //     )
    // }
}
