//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use super::script::{BaseDepositScript, CheckSig, Multisig, SpendableScript, TimelockScript};
use super::script::{ReplacementDepositScript, SpendPath};
use crate::builder::script::OtherSpendable;
use crate::builder::transaction::challenge::*;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::operator_assert::*;
use crate::builder::transaction::operator_collateral::*;
use crate::builder::transaction::operator_reimburse::*;
use crate::builder::transaction::output::UnspentTxOut;
use crate::config::protocol::ProtocolParamset;
use crate::constants::ANCHOR_AMOUNT;
use crate::errors::BridgeError;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::grpc_transaction_id;
use crate::rpc::clementine::GrpcTransactionId;
use crate::rpc::clementine::{
    NormalSignatureKind, NormalTransactionId, NumberedTransactionId, NumberedTransactionType,
};
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_RETURN};
use bitcoin::script::Builder;
use bitcoin::secp256k1::PublicKey;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use eyre::Context;
use hex;
use input::UtxoVout;
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
pub use operator_reimburse::{create_optimistic_payout_txhandler, create_payout_txhandler};
pub use txhandler::Unsigned;

pub mod challenge;
mod creator;
pub mod deposit_signature_owner;
pub mod input;
mod operator_assert;
mod operator_collateral;
mod operator_reimburse;
pub mod output;
pub mod sign;
mod txhandler;

type HiddenNode<'a> = &'a [u8; 32];

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
    #[error("BitvmSetupNotFound for operator {0:?}, deposit_txid {1}")]
    BitvmSetupNotFound(XOnlyPublicKey, Txid),
    #[error("Transaction input is missing spend info")]
    MissingSpendInfo,
    #[error("Incorrect watchtower challenge data length")]
    IncorrectWatchtowerChallengeDataLength,
    #[error("Latest blockhash script must be a single script")]
    LatestBlockhashScriptNumber,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Ord, PartialOrd,
)]
pub struct KickoffData {
    pub operator_xonly_pk: XOnlyPublicKey,
    pub round_idx: u32,
    pub kickoff_idx: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Eq)]
pub struct DepositData {
    /// Cached nofn xonly public key used for deposit.
    pub nofn_xonly_pk: Option<XOnlyPublicKey>,
    pub deposit: DepositInfo,
    pub actors: Actors,
    pub security_council: SecurityCouncil,
}

impl PartialEq for DepositData {
    fn eq(&self, other: &Self) -> bool {
        // nofn_xonly_pk only depends on verifiers pk's so it can be ignored as verifiers are already compared
        // for security council, order of keys matter as it will change the m of n multisig script,
        // thus change the scriptpubkey of move to vault tx
        self.security_council == other.security_council
            && self.deposit.deposit_outpoint == other.deposit.deposit_outpoint
            // for watchtowers/verifiers/operators, order doesn't matter, we compare sorted lists
            // get() functions already return sorted lists
            && self.get_operators() == other.get_operators()
            && self.get_verifiers() == other.get_verifiers()
            && self.get_watchtowers() == other.get_watchtowers()
            && self.deposit.deposit_type == other.deposit.deposit_type
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DepositInfo {
    pub deposit_outpoint: OutPoint,
    pub deposit_type: DepositType,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum DepositType {
    BaseDeposit(BaseDepositData),
    ReplacementDeposit(ReplacementDepositData),
}

impl DepositData {
    pub fn get_deposit_outpoint(&self) -> OutPoint {
        self.deposit.deposit_outpoint
    }
    pub fn get_nofn_xonly_pk(&mut self) -> Result<XOnlyPublicKey, BridgeError> {
        if let Some(pk) = self.nofn_xonly_pk {
            return Ok(pk);
        }
        let verifiers = self.get_verifiers();
        let nofn_xonly_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers, None)?;
        self.nofn_xonly_pk = Some(nofn_xonly_pk);
        Ok(nofn_xonly_pk)
    }
    pub fn get_num_verifiers(&self) -> usize {
        self.actors.verifiers.len()
    }
    pub fn get_num_watchtowers(&self) -> usize {
        self.get_num_verifiers() + self.actors.watchtowers.len()
    }
    pub fn get_verifier_index(&self, public_key: &PublicKey) -> Result<usize, eyre::Report> {
        self.get_verifiers()
            .iter()
            .position(|pk| pk == public_key)
            .ok_or_else(|| eyre::eyre!("Verifier with public key {} not found", public_key))
    }
    pub fn get_watchtower_index(&self, xonly_pk: &XOnlyPublicKey) -> Result<usize, eyre::Report> {
        self.get_watchtowers()
            .iter()
            .position(|pk| pk == xonly_pk)
            .ok_or_else(|| eyre::eyre!("Watchtower with xonly key {} not found", xonly_pk))
    }
    pub fn get_operator_index(&self, xonly_pk: XOnlyPublicKey) -> Result<usize, eyre::Report> {
        self.get_operators()
            .iter()
            .position(|pk| pk == &xonly_pk)
            .ok_or_else(|| eyre::eyre!("Operator with xonly key {} not found", xonly_pk))
    }
    /// Returns sorted verifiers, they are sorted so that their order is deterministic.
    pub fn get_verifiers(&self) -> Vec<PublicKey> {
        let mut verifiers = self.actors.verifiers.clone();
        verifiers.sort();
        verifiers
    }
    /// Returns sorted watchtowers, they are sorted so that their order is deterministic.
    pub fn get_watchtowers(&self) -> Vec<XOnlyPublicKey> {
        let mut watchtowers = self
            .actors
            .verifiers
            .iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect::<Vec<_>>();
        watchtowers.extend(self.actors.watchtowers.iter());
        watchtowers.sort();
        watchtowers
    }
    pub fn get_operators(&self) -> Vec<XOnlyPublicKey> {
        let mut operators = self.actors.operators.clone();
        operators.sort();
        operators
    }
    pub fn get_num_operators(&self) -> usize {
        self.actors.operators.len()
    }
    /// Returns the scripts for the deposit.
    pub fn get_deposit_scripts(
        &mut self,
        paramset: &'static ProtocolParamset,
    ) -> Result<Vec<Arc<dyn SpendableScript>>, BridgeError> {
        let nofn_xonly_pk = self.get_nofn_xonly_pk()?;

        match &mut self.deposit.deposit_type {
            DepositType::BaseDeposit(original_deposit_data) => {
                let deposit_script = Arc::new(BaseDepositScript::new(
                    nofn_xonly_pk,
                    original_deposit_data.evm_address,
                ));

                let recovery_script_pubkey = original_deposit_data
                    .recovery_taproot_address
                    .clone()
                    .assume_checked()
                    .script_pubkey();

                let recovery_extracted_xonly_pk =
                    XOnlyPublicKey::from_slice(&recovery_script_pubkey.as_bytes()[2..34])
                        .wrap_err(
                            "Failed to extract xonly public key from recovery script pubkey",
                        )?;

                let script_timelock = Arc::new(TimelockScript::new(
                    Some(recovery_extracted_xonly_pk),
                    paramset.user_takes_after,
                ));

                Ok(vec![deposit_script, script_timelock])
            }
            DepositType::ReplacementDeposit(replacement_deposit_data) => {
                let deposit_script: Arc<dyn SpendableScript> =
                    Arc::new(ReplacementDepositScript::new(
                        nofn_xonly_pk,
                        replacement_deposit_data.old_move_txid,
                    ));
                let security_council_script: Arc<dyn SpendableScript> = Arc::new(
                    Multisig::from_security_council(self.security_council.clone()),
                );

                Ok(vec![deposit_script, security_council_script])
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Actors {
    /// Public keys of verifiers that will participate in the deposit.
    pub verifiers: Vec<PublicKey>,
    /// X-only public keys of watchtowers that will participate in the deposit.
    /// NOTE: verifiers are automatically considered watchtowers. This field is only for additional watchtowers.
    pub watchtowers: Vec<XOnlyPublicKey>,
    /// X-only public keys of operators that will participate in the deposit.
    pub operators: Vec<XOnlyPublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCouncil {
    pub pks: Vec<XOnlyPublicKey>,
    pub threshold: u32,
}

impl std::str::FromStr for SecurityCouncil {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let threshold_str = parts
            .next()
            .ok_or_else(|| eyre::eyre!("Missing threshold"))?;
        let pks_str = parts
            .next()
            .ok_or_else(|| eyre::eyre!("Missing public keys"))?;

        if parts.next().is_some() {
            return Err(eyre::eyre!("Too many parts in security council string"));
        }

        let threshold = threshold_str
            .parse::<u32>()
            .map_err(|e| eyre::eyre!("Invalid threshold: {}", e))?;

        let pks: Result<Vec<XOnlyPublicKey>, _> = pks_str
            .split(',')
            .map(|pk_str| {
                let bytes = hex::decode(pk_str)
                    .map_err(|e| eyre::eyre!("Invalid hex in public key: {}", e))?;
                XOnlyPublicKey::from_slice(&bytes)
                    .map_err(|e| eyre::eyre!("Invalid public key: {}", e))
            })
            .collect();

        let pks = pks?;

        if pks.is_empty() {
            return Err(eyre::eyre!("No public keys provided"));
        }

        if threshold > pks.len() as u32 {
            return Err(eyre::eyre!(
                "Threshold cannot be greater than number of public keys"
            ));
        }

        Ok(SecurityCouncil { pks, threshold })
    }
}

impl serde::Serialize for SecurityCouncil {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for SecurityCouncil {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for SecurityCouncil {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.threshold)?;
        let pks_str = self
            .pks
            .iter()
            .map(|pk| hex::encode(pk.serialize()))
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}", pks_str)
    }
}

/// Type to uniquely identify a deposit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BaseDepositData {
    /// User's EVM address.
    pub evm_address: EVMAddress,
    /// User's recovery taproot address.
    pub recovery_taproot_address: bitcoin::Address<NetworkUnchecked>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplacementDepositData {
    /// old move_to_vault txid that was replaced
    pub old_move_txid: Txid,
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
    EmergencyStop,
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
    LatestBlockhashTimeout,
    LatestBlockhash,
    OptimisticPayout,
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
                    Normal::LatestBlockhashTimeout => Ok(Self::LatestBlockhashTimeout),
                    Normal::LatestBlockhash => Ok(Self::LatestBlockhash),
                    Normal::OptimisticPayout => Ok(Self::OptimisticPayout),
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
                TransactionType::LatestBlockhashTimeout => {
                    NormalTransaction(Normal::LatestBlockhashTimeout as i32)
                }
                TransactionType::LatestBlockhash => {
                    NormalTransaction(Normal::LatestBlockhash as i32)
                }
                TransactionType::OptimisticPayout => {
                    NormalTransaction(Normal::OptimisticPayout as i32)
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
                TransactionType::EmergencyStop => {
                    NormalTransaction(Normal::UnspecifiedTransactionType as i32)
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
    deposit_data: &mut DepositData,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    let nofn_xonly_pk = deposit_data.get_nofn_xonly_pk()?;
    let deposit_outpoint = deposit_data.get_deposit_outpoint();
    let nofn_script = Arc::new(CheckSig::new(nofn_xonly_pk));
    let security_council_script = Arc::new(Multisig::from_security_council(
        deposit_data.security_council.clone(),
    ));

    let deposit_scripts = deposit_data.get_deposit_scripts(paramset)?;

    Ok(TxHandlerBuilder::new(TransactionType::MoveToVault)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::from_scripts(
                deposit_outpoint,
                paramset.bridge_amount,
                deposit_scripts,
                None,
                paramset.network,
            ),
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            paramset.bridge_amount - ANCHOR_AMOUNT,
            vec![nofn_script, security_council_script],
            None,
            paramset.network,
        ))
        .add_output(UnspentTxOut::from_partial(anchor_output()))
        .finalize())
}

/// Creates a [`TxHandlerBuilder`] for the `emergency_stop_tx`. This transaction will move
/// the funds to a the address controlled by the security council from the move to vault txout
/// This transaction will be used to stop malicious activities if there is a security issue.
pub fn create_emergency_stop_txhandler(
    deposit_data: &mut DepositData,
    move_to_vault_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    // Hand calculated, total tx size is 11 + 126 * NUM_EMERGENCY_STOPS
    const EACH_EMERGENCY_STOP_VBYTES: Amount = Amount::from_sat(126);
    let security_council = deposit_data.security_council.clone();

    let builder = TxHandlerBuilder::new(TransactionType::EmergencyStop)
        .add_input(
            NormalSignatureKind::NotStored,
            move_to_vault_txhandler.get_spendable_output(UtxoVout::DepositInMove)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            paramset.bridge_amount - ANCHOR_AMOUNT - EACH_EMERGENCY_STOP_VBYTES * 3,
            vec![Arc::new(Multisig::from_security_council(security_council))],
            None,
            paramset.network,
        ))
        .finalize();

    Ok(builder)
}

/// We assume that the vector of (Txid, Transaction) includes input-output pairs which are signed
/// using Sighash Single | AnyoneCanPay. This function will combine the inputs and outputs of the
/// transactions into a single transaction. Beware, this may be dangerous, as there are no checks.
pub fn combine_emergency_stop_txhandler(
    txs: Vec<(Txid, Transaction)>,
    add_anchor: bool,
) -> Transaction {
    let (inputs, mut outputs): (Vec<TxIn>, Vec<TxOut>) = txs
        .into_iter()
        .map(|(_, tx)| (tx.input[0].clone(), tx.output[0].clone()))
        .unzip();

    if add_anchor {
        outputs.push(anchor_output());
    }

    Transaction {
        version: Version::non_standard(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

/// Creates a [`TxHandlerBuilder`] for the `move_to_vault_tx`. This transaction will move
/// the funds to a NofN address from the deposit intent address, after all the signature
/// collection operations are done.
pub fn create_replacement_deposit_txhandler(
    old_move_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    paramset: &'static ProtocolParamset,
    security_council: SecurityCouncil,
) -> Result<TxHandlerBuilder, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::ReplacementDeposit)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::NoSignature,
            SpendableTxIn::from_scripts(
                bitcoin::OutPoint {
                    txid: old_move_txid,
                    vout: 0,
                },
                paramset.bridge_amount - ANCHOR_AMOUNT,
                vec![
                    Arc::new(CheckSig::new(nofn_xonly_pk)),
                    Arc::new(Multisig::from_security_council(security_council.clone())),
                ],
                None,
                paramset.network,
            ),
            crate::builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            paramset.bridge_amount,
            vec![
                Arc::new(ReplacementDepositScript::new(nofn_xonly_pk, old_move_txid)),
                Arc::new(Multisig::from_security_council(security_council)),
            ],
            None,
            paramset.network,
        ))
        .add_output(UnspentTxOut::from_partial(anchor_output())))
}

pub fn create_disprove_taproot_output(
    operator_timeout_script: Arc<dyn SpendableScript>,
    additional_script: ScriptBuf,
    disprove_root_hash: HiddenNode,
    amount: Amount,
    network: bitcoin::Network,
) -> UnspentTxOut {
    use crate::bitvm_client::{SECP, UNSPENDABLE_XONLY_PUBKEY};
    use bitcoin::taproot::{TapNodeHash, TaprootBuilder};

    let builder = TaprootBuilder::new()
        .add_leaf(1, operator_timeout_script.to_script_buf())
        .expect("empty taptree will accept a script node")
        .add_leaf(2, additional_script.clone())
        .expect("taptree with one node will accept a node at depth 2")
        .add_hidden_node(2, TapNodeHash::from_byte_array(*disprove_root_hash))
        .expect("taptree with two nodes will accept a node at depth 2");

    let taproot_spend_info = builder
        .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
        .expect("cannot fail since it is a valid taptree");

    let address = Address::p2tr(
        &SECP,
        *UNSPENDABLE_XONLY_PUBKEY,
        taproot_spend_info.merkle_root(),
        network,
    );

    UnspentTxOut::new(
        TxOut {
            value: amount,
            script_pubkey: address.script_pubkey(),
        },
        vec![
            operator_timeout_script.clone(),
            Arc::new(OtherSpendable::new(additional_script)),
        ],
        Some(taproot_spend_info),
    )
}

/// Helper function to create a taproot output that combines a script and a root hash
pub fn create_taproot_output_with_hidden_node(
    script: Arc<dyn SpendableScript>,
    hidden_node: HiddenNode,
    amount: Amount,
    network: bitcoin::Network,
) -> UnspentTxOut {
    use crate::bitvm_client::{SECP, UNSPENDABLE_XONLY_PUBKEY};
    use bitcoin::taproot::{TapNodeHash, TaprootBuilder};

    let builder = TaprootBuilder::new()
        .add_leaf(1, script.to_script_buf())
        .expect("empty taptree will accept a script node")
        .add_hidden_node(1, TapNodeHash::from_byte_array(*hidden_node))
        .expect("taptree with one node will accept a node at depth 1");

    let taproot_spend_info = builder
        .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
        .expect("cannot fail since it is a valid taptree");

    let address = Address::p2tr(
        &SECP,
        *UNSPENDABLE_XONLY_PUBKEY,
        taproot_spend_info.merkle_root(),
        network,
    );

    UnspentTxOut::new(
        TxOut {
            value: amount,
            script_pubkey: address.script_pubkey(),
        },
        vec![script.clone()],
        Some(taproot_spend_info),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::XOnlyPublicKey;
    use std::str::FromStr;

    #[test]
    fn test_security_council_from_str() {
        // Create some test public keys
        let pk1 = XOnlyPublicKey::from_slice(&[1; 32]).unwrap();
        let pk2 = XOnlyPublicKey::from_slice(&[2; 32]).unwrap();

        // Test valid input
        let input = format!(
            "2:{},{}",
            hex::encode(pk1.serialize()),
            hex::encode(pk2.serialize())
        );
        let council = SecurityCouncil::from_str(&input).unwrap();
        assert_eq!(council.threshold, 2);
        assert_eq!(council.pks.len(), 2);
        assert_eq!(council.pks[0], pk1);
        assert_eq!(council.pks[1], pk2);

        // Test invalid threshold
        let input = format!(
            "3:{},{}",
            hex::encode(pk1.serialize()),
            hex::encode(pk2.serialize())
        );
        assert!(SecurityCouncil::from_str(&input).is_err());

        // Test invalid hex
        let input = "2:invalid,pk2";
        assert!(SecurityCouncil::from_str(input).is_err());

        // Test missing parts
        assert!(SecurityCouncil::from_str("2").is_err());
        assert!(SecurityCouncil::from_str(":").is_err());

        // Test too many parts
        let input = format!(
            "2:{},{}:extra",
            hex::encode(pk1.serialize()),
            hex::encode(pk2.serialize())
        );
        assert!(SecurityCouncil::from_str(&input).is_err());

        // Test empty public keys
        assert!(SecurityCouncil::from_str("2:").is_err());
    }

    #[test]
    fn test_security_council_round_trip() {
        // Create some test public keys
        let pk1 = XOnlyPublicKey::from_slice(&[1; 32]).unwrap();
        let pk2 = XOnlyPublicKey::from_slice(&[2; 32]).unwrap();

        let original = SecurityCouncil {
            pks: vec![pk1, pk2],
            threshold: 2,
        };

        let string = original.to_string();
        let parsed = SecurityCouncil::from_str(&string).unwrap();

        assert_eq!(original, parsed);
    }
}
