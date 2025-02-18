//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use std::sync::Arc;

use super::script::SpendPath;
use super::script::{CheckSig, DepositScript, TimelockScript};
pub use crate::builder::transaction::challenge::*;
pub use crate::builder::transaction::creator::{create_txhandlers, TxHandlerDbData};
use crate::builder::transaction::input::SpendableTxIn;
pub use crate::builder::transaction::operator_assert::*;
pub use crate::builder::transaction::operator_collateral::*;
pub use crate::builder::transaction::operator_reimburse::*;
use crate::builder::transaction::output::UnspentTxOut;
pub use crate::builder::transaction::txhandler::*;
use crate::constants::ANCHOR_AMOUNT;
use crate::errors::BridgeError;
use crate::rpc::clementine::grpc_transaction_id;
use crate::rpc::clementine::GrpcTransactionId;
use crate::rpc::clementine::{
    NormalSignatureKind, NormalTransactionId, WatchtowerTransactionId, WatchtowerTransactionType,
};
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_RETURN};
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey};
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

/// Type to uniquely identify a deposit.
#[derive(Debug, Clone)]
pub struct DepositData {
    /// User's deposit UTXO.
    pub deposit_outpoint: bitcoin::OutPoint,
    /// User's EVM address.
    pub evm_address: EVMAddress,
    /// User's recovery taproot address.
    pub recovery_taproot_address: bitcoin::Address<NetworkUnchecked>,
}

#[derive(Debug, Clone)]
pub struct OperatorData {
    pub xonly_pk: XOnlyPublicKey,
    pub reimburse_addr: Address,
    pub collateral_funding_outpoint: OutPoint,
}

/// Types of all transactions that can be created. Some transactions have an (usize) to as they are created
/// multiple times per kickoff.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub enum TransactionType {
    SequentialCollateral,
    ReimburseGenerator,
    Kickoff,
    MoveToVault,
    Payout,
    Challenge,
    AssertTimeout,
    KickoffUtxoTimeout,
    WatchtowerChallengeKickoff,
    StartHappyReimburse,
    HappyReimburse,
    WatchtowerChallenge(usize),
    OperatorChallengeNack(usize),
    OperatorChallengeAck(usize),
    AssertBegin,
    MiniAssert(usize),
    AssertEnd,
    Disprove,
    DisproveTimeout,
    AlreadyDisproved,
    Reimburse,
    AllNeededForVerifierDeposit, // this will include all tx's that is to be signed for a deposit for verifiers
    AllNeededForOperatorDeposit, // this will include all tx's that is to be signed for a deposit for operators
    Dummy,                       // for tests
    ReadyToReimburse,
    KickoffNotFinalized,
}

// converter from proto type to rust enum
impl TryFrom<GrpcTransactionId> for TransactionType {
    type Error = ::prost::UnknownEnumValue;
    fn try_from(value: GrpcTransactionId) -> Result<Self, Self::Error> {
        use NormalTransactionId as Normal;
        use WatchtowerTransactionType as Watchtower;
        // return err if id is None
        let inner_id = value.id.ok_or(::prost::UnknownEnumValue(0))?;
        match inner_id {
            grpc_transaction_id::Id::NormalTransaction(idx) => {
                let tx_type = NormalTransactionId::try_from(idx)?;
                match tx_type {
                    Normal::SequentialCollateral => Ok(Self::SequentialCollateral),
                    Normal::ReimburseGenerator => Ok(Self::ReimburseGenerator),
                    Normal::Kickoff => Ok(Self::Kickoff),
                    Normal::MoveToVault => Ok(Self::MoveToVault),
                    Normal::Payout => Ok(Self::Payout),
                    Normal::Challenge => Ok(Self::Challenge),
                    Normal::AssertTimeout => Ok(Self::AssertTimeout),
                    Normal::KickoffUtxoTimeout => Ok(Self::KickoffUtxoTimeout),
                    Normal::WatchtowerChallengeKickoff => Ok(Self::WatchtowerChallengeKickoff),
                    Normal::StartHappyReimburse => Ok(Self::StartHappyReimburse),
                    Normal::HappyReimburse => Ok(Self::HappyReimburse),
                    Normal::AssertBegin => Ok(Self::AssertBegin),
                    Normal::AssertEnd => Ok(Self::AssertEnd),
                    Normal::Disprove => Ok(Self::Disprove),
                    Normal::DisproveTimeout => Ok(Self::DisproveTimeout),
                    Normal::AlreadyDisproved => Ok(Self::AlreadyDisproved),
                    Normal::Reimburse => Ok(Self::Reimburse),
                    Normal::AllNeededForVerifierDeposit => Ok(Self::AllNeededForVerifierDeposit),
                    Normal::AllNeededForOperatorDeposit => Ok(Self::AllNeededForOperatorDeposit),
                    Normal::Dummy => Ok(Self::Dummy),
                    Normal::ReadyToReimburse => Ok(Self::ReadyToReimburse),
                    Normal::KickoffNotFinalized => Ok(Self::KickoffNotFinalized),
                    Normal::UnspecifiedTransactionType => Err(::prost::UnknownEnumValue(idx)),
                }
            }
            grpc_transaction_id::Id::WatchtowerTransaction(watchtower_tx) => {
                let tx_type = WatchtowerTransactionType::try_from(watchtower_tx.transaction_type)?;
                match tx_type {
                    Watchtower::WatchtowerChallenge => {
                        Ok(Self::WatchtowerChallenge(watchtower_tx.index as usize))
                    }
                    Watchtower::OperatorChallengeNack => {
                        Ok(Self::OperatorChallengeNack(watchtower_tx.index as usize))
                    }
                    Watchtower::OperatorChallengeAck => {
                        Ok(Self::OperatorChallengeAck(watchtower_tx.index as usize))
                    }
                    Watchtower::MiniAssert => Ok(Self::MiniAssert(watchtower_tx.index as usize)),
                    Watchtower::UnspecifiedIndexedTransactionType => {
                        Err(::prost::UnknownEnumValue(watchtower_tx.transaction_type))
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
        use WatchtowerTransactionType as Watchtower;
        GrpcTransactionId {
            id: Some(match value {
                TransactionType::SequentialCollateral => {
                    NormalTransaction(Normal::SequentialCollateral as i32)
                }
                TransactionType::ReimburseGenerator => {
                    NormalTransaction(Normal::ReimburseGenerator as i32)
                }
                TransactionType::Kickoff => NormalTransaction(Normal::Kickoff as i32),
                TransactionType::MoveToVault => NormalTransaction(Normal::MoveToVault as i32),
                TransactionType::Payout => NormalTransaction(Normal::Payout as i32),
                TransactionType::Challenge => NormalTransaction(Normal::Challenge as i32),
                TransactionType::AssertTimeout => NormalTransaction(Normal::AssertTimeout as i32),
                TransactionType::KickoffUtxoTimeout => {
                    NormalTransaction(Normal::KickoffUtxoTimeout as i32)
                }
                TransactionType::WatchtowerChallengeKickoff => {
                    NormalTransaction(Normal::WatchtowerChallengeKickoff as i32)
                }
                TransactionType::StartHappyReimburse => {
                    NormalTransaction(Normal::StartHappyReimburse as i32)
                }
                TransactionType::HappyReimburse => NormalTransaction(Normal::HappyReimburse as i32),
                TransactionType::AssertBegin => NormalTransaction(Normal::AssertBegin as i32),
                TransactionType::AssertEnd => NormalTransaction(Normal::AssertEnd as i32),
                TransactionType::Disprove => NormalTransaction(Normal::Disprove as i32),
                TransactionType::DisproveTimeout => {
                    NormalTransaction(Normal::DisproveTimeout as i32)
                }
                TransactionType::AlreadyDisproved => {
                    NormalTransaction(Normal::AlreadyDisproved as i32)
                }
                TransactionType::Reimburse => NormalTransaction(Normal::Reimburse as i32),
                TransactionType::AllNeededForVerifierDeposit => {
                    NormalTransaction(Normal::AllNeededForVerifierDeposit as i32)
                }
                TransactionType::AllNeededForOperatorDeposit => {
                    NormalTransaction(Normal::AllNeededForOperatorDeposit as i32)
                }
                TransactionType::Dummy => NormalTransaction(Normal::Dummy as i32),
                TransactionType::ReadyToReimburse => {
                    NormalTransaction(Normal::ReadyToReimburse as i32)
                }
                TransactionType::KickoffNotFinalized => {
                    NormalTransaction(Normal::KickoffNotFinalized as i32)
                }
                TransactionType::WatchtowerChallenge(index) => {
                    WatchtowerTransaction(WatchtowerTransactionId {
                        transaction_type: Watchtower::WatchtowerChallenge as i32,
                        index: index as i32,
                    })
                }
                TransactionType::OperatorChallengeNack(index) => {
                    WatchtowerTransaction(WatchtowerTransactionId {
                        transaction_type: Watchtower::OperatorChallengeNack as i32,
                        index: index as i32,
                    })
                }
                TransactionType::OperatorChallengeAck(index) => {
                    WatchtowerTransaction(WatchtowerTransactionId {
                        transaction_type: Watchtower::OperatorChallengeAck as i32,
                        index: index as i32,
                    })
                }
                TransactionType::MiniAssert(index) => {
                    WatchtowerTransaction(WatchtowerTransactionId {
                        transaction_type: Watchtower::MiniAssert as i32,
                        index: index as i32,
                    })
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
    deposit_outpoint: OutPoint,
    user_evm_address: EVMAddress,
    recovery_taproot_address: &Address<NetworkUnchecked>,
    nofn_xonly_pk: XOnlyPublicKey,
    user_takes_after: u16,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    let nofn_script = Arc::new(CheckSig::new(nofn_xonly_pk));

    let deposit_script = Arc::new(DepositScript::new(
        nofn_xonly_pk,
        user_evm_address,
        bridge_amount_sats,
    ));

    let recovery_script_pubkey = recovery_taproot_address
        .clone()
        .assume_checked()
        .script_pubkey();

    let recovery_extracted_xonly_pk =
        XOnlyPublicKey::from_slice(&recovery_script_pubkey.as_bytes()[2..34])?;

    let script_timelock = Arc::new(TimelockScript::new(
        Some(recovery_extracted_xonly_pk),
        user_takes_after,
    ));

    let builder = TxHandlerBuilder::new(TransactionType::MoveToVault)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::from_scripts(
                deposit_outpoint,
                bridge_amount_sats,
                vec![deposit_script, script_timelock],
                None,
                network,
            ),
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        );

    Ok(builder
        .add_output(UnspentTxOut::from_scripts(
            bridge_amount_sats - ANCHOR_AMOUNT,
            vec![nofn_script],
            None,
            network,
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
