//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use std::sync::Arc;

use super::script::SpendPath;
use super::script::{CheckSig, DepositScript, TimelockScript};
pub use crate::builder::transaction::challenge::*;
use crate::builder::transaction::input::SpendableTxIn;
pub use crate::builder::transaction::operator_assert::*;
pub use crate::builder::transaction::operator_collateral::*;
pub use crate::builder::transaction::operator_reimburse::*;
use crate::builder::transaction::output::UnspentTxOut;
pub use crate::builder::transaction::txhandler::*;
use crate::constants::ANCHOR_AMOUNT;
use crate::errors::BridgeError;
use crate::rpc::clementine::NormalSignatureKind;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_RETURN};
use bitcoin::script::Builder;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut, XOnlyPublicKey};
pub use txhandler::Unsigned;

mod challenge;
pub mod input;
mod operator_assert;
mod operator_collateral;
mod operator_reimburse;
pub mod output;
mod txhandler;

/// Types of all transactions that can be created. Some transactions have an (usize) to as they are created
/// multiple times per kickoff.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum TransactionType {
    SequentialCollateral,
    ReimburseGenerator,
    Kickoff,
    MoveToVault,
    Payout,
    Challenge,
    KickoffTimeout,
    KickoffUTXOTimeout,
    WatchtowerChallengeKickoff,
    StartHappyReimburse,
    HappyReimburse,
    WatchtowerChallenge(usize),
    OperatorChallengeNACK(usize),
    OperatorChallengeACK(usize),
    AssertBegin,
    MiniAssert(usize),
    AssertEnd,
    Disprove,
    DisproveTimeout,
    AlreadyDisproved,
    Reimburse,
    AllNeededForDeposit, // this will include all tx's that is needed for a deposit
    All, // this will also include tx's not needed for a deposit, for example OperatorChallengeACK
    Dummy, // for tests
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

    let builder = TxHandlerBuilder::new(TransactionType::MoveToVault).add_input(
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
            bridge_amount_sats,
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
