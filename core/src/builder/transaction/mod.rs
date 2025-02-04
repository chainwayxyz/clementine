//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use std::sync::Arc;

use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::builder::script::OtherSpendable;
pub use crate::builder::transaction::challenge::*;
use crate::builder::transaction::input::SpendableTxIn;
pub use crate::builder::transaction::operator_assert::*;
pub use crate::builder::transaction::operator_collateral::*;
pub use crate::builder::transaction::operator_reimburse::*;
use crate::builder::transaction::output::UnspentTxOut;
pub use crate::builder::transaction::txhandler::*;
use crate::errors::BridgeError;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Transaction;
use bitcoin::{absolute, Address, Amount, OutPoint, TxIn, TxOut, XOnlyPublicKey};
use input::create_tx_ins;
pub use txhandler::Unsigned;

use super::script::SpendableScript;

mod challenge;
pub mod input;
mod operator_assert;
mod operator_collateral;
mod operator_reimburse;
pub mod output;
mod txhandler;

/// Creates a Bitcoin V3 transaction with no locktime, using given inputs and
/// outputs.
pub fn create_btc_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version(3),
        lock_time: absolute::LockTime::from_consensus(0),
        input: tx_ins,
        output: tx_outs,
    }
}

/// Creates the `move_to_vault_tx`.
pub fn create_move_to_vault_tx(
    deposit_outpoint: OutPoint,
    nofn_xonly_pk: XOnlyPublicKey,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> Transaction {
    let (musig2_address, _) = builder::address::create_checksig_address(nofn_xonly_pk, network);

    let tx_ins = create_tx_ins(vec![deposit_outpoint].into());

    let anchor_output = builder::script::anchor_output();
    let move_txout = TxOut {
        value: bridge_amount_sats,
        script_pubkey: musig2_address.script_pubkey(),
    };

    create_btc_tx(tx_ins, vec![move_txout, anchor_output])
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
    let nofn_script = builder::script::generate_checksig_script(nofn_xonly_pk);
    let (musig2_address, musig2_spendinfo) =
        create_taproot_address(&[nofn_script.to_script_buf()], None, network);

    let (deposit_address, deposit_taproot_spend_info, deposit_scripts) =
        builder::address::generate_deposit_address(
            nofn_xonly_pk,
            recovery_taproot_address,
            user_evm_address,
            bridge_amount_sats,
            network,
            user_takes_after,
        );

    let builder = TxHandlerBuilder::new().add_input(
        SpendableTxIn::new(
            deposit_outpoint,
            TxOut {
                value: bridge_amount_sats,
                script_pubkey: deposit_address.script_pubkey(),
            },
            deposit_scripts
                .map(Into::<OtherSpendable>::into)
                .map(|a| Arc::new(a) as Arc<dyn SpendableScript>)
                .to_vec(),
            Some(deposit_taproot_spend_info.clone()),
        ),
        DEFAULT_SEQUENCE,
    );

    Ok(builder
        .add_output(UnspentTxOut::from_scripts(
            bridge_amount_sats,
            vec![Arc::new(nofn_script)],
            None,
            network,
        ))
        .add_output(UnspentTxOut::from_partial(builder::script::anchor_output()))
        .finalize())
}

#[cfg(test)]
mod tests {
    use crate::{builder, utils::SECP};
    use bitcoin::{
        hashes::Hash, key::Keypair, secp256k1::SecretKey, Amount, OutPoint, Txid, XOnlyPublicKey,
    };
    use secp256k1::rand;

    #[test]
    fn create_move_to_vault_tx() {
        let deposit_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0x45,
        };
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let nofn_xonly_pk =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &secret_key)).0;
        let bridge_amount_sats = Amount::from_sat(0x1F45);
        let network = bitcoin::Network::Regtest;

        let move_tx = super::create_move_to_vault_tx(
            deposit_outpoint,
            nofn_xonly_pk,
            bridge_amount_sats,
            network,
        );

        assert_eq!(
            move_tx.input.first().unwrap().previous_output,
            deposit_outpoint
        );
        assert_eq!(
            move_tx.output.first().unwrap().script_pubkey,
            builder::address::create_checksig_address(nofn_xonly_pk, network)
                .0
                .script_pubkey()
        );
        assert_eq!(
            *move_tx.output.get(1).unwrap(),
            builder::script::anchor_output()
        );
    }

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
