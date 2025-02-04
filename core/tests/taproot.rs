use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::Scalar;
use bitcoin::{Address, Amount, TapTweakHash, TxOut};
use bitcoincore_rpc::RpcApi;
use clementine_core::actor::Actor;
use clementine_core::builder::script::{CheckSig, SpendableScript};
use clementine_core::builder::transaction::input::SpendableTxIn;
use clementine_core::builder::transaction::output::UnspentTxOut;
use clementine_core::builder::transaction::{TxHandlerBuilder, DEFAULT_SEQUENCE};
use clementine_core::builder::{self};
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::utils::SECP;
use clementine_core::{config::BridgeConfig, database::Database, utils::initialize_logger};
use std::sync::Arc;
use std::{env, thread};

mod common;

#[tokio::test]
#[serial_test::serial]
async fn create_address_and_transaction_then_sign_transaction() {
    let config = create_test_config_with_thread_name!(None);
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url,
        config.bitcoin_rpc_user,
        config.bitcoin_rpc_password,
    )
    .await;

    let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();
    let address = Address::p2tr(&SECP, xonly_pk, None, config.network);
    let script = address.script_pubkey();
    let tweaked_pk_script: [u8; 32] = script.as_bytes()[2..].try_into().unwrap();

    // Calculate tweaked public key.
    let mut hasher = TapTweakHash::engine();
    hasher.input(&xonly_pk.serialize());
    xonly_pk
        .add_tweak(
            &SECP,
            &Scalar::from_be_bytes(TapTweakHash::from_engine(hasher).to_byte_array()).unwrap(),
        )
        .unwrap();

    // Prepare script and address.
    let script = Arc::new(CheckSig::new(
        bitcoin::XOnlyPublicKey::from_slice(&tweaked_pk_script).unwrap(),
    ));
    let scripts: Vec<Arc<dyn SpendableScript>> = vec![script.clone()];
    let (taproot_address, taproot_spend_info) = builder::address::create_taproot_address(
        &scripts
            .iter()
            .map(|s| s.to_script_buf())
            .collect::<Vec<_>>(),
        None,
        config.network,
    );

    // Create a new transaction.
    let utxo = rpc
        .send_to_address(&taproot_address, Amount::from_sat(1000))
        .await
        .unwrap();

    let mut builder = TxHandlerBuilder::new();
    builder = builder.add_input(
        SpendableTxIn::new(
            utxo,
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: taproot_address.script_pubkey(),
            },
            scripts.clone(),
            Some(taproot_spend_info.clone()),
        ),
        DEFAULT_SEQUENCE,
    );

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: Amount::from_sat(330),
            script_pubkey: taproot_address.script_pubkey(),
        },
        scripts,
        Some(taproot_spend_info),
    ));

    let mut tx_handler = builder.finalize();

    // Signer should be able to sign the new transaction.
    let signer = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.network,
    );
    let sig = signer
        .sign_taproot_script_spend_tx_new_tweaked(&mut tx_handler, 0, 0)
        .unwrap();
    tx_handler
        .set_p2tr_script_spend_witness(&[sig.as_ref()], 0, 0)
        .unwrap();
    rpc.mine_blocks(1).await.unwrap();

    // New transaction should be OK to send.
    rpc.client
        .send_raw_transaction(tx_handler.get_cached_tx())
        .await
        .unwrap();
}
