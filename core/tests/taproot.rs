use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::Builder;
use bitcoin::{Address, Amount, TapTweakHash, TxOut, XOnlyPublicKey};
use bitcoincore_rpc::RpcApi;
use clementine_core::actor::Actor;
use clementine_core::builder::transaction::TxHandler;
use clementine_core::builder::{self};
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::database::create_test_config_with_thread_name;
use clementine_core::utils::{handle_taproot_witness_new, SECP};

#[tokio::test]
#[serial_test::serial]
async fn create_address_and_transaction_then_sign_transaction() {
    let config = create_test_config_with_thread_name("test_config.toml", None).await;
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
            &secp256k1::Scalar::from_be_bytes(TapTweakHash::from_engine(hasher).to_byte_array())
                .unwrap(),
        )
        .unwrap();

    // Prepare script and address.
    let builder = Builder::new();
    let to_pay_script = builder
        .push_x_only_key(&XOnlyPublicKey::from_slice(&tweaked_pk_script).unwrap())
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let (taproot_address, taproot_spend_info) =
        builder::address::create_taproot_address(&[to_pay_script.clone()], None, config.network);

    // Create a new transaction.
    let utxo = rpc
        .send_to_address(&taproot_address, Amount::from_sat(1000))
        .await
        .unwrap();
    let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
    let tx_outs = vec![TxOut {
        value: Amount::from_sat(330),
        script_pubkey: taproot_address.script_pubkey(),
    }];
    let prevouts = vec![TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: taproot_address.script_pubkey(),
    }];
    let tx = builder::transaction::create_btc_tx(tx_ins, tx_outs.clone());
    let mut tx_details = TxHandler {
        tx: tx.clone(),
        prevouts,
        scripts: vec![vec![to_pay_script.clone()]],
        taproot_spend_infos: vec![taproot_spend_info],
    };

    // Signer should be able to sign the new transaction.
    let signer = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.network,
    );
    let sig = signer
        .sign_taproot_script_spend_tx_new_tweaked(&mut tx_details, 0, 0)
        .unwrap();
    handle_taproot_witness_new(&mut tx_details, &[sig.as_ref()], 0, Some(0)).unwrap();

    // New transaction should be OK to send.
    rpc.client
        .send_raw_transaction(&tx_details.tx)
        .await
        .unwrap();
}
