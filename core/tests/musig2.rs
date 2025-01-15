use bitcoin::key::Keypair;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::XOnlyPublicKey;
use bitcoin::{hashes::Hash, script, Amount, ScriptBuf};
use bitcoincore_rpc::RpcApi;
use clementine_core::builder::transaction::TxHandler;
use clementine_core::musig2::{
    aggregate_nonces, aggregate_partial_signatures, AggregateFromPublicKeys, MusigTweak,
};
use clementine_core::utils::{handle_taproot_witness_new, SECP};
use clementine_core::{
    actor::Actor,
    builder::{self},
    config::BridgeConfig,
    extended_rpc::ExtendedRpc,
    musig2::{nonce_pair, partial_sign, MuSigNoncePair},
    utils,
};
use clementine_core::{database::Database, utils::initialize_logger};
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce};
use std::{env, thread};

mod common;

fn get_verifiers_keys(config: &BridgeConfig) -> (Vec<Keypair>, XOnlyPublicKey, Vec<PublicKey>) {
    let verifiers_secret_keys = config.all_verifiers_secret_keys.clone().unwrap();

    let verifiers_secret_public_keys: Vec<Keypair> = verifiers_secret_keys
        .iter()
        .map(|sk| Keypair::from_secret_key(&SECP, sk))
        .collect();

    let verifier_public_keys = verifiers_secret_public_keys
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<PublicKey>>();

    let untweaked_xonly_pubkey =
        XOnlyPublicKey::from_musig2_pks(verifier_public_keys.clone(), MusigTweak::None);

    (
        verifiers_secret_public_keys,
        untweaked_xonly_pubkey,
        verifier_public_keys,
    )
}

fn get_nonces(verifiers_secret_public_keys: Vec<Keypair>) -> (Vec<MuSigNoncePair>, MusigAggNonce) {
    let nonce_pairs: Vec<MuSigNoncePair> = verifiers_secret_public_keys
        .iter()
        .map(|kp| nonce_pair(kp, &mut secp256k1::rand::thread_rng()))
        .collect();

    let agg_nonce = aggregate_nonces(
        nonce_pairs
            .iter()
            .map(|(_, musig_pub_nonces)| *musig_pub_nonces)
            .collect::<Vec<MusigPubNonce>>(),
    );

    (nonce_pairs, agg_nonce)
}

#[tokio::test]
#[serial_test::serial]
async fn key_spend() {
    let config = create_test_config_with_thread_name!(None);
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await;

    let (verifiers_secret_public_keys, untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone());

    let (to_address, to_address_spend) =
        builder::address::create_taproot_address(&[], None, config.network);
    let (from_address, from_address_spend_info) =
        builder::address::create_taproot_address(&[], Some(untweaked_xonly_pubkey), config.network);

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .await
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
    let tx_outs = builder::transaction::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);
    let dummy_tx = builder::transaction::create_btc_tx(tx_ins, tx_outs);
    let mut tx_details = TxHandler {
        txid: dummy_tx.compute_txid(),
        tx: dummy_tx,
        prevouts: vec![prevout],
        prev_scripts: vec![vec![]],
        prev_taproot_spend_infos: vec![Some(from_address_spend_info.clone())],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![Some(to_address_spend.clone())],
    };

    let message = Message::from_digest(
        Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_details, 0)
            .unwrap()
            .to_byte_array(),
    );
    let merkle_root = from_address_spend_info.merkle_root();
    let tweak = if let Some(merkle_root) = merkle_root {
        MusigTweak::ScriptSpend(merkle_root)
    } else {
        MusigTweak::KeySpend(untweaked_xonly_pubkey)
    };

    let partial_sigs: Vec<MusigPartialSignature> = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                tweak,
                nonce_pair.0,
                agg_nonce,
                kp,
                message,
            )
        })
        .collect();

    let final_signature = aggregate_partial_signatures(
        verifier_public_keys.clone(),
        tweak,
        agg_nonce,
        partial_sigs,
        message,
    )
    .unwrap();

    let agg_pk = XOnlyPublicKey::from_musig2_pks(verifier_public_keys.clone(), MusigTweak::None);
    SECP.verify_schnorr(&final_signature, &message, &agg_pk)
        .unwrap();

    rpc.mine_blocks(1).await.unwrap();

    tx_details.tx.input[0]
        .witness
        .push(final_signature.serialize());
    rpc.client
        .send_raw_transaction(&tx_details.tx)
        .await
        .unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn key_spend_with_script() {
    let config = create_test_config_with_thread_name!(None);
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await;

    let (verifiers_secret_public_keys, untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone());

    let dummy_script = script::Builder::new().push_int(1).into_script();
    let scripts: Vec<ScriptBuf> = vec![dummy_script];

    let (to_address, to_address_spend) =
        builder::address::create_taproot_address(&[], None, config.network);
    let (from_address, from_address_spend_info) = builder::address::create_taproot_address(
        &scripts,
        Some(untweaked_xonly_pubkey),
        config.network,
    );

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .await
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();
    let tx_outs = builder::transaction::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
    let dummy_tx = builder::transaction::create_btc_tx(tx_ins, tx_outs);
    let mut tx_details = TxHandler {
        txid: dummy_tx.compute_txid(),
        tx: dummy_tx,
        prevouts: vec![prevout],
        prev_scripts: vec![scripts],
        prev_taproot_spend_infos: vec![Some(from_address_spend_info.clone())],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![Some(to_address_spend.clone())],
    };
    let message = Message::from_digest(
        Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_details, 0)
            .unwrap()
            .to_byte_array(),
    );
    let merkle_root = from_address_spend_info.merkle_root();
    let tweak = if let Some(merkle_root) = merkle_root {
        MusigTweak::ScriptSpend(merkle_root)
    } else {
        MusigTweak::KeySpend(untweaked_xonly_pubkey)
    };

    let partial_sigs: Vec<MusigPartialSignature> = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                tweak,
                nonce_pair.0,
                agg_nonce,
                kp,
                message,
            )
        })
        .collect();

    let final_signature = aggregate_partial_signatures(
        verifier_public_keys.clone(),
        tweak,
        agg_nonce,
        partial_sigs,
        message,
    )
    .unwrap();

    let agg_pk = XOnlyPublicKey::from_musig2_pks(verifier_public_keys.clone(), MusigTweak::None);

    SECP.verify_schnorr(&final_signature, &message, &agg_pk)
        .unwrap();

    rpc.mine_blocks(1).await.unwrap();

    tx_details.tx.input[0]
        .witness
        .push(final_signature.serialize());
    rpc.client
        .send_raw_transaction(&tx_details.tx)
        .await
        .unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn script_spend() {
    let config = create_test_config_with_thread_name!(None);
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await;

    let (verifiers_secret_public_keys, _untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone());

    let agg_pk = XOnlyPublicKey::from_musig2_pks(verifier_public_keys.clone(), MusigTweak::None);

    let agg_xonly_pubkey = bitcoin::XOnlyPublicKey::from_slice(&agg_pk.serialize()).unwrap();
    let musig2_script = bitcoin::script::Builder::new()
        .push_x_only_key(&agg_xonly_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let scripts: Vec<ScriptBuf> = vec![musig2_script];

    let to_address = bitcoin::Address::p2tr(
        &SECP,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        None,
        bitcoin::Network::Regtest,
    );
    let (from_address, from_address_spend_info) =
        builder::address::create_taproot_address(&scripts, None, bitcoin::Network::Regtest);

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .await
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();
    let tx_outs = builder::transaction::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
    let dummy_tx = builder::transaction::create_btc_tx(tx_ins, tx_outs);
    let mut tx_details = TxHandler {
        txid: dummy_tx.compute_txid(),
        tx: dummy_tx,
        prevouts: vec![prevout],
        prev_scripts: vec![scripts],
        prev_taproot_spend_infos: vec![Some(from_address_spend_info.clone())],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    };
    let message = Message::from_digest(
        Actor::convert_tx_to_sighash_script_spend(&mut tx_details, 0, 0)
            .unwrap()
            .to_byte_array(),
    );

    let partial_sigs: Vec<MusigPartialSignature> = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                MusigTweak::None,
                nonce_pair.0,
                agg_nonce,
                kp,
                message,
            )
        })
        .collect();
    let final_signature = aggregate_partial_signatures(
        verifier_public_keys.clone(),
        MusigTweak::None,
        agg_nonce,
        partial_sigs,
        message,
    )
    .unwrap();
    utils::SECP
        .verify_schnorr(&final_signature, &message, &agg_xonly_pubkey)
        .unwrap();

    let witness_elements = vec![final_signature.as_ref()];
    handle_taproot_witness_new(&mut tx_details, &witness_elements, 0, Some(0)).unwrap();

    rpc.mine_blocks(1).await.unwrap();

    rpc.client
        .send_raw_transaction(&tx_details.tx)
        .await
        .unwrap();
}
