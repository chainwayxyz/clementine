mod common;

use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::{hashes::Hash, script, Amount, ScriptBuf};
use clementine_core::builder::transaction::TxHandler;
use clementine_core::musig2::{
    aggregate_nonces, aggregate_partial_signatures, MuSigPartialSignature, MuSigPubNonce,
};
use clementine_core::utils::{handle_taproot_witness_new, SECP};
use clementine_core::ByteArray32;
use clementine_core::{
    actor::Actor,
    builder::{self},
    config::BridgeConfig,
    musig2::{create_key_agg_ctx, nonce_pair, partial_sign, MuSigNoncePair},
    utils, ByteArray66,
};
use common::create_test_config_with_thread_name;
use secp256k1::{Keypair, Message, PublicKey};

fn get_verifiers_keys(
    config: &BridgeConfig,
) -> (Vec<Keypair>, secp256k1::XOnlyPublicKey, Vec<PublicKey>) {
    let verifiers_secret_keys = config.all_verifiers_secret_keys.clone().unwrap();

    let verifiers_secret_public_keys: Vec<Keypair> = verifiers_secret_keys
        .iter()
        .map(|sk| Keypair::from_secret_key(&SECP, sk))
        .collect();

    let verifier_public_keys = verifiers_secret_public_keys
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<secp256k1::PublicKey>>();

    let key_agg_ctx = create_key_agg_ctx(verifier_public_keys.clone(), None, true).unwrap();
    let untweaked_pubkey =
        key_agg_ctx.aggregated_pubkey_untweaked::<musig2::secp256k1::PublicKey>();
    let untweaked_xonly_pubkey: secp256k1::XOnlyPublicKey =
        secp256k1::XOnlyPublicKey::from_slice(&untweaked_pubkey.x_only_public_key().0.serialize())
            .unwrap();

    (
        verifiers_secret_public_keys,
        untweaked_xonly_pubkey,
        verifier_public_keys,
    )
}

fn get_nonces(verifiers_secret_public_keys: Vec<Keypair>) -> (Vec<MuSigNoncePair>, ByteArray66) {
    let nonce_pairs: Vec<MuSigNoncePair> = verifiers_secret_public_keys
        .iter()
        .map(|kp| nonce_pair(kp, &mut secp256k1::rand::thread_rng()))
        .collect();

    let agg_nonce = aggregate_nonces(
        nonce_pairs
            .iter()
            .map(|x| ByteArray66(x.1 .0))
            .collect::<Vec<MuSigPubNonce>>(),
    );

    (nonce_pairs, agg_nonce)
}

#[tokio::test]
async fn key_spend() {
    let mut config: BridgeConfig =
        create_test_config_with_thread_name("test_config.toml", None).await;
    let rpc = create_extended_rpc!(config);

    let (verifiers_secret_public_keys, untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone());

    let (to_address, _) = builder::address::create_taproot_address(&[], None, config.network);
    let (from_address, from_address_spend_info) =
        builder::address::create_taproot_address(&[], Some(untweaked_xonly_pubkey), config.network);

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).unwrap();

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
    let tx_outs = builder::transaction::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);
    let dummy_tx = builder::transaction::create_btc_tx(tx_ins, tx_outs);

    let mut tx_details = TxHandler {
        tx: dummy_tx,
        prevouts: vec![prevout],
        scripts: vec![vec![]],
        taproot_spend_infos: vec![from_address_spend_info.clone()],
    };
    let message = Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_details, 0)
        .unwrap()
        .to_byte_array();
    let merkle_root = from_address_spend_info.merkle_root();
    let key_agg_ctx = create_key_agg_ctx(verifier_public_keys.clone(), merkle_root, true).unwrap();

    let partial_sigs: Vec<MuSigPartialSignature> = verifiers_secret_public_keys
        .iter()
        .zip(nonce_pairs.iter())
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                merkle_root,
                true,
                nonce_pair.0,
                agg_nonce,
                kp,
                ByteArray32(message),
            )
        })
        .collect();
    let final_signature = aggregate_partial_signatures(
        verifier_public_keys.clone(),
        merkle_root,
        true,
        &agg_nonce,
        partial_sigs,
        ByteArray32(message),
    )
    .unwrap();

    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let musig_agg_xonly_pubkey = musig_agg_pubkey.x_only_public_key().0;
    let musig_agg_xonly_pubkey_wrapped =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();

    musig2::verify_single(musig_agg_pubkey, final_signature, message).unwrap();

    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();
    SECP.verify_schnorr(
        &schnorr_sig,
        &Message::from_digest(message),
        &musig_agg_xonly_pubkey_wrapped,
    )
    .unwrap();

    tx_details.tx.input[0].witness.push(final_signature);
    rpc.send_raw_transaction(&tx_details.tx).unwrap();
}

#[tokio::test]
async fn key_spend_with_script() {
    let mut config: BridgeConfig =
        create_test_config_with_thread_name("test_config.toml", None).await;
    let rpc = create_extended_rpc!(config);

    let (verifiers_secret_public_keys, untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone());

    let dummy_script = script::Builder::new().push_int(1).into_script();
    let scripts: Vec<ScriptBuf> = vec![dummy_script];

    let (to_address, _) = builder::address::create_taproot_address(&[], None, config.network);
    let (from_address, from_address_spend_info) = builder::address::create_taproot_address(
        &scripts,
        Some(untweaked_xonly_pubkey),
        config.network,
    );

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).unwrap();
    let tx_outs = builder::transaction::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
    let dummy_tx = builder::transaction::create_btc_tx(tx_ins, tx_outs);

    let mut tx_details = TxHandler {
        tx: dummy_tx,
        prevouts: vec![prevout],
        scripts: vec![scripts],
        taproot_spend_infos: vec![from_address_spend_info.clone()],
    };
    let message = Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_details, 0)
        .unwrap()
        .to_byte_array();
    let merkle_root = from_address_spend_info.merkle_root();
    let key_agg_ctx = create_key_agg_ctx(verifier_public_keys.clone(), merkle_root, true).unwrap();

    let partial_sigs: Vec<MuSigPartialSignature> = verifiers_secret_public_keys
        .iter()
        .zip(nonce_pairs.iter())
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                merkle_root,
                true,
                nonce_pair.0,
                agg_nonce,
                kp,
                ByteArray32(message),
            )
        })
        .collect();
    let final_signature: [u8; 64] = aggregate_partial_signatures(
        verifier_public_keys.clone(),
        merkle_root,
        true,
        &agg_nonce,
        partial_sigs,
        ByteArray32(message),
    )
    .unwrap();

    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let musig_agg_xonly_pubkey = musig_agg_pubkey.x_only_public_key().0;
    let musig_agg_xonly_pubkey_wrapped =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();

    musig2::verify_single(musig_agg_pubkey, final_signature, message).unwrap();

    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();
    SECP.verify_schnorr(
        &schnorr_sig,
        &Message::from_digest(message),
        &musig_agg_xonly_pubkey_wrapped,
    )
    .unwrap();

    tx_details.tx.input[0].witness.push(final_signature);
    rpc.send_raw_transaction(&tx_details.tx).unwrap();
}

#[tokio::test]
async fn script_spend() {
    let mut config: BridgeConfig =
        create_test_config_with_thread_name("test_config.toml", None).await;
    let rpc = create_extended_rpc!(config);

    let (verifiers_secret_public_keys, _untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone());

    let key_agg_ctx = create_key_agg_ctx(verifier_public_keys.clone(), None, false).unwrap();
    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let (musig_agg_xonly_pubkey, _) = musig_agg_pubkey.x_only_public_key();
    let musig_agg_xonly_pubkey_wrapped =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();

    let agg_xonly_pubkey =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();
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
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).unwrap();
    let tx_outs = builder::transaction::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
    let dummy_tx = builder::transaction::create_btc_tx(tx_ins, tx_outs);
    let mut tx_details = TxHandler {
        tx: dummy_tx,
        prevouts: vec![prevout],
        scripts: vec![scripts],
        taproot_spend_infos: vec![from_address_spend_info.clone()],
    };
    let message = Actor::convert_tx_to_sighash_script_spend(&mut tx_details, 0, 0)
        .unwrap()
        .to_byte_array();

    let partial_sigs: Vec<MuSigPartialSignature> = verifiers_secret_public_keys
        .iter()
        .zip(nonce_pairs.iter())
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                None,
                false,
                nonce_pair.0,
                agg_nonce,
                kp,
                ByteArray32(message),
            )
        })
        .collect();
    let final_signature: [u8; 64] = aggregate_partial_signatures(
        verifier_public_keys.clone(),
        None,
        false,
        &agg_nonce,
        partial_sigs,
        ByteArray32(message),
    )
    .unwrap();
    musig2::verify_single(musig_agg_pubkey, final_signature, message).unwrap();
    utils::SECP
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap(),
            &Message::from_digest(message),
            &musig_agg_xonly_pubkey_wrapped,
        )
        .unwrap();

    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();
    let witness_elements = vec![schnorr_sig.as_ref()];
    handle_taproot_witness_new(&mut tx_details, &witness_elements, 0, Some(0)).unwrap();

    rpc.send_raw_transaction(&tx_details.tx).unwrap();
}
