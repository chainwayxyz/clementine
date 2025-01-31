use bitcoin::key::Keypair;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::XOnlyPublicKey;
use bitcoin::{hashes::Hash, script, Amount, ScriptBuf};
use bitcoincore_rpc::RpcApi;
use clementine_core::builder::transaction::TxHandler;
use clementine_core::errors::BridgeError;
use clementine_core::musig2::{
    aggregate_nonces, aggregate_partial_signatures, AggregateFromPublicKeys, Musig2Mode,
};
use clementine_core::utils::{set_p2tr_key_spend_witness, set_p2tr_script_spend_witness, SECP};
use clementine_core::{
    builder::{self},
    config::BridgeConfig,
    extended_rpc::ExtendedRpc,
    musig2::{nonce_pair, partial_sign, MuSigNoncePair},
    utils,
};
use clementine_core::{database::Database, utils::initialize_logger};
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature};
use std::{env, thread};

mod common;

#[cfg(test)]
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
        XOnlyPublicKey::from_musig2_pks(verifier_public_keys.clone(), None).unwrap();

    (
        verifiers_secret_public_keys,
        untweaked_xonly_pubkey,
        verifier_public_keys,
    )
}

#[cfg(test)]
fn get_nonces(
    verifiers_secret_public_keys: Vec<Keypair>,
) -> Result<(Vec<MuSigNoncePair>, MusigAggNonce), BridgeError> {
    let nonce_pairs: Vec<MuSigNoncePair> = verifiers_secret_public_keys
        .iter()
        .map(|kp| nonce_pair(kp, &mut secp256k1::rand::thread_rng()))
        .collect::<Result<Vec<_>, _>>()?;

    let agg_nonce = aggregate_nonces(
        nonce_pairs
            .iter()
            .map(|(_, musig_pub_nonces)| musig_pub_nonces)
            .collect::<Vec<_>>()
            .as_slice(),
    );

    Ok((nonce_pairs, agg_nonce))
}

#[tokio::test]
#[serial_test::serial]
async fn key_spend() {
    let config = create_test_config_with_thread_name!(None);
    let rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .unwrap();

    let (verifiers_secret_public_keys, untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone()).unwrap();

    let (to_address, to_address_spend) =
        builder::address::create_taproot_address(&[], None, config.network);
    let (from_address, from_address_spend_info) =
        builder::address::create_taproot_address(&[], Some(untweaked_xonly_pubkey), config.network);

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .await
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo].into());
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
        tx_details
            .calculate_pubkey_spend_sighash(0, None)
            .unwrap()
            .to_byte_array(),
    );
    let merkle_root = from_address_spend_info.merkle_root();
    assert!(merkle_root.is_none());

    let partial_sigs: Vec<MusigPartialSignature> = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                Some(Musig2Mode::OnlyKeySpend),
                nonce_pair.0,
                agg_nonce,
                kp,
                message,
            )
            .unwrap()
        })
        .collect();

    let final_signature = aggregate_partial_signatures(
        &verifier_public_keys,
        Some(Musig2Mode::OnlyKeySpend),
        agg_nonce,
        &partial_sigs,
        message,
    )
    .unwrap();

    let agg_pk = XOnlyPublicKey::from_musig2_pks(
        verifier_public_keys.clone(),
        Some(Musig2Mode::OnlyKeySpend),
    )
    .unwrap();
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
    let rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .unwrap();

    let (verifiers_secret_public_keys, untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone()).unwrap();

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

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo].into());
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
        tx_details
            .calculate_pubkey_spend_sighash(0, None)
            .unwrap()
            .to_byte_array(),
    );
    let merkle_root = from_address_spend_info.merkle_root().unwrap();

    let partial_sigs: Vec<MusigPartialSignature> = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                Some(Musig2Mode::KeySpendWithScript(merkle_root)),
                nonce_pair.0,
                agg_nonce,
                kp,
                message,
            )
            .unwrap()
        })
        .collect();

    let final_signature = aggregate_partial_signatures(
        &verifier_public_keys,
        Some(Musig2Mode::KeySpendWithScript(merkle_root)),
        agg_nonce,
        &partial_sigs,
        message,
    )
    .unwrap();

    let agg_pk = XOnlyPublicKey::from_musig2_pks(
        verifier_public_keys.clone(),
        Some(Musig2Mode::KeySpendWithScript(merkle_root)),
    )
    .unwrap();

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
    let rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .unwrap();

    let (verifiers_secret_public_keys, _untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone()).unwrap();

    let agg_pk = XOnlyPublicKey::from_musig2_pks(verifier_public_keys.clone(), None).unwrap();

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

    let tx_ins = builder::transaction::create_tx_ins(vec![utxo].into());
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
        tx_details
            .calculate_script_spend_sighash(0, 0, None)
            .unwrap()
            .to_byte_array(),
    );

    let partial_sigs: Vec<MusigPartialSignature> = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifier_public_keys.clone(),
                None,
                nonce_pair.0,
                agg_nonce,
                kp,
                message,
            )
            .unwrap()
        })
        .collect();
    let final_signature = aggregate_partial_signatures(
        &verifier_public_keys,
        None,
        agg_nonce,
        &partial_sigs,
        message,
    )
    .unwrap();

    utils::SECP
        .verify_schnorr(&final_signature, &message, &agg_xonly_pubkey)
        .unwrap();

    let witness_elements = vec![final_signature.as_ref()];
    set_p2tr_script_spend_witness(&mut tx_details, &witness_elements, 0, 0).unwrap();

    rpc.mine_blocks(1).await.unwrap();

    rpc.client
        .send_raw_transaction(&tx_details.tx)
        .await
        .unwrap();
}

/// Tests spending both key and script paths of a single P2TR UTXO.
///
/// This test is designed to test the following, especially in the Musig2 case:
/// - The script spend is valid
/// - The key spend is valid with the tweaked aggregate public key
#[tokio::test]
#[serial_test::serial]
async fn key_and_script_spend() {
    use bitcoin::{Network::*, *};

    // Arrange
    let config = create_test_config_with_thread_name!(None);
    let rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .unwrap();

    // -- Musig2 Setup --
    // Generate NofN keys
    let (verifiers_secret_public_keys, _untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    // Generate NofN nonces (need two for key and script spend)
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone()).unwrap();
    let (nonce_pairs_2, agg_nonce_2) = get_nonces(verifiers_secret_public_keys.clone()).unwrap();

    // Aggregate Pks
    let agg_pk = XOnlyPublicKey::from_musig2_pks(verifier_public_keys.clone(), None).unwrap();

    // -- Script Setup --
    // Tapscript for script spending of NofN sig
    let musig2_script = bitcoin::script::Builder::new()
        .push_x_only_key(&agg_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let scripts: Vec<ScriptBuf> = vec![musig2_script];

    // -- UTXO Setup --
    // Both script and key spend in P2TR address
    let (from_address, from_address_spend_info) =
        builder::address::create_taproot_address(&scripts, Some(agg_pk), bitcoin::Network::Regtest);

    // Merkle root hash of Tapscript tree
    let merkle_root = from_address_spend_info.merkle_root().unwrap();
    // Tweaked aggregate public key
    let agg_pk_tweaked = XOnlyPublicKey::from_musig2_pks(
        verifier_public_keys.clone(),
        Some(Musig2Mode::KeySpendWithScript(merkle_root)),
    )
    .unwrap();

    // Create UTXOs
    let utxo_1 = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .await
        .unwrap();
    let utxo_2 = rpc
        .send_to_address(&from_address, Amount::from_sat(99_999_999))
        .await
        .unwrap();

    // Get UTXOs
    let prevout_1 = rpc.get_txout_from_outpoint(&utxo_1).await.unwrap();
    let prevout_2 = rpc.get_txout_from_outpoint(&utxo_2).await.unwrap();

    // TxIn of test TX
    let tx_ins_1 = builder::transaction::create_tx_ins(vec![utxo_1].into());
    let tx_ins_2 = builder::transaction::create_tx_ins(vec![utxo_2].into());

    // BTC address to execute test transaction to
    // Doesn't matter
    let to_address = bitcoin::Address::p2pkh(
        PublicKey::from(bitcoin::secp256k1::PublicKey::from_x_only_public_key(
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            key::Parity::Even,
        )),
        Regtest,
    );

    // TxOut of test TX
    let tx_outs = builder::transaction::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);

    // Test Transactions
    let test_tx_1 = builder::transaction::create_btc_tx(tx_ins_1, tx_outs.clone());
    let mut test_txhandler_1 = TxHandler {
        txid: test_tx_1.compute_txid(),
        tx: test_tx_1,
        prevouts: vec![prevout_1],
        prev_scripts: vec![scripts.clone()],
        prev_taproot_spend_infos: vec![Some(from_address_spend_info.clone())],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    };
    let test_tx_2 = builder::transaction::create_btc_tx(tx_ins_2, tx_outs);
    let mut test_txhandler_2 = TxHandler {
        txid: test_tx_2.compute_txid(),
        tx: test_tx_2,
        prevouts: vec![prevout_2],
        prev_scripts: vec![scripts],
        prev_taproot_spend_infos: vec![Some(from_address_spend_info.clone())],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    };

    let sighash_1 = Message::from_digest(
        test_txhandler_1
            .calculate_script_spend_sighash(0, 0, None)
            .unwrap()
            .to_byte_array(),
    );
    let sighash_2 = Message::from_digest(
        test_txhandler_2
            .calculate_pubkey_spend_sighash(0, None)
            .unwrap()
            .to_byte_array(),
    );

    // Act

    // Musig2 Partial Signatures
    // Script Spend
    let final_signature_1 = {
        let partial_sigs: Vec<MusigPartialSignature> = verifiers_secret_public_keys
            .iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                partial_sign(
                    verifier_public_keys.clone(),
                    None,
                    nonce_pair.0,
                    agg_nonce,
                    *kp,
                    sighash_1,
                )
                .unwrap()
            })
            .collect();

        // Musig2 Aggregate
        aggregate_partial_signatures(
            &verifier_public_keys,
            None,
            agg_nonce,
            &partial_sigs,
            sighash_1,
        )
        .unwrap()
    };

    // Key spend
    let final_signature_2 = {
        let partial_sigs: Vec<MusigPartialSignature> = verifiers_secret_public_keys
            .iter()
            .zip(nonce_pairs_2)
            .map(|(kp, nonce_pair)| {
                partial_sign(
                    verifier_public_keys.clone(),
                    Some(Musig2Mode::KeySpendWithScript(merkle_root)),
                    nonce_pair.0,
                    agg_nonce_2,
                    *kp,
                    sighash_2,
                )
                .unwrap()
            })
            .collect();

        aggregate_partial_signatures(
            &verifier_public_keys,
            Some(Musig2Mode::KeySpendWithScript(merkle_root)),
            agg_nonce_2,
            &partial_sigs,
            sighash_2,
        )
        .unwrap()
    };

    // Assert

    // -- Verify Script Spend --
    // Verify signature for script spend
    // The script will verify the aggregate public key with the signature of sighash_1
    utils::SECP
        .verify_schnorr(&final_signature_1, &sighash_1, &agg_pk)
        .unwrap();

    // Set up the witness for the script spend
    let witness_elements = vec![final_signature_1.as_ref()];
    set_p2tr_script_spend_witness(&mut test_txhandler_1, &witness_elements, 0, 0).unwrap();

    // Mine a block to confirm previous transaction
    rpc.mine_blocks(1).await.unwrap();

    // Send the transaction
    rpc.client
        .send_raw_transaction(&test_txhandler_1.tx)
        .await
        .unwrap();

    // -- Verify Key Spend --
    // Verify signature for key spend
    // The key will verify the aggregate public key with the signature of sighash_2
    // The signature should be valid with the tweaked aggregate public key
    utils::SECP
        .verify_schnorr(&final_signature_2, &sighash_2, &agg_pk_tweaked)
        .unwrap();

    set_p2tr_key_spend_witness(
        &mut test_txhandler_2,
        &taproot::Signature::from_slice(final_signature_2.as_ref()).unwrap(),
        0,
    )
    .unwrap();

    rpc.mine_blocks(1).await.unwrap();

    // Send the transaction
    rpc.client
        .send_raw_transaction(&test_txhandler_2.tx)
        .await
        .unwrap();
}
