use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::{hashes::Hash, script, Amount, ScriptBuf};
use bitcoincore_rpc::RawTx;
use clementine_core::create_extended_rpc;
use clementine_core::mock::database::create_test_config_with_thread_name;
use clementine_core::musig2::{
    aggregate_nonces, aggregate_partial_signatures, MuSigPartialSignature, MuSigPubNonce,
};
use clementine_core::utils::handle_taproot_witness_new;
use clementine_core::{
    actor::Actor,
    config::BridgeConfig,
    extended_rpc::ExtendedRpc,
    musig2::{create_key_agg_ctx, nonce_pair, partial_sign, MuSigNoncePair},
    transaction_builder::{TransactionBuilder, TxHandler},
    utils, ByteArray66,
};
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name, ByteArray32,
};
use secp256k1::{Keypair, Message};

#[tokio::test]
async fn test_musig2_key_spend() {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mut config: BridgeConfig =
        create_test_config_with_thread_name("test_config.toml", None).await;
    let rpc: ExtendedRpc<_> = create_extended_rpc!(config);
    let sks = config.all_verifiers_secret_keys.unwrap();
    let kp_vec: Vec<Keypair> = sks
        .iter()
        .map(|sk| Keypair::from_secret_key(&secp, sk))
        .collect();
    let nonce_pair_vec: Vec<MuSigNoncePair> = kp_vec
        .iter()
        .map(|kp| nonce_pair(kp, &mut secp256k1::rand::thread_rng()))
        .collect();
    let pks = kp_vec
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<secp256k1::PublicKey>>();
    let agg_nonce = aggregate_nonces(
        nonce_pair_vec
            .iter()
            .map(|x| ByteArray66(x.1 .0))
            .collect::<Vec<MuSigPubNonce>>(),
    );
    let key_agg_ctx = create_key_agg_ctx(pks.clone(), None, true).unwrap();
    let untweaked_pubkey =
        key_agg_ctx.aggregated_pubkey_untweaked::<musig2::secp256k1::PublicKey>();
    let untweaked_xonly_pubkey: secp256k1::XOnlyPublicKey =
        secp256k1::XOnlyPublicKey::from_slice(&untweaked_pubkey.x_only_public_key().0.serialize())
            .unwrap();
    let (to_address, _) = TransactionBuilder::create_taproot_address(&[], None, config.network);
    let (from_address, from_address_spend_info) = TransactionBuilder::create_taproot_address(
        &[],
        Some(untweaked_xonly_pubkey),
        config.network,
    );
    let utxo = rpc.send_to_address(&from_address, 100_000_000).unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).unwrap();
    let tx_outs = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);
    let tx_ins = TransactionBuilder::create_tx_ins(vec![utxo]);
    let dummy_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
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
    tracing::debug!("Merkle Root: {:?}", merkle_root);
    let key_agg_ctx = create_key_agg_ctx(pks.clone(), merkle_root, true).unwrap();

    let partial_sigs: Vec<MuSigPartialSignature> = kp_vec
        .iter()
        .zip(nonce_pair_vec.iter())
        .map(|(kp, nonce_pair)| {
            partial_sign(
                pks.clone(),
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
        pks.clone(),
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

    musig2::verify_single(musig_agg_pubkey, final_signature, message)
        .expect("Verification failed!");
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();
    secp.verify_schnorr(
        &schnorr_sig,
        &Message::from_digest(message),
        &musig_agg_xonly_pubkey_wrapped,
    )
    .unwrap();
    println!("MuSig2 signature verified successfully!");
    println!("SECP Verified Successfully");
    tx_details.tx.input[0].witness.push(final_signature);
    let txid = rpc.send_raw_transaction(&tx_details.tx).unwrap();
    println!("Transaction sent successfully! Txid: {}", txid);
}

#[tokio::test]
async fn test_musig2_key_spend_with_script() {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mut config: BridgeConfig =
        create_test_config_with_thread_name("test_config.toml", None).await;
    let rpc: ExtendedRpc<_> = create_extended_rpc!(config);
    let sks = config.all_verifiers_secret_keys.unwrap();
    let kp_vec: Vec<Keypair> = sks
        .iter()
        .map(|sk| Keypair::from_secret_key(&secp, sk))
        .collect();
    let nonce_pair_vec: Vec<MuSigNoncePair> = kp_vec
        .iter()
        .map(|kp| nonce_pair(kp, &mut secp256k1::rand::thread_rng()))
        .collect();
    let pks = kp_vec
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<secp256k1::PublicKey>>();
    let agg_nonce = aggregate_nonces(
        nonce_pair_vec
            .iter()
            .map(|x| ByteArray66(x.1 .0))
            .collect::<Vec<MuSigPubNonce>>(),
    );
    let key_agg_ctx = create_key_agg_ctx(pks.clone(), None, false).unwrap();
    let untweaked_pubkey =
        key_agg_ctx.aggregated_pubkey_untweaked::<musig2::secp256k1::PublicKey>();
    let untweaked_xonly_pubkey: secp256k1::XOnlyPublicKey =
        secp256k1::XOnlyPublicKey::from_slice(&untweaked_pubkey.x_only_public_key().0.serialize())
            .unwrap();
    let dummy_script = script::Builder::new().push_int(1).into_script();
    let scripts: Vec<ScriptBuf> = vec![dummy_script];
    let (to_address, _) = TransactionBuilder::create_taproot_address(&[], None, config.network);
    let (from_address, from_address_spend_info) = TransactionBuilder::create_taproot_address(
        &scripts,
        Some(untweaked_xonly_pubkey),
        config.network,
    );
    let utxo = rpc.send_to_address(&from_address, 100_000_000).unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).unwrap();
    let tx_outs = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);
    let tx_ins = TransactionBuilder::create_tx_ins(vec![utxo]);
    let dummy_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
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
    let key_agg_ctx = create_key_agg_ctx(pks.clone(), merkle_root, true).unwrap();

    let partial_sigs: Vec<MuSigPartialSignature> = kp_vec
        .iter()
        .zip(nonce_pair_vec.iter())
        .map(|(kp, nonce_pair)| {
            partial_sign(
                pks.clone(),
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
        pks.clone(),
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

    musig2::verify_single(musig_agg_pubkey, final_signature, message)
        .expect("Verification failed!");
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();
    secp.verify_schnorr(
        &schnorr_sig,
        &Message::from_digest(message),
        &musig_agg_xonly_pubkey_wrapped,
    )
    .unwrap();
    // println!("MuSig2 signature verified successfully!");
    // println!("SECP Verification: {:?}", res);
    tx_details.tx.input[0].witness.push(final_signature);
    let _txid = rpc.send_raw_transaction(&tx_details.tx).unwrap();
    // println!("Transaction sent successfully! Txid: {}", txid);
}

#[tokio::test]
async fn test_musig2_script_spend() {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mut config: BridgeConfig =
        create_test_config_with_thread_name("test_config.toml", None).await;
    let rpc: ExtendedRpc<_> = create_extended_rpc!(config);
    let sks = config.all_verifiers_secret_keys.unwrap();
    let kp_vec: Vec<Keypair> = sks
        .iter()
        .map(|sk| Keypair::from_secret_key(&secp, sk))
        .collect();
    let nonce_pair_vec: Vec<MuSigNoncePair> = kp_vec
        .iter()
        .map(|kp| nonce_pair(kp, &mut secp256k1::rand::thread_rng()))
        .collect();
    let pks = kp_vec
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<secp256k1::PublicKey>>();
    let agg_nonce = aggregate_nonces(
        nonce_pair_vec
            .iter()
            .map(|x| ByteArray66(x.1 .0))
            .collect::<Vec<MuSigPubNonce>>(),
    );
    let key_agg_ctx = create_key_agg_ctx(pks.clone(), None, false).unwrap();
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
        &secp,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        None,
        bitcoin::Network::Regtest,
    );
    let (from_address, from_address_spend_info) =
        TransactionBuilder::create_taproot_address(&scripts, None, bitcoin::Network::Regtest);
    let utxo = rpc.send_to_address(&from_address, 100_000_000).unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).unwrap();
    let tx_outs = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);
    let tx_ins = TransactionBuilder::create_tx_ins(vec![utxo]);
    let dummy_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
    let mut tx_details = TxHandler {
        tx: dummy_tx,
        prevouts: vec![prevout],
        scripts: vec![scripts],
        taproot_spend_infos: vec![from_address_spend_info.clone()],
    };
    let message = Actor::convert_tx_to_sighash_script_spend(&mut tx_details, 0, 0)
        .unwrap()
        .to_byte_array();

    let partial_sigs: Vec<MuSigPartialSignature> = kp_vec
        .iter()
        .zip(nonce_pair_vec.iter())
        .map(|(kp, nonce_pair)| {
            partial_sign(
                pks.clone(),
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
        pks.clone(),
        None,
        false,
        &agg_nonce,
        partial_sigs,
        ByteArray32(message),
    )
    .unwrap();
    musig2::verify_single(musig_agg_pubkey, final_signature, message)
        .expect("Verification failed!");
    utils::SECP
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap(),
            &Message::from_digest(message),
            &musig_agg_xonly_pubkey_wrapped,
        )
        .unwrap();
    println!("MuSig2 signature verified successfully!");
    println!("SECP Verified Successfully");
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();
    let witness_elements = vec![schnorr_sig.as_ref()];
    handle_taproot_witness_new(&mut tx_details, &witness_elements, 0, Some(0)).unwrap();
    println!("HEX: {:?}", tx_details.tx.raw_hex());
    let txid = rpc.send_raw_transaction(&tx_details.tx).unwrap();
    println!("Transaction sent successfully! Txid: {}", txid);
}
