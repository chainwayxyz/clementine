use bitcoin::{hashes::Hash, script, Amount, ScriptBuf, TapNodeHash};
use bitcoincore_rpc::Client;
use clementine_core::database::common::Database;
use clementine_core::mock::common;
use clementine_core::musig2::{aggregate_nonces, aggregate_partial_signatures, MuSigPubNonce};
use clementine_core::utils::handle_taproot_witness_new;
use clementine_core::{
    actor::Actor,
    config::BridgeConfig,
    extended_rpc::ExtendedRpc,
    musig2::{create_key_agg_ctx, nonce_pair, partial_sign, MuSigNoncePair},
    script_builder,
    transaction_builder::{CreateTxOutputs, TransactionBuilder},
    utils, ByteArray66,
};
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use musig2::{AggNonce, PubNonce};
use secp256k1::{Keypair, Message};
use std::thread;

#[tokio::test]
async fn test_musig2_key_spend() {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mut config: BridgeConfig = create_test_config_with_thread_name!("test_config_musig2.toml");
    let rpc: ExtendedRpc<Client> = create_extended_rpc!(config);
    let sks = config.all_secret_keys.unwrap();
    let kp_vec: Vec<Keypair> = sks
        .iter()
        .map(|sk| Keypair::from_secret_key(&secp, &sk))
        .collect();
    let nonce_pair_vec: Vec<MuSigNoncePair> = kp_vec
        .iter()
        .map(|kp| nonce_pair(&kp, &mut secp256k1::rand::thread_rng()))
        .collect();
    let pks = kp_vec
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<secp256k1::PublicKey>>();
    let musig_pub_nonces: Vec<PubNonce> = nonce_pair_vec
        .iter()
        .map(|x| musig2::PubNonce::from_bytes(&x.1 .0).unwrap())
        .collect::<Vec<musig2::PubNonce>>();
    let musig_agg_nonce: AggNonce = AggNonce::sum(musig_pub_nonces);
    let agg_nonce = ByteArray66(musig_agg_nonce.clone().into());
    let dummy_script = script::Builder::new().push_int(1).into_script();
    let scripts: Vec<ScriptBuf> = vec![dummy_script];
    let to_address = bitcoin::Address::p2tr(
        &secp,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        None,
        bitcoin::Network::Regtest,
    );
    let (from_address, from_address_spend_info) =
        TransactionBuilder::create_musig2_taproot_address(
            pks.clone(),
            scripts.clone(),
            bitcoin::Network::Regtest,
        )
        .unwrap();
    let utxo = rpc.send_to_address(&from_address, 100_000_000).unwrap();
    let prevout = rpc.get_txout_from_utxo(&utxo).unwrap();
    let tx_outs = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);
    let tx_ins = TransactionBuilder::create_tx_ins(vec![utxo]);
    let dummy_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
    let mut tx_details = CreateTxOutputs {
        tx: dummy_tx,
        prevouts: vec![prevout],
        scripts: vec![scripts],
        taproot_spend_infos: vec![from_address_spend_info.clone()],
    };
    let message = Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_details, 0)
        .unwrap()
        .to_byte_array();
    let merkle_root = from_address_spend_info.merkle_root();
    let tweak: [u8; 32] = match merkle_root {
        Some(root) => root.to_byte_array(),
        None => TapNodeHash::all_zeros().to_byte_array(),
    };
    let key_agg_ctx = create_key_agg_ctx(pks.clone(), Some(tweak)).unwrap();

    let partial_sigs: Vec<[u8; 32]> = kp_vec
        .iter()
        .zip(nonce_pair_vec.iter())
        .map(|(kp, nonce_pair)| {
            partial_sign(
                pks.clone(),
                Some(tweak),
                nonce_pair.0,
                agg_nonce.clone(),
                kp,
                message,
            )
        })
        .collect();
    let final_signature: [u8; 64] =
        aggregate_partial_signatures(pks.clone(), Some(tweak), &agg_nonce, partial_sigs, message)
            .unwrap();
    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let musig_agg_xonly_pubkey = musig_agg_pubkey.x_only_public_key().0;
    let musig_agg_xonly_pubkey_wrapped =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();

    musig2::verify_single(musig_agg_pubkey, &final_signature, message)
        .expect("Verification failed!");
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();
    let res = secp
        .verify_schnorr(
            &schnorr_sig,
            &Message::from_digest(message),
            &musig_agg_xonly_pubkey_wrapped,
        )
        .unwrap();
    println!("MuSig2 signature verified successfully!");
    println!("SECP Verification: {:?}", res);
    tx_details.tx.input[0].witness.push(&final_signature);
    let txid = rpc.send_raw_transaction(&tx_details.tx).unwrap();
    println!("Transaction sent successfully! Txid: {}", txid);
}

#[tokio::test]
async fn test_musig2_script_spend() {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mut config: BridgeConfig = create_test_config_with_thread_name!("test_config_musig2.toml");
    let rpc: ExtendedRpc<Client> = create_extended_rpc!(config);
    let sks = config.all_secret_keys.unwrap();
    let kp_vec: Vec<Keypair> = sks
        .iter()
        .map(|sk| Keypair::from_secret_key(&secp, &sk))
        .collect();
    let nonce_pair_vec: Vec<MuSigNoncePair> = kp_vec
        .iter()
        .map(|kp| nonce_pair(&kp, &mut secp256k1::rand::thread_rng()))
        .collect();
    let pks = kp_vec
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<secp256k1::PublicKey>>();
    let pub_nonces: Vec<MuSigPubNonce> =
        nonce_pair_vec.iter().map(|x| ByteArray66(x.1 .0)).collect();
    let agg_nonce = aggregate_nonces(pub_nonces);
    let key_agg_ctx = create_key_agg_ctx(pks.clone(), None).unwrap();
    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let (musig_agg_xonly_pubkey, _) = musig_agg_pubkey.x_only_public_key();
    let musig_agg_xonly_pubkey_wrapped =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();
    let agg_xonly_pubkey =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();
    let musig2_script = script_builder::generate_script_n_of_n(&vec![agg_xonly_pubkey]);
    let scripts: Vec<ScriptBuf> = vec![musig2_script];
    let to_address = bitcoin::Address::p2tr(
        &secp,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        None,
        bitcoin::Network::Regtest,
    );
    let (from_address, from_address_spend_info) =
        TransactionBuilder::create_musig2_taproot_address(
            pks.clone(),
            scripts.clone(),
            bitcoin::Network::Regtest,
        )
        .unwrap();
    let utxo = rpc.send_to_address(&from_address, 100_000_000).unwrap();
    let prevout = rpc.get_txout_from_utxo(&utxo).unwrap();
    let tx_outs = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(99_000_000),
        to_address.script_pubkey(),
    )]);
    let tx_ins = TransactionBuilder::create_tx_ins(vec![utxo]);
    let dummy_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
    let mut tx_details = CreateTxOutputs {
        tx: dummy_tx,
        prevouts: vec![prevout],
        scripts: vec![scripts],
        taproot_spend_infos: vec![from_address_spend_info.clone()],
    };
    let message = Actor::convert_tx_to_sighash_script_spend(&mut tx_details, 0, 0)
        .unwrap()
        .to_byte_array();

    let partial_sigs: Vec<[u8; 32]> = kp_vec
        .iter()
        .zip(nonce_pair_vec.iter())
        .map(|(kp, nonce_pair)| {
            partial_sign(
                pks.clone(),
                None,
                nonce_pair.0,
                agg_nonce.clone(),
                kp,
                message,
            )
        })
        .collect();
    let final_signature: [u8; 64] = clementine_core::musig2::aggregate_partial_signatures(
        pks.clone(),
        None,
        &agg_nonce,
        partial_sigs,
        message,
    )
    .unwrap();
    musig2::verify_single(musig_agg_pubkey, &final_signature, message)
        .expect("Verification failed!");
    let res = utils::SECP
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap(),
            &Message::from_digest(message),
            &musig_agg_xonly_pubkey_wrapped,
        )
        .unwrap();
    println!("MuSig2 signature verified successfully!");
    println!("SECP Verification: {:?}", res);
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap();
    let witness_elements = vec![schnorr_sig.as_ref()];
    handle_taproot_witness_new(&mut tx_details, &witness_elements, 0, 0).unwrap();
    let txid = rpc.send_raw_transaction(&tx_details.tx).unwrap();
    println!("Transaction sent successfully! Txid: {}", txid);
}
