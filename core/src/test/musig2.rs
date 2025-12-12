use crate::bitvm_client::SECP;
use crate::builder::script::{CheckSig, OtherSpendable, SpendPath, SpendableScript};
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
use clementine_errors::BridgeError;
use crate::musig2::{
    aggregate_nonces, aggregate_partial_signatures, AggregateFromPublicKeys, Musig2Mode,
};
use crate::rpc::clementine::NormalSignatureKind;
use crate::test::common::*;
use crate::{
    bitvm_client,
    builder::{self},
    config::BridgeConfig,
    musig2::{nonce_pair, partial_sign, MuSigNoncePair},
};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::{hashes::Hash, script, Amount, TapSighashType};
use bitcoin::{taproot, Sequence, TxOut, XOnlyPublicKey};
use bitcoincore_rpc::RpcApi;
use secp256k1::musig::AggregatedNonce;
use std::sync::Arc;

#[cfg(test)]
fn get_verifiers_keys(config: &BridgeConfig) -> (Vec<Keypair>, XOnlyPublicKey, Vec<PublicKey>) {
    let verifiers_secret_keys = &config.test_params.all_verifiers_secret_keys;

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
) -> Result<(Vec<MuSigNoncePair>, AggregatedNonce), BridgeError> {
    let nonce_pairs: Vec<MuSigNoncePair> = verifiers_secret_public_keys
        .iter()
        .map(nonce_pair)
        .collect::<Result<Vec<MuSigNoncePair>, _>>()?;

    let agg_nonce = aggregate_nonces(
        nonce_pairs
            .iter()
            .map(|(_, musig_pub_nonces)| musig_pub_nonces)
            .collect::<Vec<_>>()
            .as_slice(),
    )?;

    Ok((nonce_pairs, agg_nonce))
}

#[tokio::test]
async fn key_spend() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

    let (verifiers_secret_public_keys, untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone()).unwrap();

    let (to_address, to_address_spend) =
        builder::address::create_taproot_address(&[], None, config.protocol_paramset().network);
    let (from_address, from_address_spend_info) = builder::address::create_taproot_address(
        &[],
        Some(untweaked_xonly_pubkey),
        config.protocol_paramset().network,
    );

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .await
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();

    let mut tx_details = TxHandlerBuilder::new(TransactionType::Dummy)
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::new(utxo, prevout, vec![], Some(from_address_spend_info.clone())),
            SpendPath::Unknown,
            Sequence::default(),
        )
        .add_output(UnspentTxOut::new(
            TxOut {
                value: Amount::from_sat(99_000_000),
                script_pubkey: to_address.script_pubkey(),
            },
            vec![],
            Some(to_address_spend.clone()),
        ))
        .finalize();

    let message = Message::from_digest(
        tx_details
            .calculate_pubkey_spend_sighash(0, TapSighashType::Default)
            .unwrap()
            .to_byte_array(),
    );
    let merkle_root = from_address_spend_info.merkle_root();
    assert!(merkle_root.is_none());

    let partial_sigs = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            (
                partial_sign(
                    verifier_public_keys.clone(),
                    Some(Musig2Mode::OnlyKeySpend),
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    message,
                )
                .unwrap(),
                nonce_pair.1,
            )
        })
        .collect::<Vec<_>>();

    let final_signature = aggregate_partial_signatures(
        verifier_public_keys.clone(),
        Some(Musig2Mode::OnlyKeySpend),
        agg_nonce,
        &partial_sigs,
        message,
    )
    .unwrap();

    let agg_pk =
        XOnlyPublicKey::from_musig2_pks(verifier_public_keys, Some(Musig2Mode::OnlyKeySpend))
            .unwrap();
    SECP.verify_schnorr(&final_signature, &message, &agg_pk)
        .unwrap();

    rpc.mine_blocks(1).await.unwrap();

    tx_details
        .set_p2tr_key_spend_witness(
            &taproot::Signature::from_slice(&final_signature.serialize()).unwrap(),
            0,
        )
        .unwrap();
    rpc.send_raw_transaction(tx_details.get_cached_tx())
        .await
        .unwrap();
}

#[tokio::test]

async fn key_spend_with_script() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

    let (verifiers_secret_public_keys, untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone()).unwrap();

    let dummy_script = script::Builder::new().push_int(1).into_script();
    let scripts: Vec<Arc<dyn SpendableScript>> = vec![Arc::new(OtherSpendable::new(dummy_script))];

    let (to_address, _to_address_spend) =
        builder::address::create_taproot_address(&[], None, config.protocol_paramset().network);
    let (from_address, from_address_spend_info) = builder::address::create_taproot_address(
        &scripts
            .iter()
            .map(|a| a.to_script_buf())
            .collect::<Vec<_>>(),
        Some(untweaked_xonly_pubkey),
        config.protocol_paramset().network,
    );

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .await
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();
    let mut builder = TxHandlerBuilder::new(TransactionType::Dummy);
    builder = builder
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::new(
                utxo,
                prevout.clone(),
                scripts.clone(),
                Some(from_address_spend_info.clone()),
            ),
            SpendPath::Unknown,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: Amount::from_sat(99_000_000),
            script_pubkey: to_address.script_pubkey(),
        }));

    let mut tx_details = builder.finalize();
    let message = Message::from_digest(
        tx_details
            .calculate_pubkey_spend_sighash(0, TapSighashType::Default)
            .unwrap()
            .to_byte_array(),
    );
    let merkle_root = from_address_spend_info.merkle_root().unwrap();

    let partial_sigs = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            (
                partial_sign(
                    verifier_public_keys.clone(),
                    Some(Musig2Mode::KeySpendWithScript(merkle_root)),
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    message,
                )
                .unwrap(),
                nonce_pair.1,
            )
        })
        .collect::<Vec<_>>();

    let final_signature = aggregate_partial_signatures(
        verifier_public_keys.clone(),
        Some(Musig2Mode::KeySpendWithScript(merkle_root)),
        agg_nonce,
        &partial_sigs,
        message,
    )
    .unwrap();

    let agg_pk = XOnlyPublicKey::from_musig2_pks(
        verifier_public_keys,
        Some(Musig2Mode::KeySpendWithScript(merkle_root)),
    )
    .unwrap();

    SECP.verify_schnorr(&final_signature, &message, &agg_pk)
        .unwrap();

    rpc.mine_blocks(1).await.unwrap();

    tx_details
        .set_p2tr_key_spend_witness(
            &taproot::Signature::from_slice(&final_signature.serialize()).unwrap(),
            0,
        )
        .unwrap();
    rpc.send_raw_transaction(tx_details.get_cached_tx())
        .await
        .unwrap();
}

#[tokio::test]

async fn script_spend() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

    let (verifiers_secret_public_keys, _untweaked_xonly_pubkey, verifier_public_keys) =
        get_verifiers_keys(&config);
    let (nonce_pairs, agg_nonce) = get_nonces(verifiers_secret_public_keys.clone()).unwrap();

    let agg_pk = XOnlyPublicKey::from_musig2_pks(verifier_public_keys.clone(), None).unwrap();

    let agg_xonly_pubkey = bitcoin::XOnlyPublicKey::from_slice(&agg_pk.serialize()).unwrap();
    let scripts: Vec<Arc<dyn SpendableScript>> = vec![Arc::new(CheckSig::new(agg_xonly_pubkey))];

    let to_address = bitcoin::Address::p2tr(
        &SECP,
        *bitvm_client::UNSPENDABLE_XONLY_PUBKEY,
        None,
        bitcoin::Network::Regtest,
    );
    let (from_address, from_address_spend_info) = builder::address::create_taproot_address(
        &scripts
            .iter()
            .map(|s| s.to_script_buf())
            .collect::<Vec<_>>(),
        None,
        bitcoin::Network::Regtest,
    );

    let utxo = rpc
        .send_to_address(&from_address, Amount::from_sat(100_000_000))
        .await
        .unwrap();
    let prevout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();
    let mut tx_details = TxHandlerBuilder::new(TransactionType::Dummy)
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::new(
                utxo,
                prevout.clone(),
                scripts,
                Some(from_address_spend_info.clone()),
            ),
            SpendPath::Unknown,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: Amount::from_sat(99_000_000),
            script_pubkey: to_address.script_pubkey(),
        }))
        .finalize();
    let message = Message::from_digest(
        tx_details
            .calculate_script_spend_sighash_indexed(0, 0, bitcoin::TapSighashType::Default)
            .unwrap()
            .to_byte_array(),
    );

    let partial_sigs = verifiers_secret_public_keys
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            (
                partial_sign(
                    verifier_public_keys.clone(),
                    None,
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    message,
                )
                .unwrap(),
                nonce_pair.1,
            )
        })
        .collect::<Vec<_>>();
    let final_signature = aggregate_partial_signatures(
        verifier_public_keys,
        None,
        agg_nonce,
        &partial_sigs,
        message,
    )
    .unwrap();

    bitvm_client::SECP
        .verify_schnorr(&final_signature, &message, &agg_xonly_pubkey)
        .unwrap();

    let witness_elements = vec![final_signature.as_ref()];
    tx_details
        .set_p2tr_script_spend_witness(&witness_elements, 0, 0)
        .unwrap();

    rpc.mine_blocks(1).await.unwrap();

    rpc.send_raw_transaction(tx_details.get_cached_tx())
        .await
        .unwrap();
}

/// Tests spending both key and script paths of a single P2TR UTXO.
///
/// This test is designed to test the following, especially in the Musig2 case:
/// - The script spend is valid
/// - The key spend is valid with the tweaked aggregate public key
#[tokio::test]

async fn key_and_script_spend() {
    use bitcoin::{Network::*, *};

    // Arrange
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

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
    let musig2_script = Arc::new(CheckSig::new(agg_pk));
    let scripts: Vec<Arc<dyn SpendableScript>> = vec![musig2_script];

    // -- UTXO Setup --
    // Both script and key spend in P2TR address
    let (from_address, from_address_spend_info) = builder::address::create_taproot_address(
        &scripts
            .iter()
            .map(|s| s.to_script_buf())
            .collect::<Vec<_>>(),
        Some(agg_pk),
        bitcoin::Network::Regtest,
    );

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

    // BTC address to execute test transaction to
    // Doesn't matter
    let to_address = bitcoin::Address::p2pkh(
        PublicKey::from(bitcoin::secp256k1::PublicKey::from_x_only_public_key(
            *bitvm_client::UNSPENDABLE_XONLY_PUBKEY,
            key::Parity::Even,
        )),
        Regtest,
    );

    // Test Transactions
    let mut test_txhandler_1 = TxHandlerBuilder::new(TransactionType::Dummy)
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::new(
                utxo_1,
                prevout_1,
                scripts.clone(),
                Some(from_address_spend_info.clone()),
            ),
            SpendPath::Unknown,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: Amount::from_sat(99_000_000),
            script_pubkey: to_address.script_pubkey(),
        }))
        .finalize();

    let mut test_txhandler_2 = TxHandlerBuilder::new(TransactionType::Dummy)
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::new(
                utxo_2,
                prevout_2,
                scripts,
                Some(from_address_spend_info.clone()),
            ),
            SpendPath::Unknown,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: Amount::from_sat(99_000_000),
            script_pubkey: to_address.script_pubkey(),
        }))
        .finalize();

    let sighash_1 = Message::from_digest(
        test_txhandler_1
            .calculate_script_spend_sighash_indexed(0, 0, TapSighashType::Default)
            .unwrap()
            .to_byte_array(),
    );
    let sighash_2 = Message::from_digest(
        test_txhandler_2
            .calculate_pubkey_spend_sighash(0, TapSighashType::Default)
            .unwrap()
            .to_byte_array(),
    );

    // Act

    // Musig2 Partial Signatures
    // Script Spend
    let final_signature_1 = {
        let partial_sigs = verifiers_secret_public_keys
            .iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                (
                    partial_sign(
                        verifier_public_keys.clone(),
                        None,
                        nonce_pair.0,
                        agg_nonce,
                        *kp,
                        sighash_1,
                    )
                    .unwrap(),
                    nonce_pair.1,
                )
            })
            .collect::<Vec<_>>();

        // Musig2 Aggregate
        aggregate_partial_signatures(
            verifier_public_keys.clone(),
            None,
            agg_nonce,
            &partial_sigs,
            sighash_1,
        )
        .unwrap()
    };

    // Key spend
    let final_signature_2 = {
        let partial_sigs = verifiers_secret_public_keys
            .iter()
            .zip(nonce_pairs_2)
            .map(|(kp, nonce_pair)| {
                (
                    partial_sign(
                        verifier_public_keys.clone(),
                        Some(Musig2Mode::KeySpendWithScript(merkle_root)),
                        nonce_pair.0,
                        agg_nonce_2,
                        *kp,
                        sighash_2,
                    )
                    .unwrap(),
                    nonce_pair.1,
                )
            })
            .collect::<Vec<_>>();

        aggregate_partial_signatures(
            verifier_public_keys,
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
    bitvm_client::SECP
        .verify_schnorr(&final_signature_1, &sighash_1, &agg_pk)
        .unwrap();

    // Set up the witness for the script spend
    let witness_elements = vec![final_signature_1.as_ref()];
    test_txhandler_1
        .set_p2tr_script_spend_witness(&witness_elements, 0, 0)
        .unwrap();

    // Mine a block to confirm previous transaction
    rpc.mine_blocks(1).await.unwrap();

    // Send the transaction
    rpc.send_raw_transaction(test_txhandler_1.get_cached_tx())
        .await
        .unwrap();

    // -- Verify Key Spend --
    // Verify signature for key spend
    // The key will verify the aggregate public key with the signature of sighash_2
    // The signature should be valid with the tweaked aggregate public key
    bitvm_client::SECP
        .verify_schnorr(&final_signature_2, &sighash_2, &agg_pk_tweaked)
        .unwrap();

    (test_txhandler_2)
        .set_p2tr_key_spend_witness(
            &taproot::Signature::from_slice(final_signature_2.as_ref()).unwrap(),
            0,
        )
        .unwrap();

    rpc.mine_blocks(1).await.unwrap();

    // Send the transaction
    rpc.send_raw_transaction(test_txhandler_2.get_cached_tx())
        .await
        .unwrap();
}
