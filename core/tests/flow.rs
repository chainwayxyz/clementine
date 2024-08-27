// //! # Deposit and Withdraw Flow Test
// //!
// //! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::Address;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::actor::Actor;
use clementine_core::database::common::Database;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::musig2::aggregate_nonces;
use clementine_core::musig2::create_key_agg_ctx;
use clementine_core::servers::*;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::traits::rpc::VerifierRpcClient;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::user::User;
use clementine_core::utils::aggregate_move_partial_sigs;
use clementine_core::utils::aggregate_operator_takes_partial_sigs;
use clementine_core::utils::aggregate_slash_or_take_partial_sigs;
use clementine_core::utils::handle_taproot_witness_new;
use clementine_core::EVMAddress;
use clementine_core::UTXO;
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use std::thread;

#[tokio::test]
async fn test_deposit() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name!("test_config_flow.toml");
    let rpc = create_extended_rpc!(config);

    let (verifiers, operators) = create_verifiers_and_operators("test_config_flow.toml").await;

    // println!("Operators: {:#?}", operators);
    // println!("Verifiers: {:#?}", verifiers);

    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

    let signer_address = Actor::new(secret_key, config.network.clone())
        .address
        .as_unchecked()
        .clone();
    let user = User::new(rpc.clone(), secret_key, config.clone());

    let evm_address = EVMAddress([1u8; 20]);
    let deposit_address = user.get_deposit_address(evm_address).unwrap();
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)
        .unwrap();

    rpc.mine_blocks(18).unwrap();

    // for every verifier, we call new_deposit
    // aggregate nonces
    let mut pub_nonces = Vec::new();

    for (client, _, _) in verifiers.iter() {
        let musig_pub_nonces = client
            .verifier_new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
            .await
            .unwrap();

        // tracing::info!("Musig Pub Nonces: {:?}", musig_pub_nonces);

        pub_nonces.push(musig_pub_nonces);
    }

    let mut agg_nonces = Vec::new();
    for i in 0..pub_nonces[0].len() {
        let agg_nonce = aggregate_nonces(
            pub_nonces
                .iter()
                .map(|v| v.get(i).cloned().unwrap())
                .collect::<Vec<_>>(),
        );

        agg_nonces.push(agg_nonce);
    }

    // call operators' new_deposit
    let mut kickoff_utxos = Vec::new();
    let mut signatures = Vec::new();

    for (i, (client, _, _)) in operators.iter().enumerate() {
        // Send operators some bitcoin so that they can afford the kickoff tx
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let operator_internal_xonly_pk = config.operators_xonly_pks.get(i).unwrap();
        let operator_address = Address::p2tr(
            &secp,
            *operator_internal_xonly_pk,
            None,
            config.network.clone(),
        );
        let operator_funding_outpoint = rpc
            .send_to_address(&operator_address, 2 * BRIDGE_AMOUNT_SATS)
            .unwrap();
        let operator_funding_txout = rpc
            .get_txout_from_outpoint(&operator_funding_outpoint)
            .unwrap();
        let operator_funding_utxo = UTXO {
            outpoint: operator_funding_outpoint,
            txout: operator_funding_txout,
        };

        tracing::debug!("Operator {:?} funding utxo: {:?}", i, operator_funding_utxo);
        client
            .set_funding_utxo_rpc(operator_funding_utxo)
            .await
            .unwrap();

        // Create deposit kickoff transaction
        let (kickoff_utxo, signature) = client
            .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
            .await
            .unwrap();

        kickoff_utxos.push(kickoff_utxo);
        signatures.push(signature);
    }

    tracing::debug!("Now the verifiers sequence starts");
    let mut slash_or_take_partial_sigs = Vec::new();

    for (_i, (client, ..)) in verifiers.iter().enumerate() {
        let (partial_sigs, _) = client
            .operator_kickoffs_generated_rpc(
                deposit_outpoint,
                kickoff_utxos.clone(),
                signatures.clone(),
                agg_nonces.clone(),
            )
            .await
            .unwrap();

        slash_or_take_partial_sigs.push(partial_sigs);
    }
    tracing::debug!(
        "Slash or take partial sigs: {:#?}",
        slash_or_take_partial_sigs
    );
    let mut slash_or_take_sigs = Vec::new();
    for i in 0..slash_or_take_partial_sigs[0].len() {
        let agg_sig = aggregate_slash_or_take_partial_sigs(
            deposit_outpoint,
            kickoff_utxos[i].clone(),
            config.verifiers_public_keys.clone(),
            config.operators_xonly_pks[i].clone(),
            i,
            &agg_nonces[i + 1 + config.operators_xonly_pks.len()].clone(),
            slash_or_take_partial_sigs
                .iter()
                .map(|v| v.get(i).cloned().unwrap())
                .collect::<Vec<_>>(),
            config.network.clone(),
        )?;

        slash_or_take_sigs.push(secp256k1::schnorr::Signature::from_slice(&agg_sig)?);
    }
    // tracing::debug!("Slash or take sigs: {:#?}", slash_or_take_sigs);
    // call burn_txs_signed_rpc
    let mut operator_take_partial_sigs: Vec<Vec<[u8; 32]>> = Vec::new();
    for (_i, (client, _, _)) in verifiers.iter().enumerate() {
        let partial_sigs = client
            .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs.clone())
            .await
            .unwrap();
        operator_take_partial_sigs.push(partial_sigs);
    }
    // tracing::debug!(
    //     "Operator take partial sigs: {:#?}",
    //     operator_take_partial_sigs
    // );
    let mut operator_take_sigs = Vec::new();
    for i in 0..operator_take_partial_sigs.len() {
        let agg_sig = aggregate_operator_takes_partial_sigs(
            deposit_outpoint,
            kickoff_utxos[i].clone(),
            &config.operators_xonly_pks[i].clone(),
            i,
            config.verifiers_public_keys.clone(),
            &agg_nonces[i + 1].clone(),
            operator_take_partial_sigs
                .iter()
                .map(|v| v[i].clone())
                .collect(),
            config.network.clone(),
        )?;

        operator_take_sigs.push(secp256k1::schnorr::Signature::from_slice(&agg_sig)?);
    }
    // tracing::debug!("Operator take sigs: {:#?}", operator_take_sigs);
    // call operator_take_txs_signed_rpc
    let mut move_tx_partial_sigs = Vec::new();
    for (client, _, _) in verifiers.iter() {
        let move_tx_partial_sig = client
            .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs.clone())
            .await
            .unwrap();
        move_tx_partial_sigs.push(move_tx_partial_sig);
    }

    // tracing::debug!("Move tx partial sigs: {:#?}", move_tx_partial_sigs);

    // aggreagte move_tx_partial_sigs
    let agg_move_tx_final_sig = aggregate_move_partial_sigs(
        deposit_outpoint,
        &evm_address,
        &signer_address,
        config.verifiers_public_keys.clone(),
        &agg_nonces[0].clone(),
        move_tx_partial_sigs,
        config.network.clone(),
    )?;

    let move_tx_sig = secp256k1::schnorr::Signature::from_slice(&agg_move_tx_final_sig)?;

    let key_agg_ctx = create_key_agg_ctx(config.verifiers_public_keys.clone(), None)?;
    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let (musig_agg_xonly_pubkey, _) = musig_agg_pubkey.x_only_public_key();
    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();

    let mut move_tx_handler = TransactionBuilder::create_move_tx(
        deposit_outpoint,
        &evm_address,
        &signer_address,
        &nofn_xonly_pk,
        config.network,
    );
    let mut move_tx_witness_elements = Vec::new();
    move_tx_witness_elements.push(move_tx_sig.serialize().to_vec());
    handle_taproot_witness_new(&mut move_tx_handler, &move_tx_witness_elements, 0, 0)?;
    tracing::debug!("Move tx: {:#?}", move_tx_handler.tx);
    // tracing::debug!("Move tx_hex: {:?}", move_tx_handler.tx.raw_hex());
    tracing::debug!("Move tx weight: {:?}", move_tx_handler.tx.weight());
    let move_txid = rpc.send_raw_transaction(&move_tx_handler.tx).unwrap();
    tracing::debug!("Move txid: {:?}", move_txid);
    Ok(())
}
