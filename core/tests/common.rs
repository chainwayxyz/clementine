// //! # Common utilities for tests

use bitcoin::Address;
use bitcoin::OutPoint;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::actor::Actor;
use clementine_core::config::BridgeConfig;
use clementine_core::database::common::Database;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::servers::*;
use clementine_core::traits::rpc::AggregatorClient;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::traits::rpc::VerifierRpcClient;
use clementine_core::user::User;
use clementine_core::EVMAddress;
use clementine_core::UTXO;
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::server::ServerHandle;
use std::net::SocketAddr;
use std::thread;

pub async fn run_single_deposit(
    test_config_name: &str,
) -> Result<
    (
        Vec<(HttpClient, ServerHandle, SocketAddr)>,
        Vec<(HttpClient, ServerHandle, SocketAddr)>,
        BridgeConfig,
        OutPoint,
    ),
    BridgeError,
> {
    let mut config = create_test_config_with_thread_name!(test_config_name);
    let rpc = create_extended_rpc!(config);

    let (verifiers, operators, aggregator) =
        create_verifiers_and_operators("test_config_flow.toml").await;

    // println!("Operators: {:#?}", operators);
    // println!("Verifiers: {:#?}", verifiers);

    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

    let signer_address = Actor::new(secret_key, config.network)
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

    let agg_nonces = aggregator
        .0
        .aggregate_pub_nonces_rpc(pub_nonces)
        .await
        .unwrap();
    // call operators' new_deposit
    let mut kickoff_utxos = Vec::new();
    let mut signatures = Vec::new();

    for (i, (client, _, _)) in operators.iter().enumerate() {
        // Send operators some bitcoin so that they can afford the kickoff tx
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let operator_internal_xonly_pk = config.operators_xonly_pks.get(i).unwrap();
        let operator_address =
            Address::p2tr(&secp, *operator_internal_xonly_pk, None, config.network);
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

    for (client, ..) in verifiers.iter() {
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

    let slash_or_take_sigs = aggregator
        .0
        .aggregate_slash_or_take_sigs_rpc(
            deposit_outpoint,
            kickoff_utxos.clone(),
            agg_nonces[config.num_operators + 1..2 * config.num_operators + 1].to_vec(),
            slash_or_take_partial_sigs,
        )
        .await
        .unwrap();

    // tracing::debug!("Slash or take sigs: {:#?}", slash_or_take_sigs);
    // call burn_txs_signed_rpc
    let mut operator_take_partial_sigs: Vec<Vec<[u8; 32]>> = Vec::new();
    for (client, ..) in verifiers.iter() {
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
    let operator_take_sigs = aggregator
        .0
        .aggregate_operator_take_sigs_rpc(
            deposit_outpoint,
            kickoff_utxos.clone(),
            agg_nonces[1..config.num_operators + 1].to_vec(),
            operator_take_partial_sigs,
        )
        .await
        .unwrap();
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

    let move_tx = aggregator
        .0
        .aggregate_move_tx_sigs_rpc(
            deposit_outpoint,
            signer_address,
            evm_address,
            agg_nonces[0].clone(),
            move_tx_partial_sigs,
        )
        .await
        .unwrap();
    tracing::debug!("Move tx: {:#?}", move_tx);
    // tracing::debug!("Move tx_hex: {:?}", move_tx_handler.tx.raw_hex());
    tracing::debug!("Move tx weight: {:?}", move_tx.weight());
    let move_txid = rpc.send_raw_transaction(&move_tx).unwrap();
    tracing::debug!("Move txid: {:?}", move_txid);
    Ok((verifiers, operators, config, deposit_outpoint))
}
