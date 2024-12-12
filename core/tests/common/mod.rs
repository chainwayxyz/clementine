//! # Common Utilities for Integration Tests

#[path = "../../src/mock_macro.rs"]
mod mock_macro;

use crate::{create_test_config_with_thread_name, initialize_database};
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoincore_rpc::RpcApi;
use clementine_core::actor::Actor;
use clementine_core::config::BridgeConfig;
use clementine_core::database::Database;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::musig2::MuSigPartialSignature;
use clementine_core::servers::*;
use clementine_core::traits::rpc::AggregatorClient;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::traits::rpc::VerifierRpcClient;
use clementine_core::user::User;
use clementine_core::utils::initialize_logger;
use clementine_core::EVMAddress;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::server::ServerHandle;
use std::net::SocketAddr;
use std::{env, thread};

pub async fn run_multiple_deposits(test_config_name: &str) {
    let config = create_test_config_with_thread_name!(test_config_name, None);
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await;
    let secp = secp256k1::Secp256k1::new();
    let (verifiers, operators, aggregator) =
        create_verifiers_and_operators("test_config.toml").await;

    // println!("Operators: {:#?}", operators);
    // println!("Verifiers: {:#?}", verifiers);

    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

    let signer_address = Actor::new(secret_key, config.winternitz_secret_key, config.network)
        .address
        .as_unchecked()
        .clone();
    let user = User::new(rpc.clone(), secret_key, config.clone());

    let evm_address = EVMAddress([1u8; 20]);
    let deposit_address = user.get_deposit_address(evm_address).unwrap();
    let mut deposit_outpoints = Vec::new();
    for _ in 0..config.operator_num_kickoff_utxos_per_tx + 1 {
        let deposit_outpoint = rpc
            .send_to_address(&deposit_address, config.bridge_amount_sats)
            .await
            .unwrap();

        rpc.mine_blocks(18).await.unwrap();

        let mut pub_nonces = Vec::new();

        for (client, _, _) in verifiers.iter() {
            let musig_pub_nonces = client
                .verifier_new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
                .await
                .unwrap();

            pub_nonces.push(musig_pub_nonces);
        }

        let agg_nonces = aggregator
            .0
            .aggregate_pub_nonces_rpc(pub_nonces)
            .await
            .unwrap();
        let mut kickoff_utxos = Vec::new();
        let mut signatures = Vec::new();

        for (client, _, _) in operators.iter() {
            let (kickoff_utxo, signature) = client
                .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
                .await
                .unwrap();

            kickoff_utxos.push(kickoff_utxo);
            signatures.push(signature);
        }

        println!("Now the verifiers sequence starts");
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
        let mut operator_take_partial_sigs: Vec<Vec<MuSigPartialSignature>> = Vec::new();
        for (client, ..) in verifiers.iter() {
            let partial_sigs = client
                .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs.clone())
                .await
                .unwrap();
            operator_take_partial_sigs.push(partial_sigs);
        }

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

        let mut move_tx_partial_sigs = Vec::new();
        for (client, _, _) in verifiers.iter() {
            let move_tx_partial_sig = client
                .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs.clone())
                .await
                .unwrap();
            move_tx_partial_sigs.push(move_tx_partial_sig);
        }

        let (move_tx, _) = aggregator
            .0
            .aggregate_move_tx_sigs_rpc(
                deposit_outpoint,
                signer_address.clone(),
                evm_address,
                agg_nonces[0],
                move_tx_partial_sigs,
            )
            .await
            .unwrap();
        let move_tx: Transaction = deserialize_hex(&move_tx).unwrap();

        println!("Move tx weight: {:?}", move_tx.weight());
        let move_txid = rpc.client.send_raw_transaction(&move_tx).await.unwrap();
        println!("Move txid: {:?}", move_txid);
        deposit_outpoints.push(deposit_outpoint);
    }
    let withdrawal_address = Address::p2tr(
        &secp,
        secret_key.x_only_public_key(&secp).0,
        None,
        config.network,
    );
    let (user_utxo, user_txout, user_sig) = user
        .generate_withdrawal_transaction_and_signature(
            withdrawal_address.clone(),
            Amount::from_sat(
                config.bridge_amount_sats.to_sat()
                    - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
            ),
        )
        .await
        .unwrap();
    let withdrawal_provide_txid = operators[0]
        .0
        .new_withdrawal_sig_rpc(0, user_sig, user_utxo, user_txout)
        .await
        .unwrap();
    println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
    let txs_to_be_sent_0 = operators[0]
        .0
        .withdrawal_proved_on_citrea_rpc(0, deposit_outpoints[0])
        .await
        .unwrap();
    assert!(txs_to_be_sent_0.len() == 3);
    let (user_utxo, user_txout, user_sig) = user
        .generate_withdrawal_transaction_and_signature(
            withdrawal_address.clone(),
            Amount::from_sat(
                config.bridge_amount_sats.to_sat()
                    - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
            ),
        )
        .await
        .unwrap();
    let withdrawal_provide_txid = operators[1]
        .0
        .new_withdrawal_sig_rpc(
            config.operator_num_kickoff_utxos_per_tx as u32 - 1,
            user_sig,
            user_utxo,
            user_txout,
        )
        .await
        .unwrap();
    println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
    let txs_to_be_sent_penultimate = operators[1]
        .0
        .withdrawal_proved_on_citrea_rpc(
            config.operator_num_kickoff_utxos_per_tx as u32 - 1,
            deposit_outpoints[config.operator_num_kickoff_utxos_per_tx - 1],
        )
        .await
        .unwrap();
    assert!(txs_to_be_sent_penultimate.len() == 3);
    let (user_utxo, user_txout, user_sig) = user
        .generate_withdrawal_transaction_and_signature(
            withdrawal_address.clone(),
            Amount::from_sat(
                config.bridge_amount_sats.to_sat()
                    - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
            ),
        )
        .await
        .unwrap();
    let withdrawal_provide_txid = operators[0]
        .0
        .new_withdrawal_sig_rpc(2, user_sig, user_utxo, user_txout)
        .await
        .unwrap();
    println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
    let txs_to_be_sent_last = operators[2]
        .0
        .withdrawal_proved_on_citrea_rpc(
            config.operator_num_kickoff_utxos_per_tx as u32,
            deposit_outpoints[config.operator_num_kickoff_utxos_per_tx],
        )
        .await
        .unwrap();
    assert!(txs_to_be_sent_last.len() == 4);
}

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
    let config = create_test_config_with_thread_name!(test_config_name, None);
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await;

    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
    let signer_address = Actor::new(secret_key, config.winternitz_secret_key, config.network)
        .address
        .as_unchecked()
        .clone();

    let user = User::new(rpc.clone(), secret_key, config.clone());

    let evm_address = EVMAddress([1u8; 20]);
    let deposit_address = user.get_deposit_address(evm_address).unwrap();

    let (verifiers, operators, aggregator) =
        create_verifiers_and_operators("test_config.toml").await;

    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.bridge_amount_sats)
        .await
        .unwrap();
    rpc.mine_blocks(18).await.unwrap();

    // for every verifier, we call new_deposit
    // aggregate nonces
    let mut pub_nonces = Vec::new();
    for (client, _, _) in verifiers.iter() {
        let musig_pub_nonces = client
            .verifier_new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
            .await
            .unwrap();

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
    for (client, _, _) in operators.iter() {
        // Create deposit kickoff transaction
        let (kickoff_utxo, signature) = client
            .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
            .await
            .unwrap();

        kickoff_utxos.push(kickoff_utxo);
        signatures.push(signature);
    }

    // Verifiers part starts here.
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

    // call burn_txs_signed_rpc
    let mut operator_take_partial_sigs: Vec<Vec<MuSigPartialSignature>> = Vec::new();
    for (client, ..) in verifiers.iter() {
        let partial_sigs = client
            .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs.clone())
            .await
            .unwrap();

        operator_take_partial_sigs.push(partial_sigs);
    }

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

    // Call operator_take_txs_signed_rpc
    let mut move_tx_partial_sigs = Vec::new();
    for (client, _, _) in verifiers.iter() {
        let move_tx_partial_sig = client
            .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs.clone())
            .await
            .unwrap();

        move_tx_partial_sigs.push(move_tx_partial_sig);
    }

    // Aggregate move_tx_partial_sigs
    let (move_tx, _) = aggregator
        .0
        .aggregate_move_tx_sigs_rpc(
            deposit_outpoint,
            signer_address,
            evm_address,
            agg_nonces[0],
            move_tx_partial_sigs,
        )
        .await
        .unwrap();

    let move_tx: Transaction = deserialize_hex(&move_tx).unwrap();
    println!("Move tx weight: {:?}", move_tx.weight());

    let move_txid = rpc.client.send_raw_transaction(&move_tx).await.unwrap();
    println!("Move txid: {:?}", move_txid);

    Ok((verifiers, operators, config, deposit_outpoint))
}

#[cfg(test)]
mod tests {
    use crate::common::{run_multiple_deposits, run_single_deposit};

    #[ignore = "We are switching to gRPC"]
    #[tokio::test]
    async fn test_deposit() {
        run_single_deposit("test_config.toml").await.unwrap();
    }

    #[ignore = "We are switching to gRPC"]
    #[tokio::test]
    async fn multiple_deposits_for_operator() {
        run_multiple_deposits("test_config.toml").await;
    }
}
