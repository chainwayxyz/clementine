//! # Common utilities for tests

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use clementine_core::actor::Actor;
use clementine_core::config::BridgeConfig;
use clementine_core::create_extended_rpc;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::database::create_test_config_with_thread_name;
use clementine_core::musig2::MuSigPartialSignature;
use clementine_core::servers::*;
use clementine_core::traits::rpc::AggregatorClient;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::traits::rpc::VerifierRpcClient;
use clementine_core::user::User;
use clementine_core::EVMAddress;
use clementine_core::UTXO;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::server::ServerHandle;
use secp256k1::schnorr;
use std::net::SocketAddr;

pub async fn run_multiple_deposit(
    test_config_name: &str,
) -> Result<(Vec<UTXO>, Vec<schnorr::Signature>), BridgeError> {
    let mut config = create_test_config_with_thread_name(test_config_name, None).await;
    let rpc = create_extended_rpc!(config);

    let (_, operators, _) = create_verifiers_and_operators("test_config.toml").await;

    // println!("Operators: {:#?}", operators);
    // println!("Verifiers: {:#?}", verifiers);

    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

    let signer_address = Actor::new(secret_key, config.bitcoin.network)
        .address
        .as_unchecked()
        .clone();
    let user = User::new(rpc.clone(), secret_key, config.clone());

    let evm_address = EVMAddress([1u8; 20]);
    let deposit_address = user.get_deposit_address(evm_address).unwrap();
    let deposit_outpoints = (0..config.operator.kickoff_utxos_per_tx + 5).map(|_| {
        let outpoint = rpc
            .send_to_address(&deposit_address, config.bridge_amount_sats)
            .unwrap();
        rpc.mine_blocks(1).unwrap();
        outpoint
    });

    for _ in 0..18 {
        rpc.mine_blocks(1).unwrap();
    }

    let mut kickoff_utxos = vec![];
    let mut signatures = vec![];
    for deposit_outpoint in deposit_outpoints {
        println!("Deposit outpoint: {:#?}", deposit_outpoint);
        let (kickoff_utxo, signature) = operators[0]
            .0
            .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
            .await
            .unwrap();

        kickoff_utxos.push(kickoff_utxo);
        signatures.push(signature);
    }
    Ok((kickoff_utxos, signatures))
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
    let mut config = create_test_config_with_thread_name(test_config_name, None).await;
    let rpc = create_extended_rpc!(config);

    let (verifiers, operators, aggregator) =
        create_verifiers_and_operators("test_config.toml").await;

    // println!("Operators: {:#?}", operators);
    // println!("Verifiers: {:#?}", verifiers);

    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

    let signer_address = Actor::new(secret_key, config.bitcoin.network)
        .address
        .as_unchecked()
        .clone();
    let user = User::new(rpc.clone(), secret_key, config.clone());

    let evm_address = EVMAddress([1u8; 20]);
    let deposit_address = user.get_deposit_address(evm_address).unwrap();
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.bridge_amount_sats)
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

    for (client, _, _) in operators.iter() {
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
            agg_nonces[config.operator.count + 1..2 * config.operator.count + 1].to_vec(),
            slash_or_take_partial_sigs,
        )
        .await
        .unwrap();

    // tracing::debug!("Slash or take sigs: {:#?}", slash_or_take_sigs);
    // call burn_txs_signed_rpc
    let mut operator_take_partial_sigs: Vec<Vec<MuSigPartialSignature>> = Vec::new();
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
            agg_nonces[1..config.operator.count + 1].to_vec(),
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
    // tracing::debug!("Move tx: {:#?}", move_tx);
    // tracing::debug!("Move tx_hex: {:?}", move_tx_handler.tx.raw_hex());
    tracing::debug!("Move tx weight: {:?}", move_tx.weight());
    let move_txid = rpc.send_raw_transaction(&move_tx).unwrap();
    tracing::debug!("Move txid: {:?}", move_txid);
    Ok((verifiers, operators, config, deposit_outpoint))
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::deserialize_hex;
    use bitcoin::Transaction;
    use clementine_core::actor::Actor;
    use clementine_core::create_extended_rpc;
    use clementine_core::extended_rpc::ExtendedRpc;
    use clementine_core::mock::database::create_test_config_with_thread_name;
    use clementine_core::musig2::MuSigPartialSignature;
    use clementine_core::servers::*;
    use clementine_core::traits::rpc::AggregatorClient;
    use clementine_core::traits::rpc::OperatorRpcClient;
    use clementine_core::traits::rpc::VerifierRpcClient;
    use clementine_core::user::User;
    use clementine_core::EVMAddress;

    #[tokio::test]
    async fn test_deposit_retry() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);

        let (verifiers, operators, aggregator) =
            create_verifiers_and_operators("test_config.toml").await;

        // println!("Operators: {:#?}", operators);
        // println!("Verifiers: {:#?}", verifiers);

        let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

        let signer_address = Actor::new(secret_key, config.bitcoin.network)
            .address
            .as_unchecked()
            .clone();
        let user = User::new(rpc.clone(), secret_key, config.clone());

        let evm_address = EVMAddress([1u8; 20]);
        let deposit_address = user.get_deposit_address(evm_address).unwrap();
        let deposit_outpoint = rpc
            .send_to_address(&deposit_address, config.bridge_amount_sats)
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

        // Oops, we lost the pub_nonces, need to call the verifiers again
        let mut pub_nonces_retry = Vec::new();

        for (client, _, _) in verifiers.iter() {
            let musig_pub_nonces = client
                .verifier_new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
                .await
                .unwrap();

            // tracing::info!("Musig Pub Nonces: {:?}", musig_pub_nonces);

            pub_nonces_retry.push(musig_pub_nonces);
        }

        let agg_nonces_retry = aggregator
            .0
            .aggregate_pub_nonces_rpc(pub_nonces_retry)
            .await
            .unwrap();

        // Sanity check
        assert_eq!(agg_nonces, agg_nonces_retry);

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

        // Oops, we lost the kickoff_utxos, need to call the operators again
        let mut kickoff_utxos_retry = Vec::new();
        let mut signatures_retry = Vec::new();

        for (client, _, _) in operators.iter() {
            // Create deposit kickoff transaction
            let (kickoff_utxo, signature) = client
                .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
                .await
                .unwrap();

            kickoff_utxos_retry.push(kickoff_utxo);
            signatures_retry.push(signature);
        }

        // Sanity check
        assert_eq!(kickoff_utxos, kickoff_utxos_retry);

        tracing::debug!("Now the verifiers sequence starts");
        let mut slash_or_take_partial_sigs = Vec::new();

        for (client, ..) in verifiers.iter() {
            let (partial_sigs, _) = client
                .operator_kickoffs_generated_rpc(
                    deposit_outpoint,
                    kickoff_utxos_retry.clone(),
                    signatures_retry.clone(),
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
                agg_nonces[config.operator.count + 1..2 * config.operator.count + 1].to_vec(),
                slash_or_take_partial_sigs,
            )
            .await
            .unwrap();

        // tracing::debug!("Slash or take sigs: {:#?}", slash_or_take_sigs);

        // Oops, we lost the slash_or_take_sigs, need to call the verifiers again

        let mut slash_or_take_partial_sigs_retry = Vec::new();

        for (client, ..) in verifiers.iter() {
            let (partial_sigs, _) = client
                .operator_kickoffs_generated_rpc(
                    deposit_outpoint,
                    kickoff_utxos_retry.clone(),
                    signatures_retry.clone(),
                    agg_nonces.clone(),
                )
                .await
                .unwrap();

            slash_or_take_partial_sigs_retry.push(partial_sigs);
        }

        let slash_or_take_sigs_retry = aggregator
            .0
            .aggregate_slash_or_take_sigs_rpc(
                deposit_outpoint,
                kickoff_utxos.clone(),
                agg_nonces[config.operator.count + 1..2 * config.operator.count + 1].to_vec(),
                slash_or_take_partial_sigs_retry,
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
        // tracing::debug!(
        //     "Operator take partial sigs: {:#?}",
        //     operator_take_partial_sigs
        // );
        let operator_take_sigs = aggregator
            .0
            .aggregate_operator_take_sigs_rpc(
                deposit_outpoint,
                kickoff_utxos.clone(),
                agg_nonces[1..config.operator.count + 1].to_vec(),
                operator_take_partial_sigs,
            )
            .await
            .unwrap();

        // Oops, we lost the operator_take_sigs, need to call the verifiers again

        let mut operator_take_partial_sigs_retry = Vec::new();

        for (client, ..) in verifiers.iter() {
            let partial_sigs = client
                .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs_retry.clone())
                .await
                .unwrap();
            operator_take_partial_sigs_retry.push(partial_sigs);
        }

        let operator_take_sigs_retry = aggregator
            .0
            .aggregate_operator_take_sigs_rpc(
                deposit_outpoint,
                kickoff_utxos.clone(),
                agg_nonces[1..config.operator.count + 1].to_vec(),
                operator_take_partial_sigs_retry,
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

        // Oops, we lost the move_tx_partial_sigs, need to call the verifiers again

        let mut move_tx_partial_sigs_retry = Vec::new();

        for (client, _, _) in verifiers.iter() {
            let move_tx_partial_sig = client
                .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs_retry.clone())
                .await
                .unwrap();
            move_tx_partial_sigs_retry.push(move_tx_partial_sig);
        }

        // tracing::debug!("Move tx partial sigs: {:#?}", move_tx_partial_sigs);

        // aggreagte move_tx_partial_sigs

        let (_move_tx, _) = aggregator
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

        let (move_tx_retry, _) = aggregator
            .0
            .aggregate_move_tx_sigs_rpc(
                deposit_outpoint,
                signer_address,
                evm_address,
                agg_nonces[0],
                move_tx_partial_sigs_retry,
            )
            .await
            .unwrap();

        let move_tx_retry: Transaction = deserialize_hex(&move_tx_retry).unwrap();
        // tracing::debug!("Move tx: {:#?}", move_tx);
        // tracing::debug!("Move tx_hex: {:?}", move_tx_handler.tx.raw_hex());
        tracing::debug!("Move tx retry weight: {:?}", move_tx_retry.weight());
        let move_txid = rpc.send_raw_transaction(&move_tx_retry).unwrap();
        tracing::debug!("Move txid: {:?}", move_txid);
    }
}
