//! # Deposit Tests

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

#[ignore = "We are switching to gRPC"]
#[tokio::test]
#[serial_test::serial]
async fn deposit_with_retry_checks() {
    let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
    let rpc = create_extended_rpc!(config);

    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
    let signer_address = Actor::new(secret_key, config.network)
        .address
        .as_unchecked()
        .clone();
    let user = User::new(rpc.clone(), secret_key, config.clone());

    let evm_address: EVMAddress = EVMAddress([1u8; 20]);
    let deposit_address = user.get_deposit_address(evm_address).unwrap();

    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.bridge_amount_sats)
        .unwrap();
    rpc.mine_blocks((config.confirmation_threshold + 2).into())
        .unwrap();

    let (verifiers, operators, aggregator) =
        create_verifiers_and_operators("test_config.toml").await;

    let agg_nonces = {
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

        let mut pub_nonces_retry = Vec::new();
        for (client, _, _) in verifiers.iter() {
            let musig_pub_nonces = client
                .verifier_new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
                .await
                .unwrap();

            pub_nonces_retry.push(musig_pub_nonces);
        }
        let agg_nonces_retry = aggregator
            .0
            .aggregate_pub_nonces_rpc(pub_nonces_retry)
            .await
            .unwrap();

        assert_eq!(agg_nonces, agg_nonces_retry);

        agg_nonces
    };

    let (kickoff_utxos, signatures) = {
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

        let mut kickoff_utxos_retry = Vec::new();
        let mut signatures_retry = Vec::new();
        for (client, _, _) in operators.iter() {
            let (kickoff_utxo, signature) = client
                .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
                .await
                .unwrap();

            kickoff_utxos_retry.push(kickoff_utxo);
            signatures_retry.push(signature);
        }

        assert_eq!(kickoff_utxos, kickoff_utxos_retry);

        (kickoff_utxos, signatures)
    };

    // Operator part is done; Verifier part starts.

    let slash_or_take_sigs = {
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
                slash_or_take_partial_sigs.clone(),
            )
            .await
            .unwrap();

        let mut slash_or_take_partial_sigs_retry = Vec::new();
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

            slash_or_take_partial_sigs_retry.push(partial_sigs);
        }
        let slash_or_take_sigs_retry = aggregator
            .0
            .aggregate_slash_or_take_sigs_rpc(
                deposit_outpoint,
                kickoff_utxos.clone(),
                agg_nonces[config.num_operators + 1..2 * config.num_operators + 1].to_vec(),
                slash_or_take_partial_sigs_retry.clone(),
            )
            .await
            .unwrap();

        assert_eq!(slash_or_take_partial_sigs, slash_or_take_partial_sigs_retry);
        assert_eq!(slash_or_take_sigs, slash_or_take_sigs_retry);

        slash_or_take_sigs
    };

    let operator_take_sigs = {
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

        let mut operator_take_partial_sigs_retry = Vec::new();
        for (client, ..) in verifiers.iter() {
            let partial_sigs = client
                .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs.clone())
                .await
                .unwrap();
            operator_take_partial_sigs_retry.push(partial_sigs);
        }
        let operator_take_sigs_retry = aggregator
            .0
            .aggregate_operator_take_sigs_rpc(
                deposit_outpoint,
                kickoff_utxos.clone(),
                agg_nonces[1..config.num_operators + 1].to_vec(),
                operator_take_partial_sigs_retry,
            )
            .await
            .unwrap();

        assert_eq!(operator_take_sigs, operator_take_sigs_retry);

        operator_take_sigs
    };

    let move_tx_partial_sigs = {
        let mut move_tx_partial_sigs = Vec::new();
        for (client, _, _) in verifiers.iter() {
            let move_tx_partial_sig = client
                .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs.clone())
                .await
                .unwrap();
            move_tx_partial_sigs.push(move_tx_partial_sig);
        }

        let mut move_tx_partial_sigs_retry = Vec::new();
        for (client, _, _) in verifiers.iter() {
            let move_tx_partial_sig = client
                .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs.clone())
                .await
                .unwrap();
            move_tx_partial_sigs_retry.push(move_tx_partial_sig);
        }

        assert_eq!(move_tx_partial_sigs, move_tx_partial_sigs_retry);

        move_tx_partial_sigs
    };

    let move_tx = {
        let (move_tx, _) = aggregator
            .0
            .aggregate_move_tx_sigs_rpc(
                deposit_outpoint,
                signer_address.clone(),
                evm_address,
                agg_nonces[0],
                move_tx_partial_sigs.clone(),
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
                move_tx_partial_sigs,
            )
            .await
            .unwrap();

        assert_eq!(move_tx, move_tx_retry);

        move_tx
    };

    let move_tx: Transaction = deserialize_hex(&move_tx).unwrap();

    println!("Move tx weight: {:?}", move_tx.weight());
}
