// //! # Deposit and Withdraw Flow Test
// //!
// //! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::Address;
use bitcoin::Transaction;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::actor::Actor;
use clementine_core::config::BridgeConfig;
use clementine_core::database::common::Database;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::musig2::aggregate_nonces;
use clementine_core::servers::*;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::traits::rpc::VerifierRpcClient;
use clementine_core::user::User;
use clementine_core::utils::aggregate_operator_takes_partial_sigs;
use clementine_core::utils::aggregate_slash_or_take_partial_sigs;
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

    for (i, (client, ..)) in verifiers.iter().enumerate() {
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

    // call verifiers' operator_kickoffs_generated_rpc
    // aggreate partial signatures here
    // let mut agg_signatures = Vec::new();

    let mut slash_or_take_partial_sigs = Vec::new();

    for (i, (client, ..)) in verifiers.iter().enumerate() {
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

    // call burn_txs_signed_rpc
    let mut operator_take_partial_signs: Vec<Vec<[u8; 32]>> = Vec::new();
    for _ in 0..operators.len() {
        operator_take_partial_signs.push(Vec::new());
    }
    for (i, (client, _, _)) in verifiers.iter().enumerate() {
        let operator_take_partial_sigs = client
            .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs.clone())
            .await
            .unwrap();
        println!(
            "Operator take partial sigs: {:#?}",
            operator_take_partial_sigs
        );
        for (j, sig) in operator_take_partial_sigs.iter().enumerate() {
            operator_take_partial_signs[j].push(*sig);
        }
    }

    let move_tx_handler = TransactionBuilder::create_move_tx(
        deposit_outpoint,
        evm_address,
        signer_address.clone(),
        BRIDGE_AMOUNT_SATS,
        config.user_takes_after,
        config.network,
    );
    let deposit_fund_outpoint = OutPoint {
        txid: move_tx_handler.tx.compute_txid(),
        vout: 0,
    };
    // aggregate partial signatures
    let mut operator_take_signatures = Vec::new();
    for i in 0..operator_take_partial_signs[0].len() {
        let agg_signature = secp256k1::schnorr::Signature::from_slice(
            aggregate_operator_takes_partial_sigs(
                deposit_fund_outpoint,
                config.verifiers_public_keys.clone(),
                config.operators_xonly_pks.clone(),
                i,
                operator_take_partial_signs
                    .iter()
                    .map(|v| v.get(i).cloned().unwrap())
                    .collect::<Vec<_>>(),
                config.network.clone(),
            )?
            )
        )
        .unwrap();

        signatures.push(agg_signature);
    }

    // // call operator_take_txs_signed_rpc
    // for (i, (client, ..)) in operators.iter().enumerate() {
    //     let _ = client
    //         .operator_take_txs_signed_rpc(deposit_outpoints[i], signatures.clone())
    //         .await
    //         .unwrap();
    // }

    Ok(())
}
