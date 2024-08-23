// //! # Deposit and Withdraw Flow Test
// //!
// //! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::Address;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
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
use clementine_core::EVMAddress;
use clementine_core::UTXO;
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use std::thread;

#[tokio::test]
async fn test_deposit() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name!("test_config_flow_1.toml");
    let rpc = create_extended_rpc!(config);

    // Create temporary databases for testing.
    let handle = thread::current()
        .name()
        .unwrap()
        .split(':')
        .last()
        .unwrap()
        .to_owned();
    for i in 0..4 {
        create_test_config!(
            handle.clone() + i.to_string().as_str(),
            "test_config_flow_1.toml"
        );
    }

    let mut operators = Vec::new();
    let mut evm_addresses = Vec::new();
    for i in 0..config.num_operators {
        let secret_key = config.all_operators_secret_keys.clone().unwrap()[i].clone();
        let operator = create_operator_server(
            BridgeConfig {
                secret_key,
                ..config.clone()
            },
            rpc.clone(),
        )
        .await
        .unwrap();

        operators.push((operator.0, operator.1, secret_key));
        evm_addresses.push(EVMAddress([(i + 1) as u8; 20]));
    }
    let mut verifiers = Vec::new();
    for i in 0..config.num_verifiers {
        verifiers.push(
            create_verifier_server(
                BridgeConfig {
                    secret_key: config.all_verifiers_secret_keys.clone().unwrap()[i].clone(),
                    ..config.clone()
                },
                rpc.clone(),
            )
            .await
            .unwrap(),
        );
    }

    println!("Operators: {:#?}", operators);
    println!("Verifiers: {:#?}", verifiers);

    let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

    let user = User::new(
        rpc.clone(),
        config.verifiers_public_keys.clone(),
        secret_key,
        config.clone(),
    );

    let deposit_outpoints: Vec<_> = evm_addresses
        .iter()
        .map(|&address| {
            let deposit_address = user.get_deposit_address(address).unwrap();
            let deposit_outpoint = rpc
                .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)
                .unwrap();

            deposit_outpoint
        })
        .collect();

    rpc.mine_blocks(18).unwrap();

    // for every verifier, we call new_deposit
    // aggregate nonces
    let mut agg_nonces = Vec::new();

    for (i, (client, _)) in verifiers.iter().enumerate() {
        let musig_pub_nonces = client
            .verifier_new_deposit_rpc(
                deposit_outpoints[i],
                user.signer.address.as_unchecked().clone(),
                evm_addresses[i],
            )
            .await
            .unwrap();

        println!("Musig Pub Nonces: {:?}", musig_pub_nonces);

        agg_nonces.push(aggregate_nonces(musig_pub_nonces));
    }

    // call operators' new_deposit
    let mut kickoff_utxos = Vec::new();
    let mut signatures = Vec::new();

    for (i, (client, _, secret_key)) in operators.iter().enumerate() {
        // Send operators some bitcoin so that they can afford the kickoff tx
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (operator_internal_xonly_pk, _) = secret_key.public_key(&secp).x_only_public_key();
        let operator_address = Address::p2tr(
            &secp,
            operator_internal_xonly_pk,
            None,
            config.network.clone(),
        );
        let operator_funding_outpoint = rpc
            .send_to_address(&operator_address, 2 * BRIDGE_AMOUNT_SATS)
            .unwrap();
        let operator_funding_txout = rpc.get_txout_from_utxo(&operator_funding_outpoint).unwrap();
        let operator_funding_utxo = UTXO {
            outpoint: operator_funding_outpoint,
            txout: operator_funding_txout,
        };

        client
            .set_operator_funding_utxo_rpc(operator_funding_utxo)
            .await
            .unwrap();

        // Create deposit kickoff transaction
        let (kickoff_utxo, signature) = client
            .new_deposit_rpc(
                deposit_outpoints[i],
                user.signer.address.as_unchecked().clone(),
                evm_addresses[i],
            )
            .await
            .unwrap();

        kickoff_utxos.push(kickoff_utxo);
        signatures.push(signature);
    }

    // call verifiers' operator_kickoffs_generated_rpc
    // aggreate partial signatures here
    // let mut agg_signatures = Vec::new();
    //
    // for (i, (client, _)) in verifiers.iter().enumerate() {
    //     let musig_partial_signatures = client
    //         .operator_kickoffs_generated_rpc(
    //             deposit_outpoints[i],
    //             vec![kickoff_utxos.get(i).cloned().unwrap()],
    //             vec![signatures.get(i).cloned().unwrap()],
    //             vec![agg_nonces.get(i).cloned().unwrap()],
    //         )
    //         .await
    //         .unwrap();
    //
    //     println!("Musig Pub Nonces: {:?}", musig_partial_signatures);
    //
    //     agg_signatures.push(
    //         secp256k1::schnorr::Signature::from_slice(
    //             &aggregate_partial_signatures(
    //                 vec![], // todo pks?
    //                 None,
    //                 agg_nonces.get(i).unwrap(),
    //                 musig_partial_signatures.clone(),
    //                 [0u8; 32], // todo msg?
    //             )
    //             .unwrap(),
    //         )
    //         .unwrap(),
    //     );
    // }
    //
    // // call burn_txs_signed_rpc
    // let mut agg_burned_signs = Vec::new();
    // for (i, (client, ..)) in operators.iter().enumerate() {
    //     let musig_partial_signatures = client
    //         .burn_txs_signed_rpc(deposit_outpoints[i], agg_signatures.clone())
    //         .await
    //         .unwrap();
    //     println!("Musig Pub Nonces: {:#?}", musig_partial_signatures);
    //     agg_burned_signs.push(
    //         musig_partial_signatures
    //             .iter()
    //             .map(|v| secp256k1::schnorr::Signature::from_slice(v).unwrap())
    //             .collect::<Vec<_>>(),
    //     );
    // }
    //
    // // call operator_take_txs_signed_rpc
    // for (i, (client, ..)) in operators.iter().enumerate() {
    //     let _ = client
    //         .operator_take_txs_signed_rpc(deposit_outpoints[i], signatures.clone())
    //         .await
    //         .unwrap();
    // }

    Ok(())
}
