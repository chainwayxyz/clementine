// //! # Deposit and Withdraw Flow Test
// //!
// //! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::{Address, Amount};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::actor::Actor;
use clementine_core::config::BridgeConfig;
use clementine_core::database::common::Database;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::musig2::{aggregate_nonces, aggregate_partial_signatures};
use clementine_core::script_builder;
use clementine_core::servers::*;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::traits::rpc::VerifierRpcClient;
use clementine_core::transaction_builder::{TransactionBuilder, TxHandler};
use clementine_core::user::User;
use clementine_core::utils;
use clementine_core::utils::handle_taproot_witness_new;
use clementine_core::utils::SECP;
use clementine_core::EVMAddress;
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use crypto_bigint::rand_core::OsRng;
use std::thread;

#[tokio::test]
async fn test_flow_1() -> Result<(), BridgeError> {
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
    for i in 0..config.num_operators {
        operators.push(
            create_operator_server(
                BridgeConfig {
                    secret_key: config.all_operators_secret_keys.clone().unwrap()[i].clone(),
                    ..config.clone()
                },
                rpc.clone(),
            )
            .await?,
        );
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
        config,
    );

    let deposit_address = user.get_deposit_address(EVMAddress([1u8; 20])).unwrap();
    println!("Deposit address: {:#?}", deposit_address);
    let deposit_outpoint = rpc.send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)?;

    rpc.mine_blocks(18).unwrap();

    println!("Deposit outpoint: {:#?}", deposit_outpoint);

    // for every verifier, we call new_deposit
    // aggregate nonces
    let mut agg_nonces = Vec::new();
    for (client, _) in verifiers.iter() {
        let musig_pub_nonces = client
            .verifier_new_deposit_rpc(
                deposit_outpoint,
                user.signer.address.as_unchecked().clone(),
                EVMAddress([1u8; 20]),
            )
            .await?;
        println!("Musig Pub Nonces: {:#?}", musig_pub_nonces);
        agg_nonces.push(aggregate_nonces(musig_pub_nonces));
    }

    // call operators' new_deposit
    let mut kickoff_utxos = Vec::new();
    let mut signatures = Vec::new();
    for (client, _) in operators.iter() {
        let (kickoff_utxo, signature) = client
            .new_deposit_rpc(
                deposit_outpoint,
                user.signer.address.as_unchecked().clone(),
                EVMAddress([1u8; 20]),
            )
            .await
            .unwrap();

        kickoff_utxos.push(kickoff_utxo);
        signatures.push(signature);
    }

    // call verifiers' operator_kickoffs_generated_rpc
    // aggreate partial signatures here
    let mut agg_signatures = Vec::new();
    for (idx, (client, _)) in verifiers.iter().enumerate() {
        let musig_partial_signatures = client
            .operator_kickoffs_generated_rpc(
                deposit_outpoint,
                kickoff_utxos.clone(),
                signatures.clone(),
                agg_nonces.clone(),
            )
            .await
            .unwrap();
        println!("Musig Pub Nonces: {:#?}", musig_partial_signatures);
        agg_signatures.push(
            secp256k1::schnorr::Signature::from_slice(&aggregate_partial_signatures(
                vec![], // todo pks?
                None,
                agg_nonces.get(idx).unwrap(),
                musig_partial_signatures.clone(),
                [0u8; 32], // todo msg?
            )?)
            .unwrap(),
        );
    }

    // call burn_txs_signed_rpc
    let mut agg_burned_signs = Vec::new();
    for (idx, (client, _)) in operators.iter().enumerate() {
        let musig_partial_signatures = client
            .burn_txs_signed_rpc(deposit_outpoint, agg_signatures.clone())
            .await
            .unwrap();
        println!("Musig Pub Nonces: {:#?}", musig_partial_signatures);
        agg_burned_signs.push(
            musig_partial_signatures
                .iter()
                .map(|v| secp256k1::schnorr::Signature::from_slice(v).unwrap())
                .collect::<Vec<_>>(),
        );
    }

    // call operator_take_txs_signed_rpc
    for (idx, (client, _)) in operators.iter().enumerate() {
        let _ = client
            .operator_take_txs_signed_rpc(deposit_outpoint, agg_burned_signs[idx].clone())
            .await?;
    }

    Ok(())
    // // let (operator_client, _operator_handler, _results) =
    // //     create_operator_and_verifiers(config.clone(), rpc.clone()).await;

    // let secp = bitcoin::secp256k1::Secp256k1::new();
    // let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    // let taproot_address = Address::p2tr(&secp, xonly_pk, None, config.network);
    // let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config.network);

    // let evm_addresses = [
    //     EVMAddress([1u8; 20]),
    //     EVMAddress([2u8; 20]),
    //     EVMAddress([3u8; 20]),
    //     EVMAddress([4u8; 20]),
    // ];

    // let deposit_addresses = evm_addresses
    //     .iter()
    //     .map(|evm_address| {
    //         TransactionBuilder::generate_deposit_address(
    //             taproot_address.as_unchecked(),
    //             evm_address,
    //             BRIDGE_AMOUNT_SATS,
    //             config.user_takes_after,
    //         )
    //         .unwrap()
    //         .0
    //     })
    //     .collect::<Vec<_>>();
    // tracing::debug!("Deposit addresses: {:#?}", deposit_addresses);

    // for (idx, deposit_address) in deposit_addresses.iter().enumerate() {
    //     let deposit_utxo = rpc
    //         .send_to_address(deposit_address, BRIDGE_AMOUNT_SATS)
    //         .unwrap();
    //     tracing::debug!("Deposit UTXO #{}: {:#?}", idx, deposit_utxo);

    //     rpc.mine_blocks(18).unwrap();

    //     let output = operator_client
    //         .new_deposit_rpc(
    //             deposit_utxo,
    //             taproot_address.as_unchecked().clone(),
    //             evm_addresses[idx],
    //         )
    //         .await
    //         .unwrap();
    //     tracing::debug!("Output #{}: {:#?}", idx, output);
    // }

    // let withdrawal_address = Address::p2tr(&secp, xonly_pk, None, config.network);

    // // This index is 3 since when testing the unit tests complete first and the index=1,2 is not sane
    // let withdraw_txid = operator_client
    //     .new_withdrawal_direct_rpc(0, withdrawal_address.as_unchecked().clone())
    //     .await
    //     .unwrap();
    // tracing::debug!("Withdrawal sent to address: {:?}", withdrawal_address);
    // tracing::debug!("Withdrawal TXID: {:#?}", withdraw_txid);

    // // get the tx details from rpc with txid
    // let tx = rpc.get_raw_transaction(&withdraw_txid, None).unwrap();
    // // tracing::debug!("Withdraw TXID raw transaction: {:#?}", tx);

    // // check whether it has an output with the withdrawal address
    // let rpc_withdraw_script = tx.output[0].script_pubkey.clone();
    // let rpc_withdraw_amount = tx.output[0].value;
    // let expected_withdraw_script = withdrawal_address.script_pubkey();
    // assert_eq!(rpc_withdraw_script, expected_withdraw_script);
    // let anyone_can_spend_amount = script_builder::anyone_can_spend_txout().value;

    // // check if the amounts match
    // let expected_withdraw_amount = Amount::from_sat(BRIDGE_AMOUNT_SATS - 2 * config.min_relay_fee)
    //     - anyone_can_spend_amount * 2;
    // assert_eq!(expected_withdraw_amount, rpc_withdraw_amount);
}

// #[tokio::test]
// async fn test_flow_2() {
//     let mut config = create_test_config_with_thread_name!("test_config_flow_2.toml");
//     let rpc = create_extended_rpc!(config);

//     // Create temporary databases for testing.
//     let handle = thread::current()
//         .name()
//         .unwrap()
//         .split(':')
//         .last()
//         .unwrap()
//         .to_owned();
//     for i in 0..4 {
//         create_test_config!(
//             handle.clone() + i.to_string().as_str(),
//             "test_config_flow_2.toml"
//         );
//     }

//     let (_operator_client, _operator_handler, _results) =
//         create_operator_and_verifiers(config.clone(), rpc.clone()).await;
//     let secp = bitcoin::secp256k1::Secp256k1::new();
//     let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
//     let taproot_address = Address::p2tr(&secp, xonly_pk, None, config.network);
//     tracing::debug!(
//         "Taproot address script pubkey: {:#?}",
//         taproot_address.script_pubkey()
//     );
//     let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config.network);

//     let evm_address = EVMAddress([1u8; 20]);

//     let deposit_address_info = tx_builder
//         .generate_deposit_address(
//             taproot_address.as_unchecked(),
//             &evm_address,
//             BRIDGE_AMOUNT_SATS,
//             config.user_takes_after,
//         )
//         .unwrap();

//     tracing::debug!(
//         "Deposit address taproot spend info: {:#?}",
//         deposit_address_info.1
//     );
//     tracing::debug!("Deposit address: {:#?}", deposit_address_info.0);

//     let deposit_utxo = rpc
//         .send_to_address(&deposit_address_info.0, BRIDGE_AMOUNT_SATS)
//         .unwrap();
//     tracing::debug!("Deposit UTXO: {:#?}", deposit_utxo);
//     rpc.mine_blocks(config.user_takes_after as u64 + 2).unwrap();
//     let signer = Actor::new(config.secret_key, config.network);
//     let anyone_can_spend_txout = script_builder::anyone_can_spend_txout();
//     let tx_ins = TransactionBuilder::create_tx_ins_with_sequence(
//         vec![deposit_utxo],
//         config.user_takes_after as u16 + 1,
//     );
//     let tx_outs = TransactionBuilder::create_tx_outs(vec![
//         (
//             Amount::from_sat(BRIDGE_AMOUNT_SATS - 2 * config.min_relay_fee)
//                 - anyone_can_spend_txout.value * 2,
//             taproot_address.script_pubkey(),
//         ),
//         (
//             anyone_can_spend_txout.value,
//             anyone_can_spend_txout.script_pubkey,
//         ),
//     ]);
//     let takes_after_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
//     let deposit_tx = rpc.get_raw_transaction(&deposit_utxo.txid, None).unwrap();
//     let prevouts = vec![deposit_tx.output[deposit_utxo.vout as usize].clone()];

//     let takes_after_script = script_builder::generate_timelock_script(
//         taproot_address.as_unchecked(),
//         config.user_takes_after,
//     );
//     let bridge_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);

//     let mut takes_after_tx_details = TxHandler {
//         tx: takes_after_tx.clone(),
//         prevouts,
//         scripts: vec![vec![bridge_script, takes_after_script]],
//         taproot_spend_infos: vec![deposit_address_info.1],
//     };

//     let sig = signer
//         .sign_taproot_script_spend_tx_new_tweaked(&mut takes_after_tx_details, 0, 1)
//         .unwrap();

//     handle_taproot_witness_new(&mut takes_after_tx_details, &vec![sig.as_ref()], 0, 1).unwrap();
//     tracing::debug!(
//         "now sending takes_after_tx: {:#?}",
//         takes_after_tx_details.tx
//     );
//     let user_takes_back_txid = rpc
//         .send_raw_transaction(&takes_after_tx_details.tx)
//         .unwrap();
//     tracing::debug!("User takes back txid: {:?}", user_takes_back_txid);
//     let user_takes_back_tx = rpc
//         .get_raw_transaction(&user_takes_back_txid, None)
//         .unwrap();
//     tracing::debug!("User takes back tx: {:#?}", user_takes_back_tx);
// }

// #[tokio::test]
// async fn verifier_down_for_withdrawal_signature() {
//     let mut config = create_test_config_with_thread_name!(
//         "test_config_verifier_down_for_withdrawal_signature.toml"
//     );
//     let rpc = create_extended_rpc!(config);
//     let handle = thread::current()
//         .name()
//         .unwrap()
//         .split(':')
//         .last()
//         .unwrap()
//         .to_owned();
//     for i in 0..4 {
//         create_test_config!(
//             handle.clone() + i.to_string().as_str(),
//             "test_config_verifier_down_for_withdrawal_signature.toml"
//         );
//     }

//     let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();
//     let taproot_address = Address::p2tr(&SECP, xonly_pk, None, config.network);

//     let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config.network);

//     let (operator_client, _operator_handler, results) =
//         create_operator_and_verifiers(config.clone(), rpc.clone()).await;

//     let evm_addresses = [
//         EVMAddress([1u8; 20]),
//         EVMAddress([2u8; 20]),
//         EVMAddress([3u8; 20]),
//         EVMAddress([4u8; 20]),
//     ];
//     let deposit_addresses = evm_addresses
//         .iter()
//         .map(|evm_address| {
//             tx_builder
//                 .generate_deposit_address(
//                     taproot_address.as_unchecked(),
//                     evm_address,
//                     BRIDGE_AMOUNT_SATS,
//                     config.user_takes_after,
//                 )
//                 .unwrap()
//                 .0
//         })
//         .collect::<Vec<_>>();
//     println!("Deposit addresses: {:#?}", deposit_addresses);

//     for (idx, deposit_address) in deposit_addresses.iter().enumerate() {
//         let deposit_utxo = rpc
//             .send_to_address(deposit_address, BRIDGE_AMOUNT_SATS)
//             .unwrap();
//         println!("Deposit UTXO #{}: {:#?}", idx, deposit_utxo);

//         rpc.mine_blocks(18).unwrap();

//         let output = operator_client
//             .new_deposit_rpc(
//                 deposit_utxo,
//                 taproot_address.as_unchecked().clone(),
//                 evm_addresses[idx],
//             )
//             .await
//             .unwrap();
//         println!("Output #{}: {:#?}", idx, output);
//     }

//     // Assume one of the verifier is down.
//     const VERIFIER_IDX: usize = 3;
//     results.get(VERIFIER_IDX).unwrap().1.stop().unwrap();

//     let withdrawal_address = Address::p2tr(&SECP, xonly_pk, None, config.network);

//     if let Ok(_withdraw_txid) = operator_client
//         .new_withdrawal_direct_rpc(0, withdrawal_address.as_unchecked().clone())
//         .await
//     {
//         println!(
//             "Verifier {} is down, this should not be possible.",
//             VERIFIER_IDX
//         );
//         assert!(false);
//     };

//     // Restart all servers.
//     results.iter().for_each(|server| {
//         let _ = server.1.stop();
//     });
//     let (operator_client, _operator_handler, _results) =
//         create_operator_and_verifiers(config.clone(), rpc.clone()).await;

//     let withdraw_txid = operator_client
//         .new_withdrawal_direct_rpc(0, withdrawal_address.as_unchecked().clone())
//         .await
//         .unwrap();
//     println!("Withdrawal send to address: {:?}", withdrawal_address);
//     println!("Withdrawal TXID: {:#?}", withdraw_txid);

//     // check whether it has an output with the withdrawal address
//     let tx = rpc.get_raw_transaction(&withdraw_txid, None).unwrap();
//     let rpc_withdraw_script = tx.output[0].script_pubkey.clone();
//     let rpc_withdraw_amount = tx.output[0].value;
//     let expected_withdraw_script = withdrawal_address.script_pubkey();
//     assert_eq!(rpc_withdraw_script, expected_withdraw_script);

//     // check if the amounts match
//     let anyone_can_spend_amount = script_builder::anyone_can_spend_txout().value;
//     let expected_withdraw_amount = Amount::from_sat(BRIDGE_AMOUNT_SATS - 2 * config.min_relay_fee)
//         - anyone_can_spend_amount * 2;
//     assert_eq!(expected_withdraw_amount, rpc_withdraw_amount);
// }
