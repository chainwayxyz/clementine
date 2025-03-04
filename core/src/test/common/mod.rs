//! # Common Utilities for Integration Tests

#![allow(unused)]

use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use crate::rpc::clementine::{DepositParams, Empty};
use crate::servers::{
    create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    create_watchtower_grpc_server,
};
use crate::EVMAddress;
use crate::{builder, musig2::AggregateFromPublicKeys};
use bitcoin::{OutPoint, XOnlyPublicKey};
pub use test_utils::*;
use tonic::transport::Channel;
use tonic::Request;

mod test_utils;
// pub async fn run_multiple_deposits(test_config_name: &str) {
//     let config = create_test_config_with_thread_name(test_config_name, None);
//     let rpc = ExtendedRpc::connect(
//         config.bitcoin_rpc_url.clone(),
//         config.bitcoin_rpc_user.clone(),
//         config.bitcoin_rpc_password.clone(),
//     )
//     .await;
//     let secp = secp256k1::Secp256k1::new();
//     let (verifiers, operators, aggregator) =
//         create_verifiers_and_operators("test_config.toml").await;

//     // println!("Operators: {:#?}", operators);
//     // println!("Verifiers: {:#?}", verifiers);

//     let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

//     let signer_address = Actor::new(secret_key, config.winternitz_secret_key, config.protocol_paramset().network)
//         .address
//         .as_unchecked()
//         .clone();
//     let user = User::new(rpc.clone_inner().await.unwrap(), secret_key, config.clone());

//     let evm_address = EVMAddress([1u8; 20]);
//     let deposit_address = user.get_deposit_address(evm_address).unwrap(); This line needs to be converted into get_deposit_address
//     let mut deposit_outpoints = Vec::new();
//     for _ in 0..config.operator_num_kickoff_utxos_per_tx + 1 {
//         let deposit_outpoint = rpc
//             .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
//             .await
//             .unwrap();

//         rpc.mine_blocks(18).await.unwrap();

//         let mut pub_nonces = Vec::new();

//         for (client, _, _) in verifiers.iter() {
//             let musig_pub_nonces = client
//                 .verifier_new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
//                 .await
//                 .unwrap();

//             pub_nonces.push(musig_pub_nonces);
//         }

//         let agg_nonces = aggregator
//             .0
//             .aggregate_pub_nonces_rpc(pub_nonces)
//             .await
//             .unwrap();
//         let mut kickoff_utxos = Vec::new();
//         let mut signatures = Vec::new();

//         for (client, _, _) in operators.iter() {
//             let (kickoff_utxo, signature) = client
//                 .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
//                 .await
//                 .unwrap();

//             kickoff_utxos.push(kickoff_utxo);
//             signatures.push(signature);
//         }

//         println!("Now the verifiers sequence starts");
//         let mut slash_or_take_partial_sigs = Vec::new();

//         for (client, ..) in verifiers.iter() {
//             let (partial_sigs, _) = client
//                 .operator_kickoffs_generated_rpc(
//                     deposit_outpoint,
//                     kickoff_utxos.clone(),
//                     signatures.clone(),
//                     agg_nonces.clone(),
//                 )
//                 .await
//                 .unwrap();

//             slash_or_take_partial_sigs.push(partial_sigs);
//         }

//         let slash_or_take_sigs = aggregator
//             .0
//             .aggregate_slash_or_take_sigs_rpc(
//                 deposit_outpoint,
//                 kickoff_utxos.clone(),
//                 agg_nonces[config.num_operators + 1..2 * config.num_operators + 1].to_vec(),
//                 slash_or_take_partial_sigs,
//             )
//             .await
//             .unwrap();
//         let mut operator_take_partial_sigs: Vec<Vec<MuSigPartialSignature>> = Vec::new();
//         for (client, ..) in verifiers.iter() {
//             let partial_sigs = client
//                 .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs.clone())
//                 .await
//                 .unwrap();
//             operator_take_partial_sigs.push(partial_sigs);
//         }

//         let operator_take_sigs = aggregator
//             .0
//             .aggregate_operator_take_sigs_rpc(
//                 deposit_outpoint,
//                 kickoff_utxos.clone(),
//                 agg_nonces[1..config.num_operators + 1].to_vec(),
//                 operator_take_partial_sigs,
//             )
//             .await
//             .unwrap();

//         let mut move_tx_partial_sigs = Vec::new();
//         for (client, _, _) in verifiers.iter() {
//             let move_tx_partial_sig = client
//                 .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs.clone())
//                 .await
//                 .unwrap();
//             move_tx_partial_sigs.push(move_tx_partial_sig);
//         }

//         let (move_tx, _) = aggregator
//             .0
//             .aggregate_move_tx_sigs_rpc(
//                 deposit_outpoint,
//                 signer_address.clone(),
//                 evm_address,
//                 agg_nonces[0],
//                 move_tx_partial_sigs,
//             )
//             .await
//             .unwrap();
//         let move_tx: Transaction = deserialize_hex(&move_tx).unwrap();

//         println!("Move tx weight: {:?}", move_tx.weight());
//         let move_txid = rpc.client.send_raw_transaction(&move_tx).await.unwrap();
//         println!("Move txid: {:?}", move_txid);
//         deposit_outpoints.push(deposit_outpoint);
//     }
//     let withdrawal_address = Address::p2tr(
//         &secp,
//         secret_key.x_only_public_key(&secp).0,
//         None,
//         config.protocol_paramset().network,
//     );
//     let (user_utxo, user_txout, user_sig) = user
//         .generate_withdrawal_transaction_and_signature(
//             withdrawal_address.clone(),
//             Amount::from_sat(
//                 config.protocol_paramset().bridge_amount.to_sat()
//                     - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
//             ),
//         )
//         .await
//         .unwrap(); This line needs to be converted into generate_withdrawal_transaction_and_signature
//     let withdrawal_provide_txid = operators[0]
//         .0
//         .new_withdrawal_sig_rpc(0, user_sig, user_utxo, user_txout)
//         .await
//         .unwrap();
//     println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
//     let txs_to_be_sent_0 = operators[0]
//         .0
//         .withdrawal_proved_on_citrea_rpc(0, deposit_outpoints[0])
//         .await
//         .unwrap();
//     assert!(txs_to_be_sent_0.len() == 3);
//     let (user_utxo, user_txout, user_sig) = user
//         .generate_withdrawal_transaction_and_signature(
//             withdrawal_address.clone(),
//             Amount::from_sat(
//                 config.protocol_paramset().bridge_amount.to_sat()
//                     - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
//             ),
//         )
//         .await
//         .unwrap(); This line needs to be converted into generate_withdrawal_transaction_and_signature
//     let withdrawal_provide_txid = operators[1]
//         .0
//         .new_withdrawal_sig_rpc(
//             config.operator_num_kickoff_utxos_per_tx as u32 - 1,
//             user_sig,
//             user_utxo,
//             user_txout,
//         )
//         .await
//         .unwrap();
//     println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
//     let txs_to_be_sent_penultimate = operators[1]
//         .0
//         .withdrawal_proved_on_citrea_rpc(
//             config.operator_num_kickoff_utxos_per_tx as u32 - 1,
//             deposit_outpoints[config.operator_num_kickoff_utxos_per_tx - 1],
//         )
//         .await
//         .unwrap();
//     assert!(txs_to_be_sent_penultimate.len() == 3);
//     let (user_utxo, user_txout, user_sig) = user
//         .generate_withdrawal_transaction_and_signature(
//             withdrawal_address.clone(),
//             Amount::from_sat(
//                 config.protocol_paramset().bridge_amount.to_sat()
//                     - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
//             ),
//         )
//         .await
//         .unwrap(); This line needs to be converted into generate_withdrawal_transaction_and_signature
//     let withdrawal_provide_txid = operators[0]
//         .0
//         .new_withdrawal_sig_rpc(2, user_sig, user_utxo, user_txout)
//         .await
//         .unwrap();
//     println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
//     let txs_to_be_sent_last = operators[2]
//         .0
//         .withdrawal_proved_on_citrea_rpc(
//             config.operator_num_kickoff_utxos_per_tx as u32,
//             deposit_outpoints[config.operator_num_kickoff_utxos_per_tx],
//         )
//         .await
//         .unwrap();
//     assert!(txs_to_be_sent_last.len() == 4);
// }

pub async fn run_single_deposit(
    mut config: BridgeConfig,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        Vec<ClementineWatchtowerClient<Channel>>,
        OutPoint,
    ),
    BridgeError,
> {
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(&config, evm_address)?;

    let (verifiers, operators, mut aggregator, watchtowers, _regtest) =
        create_actors(&config).await;

    aggregator.setup(Request::new(Empty {})).await?;

    let nofn_xonly_pk =
        XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)?;

    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    tracing::warn!("before mining extra blocks");
    rpc.mine_blocks(180).await?;

    let _move_tx = aggregator
        .new_deposit(DepositParams {
            deposit_outpoint: Some(deposit_outpoint.into()),
            evm_address: evm_address.0.to_vec(),
            recovery_taproot_address: deposit_address.to_string(),
            nofn_xonly_pk: nofn_xonly_pk.serialize().to_vec(),
        })
        .await?
        .into_inner();

    // let move_tx: Transaction =
    //     Transaction::consensus_decode(&mut move_tx.raw_tx.as_slice())?;
    // let move_txid = rpc.client.send_raw_transaction(&move_tx).await?;
    // println!("Move txid: {:?}", move_txid);
    // println!("Move tx weight: {:?}", move_tx.weight());
    tokio::time::sleep(tokio::time::Duration::from_secs(1000)).await;
    Ok((
        verifiers,
        operators,
        aggregator,
        watchtowers,
        deposit_outpoint,
    ))
}
