//! # Deposit Tests

use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::{
    config::{BitcoinConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use clementine_core::{
    builder, config::BridgeConfig, database::Database, extended_rpc::ExtendedRpc,
    utils::initialize_logger,
};
use common::{
    citrea::{start_citrea, update_config_with_citrea_e2e_da},
    run_single_deposit,
};

mod common;

struct DepositOnCitrea;
#[async_trait]
impl TestCase for DepositOnCitrea {
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-txindex=1",
                "-fallbackfee=0.000001",
                "-rpcallowip=0.0.0.0/0",
            ],
            ..Default::default()
        }
    }

    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: false,
            with_sequencer: true,
            with_full_node: true,
            docker: TestCaseDockerConfig {
                bitcoin: true,
                citrea: true,
            },
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (_sequencer, full_node, da) = start_citrea(Self::sequencer_config(), f).await?;

        let mut config = create_test_config_with_thread_name!(None);
        update_config_with_citrea_e2e_da(&mut config, da);

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let citrea_url = format!(
            "http://{}:{}",
            full_node.config.rollup.rpc.bind_host, full_node.config.rollup.rpc.bind_port
        );
        config.citrea_rpc_url = citrea_url;

        let (_verifiers, _operators, _aggregator, _watchtowers, _deposit_outpoint, move_txid) =
            run_single_deposit(&mut config, rpc.clone()).await?;

        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        let tx_info = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await?;
        let block = rpc
            .client
            .get_block(&tx_info.blockhash.expect("Not None"))
            .await?;
        let block_height = rpc.client.get_block_info(&block.block_hash()).await?.height;

        builder::citrea::initialized(full_node.client.http_client().clone()).await?;

        let deposit = builder::citrea::deposit(
            full_node.client.http_client().clone(),
            block,
            block_height.try_into().expect("Will not fail"),
            tx,
        )
        .await;
        tracing::info!("Deposit result: {:?}", deposit);

        Ok(())
    }
}

#[tokio::test]
async fn send_deposit_details_to_citrea() -> Result<()> {
    TestCaseRunner::new(DepositOnCitrea).run().await
}

// #[ignore = "We are switching to gRPC"]
// #[tokio::test]
//
// async fn deposit_with_retry_checks() {
// let mut config = create_test_config_with_thread_name!(None);
// let rpc = ExtendedRpc::connect(
//     config.bitcoin_rpc_url.clone(),
//     config.bitcoin_rpc_user.clone(),
//     config.bitcoin_rpc_password.clone(),
// )
// .await;

// let secret_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
// let signer_address = Actor::new(secret_key, config.winternitz_secret_key, config.network)
//     .address
//     .as_unchecked()
//     .clone();
// let user = User::new(rpc.clone_inner().await.unwrap(), secret_key, config.clone());

// let evm_address: EVMAddress = EVMAddress([1u8; 20]);
// let deposit_address = user.get_deposit_address(evm_address).unwrap(); This line needs to be converted into get_deposit_address!

// let deposit_outpoint = rpc
//     .send_to_address(&deposit_address, config.bridge_amount_sats)
//     .await
//     .unwrap();
// rpc.mine_blocks((config.confirmation_threshold + 2).into())
//     .await
//     .unwrap();

// let (verifiers, operators, aggregator) =
//     create_verifiers_and_operators("test_config.toml").await;

// let agg_nonces = {
//     let mut pub_nonces = Vec::new();

//     for (client, _, _) in verifiers.iter() {
//         let musig_pub_nonces = client
//             .verifier_new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
//             .await
//             .unwrap();

//         pub_nonces.push(musig_pub_nonces);
//     }
//     let agg_nonces = aggregator
//         .0
//         .aggregate_pub_nonces_rpc(pub_nonces)
//         .await
//         .unwrap();

//     let mut pub_nonces_retry = Vec::new();
//     for (client, _, _) in verifiers.iter() {
//         let musig_pub_nonces = client
//             .verifier_new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
//             .await
//             .unwrap();

//         pub_nonces_retry.push(musig_pub_nonces);
//     }
//     let agg_nonces_retry = aggregator
//         .0
//         .aggregate_pub_nonces_rpc(pub_nonces_retry)
//         .await
//         .unwrap();

//     assert_eq!(agg_nonces, agg_nonces_retry);

//     agg_nonces
// };

// let (kickoff_utxos, signatures) = {
//     let mut kickoff_utxos = Vec::new();
//     let mut signatures = Vec::new();

//     for (client, _, _) in operators.iter() {
//         let (kickoff_utxo, signature) = client
//             .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
//             .await
//             .unwrap();

//         kickoff_utxos.push(kickoff_utxo);
//         signatures.push(signature);
//     }

//     let mut kickoff_utxos_retry = Vec::new();
//     let mut signatures_retry = Vec::new();
//     for (client, _, _) in operators.iter() {
//         let (kickoff_utxo, signature) = client
//             .new_deposit_rpc(deposit_outpoint, signer_address.clone(), evm_address)
//             .await
//             .unwrap();

//         kickoff_utxos_retry.push(kickoff_utxo);
//         signatures_retry.push(signature);
//     }

//     assert_eq!(kickoff_utxos, kickoff_utxos_retry);

//     (kickoff_utxos, signatures)
// };

// // Operator part is done; Verifier part starts.

// let slash_or_take_sigs = {
//     let mut slash_or_take_partial_sigs = Vec::new();
//     for (client, ..) in verifiers.iter() {
//         let (partial_sigs, _) = client
//             .operator_kickoffs_generated_rpc(
//                 deposit_outpoint,
//                 kickoff_utxos.clone(),
//                 signatures.clone(),
//                 agg_nonces.clone(),
//             )
//             .await
//             .unwrap();

//         slash_or_take_partial_sigs.push(partial_sigs);
//     }
//     let slash_or_take_sigs = aggregator
//         .0
//         .aggregate_slash_or_take_sigs_rpc(
//             deposit_outpoint,
//             kickoff_utxos.clone(),
//             agg_nonces[config.num_operators + 1..2 * config.num_operators + 1].to_vec(),
//             slash_or_take_partial_sigs.clone(),
//         )
//         .await
//         .unwrap();

//     let mut slash_or_take_partial_sigs_retry = Vec::new();
//     for (client, ..) in verifiers.iter() {
//         let (partial_sigs, _) = client
//             .operator_kickoffs_generated_rpc(
//                 deposit_outpoint,
//                 kickoff_utxos.clone(),
//                 signatures.clone(),
//                 agg_nonces.clone(),
//             )
//             .await
//             .unwrap();

//         slash_or_take_partial_sigs_retry.push(partial_sigs);
//     }
//     let slash_or_take_sigs_retry = aggregator
//         .0
//         .aggregate_slash_or_take_sigs_rpc(
//             deposit_outpoint,
//             kickoff_utxos.clone(),
//             agg_nonces[config.num_operators + 1..2 * config.num_operators + 1].to_vec(),
//             slash_or_take_partial_sigs_retry.clone(),
//         )
//         .await
//         .unwrap();

//     assert_eq!(slash_or_take_partial_sigs, slash_or_take_partial_sigs_retry);
//     assert_eq!(slash_or_take_sigs, slash_or_take_sigs_retry);

//     slash_or_take_sigs
// };

// let operator_take_sigs = {
//     let mut operator_take_partial_sigs: Vec<Vec<MuSigPartialSignature>> = Vec::new();
//     for (client, ..) in verifiers.iter() {
//         let partial_sigs = client
//             .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs.clone())
//             .await
//             .unwrap();
//         operator_take_partial_sigs.push(partial_sigs);
//     }
//     let operator_take_sigs = aggregator
//         .0
//         .aggregate_operator_take_sigs_rpc(
//             deposit_outpoint,
//             kickoff_utxos.clone(),
//             agg_nonces[1..config.num_operators + 1].to_vec(),
//             operator_take_partial_sigs,
//         )
//         .await
//         .unwrap();

//     let mut operator_take_partial_sigs_retry = Vec::new();
//     for (client, ..) in verifiers.iter() {
//         let partial_sigs = client
//             .burn_txs_signed_rpc(deposit_outpoint, vec![], slash_or_take_sigs.clone())
//             .await
//             .unwrap();
//         operator_take_partial_sigs_retry.push(partial_sigs);
//     }
//     let operator_take_sigs_retry = aggregator
//         .0
//         .aggregate_operator_take_sigs_rpc(
//             deposit_outpoint,
//             kickoff_utxos.clone(),
//             agg_nonces[1..config.num_operators + 1].to_vec(),
//             operator_take_partial_sigs_retry,
//         )
//         .await
//         .unwrap();

//     assert_eq!(operator_take_sigs, operator_take_sigs_retry);

//     operator_take_sigs
// };

// let move_tx_partial_sigs = {
//     let mut move_tx_partial_sigs = Vec::new();
//     for (client, _, _) in verifiers.iter() {
//         let move_tx_partial_sig = client
//             .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs.clone())
//             .await
//             .unwrap();
//         move_tx_partial_sigs.push(move_tx_partial_sig);
//     }

//     let mut move_tx_partial_sigs_retry = Vec::new();
//     for (client, _, _) in verifiers.iter() {
//         let move_tx_partial_sig = client
//             .operator_take_txs_signed_rpc(deposit_outpoint, operator_take_sigs.clone())
//             .await
//             .unwrap();
//         move_tx_partial_sigs_retry.push(move_tx_partial_sig);
//     }

//     assert_eq!(move_tx_partial_sigs, move_tx_partial_sigs_retry);

//     move_tx_partial_sigs
// };

// let move_tx = {
//     let (move_tx, _) = aggregator
//         .0
//         .aggregate_move_tx_sigs_rpc(
//             deposit_outpoint,
//             signer_address.clone(),
//             evm_address,
//             agg_nonces[0],
//             move_tx_partial_sigs.clone(),
//         )
//         .await
//         .unwrap();

//     let (move_tx_retry, _) = aggregator
//         .0
//         .aggregate_move_tx_sigs_rpc(
//             deposit_outpoint,
//             signer_address,
//             evm_address,
//             agg_nonces[0],
//             move_tx_partial_sigs,
//         )
//         .await
//         .unwrap();

//     assert_eq!(move_tx, move_tx_retry);

//     move_tx
// };

// let move_tx: Transaction = deserialize_hex(&move_tx).unwrap();

// println!("Move tx weight: {:?}", move_tx.weight());
// }
