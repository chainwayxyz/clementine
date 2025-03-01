use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self, SATS_TO_WEI_MULTIPLIER},
        create_test_config_with_thread_name, run_single_deposit,
    },
    EVMAddress,
};
use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use std::{thread::sleep, time::Duration};

struct DepositToCitrea;
#[async_trait]
impl TestCase for DepositToCitrea {
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

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            // min_soft_confirmations_per_commitment: 50,
            test_mode: false,
            bridge_initialize_params: "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000000000000002d4a20423a0b35060e62053765e2aba342f1c242e78d68f5248aca26e703c0c84ca322ac0063066369747265611400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a08000000003b9aca006800000000000000000000000000000000000000000000".to_string(),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (sequencer, _full_node, da) = citrea::start_citrea(Self::sequencer_config(), f)
            .await
            .unwrap();

        let mut config = create_test_config_with_thread_name(None).await;
        citrea::update_config_with_citrea_e2e_values(&mut config, da, sequencer);

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let (_verifiers, _operators, _aggregator, _watchtowers, _deposit_outpoint, move_txid) =
            run_single_deposit(&mut config, rpc.clone(), None).await?;

        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        let tx_info = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await?;
        let block = rpc
            .client
            .get_block(&tx_info.blockhash.expect("Not None"))
            .await?;
        rpc.mine_blocks(101).await.unwrap();
        let block_height = rpc.client.get_block_info(&block.block_hash()).await?.height;

        while citrea::block_number(sequencer.client.http_client().clone()).await?
            < block_height.try_into().unwrap()
        {
            tracing::debug!("Waiting for block to be mined");
            rpc.mine_blocks(1).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        citrea::deposit(
            sequencer.client.http_client().clone(),
            block,
            block_height.try_into().expect("Will not fail"),
            tx,
        )
        .await?;

        sleep(Duration::from_secs(3));
        let balance =
            citrea::eth_get_balance(sequencer.client.http_client().clone(), EVMAddress([1; 20]))
                .await
                .unwrap();
        assert_eq!(
            balance,
            (config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER).into()
        );

        Ok(())
    }
}

#[tokio::test]
async fn send_deposit_details_to_citrea() -> Result<()> {
    TestCaseRunner::new(DepositToCitrea).run().await
}
