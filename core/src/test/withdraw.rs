use super::common::citrea::get_bridge_params;
use crate::citrea::{CitreaClient, CitreaClientT, SATS_TO_WEI_MULTIPLIER};
use crate::test::common::citrea::SECRET_KEYS;
use crate::test::common::{citrea, create_test_config_with_thread_name};
use crate::utils::initialize_logger;
use alloy::primitives::FixedBytes;
use alloy::primitives::U256;
use alloy::providers::Provider;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};

struct CitreaWithdrawAndGetUTXO;
#[async_trait]
impl TestCase for CitreaWithdrawAndGetUTXO {
    fn bitcoin_config() -> BitcoinConfig {
        crate::test::e2e_bitcoin_config(vec!["-dustrelayfee=0"])
    }

    fn test_config() -> TestCaseConfig {
        crate::test::paired_citrea(TestCaseConfig {
            with_batch_prover: false,
            with_sequencer: true,
            with_full_node: true,
            ..Default::default()
        })
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            bridge_initialize_params: get_bridge_params(),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        crate::test::common::mark_citrea_e2e_test_started();
        let (sequencer, _full_node, _, _, da) = citrea::start_citrea(Self::sequencer_config(), f)
            .await
            .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da.get(0).expect("There is a bitcoin node"),
            sequencer,
            None,
        );

        // `Bridge.withdraw` does not check Bitcoin inclusion; only `safeWithdraw` does.
        // A live Bitcoin tx cannot have vout `u32::MAX`, but the unguarded path still stores it.
        let withdrawal_utxo = OutPoint::new(Txid::from_byte_array([0x11; 32]), u32::MAX);

        let citrea_client = CitreaClient::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
            config.citrea_request_timeout,
        )
        .await
        .unwrap();

        let balance = citrea_client
            .contract
            .provider()
            .get_balance(citrea_client.wallet_address)
            .await
            .unwrap();
        println!("Initial balance: {balance}");

        let withdrawal_count = citrea_client
            .contract
            .getWithdrawalCount()
            .call()
            .await
            .unwrap();
        assert_eq!(withdrawal_count, U256::from(0));

        let withdrawal_tx_height_block_height = sequencer
            .client
            .ledger_get_head_l2_block_height()
            .await
            .unwrap()
            + 1;
        let citrea_withdrawal_tx = citrea_client
            .contract
            .withdraw(
                FixedBytes::from(withdrawal_utxo.txid.to_raw_hash().to_byte_array()),
                FixedBytes::from(withdrawal_utxo.vout.to_le_bytes()),
            )
            .value(U256::from(
                config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER,
            ))
            .send()
            .await
            .unwrap();
        sequencer.client.send_publish_batch_request().await.unwrap();

        let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
        println!("Citrea withdrawal tx receipt: {receipt:?}");

        let withdrawal_count = citrea_client
            .contract
            .getWithdrawalCount()
            .call()
            .await
            .unwrap();
        assert_eq!(withdrawal_count, U256::from(1));

        let stored_utxo = citrea_client
            .contract
            .withdrawalUTXOs(U256::ZERO)
            .call()
            .await
            .unwrap();
        assert_eq!(stored_utxo.txId.0, withdrawal_utxo.txid.to_byte_array());
        assert_eq!(
            u32::from_le_bytes(stored_utxo.outputId.0),
            withdrawal_utxo.vout
        );

        let utxos = citrea_client
            .collect_withdrawal_utxos(None, withdrawal_tx_height_block_height)
            .await
            .unwrap();
        assert_eq!(withdrawal_utxo, utxos[0].1);

        Ok(())
    }
}

#[tokio::test]
async fn citrea_withdraw_and_get_utxo() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    crate::test::common::run_citrea_e2e_with_retry(|| {
        TestCaseRunner::new(CitreaWithdrawAndGetUTXO).run()
    })
    .await
}
