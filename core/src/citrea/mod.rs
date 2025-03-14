//! # Citrea Related Utilities

use crate::errors::BridgeError;
use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    primitives::U256,
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Provider, ProviderBuilder, RootProvider,
    },
    rpc::types::{Filter, Log},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::SolEvent,
    transports::http::reqwest::Url,
};
use bitcoin::{hashes::Hash, OutPoint, Txid};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::proc_macros::rpc;
use std::fmt::Debug;
use tonic::async_trait;
use BRIDGE_CONTRACT::{Deposit, Withdrawal};

#[cfg(test)]
pub mod mock;

pub const CITREA_CHAIN_ID: u64 = 5655;
pub const LIGHT_CLIENT_ADDRESS: &str = "0x3100000000000000000000000000000000000001";
pub const BRIDGE_CONTRACT_ADDRESS: &str = "0x3100000000000000000000000000000000000002";
pub const SATS_TO_WEI_MULTIPLIER: u64 = 10_000_000_000;

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    BRIDGE_CONTRACT,
    "src/citrea/Bridge.json"
);

#[async_trait]
pub trait CitreaClientTrait: Send + Sync + Debug + Clone + 'static {
    type Client: Debug + Clone + Sync + Send;

    /// # Parameters
    ///
    /// - `citrea_rpc_url`: URL of the Citrea RPC.
    /// - `light_client_prover_url`: URL of the Citrea light client prover RPC.
    /// - `secret_key`: EVM secret key of the EVM user. If not given, random
    ///   secret key is used (wallet is not required). This is given mostly for
    ///   testing purposes.
    fn new(
        citrea_rpc_url: String,
        light_client_prover_url: String,
        secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self::Client, BridgeError>;

    /// Fetches an UTXO from Citrea for the given withdrawal index.
    ///
    /// # Parameters
    ///
    /// - `withdrawal_index`: Index of the withdrawal.
    ///
    /// # Returns
    ///
    /// - [`OutPoint`]: UTXO for the given withdrawal.
    async fn withdrawal_utxos(&self, withdrawal_index: u64) -> Result<OutPoint, BridgeError>;

    /// Returns deposit move txids with index for a given range of blocks.
    ///
    /// # Parameters
    ///
    /// - `from_height`: Start block height (inclusive)
    /// - `to_height`: End block height (inclusive)
    async fn collect_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError>;

    /// Returns withdrawal utxos with index for given range of blocks.
    ///
    /// # Parameters
    ///
    /// - `from_height`: Start block height (inclusive)
    /// - `to_height`: End block height (inclusive)
    async fn collect_withdrawal_utxos(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, OutPoint)>, BridgeError>;
}

/// Citrea client is responsible for interacting with the Citrea EVM and Citrea
/// RPC.
#[derive(Clone, Debug)]
pub struct CitreaClient {
    pub client: HttpClient,
    pub light_client_prover_client: HttpClient,
    pub wallet_address: alloy::primitives::Address,
    pub contract: CitreaContract,
}

impl CitreaClient {
    /// Returns all logs for the given filter and block range while considering
    /// about the 1000 block limit.
    async fn get_logs(
        &self,
        filter: Filter,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<Log>, BridgeError> {
        let mut logs = vec![];

        let mut from_height = from_height;
        while from_height <= to_height {
            // Block num is 999 because limits are inclusive.
            let to_height = std::cmp::min(from_height + 999, to_height);
            tracing::debug!("Fetching logs from {} to {}", from_height, to_height);

            // Update filter with the new range.
            let filter = filter.clone();
            let filter = filter.from_block(BlockNumberOrTag::Number(from_height));
            let filter = filter.to_block(BlockNumberOrTag::Number(to_height));

            let logs_chunk = self.contract.provider().get_logs(&filter).await?;
            logs.extend(logs_chunk);

            from_height += to_height;
        }

        Ok(logs)
    }
}

#[async_trait]
impl CitreaClientTrait for CitreaClient {
    type Client = CitreaClient;
    fn new(
        citrea_rpc_url: String,
        light_client_prover_url: String,
        secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self, BridgeError> {
        let citrea_rpc_url = Url::parse(&citrea_rpc_url)
            .map_err(|e| BridgeError::Error(format!("Can't parse Citrea RPC URL: {:?}", e)))?;
        let light_client_prover_url = Url::parse(&light_client_prover_url)
            .map_err(|e| BridgeError::Error(format!("Can't parse Citrea LCP RPC URL: {:?}", e)))?;
        let secret_key = secret_key.unwrap_or(PrivateKeySigner::random());

        let key = secret_key.with_chain_id(Some(CITREA_CHAIN_ID));
        let wallet_address = key.address();

        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(key))
            .on_http(citrea_rpc_url.clone());

        let contract = BRIDGE_CONTRACT::new(
            BRIDGE_CONTRACT_ADDRESS
                .parse()
                .expect("Correct contract address"),
            provider,
        );

        let client = HttpClientBuilder::default().build(citrea_rpc_url)?;
        let light_client_prover_client =
            HttpClientBuilder::default().build(light_client_prover_url)?;

        Ok(CitreaClient {
            client,
            light_client_prover_client,
            wallet_address,
            contract,
        })
    }

    async fn withdrawal_utxos(&self, withdrawal_index: u64) -> Result<OutPoint, BridgeError> {
        let withdrawal_utxo = self
            .contract
            .withdrawalUTXOs(U256::from(withdrawal_index))
            .call()
            .await?;

        let txid = withdrawal_utxo.txId.0;
        let txid = Txid::from_slice(txid.as_slice())?;

        let vout = withdrawal_utxo.outputId.0;
        let vout = u32::from_be_bytes(vout);

        Ok(OutPoint { txid, vout })
    }

    async fn collect_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError> {
        let filter = self.contract.event_filter::<Deposit>().filter;
        let logs = self.get_logs(filter, from_height, to_height).await?;

        let mut move_txids = vec![];
        for log in logs {
            let deposit_raw_data = log.data().clone().data.clone();

            let deposit_index = Deposit::abi_decode_data(&deposit_raw_data, false)?.4;
            let deposit_index: u64 = deposit_index
                .try_into()
                .map_err(|e| BridgeError::Error(format!("Can't convert deposit index: {:?}", e)))?;

            let move_txid = Deposit::abi_decode_data(deposit_raw_data.as_ref(), false)?.1;
            let move_txid = Txid::from_slice(move_txid.as_slice())?;

            move_txids.push((deposit_index, move_txid));
        }

        Ok(move_txids)
    }

    async fn collect_withdrawal_utxos(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, OutPoint)>, BridgeError> {
        let filter = self.contract.event_filter::<Withdrawal>().filter;
        let logs = self.get_logs(filter, from_height, to_height).await?;

        let mut utxos = vec![];
        for log in logs {
            let withdrawal_raw_data = log.data().clone().data.clone();

            let withdrawal_index = Withdrawal::abi_decode_data(&withdrawal_raw_data, false)?.1;
            let withdrawal_index: u64 = withdrawal_index.try_into().map_err(|e| {
                BridgeError::Error(format!("Can't convert withdrawal index: {:?}", e))
            })?;

            let withdrawal_utxo =
                Withdrawal::abi_decode_data(withdrawal_raw_data.as_ref(), false)?.0;

            let txid = withdrawal_utxo.txId.0;
            let txid = Txid::from_slice(txid.as_slice())?;

            let vout = withdrawal_utxo.outputId.0;
            let vout = u32::from_be_bytes(vout);

            utxos.push((withdrawal_index, OutPoint { txid, vout }));
        }

        Ok(utxos)
    }
}

#[rpc(client, namespace = "lightClientProver")]
pub trait LightClientProverRpc {
    /// Generate state transition data for the given L1 block height, and return the data as a borsh serialized hex string.
    #[method(name = "getLightClientProofByL1Height")]
    async fn get_light_client_proof_by_l1_height(
        &self,
        l1_height: u64,
    ) -> RpcResult<Option<sov_rollup_interface::rpc::LightClientProofResponse>>;
}

// Ugly typedefs.
type CitreaContract = BRIDGE_CONTRACT::BRIDGE_CONTRACTInstance<
    (),
    FillProvider<
        JoinFill<
            JoinFill<
                alloy::providers::Identity,
                JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
            >,
            WalletFiller<EthereumWallet>,
        >,
        RootProvider,
    >,
>;

#[cfg(test)]
mod tests {
    use crate::citrea::CitreaClientTrait;
    use crate::citrea::BRIDGE_CONTRACT::Withdrawal;
    use crate::test::common::citrea::BRIDGE_PARAMS;
    use crate::{
        citrea::CitreaClient,
        test::common::{
            citrea::{self, SECRET_KEYS},
            create_test_config_with_thread_name,
        },
    };
    use alloy::providers::Provider;
    use citrea_e2e::{
        config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
        framework::TestFramework,
        test_case::{TestCase, TestCaseRunner},
    };
    use tonic::async_trait;

    struct CitreaGetLogsLimitCheck;
    #[async_trait]
    impl TestCase for CitreaGetLogsLimitCheck {
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
                bridge_initialize_params: BRIDGE_PARAMS.to_string(),
                ..Default::default()
            }
        }

        async fn run_test(&mut self, f: &mut TestFramework) -> citrea_e2e::Result<()> {
            let (sequencer, _full_node, _, _, da) =
                citrea::start_citrea(Self::sequencer_config(), f)
                    .await
                    .unwrap();

            let mut config = create_test_config_with_thread_name(None).await;
            citrea::update_config_with_citrea_e2e_values(&mut config, da, sequencer, None);

            let citrea_client = CitreaClient::new(
                config.citrea_rpc_url,
                config.citrea_light_client_prover_url,
                Some(SECRET_KEYS[0].to_string().parse().unwrap()),
            )
            .unwrap();

            let filter = citrea_client.contract.event_filter::<Withdrawal>().filter;
            let start = 0;
            let end = 1001;

            // Generate blocks because Citrea will default `to_block` as the
            // height if `to_block` is exceeded height.
            for _ in start..end {
                sequencer.client.send_publish_batch_request().await.unwrap();
            }

            let logs_from_citrea_module = citrea_client
                .get_logs(filter.clone(), start, end)
                .await
                .unwrap();
            println!("Logs from Citrea module: {:?}", logs_from_citrea_module);

            let filter = filter.from_block(start).to_block(end);
            let logs_from_direct_call = citrea_client.contract.provider().get_logs(&filter).await;
            println!("Logs from direct call: {:?}", logs_from_direct_call);
            assert!(logs_from_direct_call.is_err());

            Ok(())
        }
    }

    #[tokio::test]
    async fn citrea_get_logs_limit_check() -> citrea_e2e::Result<()> {
        // TODO: temp hack to use the correct docker image
        std::env::set_var(
            "CITREA_DOCKER_IMAGE",
            "chainwayxyz/citrea-test:60d9fd633b9e62b647039f913c6f7f8c085ad42e",
        );
        TestCaseRunner::new(CitreaGetLogsLimitCheck).run().await
    }
}
