//! # Citrea Related Utilities

use crate::citrea::BRIDGE_CONTRACT::DepositReplaced;
use crate::errors::BridgeError;

use alloy::{
    eips::{BlockId, BlockNumberOrTag},
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
use bitcoin::{hashes::Hash, OutPoint, Txid, XOnlyPublicKey};
use eyre::Context;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::proc_macros::rpc;
use lazy_static::lazy_static;
use std::{fmt::Debug, time::Duration};
use tonic::async_trait;

#[cfg(test)]
pub mod mock;

lazy_static! {
    pub static ref CITREA_CHAIN_ID: u64 = std::env::var("CITREA_CHAIN_ID")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5655);
}

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
pub trait CitreaClientT: Send + Sync + Debug + Clone + 'static {
    /// # Parameters
    ///
    /// - `citrea_rpc_url`: URL of the Citrea RPC.
    /// - `light_client_prover_url`: URL of the Citrea light client prover RPC.
    /// - `secret_key`: EVM secret key of the EVM user. If not given, random
    ///   secret key is used (wallet is not required). This is given mostly for
    ///   testing purposes.
    async fn new(
        citrea_rpc_url: String,
        light_client_prover_url: String,
        secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self, BridgeError>;

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

    /// Returns deposit move txids, starting from the last deposit index.
    ///
    /// # Parameters
    ///
    /// - `last_deposit_idx`: Last deposit index. None if no deposit
    /// - `to_height`: End block height (inclusive)
    async fn collect_deposit_move_txids(
        &self,
        last_deposit_idx: Option<u32>,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError>;

    /// Returns withdrawal utxos, starting from the last withdrawal index.
    ///
    /// # Parameters
    ///
    /// - `last_withdrawal_idx`: Last withdrawal index. None if no withdrawal
    /// - `to_height`: End block height (inclusive)
    async fn collect_withdrawal_utxos(
        &self,
        last_withdrawal_idx: Option<u32>,
        to_height: u64,
    ) -> Result<Vec<(u64, OutPoint)>, BridgeError>;

    /// Returns the light client proof and its L2 height for the given L1 block
    /// height.
    ///
    /// # Returns
    ///
    /// A tuple, wrapped around a [`Some`] if present:
    ///
    /// - [`u64`]: Last L2 block height.
    ///
    /// If not present, [`None`] is returned.
    async fn get_light_client_proof(
        &self,
        l1_height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, BridgeError>;

    /// Returns the L2 block height range for the given L1 block height.
    ///
    /// TODO: This is not the best way to do this, but it's a quick fix for now
    /// it will attempt to fetch the light client proof max_attempts times with
    /// 1 second intervals.
    ///
    /// # Parameters
    ///
    /// - `block_height`: L1 block height.
    /// - `timeout`: Timeout duration.
    ///
    /// # Returns
    ///
    /// A tuple of:
    ///
    /// - [`u64`]: Start of the L2 block height (not inclusive)
    /// - [`u64`]: End of the L2 block height (inclusive)
    async fn get_citrea_l2_height_range(
        &self,
        block_height: u64,
        timeout: Duration,
    ) -> Result<(u64, u64), BridgeError>;

    /// Returns the replacement deposit move txids for the given range of blocks.
    ///
    /// # Parameters
    ///
    /// - `from_height`: Start block height (inclusive)
    /// - `to_height`: End block height (inclusive)
    ///
    /// # Returns
    ///
    /// A vector of tuples, each containing:
    ///
    /// - [`Txid`]: The original move txid.
    /// - [`Txid`]: The replacement move txid.
    async fn get_replacement_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(Txid, Txid)>, BridgeError>;

    async fn check_nofn_correctness(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
    ) -> Result<(), BridgeError>;
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

            let logs_chunk = self
                .contract
                .provider()
                .get_logs(&filter)
                .await
                .wrap_err("Failed to get logs")?;
            logs.extend(logs_chunk);

            from_height = to_height + 1;
        }

        Ok(logs)
    }
}

#[async_trait]
impl CitreaClientT for CitreaClient {
    async fn new(
        citrea_rpc_url: String,
        light_client_prover_url: String,
        secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self, BridgeError> {
        let citrea_rpc_url = Url::parse(&citrea_rpc_url).wrap_err("Can't parse Citrea RPC URL")?;
        let light_client_prover_url =
            Url::parse(&light_client_prover_url).wrap_err("Can't parse Citrea LCP RPC URL")?;
        let secret_key = secret_key.unwrap_or(PrivateKeySigner::random());

        let key = secret_key.with_chain_id(Some(*CITREA_CHAIN_ID));
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

        let client = HttpClientBuilder::default()
            .build(citrea_rpc_url)
            .wrap_err("Failed to create Citrea RPC client")?;
        let light_client_prover_client = HttpClientBuilder::default()
            .build(light_client_prover_url)
            .wrap_err("Failed to create Citrea LCP RPC client")?;

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
            .await
            .wrap_err("Failed to get withdrawal UTXO")?;

        let txid = withdrawal_utxo.txId.0;
        let txid = Txid::from_slice(txid.as_slice())?;

        let vout = withdrawal_utxo.outputId.0;
        let vout = u32::from_be_bytes(vout);

        Ok(OutPoint { txid, vout })
    }

    async fn collect_deposit_move_txids(
        &self,
        last_deposit_idx: Option<u32>,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError> {
        let mut move_txids = vec![];

        let mut start_idx = match last_deposit_idx {
            Some(idx) => idx + 1,
            None => 0,
        };

        loop {
            let deposit_txid = self
                .contract
                .depositTxIds(U256::from(start_idx))
                .block(BlockId::Number(BlockNumberOrTag::Number(to_height)))
                .call()
                .await;
            if deposit_txid.is_err() {
                tracing::info!(
                    "Deposit txid not found for index, error: {:?}",
                    deposit_txid
                );
                break;
            }
            tracing::info!("Deposit txid found for index: {:?}", deposit_txid);

            let deposit_txid = deposit_txid.expect("Failed to get deposit txid");
            let move_txid = Txid::from_slice(deposit_txid._0.as_ref())
                .wrap_err("Failed to convert move txid to Txid")?;
            move_txids.push((start_idx as u64, move_txid));
            start_idx += 1;
        }
        Ok(move_txids)
    }

    async fn collect_withdrawal_utxos(
        &self,
        last_withdrawal_idx: Option<u32>,
        to_height: u64,
    ) -> Result<Vec<(u64, OutPoint)>, BridgeError> {
        let mut utxos = vec![];

        let mut start_idx = match last_withdrawal_idx {
            Some(idx) => idx + 1,
            None => 0,
        };

        loop {
            let withdrawal_utxo = self
                .contract
                .withdrawalUTXOs(U256::from(start_idx))
                .block(BlockId::Number(BlockNumberOrTag::Number(to_height)))
                .call()
                .await;
            if withdrawal_utxo.is_err() {
                break;
            }
            let withdrawal_utxo = withdrawal_utxo.expect("Failed to get withdrawal UTXO");
            let txid = withdrawal_utxo.txId.0;
            let txid =
                Txid::from_slice(txid.as_ref()).wrap_err("Failed to convert txid to Txid")?;
            let vout = withdrawal_utxo.outputId.0;
            let vout = u32::from_be_bytes(vout);
            let utxo = OutPoint { txid, vout };
            utxos.push((start_idx as u64, utxo));
            start_idx += 1;
        }
        Ok(utxos)
    }

    async fn get_light_client_proof(
        &self,
        l1_height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, BridgeError> {
        let proof_result = self
            .light_client_prover_client
            .get_light_client_proof_by_l1_height(l1_height)
            .await
            .wrap_err("Failed to get light client proof")?;
        tracing::debug!(
            "Light client proof result {}: {:?}",
            l1_height,
            proof_result
        );

        let ret = if let Some(proof_result) = proof_result {
            Some((
                proof_result
                    .light_client_proof_output
                    .last_l2_height
                    .try_into()
                    .wrap_err("Can't convert last_l2_height to u64")?,
                proof_result.proof,
            ))
        } else {
            None
        };

        Ok(ret)
    }

    async fn get_citrea_l2_height_range(
        &self,
        block_height: u64,
        timeout: Duration,
    ) -> Result<(u64, u64), BridgeError> {
        let start = std::time::Instant::now();
        let proof_current = loop {
            if let Some(proof) = self.get_light_client_proof(block_height).await? {
                break proof;
            }

            if start.elapsed() > timeout {
                return Err(eyre::eyre!(
                    "Light client proof not found for block height {} after {} seconds",
                    block_height,
                    timeout.as_secs()
                )
                .into());
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        };

        let proof_previous =
            self.get_light_client_proof(block_height - 1)
                .await?
                .ok_or(eyre::eyre!(
                    "Light client proof not found for block height: {}",
                    block_height - 1
                ))?;

        let l2_height_end: u64 = proof_current.0;
        let l2_height_start: u64 = proof_previous.0;

        Ok((l2_height_start, l2_height_end))
    }

    async fn get_replacement_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(Txid, Txid)>, BridgeError> {
        let mut replacement_move_txids = vec![];

        // get logs
        let filter = self.contract.event_filter::<DepositReplaced>().filter;
        let logs = self.get_logs(filter, from_height, to_height).await?;

        for log in logs {
            let replacement_raw_data = &log.data().data;

            let old_move_txid = DepositReplaced::abi_decode_data(replacement_raw_data, false)
                .wrap_err("Failed to decode replacement deposit data")?
                .1;
            let new_move_txid = DepositReplaced::abi_decode_data(replacement_raw_data, false)
                .wrap_err("Failed to decode replacement deposit data")?
                .2;

            let old_move_txid = Txid::from_slice(old_move_txid.as_ref())
                .wrap_err("Failed to convert old move txid to Txid")?;
            let new_move_txid = Txid::from_slice(new_move_txid.as_ref())
                .wrap_err("Failed to convert new move txid to Txid")?;

            replacement_move_txids.push((old_move_txid, new_move_txid));
        }

        Ok(replacement_move_txids)
    }

    /// TODO: This is not the best way to do this, but it's a quick fix for now
    async fn check_nofn_correctness(
        &self,
        _nofn_xonly_pk: XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        // let script_prefix = self
        //     .contract
        //     .scriptPrefix()
        //     .call()
        //     .await
        //     .wrap_err("Failed to get script prefix")?
        //     ._0;
        // if script_prefix.len() < 34 {
        //     return Err(eyre::eyre!("script_prefix is too short").into());
        // }
        // let script_nofn_bytes = &script_prefix[2..2 + 32];
        // let contract_nofn_xonly_pk = XOnlyPublicKey::from_slice(script_nofn_bytes)
        //     .wrap_err("Failed to convert citrea contract script nofn bytes to xonly pk")?;
        // if contract_nofn_xonly_pk != nofn_xonly_pk {
        //     return Err(eyre::eyre!("Nofn of deposit does not match with citrea contract").into());
        // }
        Ok(())
    }
}

#[rpc(client, namespace = "lightClientProver")]
trait LightClientProverRpc {
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
    use crate::citrea::CitreaClientT;
    use crate::citrea::BRIDGE_CONTRACT::Withdrawal;
    use crate::test::common::citrea::get_bridge_params;
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
                bridge_initialize_params: get_bridge_params().to_string(),
                ..Default::default()
            }
        }

        async fn run_test(&mut self, f: &mut TestFramework) -> citrea_e2e::Result<()> {
            let (sequencer, _full_node, _, _, da) =
                citrea::start_citrea(Self::sequencer_config(), f)
                    .await
                    .unwrap();

            let mut config = create_test_config_with_thread_name().await;
            citrea::update_config_with_citrea_e2e_values(&mut config, da, sequencer, None);

            let citrea_client = CitreaClient::new(
                config.citrea_rpc_url,
                config.citrea_light_client_prover_url,
                Some(SECRET_KEYS[0].to_string().parse().unwrap()),
            )
            .await
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
    #[ignore = "Includes code that won't change much and the test itself is too flaky; Ignoring..."]
    async fn citrea_get_logs_limit_check() -> citrea_e2e::Result<()> {
        std::env::set_var(
            "CITREA_DOCKER_IMAGE",
            "chainwayxyz/citrea-test:46096297b7663a2e4a105b93e57e6dd3215af91c",
        );
        TestCaseRunner::new(CitreaGetLogsLimitCheck).run().await
    }
}
