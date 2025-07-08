//! # Citrea Related Utilities

use crate::citrea::BRIDGE_CONTRACT::DepositReplaced;
use crate::errors::BridgeError;
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    network::EthereumWallet,
    primitives::{keccak256, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Provider, ProviderBuilder, RootProvider,
    },
    rpc::types::{EIP1186AccountProofResponse, Filter, Log},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::SolEvent,
    transports::http::reqwest::Url,
};
use bitcoin::{hashes::Hash, OutPoint, Txid, XOnlyPublicKey};
use bridge_circuit_host::receipt_from_inner;
use circuits_lib::bridge_circuit::structs::{LightClientProof, StorageProof};
use eyre::Context;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::proc_macros::rpc;
use risc0_zkvm::{InnerReceipt, Receipt};
use std::{fmt::Debug, time::Duration};
use tonic::async_trait;

pub const LIGHT_CLIENT_ADDRESS: &str = "0x3100000000000000000000000000000000000001";
pub const BRIDGE_CONTRACT_ADDRESS: &str = "0x3100000000000000000000000000000000000002";
pub const SATS_TO_WEI_MULTIPLIER: u64 = 10_000_000_000;
const UTXOS_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000007");
const DEPOSIT_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000008");

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    BRIDGE_CONTRACT,
    "../scripts/Bridge.json"
);

#[async_trait]
pub trait CitreaClientT: Send + Sync + Debug + Clone + 'static {
    /// # Parameters
    ///
    /// - `citrea_rpc_url`: URL of the Citrea RPC.
    /// - `light_client_prover_url`: URL of the Citrea light client prover RPC.
    /// - `chain_id`: Citrea's EVM chain id.
    /// - `secret_key`: EVM secret key of the EVM user. If not given, random
    ///   secret key is used (wallet is not required). This is given mostly for
    ///   testing purposes.
    async fn new(
        citrea_rpc_url: String,
        light_client_prover_url: String,
        chain_id: u32,
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
    ) -> Result<Option<(LightClientProof, Receipt, u64)>, BridgeError>;

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
    ) -> Result<Vec<(u32, Txid)>, BridgeError>;

    async fn check_nofn_correctness(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
    ) -> Result<(), BridgeError>;

    async fn get_storage_proof(
        &self,
        l2_height: u64,
        deposit_index: u32,
    ) -> Result<StorageProof, BridgeError>;

    /// Updates the nofn aggregated key in the Citrea contract.
    ///
    /// # Parameters
    ///
    /// - `nofn_xonly_pk`: The new nofn aggregated key.
    /// - `paramset`: The protocol paramset.
    #[cfg(test)]
    async fn update_nofn_aggregated_key(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
        paramset: &'static crate::config::protocol::ProtocolParamset,
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
    /// Fetches the storage proof for a given deposit index and transaction ID.
    ///
    /// This function interacts with an Citrea RPC endpoint to retrieve a storage proof,
    /// which includes proof details for both the UTXO and the deposit index.
    ///
    /// # Arguments
    /// * `l2_height` - A `u64` representing the L2 block height.
    /// * `deposit_index` - A `u32` representing the deposit index.
    ///
    /// # Returns
    /// Returns a `StorageProof` struct containing serialized storage proofs for the UTXO and deposit index.
    async fn get_storage_proof(
        &self,
        l2_height: u64,
        deposit_index: u32,
    ) -> Result<StorageProof, BridgeError> {
        let ind = deposit_index;
        let tx_index: u32 = ind * 2;

        let storage_address_wd_utxo_bytes = keccak256(UTXOS_STORAGE_INDEX);
        let storage_address_wd_utxo: U256 = U256::from_be_bytes(
            <[u8; 32]>::try_from(&storage_address_wd_utxo_bytes[..])
                .wrap_err("Storage address wd utxo bytes slice with incorrect length")?,
        );

        // Storage key address calculation UTXO
        let storage_key_wd_utxo: U256 = storage_address_wd_utxo + U256::from(tx_index);
        let storage_key_wd_utxo_hex =
            format!("0x{}", hex::encode(storage_key_wd_utxo.to_be_bytes::<32>()));

        // Storage key address calculation Vout
        let storage_key_vout: U256 = storage_address_wd_utxo + U256::from(tx_index + 1);
        let storage_key_vout_hex =
            format!("0x{}", hex::encode(storage_key_vout.to_be_bytes::<32>()));

        // Storage key address calculation Deposit
        let storage_address_deposit_bytes = keccak256(DEPOSIT_STORAGE_INDEX);
        let storage_address_deposit: U256 = U256::from_be_bytes(
            <[u8; 32]>::try_from(&storage_address_deposit_bytes[..])
                .wrap_err("Storage address deposit bytes slice with incorrect length")?,
        );

        let storage_key_deposit: U256 = storage_address_deposit + U256::from(deposit_index);
        let storage_key_deposit_hex = hex::encode(storage_key_deposit.to_be_bytes::<32>());
        let storage_key_deposit_hex = format!("0x{}", storage_key_deposit_hex);

        let response: serde_json::Value = self
            .client
            .get_proof(
                BRIDGE_CONTRACT_ADDRESS,
                vec![
                    storage_key_wd_utxo_hex,
                    storage_key_vout_hex,
                    storage_key_deposit_hex,
                ],
                format!("0x{:x}", l2_height),
            )
            .await
            .wrap_err("Failed to get storage proof from rpc")?;

        let response: EIP1186AccountProofResponse = serde_json::from_value(response)
            .wrap_err("Failed to deserialize EIP1186AccountProofResponse")?;

        // It does not seem possible to get a storage proof with less than 3 items. But still
        // we check it to avoid panics.
        if response.storage_proof.len() < 3 {
            return Err(eyre::eyre!(
                "Expected at least 3 storage proofs, got {}",
                response.storage_proof.len()
            )
            .into());
        }

        let serialized_utxo = serde_json::to_string(&response.storage_proof[0])
            .wrap_err("Failed to serialize storage proof utxo")?;

        let serialized_vout = serde_json::to_string(&response.storage_proof[1])
            .wrap_err("Failed to serialize storage proof vout")?;

        let serialized_deposit = serde_json::to_string(&response.storage_proof[2])
            .wrap_err("Failed to serialize storage proof deposit")?;

        Ok(StorageProof {
            storage_proof_utxo: serialized_utxo,
            storage_proof_vout: serialized_vout,
            storage_proof_deposit_txid: serialized_deposit,
            index: ind,
        })
    }

    async fn new(
        citrea_rpc_url: String,
        light_client_prover_url: String,
        chain_id: u32,
        secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self, BridgeError> {
        let citrea_rpc_url = Url::parse(&citrea_rpc_url).wrap_err("Can't parse Citrea RPC URL")?;
        let light_client_prover_url =
            Url::parse(&light_client_prover_url).wrap_err("Can't parse Citrea LCP RPC URL")?;
        let secret_key = secret_key.unwrap_or(PrivateKeySigner::random());

        let key = secret_key.with_chain_id(Some(chain_id.into()));
        let wallet_address = key.address();

        tracing::info!("Wallet address: {}", wallet_address);

        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(key))
            .on_http(citrea_rpc_url.clone());

        tracing::info!("Provider created");

        let contract = BRIDGE_CONTRACT::new(
            BRIDGE_CONTRACT_ADDRESS
                .parse()
                .expect("Correct contract address"),
            provider,
        );

        tracing::info!("Contract created");

        let client = HttpClientBuilder::default()
            .build(citrea_rpc_url)
            .wrap_err("Failed to create Citrea RPC client")?;

        tracing::info!("Citrea RPC client created");

        let light_client_prover_client = HttpClientBuilder::default()
            .build(light_client_prover_url)
            .wrap_err("Failed to create Citrea LCP RPC client")?;

        tracing::info!("Citrea LCP RPC client created");

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
                tracing::trace!(
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
            let vout = u32::from_le_bytes(vout);
            let utxo = OutPoint { txid, vout };
            utxos.push((start_idx as u64, utxo));
            start_idx += 1;
        }
        Ok(utxos)
    }

    async fn get_light_client_proof(
        &self,
        l1_height: u64,
    ) -> Result<Option<(LightClientProof, Receipt, u64)>, BridgeError> {
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
            let decoded: InnerReceipt = bincode::deserialize(&proof_result.proof)
                .wrap_err("Failed to deserialize light client proof from citrea lcp")?;
            let receipt = receipt_from_inner(decoded)
                .wrap_err("Failed to create receipt from light client proof")?;

            let l2_height = u64::try_from(proof_result.light_client_proof_output.last_l2_height)
                .wrap_err("Failed to convert l2 height to u64")?;
            let hex_l2_str = format!("0x{:x}", l2_height);

            Some((
                LightClientProof {
                    lc_journal: receipt.journal.bytes.clone(),
                    l2_height: hex_l2_str,
                },
                receipt,
                l2_height,
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

        let l2_height_end: u64 = proof_current.2;
        let l2_height_start: u64 = proof_previous.2;

        Ok((l2_height_start, l2_height_end))
    }

    async fn get_replacement_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u32, Txid)>, BridgeError> {
        let mut replacement_move_txids = vec![];

        // get logs
        let filter = self.contract.event_filter::<DepositReplaced>().filter;
        let logs = self.get_logs(filter, from_height, to_height).await?;

        for log in logs {
            let replacement_raw_data = &log.data().data;

            let idx = DepositReplaced::abi_decode_data(replacement_raw_data, false)
                .wrap_err("Failed to decode replacement deposit data")?
                .0;
            let new_move_txid = DepositReplaced::abi_decode_data(replacement_raw_data, false)
                .wrap_err("Failed to decode replacement deposit data")?
                .2;

            let idx = u32::try_from(idx).wrap_err("Failed to convert idx to u32")?;
            let new_move_txid = Txid::from_slice(new_move_txid.as_ref())
                .wrap_err("Failed to convert new move txid to Txid")?;

            replacement_move_txids.push((idx, new_move_txid));
        }

        Ok(replacement_move_txids)
    }

    async fn check_nofn_correctness(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        if std::env::var("DISABLE_NOFN_CHECK").is_ok() {
            return Ok(());
        }

        let contract_nofn_xonly_pk = self
            .contract
            .getAggregatedKey()
            .call()
            .await
            .wrap_err("Failed to get script prefix")?
            ._0;

        let contract_nofn_xonly_pk = XOnlyPublicKey::from_slice(contract_nofn_xonly_pk.as_ref())
            .wrap_err("Failed to convert citrea contract script nofn bytes to xonly pk")?;
        if contract_nofn_xonly_pk != nofn_xonly_pk {
            return Err(eyre::eyre!("Nofn of deposit does not match with citrea contract").into());
        }
        Ok(())
    }

    #[cfg(test)]
    async fn update_nofn_aggregated_key(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
        paramset: &'static crate::config::protocol::ProtocolParamset,
    ) -> Result<(), BridgeError> {
        use std::str::FromStr;

        use crate::deposit::{
            Actors, BaseDepositData, DepositData, DepositInfo, DepositType, SecurityCouncil,
        };
        use crate::EVMAddress;

        // create a dummy script with nofn xonly pk
        let dummy_evm_address: EVMAddress = EVMAddress(std::array::from_fn(|i| i as u8));
        let mut dummy_base_deposit_data = DepositData {
            nofn_xonly_pk: Some(nofn_xonly_pk),
            deposit: DepositInfo {
                deposit_outpoint: OutPoint::default(),
                deposit_type: DepositType::BaseDeposit(BaseDepositData {
                    evm_address: dummy_evm_address,
                    recovery_taproot_address: bitcoin::Address::from_str(
                        "bcrt1p65yp9q9fxtf7dyvthyrx26xxm2czanvrnh9rtvphmlsjvhdt4k6qw4pkss",
                    )
                    .unwrap(),
                }),
            },
            actors: Actors {
                verifiers: vec![],
                watchtowers: vec![],
                operators: vec![],
            },
            security_council: SecurityCouncil {
                pks: vec![],
                threshold: 0,
            },
        };

        let base_deposit_script =
            dummy_base_deposit_data.get_deposit_scripts(paramset)?[0].to_script_buf();
        tracing::warn!("Base deposit script: {:?}", base_deposit_script);

        let (deposit_prefix, deposit_suffix) =
            crate::deposit::extract_suffix_and_prefix_from_script(
                &base_deposit_script,
                &dummy_evm_address.0,
            );

        // self.contract
        //     .setDepositScript(depositPrefix, depositSuffix)
        //     .call()
        //     .await
        //     .wrap_err("Failed to update nofn aggregated key")?;

        // self.contract
        //     .setReplacementScript(replacementPrefix, replacementSuffix)
        //     .call()
        //     .await
        //     .wrap_err("Failed to update nofn aggregated key")?;

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

#[rpc(client, namespace = "eth")]
pub trait CitreaRpc {
    #[method(name = "getProof")]
    async fn get_proof(
        &self,
        address: &str,
        storage_keys: Vec<String>,
        block: String,
    ) -> RpcResult<serde_json::Value>;
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
