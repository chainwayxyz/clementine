//! # Citrea Related Utilities

use crate::errors::BridgeError;
use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    primitives::{Uint, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Provider, ProviderBuilder, RootProvider,
    },
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::SolEvent,
    transports::http::reqwest::Url,
};
use bitcoin::{hashes::Hash, OutPoint, Txid};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::proc_macros::rpc;
use BRIDGE_CONTRACT::{Deposit, Withdrawal};

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
    "src/Bridge.json"
);

/// Citrea client is responsible for creating contracts, interacting with the
/// EVM and Citrea RPC.
#[derive(Clone, Debug)]
pub struct CitreaClient {
    pub client: HttpClient,
    pub wallet_address: alloy::primitives::Address,
    pub provider: CitreaProvider,
    pub contract: CitreaContract,
}

impl CitreaClient {
    /// # Parameters
    ///
    /// - `citrea_rpc_url`: URL of the Citrea RPC.
    /// - `secret_key`: Etherium secret key of the EVM user. If not give, dummy
    ///   secret key is used (wallet is not required).
    pub fn new(citrea_rpc_url: Url, secret_key: Option<String>) -> Result<Self, BridgeError> {
        let secret_key = secret_key.unwrap_or(["01"; 32].concat());

        let key = secret_key
            .parse::<PrivateKeySigner>()
            .map_err(|e| BridgeError::Error(format!("Can't parse secret key: {:?}", e)))?
            .with_chain_id(Some(CITREA_CHAIN_ID));
        let wallet_address = key.address();

        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(key))
            .on_http(citrea_rpc_url.clone());

        let contract = BRIDGE_CONTRACT::new(
            BRIDGE_CONTRACT_ADDRESS.parse().map_err(|e| {
                BridgeError::Error(format!("Can't create bridge contract address {:?}", e))
            })?,
            provider.clone(),
        );

        let client = HttpClientBuilder::default().build(citrea_rpc_url)?;

        Ok(CitreaClient {
            client,
            wallet_address,
            provider,
            contract,
        })
    }

    /// Fetches an UTXO from Citrea for the given withdrawal index.
    ///
    /// # Parameters
    ///
    /// - `withdrawal_index`: Index of the withdrawal.
    ///
    /// # Returns
    ///
    /// - [`OutPoint`]: UTXO for the given withdrawal.
    pub async fn withdrawal_utxos(&self, withdrawal_index: u64) -> Result<OutPoint, BridgeError> {
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

    /// Returns deposit move txids with index for a block.
    pub async fn collect_deposit_move_txids(
        &self,
        height: u64,
    ) -> Result<Vec<(Uint<256, 4>, Txid)>, BridgeError> {
        let filter = self.contract.event_filter::<Deposit>().filter;
        let filter = filter.from_block(BlockNumberOrTag::Number(height));
        let filter = filter.to_block(BlockNumberOrTag::Number(height));
        let logs = self.provider.get_logs(&filter).await?;

        let mut move_txids = vec![];
        for log in logs {
            let deposit_raw_data = log.data().clone().data.clone();

            let deposit_index = Withdrawal::abi_decode_data(&deposit_raw_data, false)?.1;

            let move_txid = Deposit::abi_decode_data(deposit_raw_data.as_ref(), false)?.1;
            let move_txid = Txid::from_slice(move_txid.as_slice())?;

            move_txids.push((deposit_index, move_txid));
        }

        Ok(move_txids)
    }

    /// Returns withdrawal utxos with index for a block.
    pub async fn collect_withdrawal_utxos(
        &self,
        height: u64,
    ) -> Result<Vec<(Uint<256, 4>, OutPoint)>, BridgeError> {
        let filter = self.contract.event_filter::<Withdrawal>().filter;
        let filter = filter.from_block(BlockNumberOrTag::Number(height));
        let filter = filter.to_block(BlockNumberOrTag::Number(height));
        let logs = self.provider.get_logs(&filter).await?;

        let mut utxos = vec![];
        for log in logs {
            let withdrawal_raw_data = log.data().clone().data.clone();

            let withdrawal_index = Withdrawal::abi_decode_data(&withdrawal_raw_data, false)?.1;

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
type CitreaProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;
