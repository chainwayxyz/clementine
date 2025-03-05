//! # Citrea Related Utilities

use crate::errors::BridgeError;
use alloy::{
    network::EthereumWallet,
    primitives::U256,
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        ProviderBuilder, RootProvider,
    },
    signers::{local::PrivateKeySigner, Signer},
    sol,
    transports::http::reqwest::Url,
};
use bitcoin::{hashes::Hash, OutPoint, Txid};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};

pub const CITREA_CHAIN_ID: u64 = 5655;
pub const LIGHT_CLIENT_ADDRESS: &str = "0x3100000000000000000000000000000000000001";
pub const BRIDGE_CONTRACT_ADDRESS: &str = "0x3100000000000000000000000000000000000002";
pub const SATS_TO_WEI_MULTIPLIER: u64 = 10_000_000_000;

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    BRIDGE_CONTRACT,
    "src/Bridge.json"
);

// Ugly typedefs.
type Contract = BRIDGE_CONTRACT::BRIDGE_CONTRACTInstance<
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
type Provider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

/// Citrea client is responsible for creating contracts, interacting with the
/// EVM and Citrea RPC.
#[derive(Clone, Debug)]
pub struct CitreaClient {
    pub client: HttpClient,
    pub wallet_address: alloy::primitives::Address,
    pub provider: Provider,
    pub contract: Contract,
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

    /// Fetches an UTXO from Citrea for the given withdrawal with the index.
    ///
    /// # Parameters
    ///
    /// - `provider`: Provider to interact with the Ethereum network.
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

    /// Returns light client proof for the given L1 height.
    pub async fn get_light_client_proof(&self) -> Result<([u8; 32], u64), BridgeError> {
        let params = rpc_params!["1"];

        let response: String = self
            .client
            .request("lightClientProver_getLightClientProofByL1Height", params)
            .await?;
        println!("response {:?}", response);

        // Dummy values for now.
        Ok(([0; 32], 0))
    }
}
