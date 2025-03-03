//! # Citrea Related Utilities

use crate::errors::BridgeError;
use alloy::{primitives::U256, sol};
use bitcoin::{hashes::Hash, OutPoint, Txid};

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
pub async fn withdrawal_utxos<T, P>(
    provider: P,
    withdrawal_index: u64,
) -> Result<OutPoint, BridgeError>
where
    P: alloy::contract::private::Provider<T, alloy::network::Ethereum>,
    T: alloy::contract::private::Transport + Clone,
{
    let contract = BRIDGE_CONTRACT::new(
        BRIDGE_CONTRACT_ADDRESS.parse().map_err(|e| {
            BridgeError::Error(format!("Can't create bridge contract address {:?}", e))
        })?,
        provider,
    );

    let withdrawal_utxo = contract
        .withdrawalUTXOs(U256::from(withdrawal_index))
        .call()
        .await?;

    let txid = withdrawal_utxo.txId.0;
    let txid = Txid::from_slice(txid.as_slice())?;

    let vout = withdrawal_utxo.outputId.0;
    let vout = u32::from_be_bytes(vout);

    Ok(OutPoint { txid, vout })
}
