use crate::{errors::BridgeError, operator::DepositPresigns, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use jsonrpsee::proc_macros::rpc;
use secp256k1::schnorr;

/// This trait defines non-functional interfaces for RPC interfaces, like
/// `new()`.
pub trait RpcApiWrapper: RpcApi + std::marker::Sync + std::marker::Send + 'static {
    fn new(url: &str, auth: Auth) -> bitcoincore_rpc::Result<Self>;
}

/// Compatibility implementation for `bitcoincore_rpc::Client`.
impl RpcApiWrapper for Client {
    fn new(url: &str, auth: Auth) -> bitcoincore_rpc::Result<Self> {
        Client::new(url, auth)
    }
}

#[rpc(client, server, namespace = "verifier")]
pub trait VerifierRpc {
    #[method(name = "new_deposit")]
    async fn new_deposit_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        deposit_index: u32,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
    ) -> Result<DepositPresigns, BridgeError>;
    #[method(name = "new_withdrawal")]
    async fn new_withdrawal_direct_rpc(
        &self,
        withdrawal_idx: usize,
        bridge_fund_txid: Txid,
        withdrawal_address: Address<NetworkUnchecked>,
    ) -> Result<schnorr::Signature, BridgeError>;
}

#[rpc(client, server, namespace = "operator")]
pub trait OperatorRpc {
    #[method(name = "new_deposit")]
    async fn new_deposit_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<Txid, BridgeError>;

    #[method(name = "new_withdrawal")]
    async fn new_withdrawal_direct_rpc(
        &self,
        idx: usize,
        withdrawal_address: Address<NetworkUnchecked>,
    ) -> Result<Txid, BridgeError>;
}
