use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, TxOut, Txid};
use secp256k1::schnorr;

use crate::{errors::BridgeError, operator::DepositPresigns, EVMAddress};

use jsonrpsee::proc_macros::rpc;

#[rpc(client, server, namespace = "verifier")]
pub trait VerifierRpc {
    #[method(name = "new_deposit")]
    async fn new_deposit_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_address: Address<NetworkUnchecked>,
        deposit_index: u32,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
    ) -> Result<DepositPresigns, BridgeError>;
    #[method(name = "new_withdrawal")]
    async fn new_withdrawal_direct_rpc(
        &self,
        deposit_utxo: OutPoint,
        bridge_txout: TxOut,
        withdrawal_address: Address<NetworkUnchecked>,
    ) -> Result<schnorr::Signature, BridgeError>;
}

#[rpc(client, server, namespace = "operator")]
pub trait OperatorRpc {
    #[method(name = "new_deposit")]
    async fn new_deposit_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<Txid, BridgeError>;

    #[method(name = "new_withdrawal")]
    async fn new_withdrawal_direct_rpc(
        &self,
        idx: usize,
        withdrawal_address: Address<NetworkUnchecked>,
    ) -> Result<Txid, BridgeError>;
}
