use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, Txid};
use secp256k1::schnorr;

use crate::operator::{AggNonces, DepositPubNonces};
use crate::ByteArray66;
use crate::{errors::BridgeError, operator::DepositPresigns, EVMAddress};

use jsonrpsee::proc_macros::rpc;

#[rpc(client, server, namespace = "verifier")]
pub trait VerifierRpc {
    #[method(name = "new_deposit_first_round")]
    async fn new_deposit_first_round_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
    ) -> Result<DepositPubNonces, BridgeError>;
    #[method(name = "new_deposit_second_round")]
    async fn new_deposit_second_round_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
        aggregated_nonces: AggNonces,
    ) -> Result<DepositPresigns, BridgeError>;
    #[method(name = "new_withdrawal_first_round")]
    async fn new_withdrawal_first_round_rpc(
        &self,
        withdrawal_idx: usize,
        withdrawal_address: Address<NetworkUnchecked>,
    ) -> Result<ByteArray66, BridgeError>;
    #[method(name = "new_withdrawal_second_round")]
    async fn new_withdrawal_second_round_rpc(
        &self,
        withdrawal_idx: usize,
        withdrawal_address: Address<NetworkUnchecked>,
        aggregated_nonce: ByteArray66,
    ) -> Result<[u8; 32], BridgeError>;
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
