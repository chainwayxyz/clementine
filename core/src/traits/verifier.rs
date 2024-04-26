use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint};
use secp256k1::XOnlyPublicKey;

use crate::{errors::BridgeError, operator::DepositPresigns, EVMAddress};

use jsonrpsee::proc_macros::rpc;

#[rpc(client, server, namespace = "verifier")]
pub trait VerifierRpc {
    #[method(name = "new_deposit")]
    async fn new_deposit_rpc(
        &self,
        start_utxo: OutPoint,
        return_address: XOnlyPublicKey,
        deposit_index: u32,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
    ) -> Result<DepositPresigns, BridgeError>;
}


#[rpc(server, namespace = "operator")]
pub trait OperatorRpc {
    #[method(name = "new_deposit")]
    async fn new_deposit_rpc(
        &self,
        start_utxo: OutPoint,
        return_address: XOnlyPublicKey,
        evm_address: EVMAddress,
    ) -> Result<OutPoint, BridgeError>;
}
