use crate::musig2::{MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce};
use crate::UTXO;
use crate::{errors::BridgeError, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, TxOut, Txid};
use jsonrpsee::proc_macros::rpc;
use secp256k1::schnorr;

#[rpc(client, server, namespace = "operator")]
pub trait OperatorRpc {
    #[method(name = "new_deposit")]
    /// - Create kickoffUTXO, make sure to not send it to bitcoin yet
    async fn new_deposit_rpc(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(UTXO, secp256k1::schnorr::Signature), BridgeError>;

    #[method(name = "set_funding_utxo")]
    async fn set_funding_utxo_rpc(&self, funding_utxo: UTXO) -> Result<(), BridgeError>;

    #[method(name = "new_withdrawal_sig")]
    /// Gets the withdrawal utxo from citrea,
    /// checks wheter sig is for a correct withdrawal from citrea,
    /// checks the signature, calls is_profitable, if is profitable pays the withdrawal,
    /// adds it to flow, when its finalized, proves on citrea, sends kickoff2
    async fn new_withdrawal_sig_rpc(
        &self,
        withdrawal_idx: u32,
        user_sig: schnorr::Signature,
        input_utxo: UTXO,
        output_txout: TxOut,
    ) -> Result<Txid, BridgeError>;

    #[method(name = "withdrawal_proved_on_citrea")]
    /// 1- Calculate move_txid, check if the withdrawal idx matches the move_txid
    /// 2- Check if it is really proved on citrea
    /// 3- If it is, send operator_take_txs
    async fn withdrawal_proved_on_citrea_rpc(
        &self,
        withdrawal_idx: u32,
        deposit_outpoint: OutPoint,
    ) -> Result<Vec<String>, BridgeError>;

    // #[method(name = "operator_take_sendable")]
    // async fn operator_take_sendable_rpc(&self, withdrawal_idx: usize) -> Result<(), BridgeError>;
}

#[rpc(client, server, namespace = "aggregator")]
pub trait Aggregator {
    #[method(name = "aggregate_pub_nonces")]
    async fn aggregate_pub_nonces_rpc(
        &self,
        pub_nonces: Vec<Vec<MuSigPubNonce>>,
    ) -> Result<Vec<MuSigAggNonce>, BridgeError>;

    #[method(name = "aggregate_slash_or_take_sigs")]
    async fn aggregate_slash_or_take_sigs_rpc(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError>;

    #[method(name = "aggregate_operator_take_sigs")]
    async fn aggregate_operator_take_sigs_rpc(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError>;

    #[method(name = "aggregate_move_tx_sigs")]
    async fn aggregate_move_tx_sigs_rpc(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        agg_nonce: MuSigAggNonce,
        partial_sigs: Vec<MuSigPartialSignature>,
    ) -> Result<(String, Txid), BridgeError>;
}
