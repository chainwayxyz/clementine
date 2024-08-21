use crate::musig2::{MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce};
use crate::UTXO;
use crate::{errors::BridgeError, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, TxOut, Txid};
use jsonrpsee::proc_macros::rpc;
use secp256k1::schnorr;

#[rpc(client, server, namespace = "verifier")]
pub trait VerifierRpc {
    #[method(name = "new_deposit")]
    /// - Check deposit UTXO,
    /// - Generate random pubNonces, secNonces
    /// - Save pubNonces and secNonces to a in-memory db
    /// - Return pubNonces
    async fn new_deposit_rpc(
        &self,
        deposit_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<Vec<MuSigPubNonce>, BridgeError>;

    #[method(name = "operator_kickoffs_generated")]
    /// - Check the kickoff_utxos
    /// - for every kickoff_utxo, calculate kickoff2_tx
    /// - for every kickoff2_tx, partial sign burn_tx (ommitted for now)
    /// - return MuSigPartialSignature of sign(kickoff2_txids)
    async fn operator_kickoffs_generated_rpc(
        &self,
        deposit_utxo: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        operators_kickoff_sigs: Vec<schnorr::Signature>,
        agg_nonces: Vec<MuSigAggNonce>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError>;

    #[method(name = "burn_txs_signed")]
    /// verify burn txs are signed by verifiers
    /// sign operator_takes_txs
    async fn burn_txs_signed_rpc(
        &self,
        deposit_utxo: OutPoint,
        burn_sigs: Vec<schnorr::Signature>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError>;

    // operator_take_txs_signed
    #[method(name = "operator_take_txs_signed")]
    /// verify the operator_take_sigs
    /// sign move_tx
    async fn operator_take_txs_signed_rpc(
        &self,
        deposit_utxo: OutPoint,
        operator_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<(MuSigPartialSignature, MuSigPartialSignature), BridgeError>;
}

#[rpc(client, server, namespace = "operator")]
pub trait OperatorRpc {
    #[method(name = "new_deposit")]
    /// - Create kickoffUTXO, make sure to not send it to bitcoin yet
    async fn new_deposit_rpc(
        &self,
        deposit_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(UTXO, secp256k1::schnorr::Signature), BridgeError>;

    #[method(name = "set_operator_funding_utxo")]
    async fn set_operator_funding_utxo_rpc(&self, funding_utxo: UTXO) -> Result<(), BridgeError>;

    #[method(name = "new_withdrawal_sig")]
    /// Gets the withdrawal utxo from citrea,
    /// checks wheter sig is for a correct withdrawal from citrea,
    /// checks the signature, calls is_profitable, if is profitable pays the withdrawal,
    /// adds it to flow, when its finalized, proves on citrea, sends kickoff2
    async fn new_withdrawal_sig_rpc(
        &self,
        withdrawal_idx: usize,
        user_sig: schnorr::Signature,
        input_utxo: UTXO,
        output_txout: TxOut,
    ) -> Result<Option<Txid>, BridgeError>;

    #[method(name = "withdrawal_proved_on_citrea")]
    async fn withdrawal_proved_on_citrea_rpc(&self, withdrawal_idx: usize) -> Result<(), BridgeError>;

    #[method(name = "operator_take_sendable")]
    async fn operator_take_sendable_rpc(&self, withdrawal_idx: usize) -> Result<(), BridgeError>;
}
