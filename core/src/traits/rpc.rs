use crate::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce};
use crate::PsbtOutPoint;
use crate::{errors::BridgeError, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint};
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
    ) -> Result<Vec<MusigPubNonce>, BridgeError>;

    #[method(name = "operator_kickoffs_generated")]
    /// - Check the kickoff_utxos
    /// - for every kickoff_utxo, calculate kickoff2_tx
    /// - for every kickoff2_tx, partial sign burn_tx (ommitted for now)
    /// - return MusigPartialSignature of sign(kickoff2_txids)
    async fn operator_kickoffs_generated_rpc(
        &self,
        kickoff_utxos: Vec<PsbtOutPoint>,
        agg_nonces: Vec<MusigAggNonce>,
    ) -> Result<MusigPartialSignature, BridgeError>;

    #[method(name = "burn_txs_signed")]
    /// verify burn txs are signed by verifiers
    /// sign operator_takes_txs
    async fn burn_txs_signed_rpc(
        &self,
        burn_sigs: Vec<schnorr::Signature>,
    ) -> Result<Vec<MusigPartialSignature>, BridgeError>;

    // operator_take_txs_signed
    #[method(name = "operator_take_txs_signed")]
    /// verify the operator_take_sigs
    /// sign move_tx
    async fn operator_take_txs_signed_rpc(
        &self,
        operator_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<MusigPartialSignature, BridgeError>;
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
    ) -> Result<PsbtOutPoint, BridgeError>;

    #[method(name = "set_operator_funding_utxo")]
    async fn set_operator_funding_utxo_rpc(
        &self,
        funding_utxo: OutPoint,
    ) -> Result<(), BridgeError>;

    // #[method(name = "new_withdrawal_sig")]
    // /// Gets the withdrawal utxo from citrea,
    // /// checks wheter sig is for a correct withdrawal from citrea,
    // /// checks the signature, calls is_profitable, if is profitable pays the withdrawal,
    // /// adds it to flow, when its finalized, proves on citrea, sends kickoff2
    // async fn new_withdrawal_sig_rpc(
    //     &self,
    //     withdrawal_idx: usize,
    //     alice_sig: schnorr::Signature,
    // ) -> Result<Txid, BridgeError>;
}
