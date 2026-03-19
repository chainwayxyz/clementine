//! JSON-RPC client for the tx-sender service.

use jsonrpsee::core::client::ClientT as _;
use jsonrpsee::core::client::Error as JsonRpcError;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;

#[cfg(feature = "clementine")]
use bitcoin::{consensus, Transaction};
#[cfg(feature = "citrea")]
pub use tx_sender_types::citrea::InsertCitreaRawTxParams;
#[cfg(feature = "citrea")]
pub use tx_sender_types::CitreaTxRequest;
#[cfg(feature = "clementine")]
pub use tx_sender_types::{
    ActivatedWithTxid, FeePayingType, InsertTryToSendParams, RbfSigningInfo, RbfSigningSpendPath,
    TxMetadata,
};
pub use tx_sender_types::{
    ActivationBlocker, ActivationBlockerReason, ActivationState, BitcoinTxStatus,
    CitreaRevealStatus, CitreaStatus, CitreaTxKind, SubmissionStatus, TrackRequest,
    TrackResponse, TrackStatus,
};

#[derive(Debug, Clone)]
pub struct JsonRpcTxSenderClient {
    inner: HttpClient,
}

impl JsonRpcTxSenderClient {
    pub fn new(url: &str) -> Result<Self, JsonRpcError> {
        let inner = HttpClientBuilder::default().build(url)?;
        Ok(Self { inner })
    }

    #[cfg(feature = "clementine")]
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_try_to_send(
        &self,
        tx_metadata: Option<TxMetadata>,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        rbf_signing_info: Option<RbfSigningInfo>,
        activate_txids: &[ActivatedWithTxid],
    ) -> Result<u32, JsonRpcError> {
        let signed_tx_hex = consensus::encode::serialize_hex(signed_tx);

        let req = InsertTryToSendParams {
            tx_metadata,
            signed_tx_hex,
            fee_paying_type,
            rbf_signing_info,
            activate_txids: activate_txids.to_vec(),
        };

        self.inner
            .request::<u32, _>("send_tx", rpc_params![req])
            .await
    }

    /// Citrea-only RPC to submit a DA payload described by `CitreaTxRequest`.
    ///
    /// When the `citrea` feature is enabled on this crate, the JSON-RPC server exposes the
    /// `send_citrea_raw_tx` method which expects a single `InsertCitreaRawTxParams` argument.
    /// This helper takes a strongly-typed `CitreaTxRequest` and forwards it to that method.
    #[cfg(feature = "citrea")]
    pub async fn send_citrea_tx(
        &self,
        citrea_tx_request: CitreaTxRequest,
    ) -> Result<i64, JsonRpcError> {
        let req = InsertCitreaRawTxParams { citrea_tx_request };

        self.inner
            .request::<i64, _>("send_citrea_tx", rpc_params![req])
            .await
    }

    pub async fn track_tx(&self, request: TrackRequest) -> Result<TrackResponse, JsonRpcError> {
        self.inner
            .request::<TrackResponse, _>("track_tx", rpc_params![request])
            .await
    }
}
