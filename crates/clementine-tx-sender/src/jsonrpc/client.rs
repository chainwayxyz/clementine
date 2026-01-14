use bitcoin::{consensus, OutPoint, Transaction, Txid};
use clementine_errors::BridgeError;
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use jsonrpsee::core::client::ClientT as _;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;

use crate::{ActivatedWithOutpoint, ActivatedWithTxid};

use super::server::InsertTryToSendParams;

#[derive(Debug, Clone)]
pub struct JsonRpcTxSenderClient {
    inner: HttpClient,
}

impl JsonRpcTxSenderClient {
    pub fn new(url: &str) -> Result<Self, BridgeError> {
        let inner = HttpClientBuilder::default()
            .build(url)
            .map_err(|e| BridgeError::Eyre(e.into()))?;
        Ok(Self { inner })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_try_to_send(
        &self,
        tx_metadata: Option<TxMetadata>,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        rbf_signing_info: Option<RbfSigningInfo>,
        cancel_outpoints: &[OutPoint],
        cancel_txids: &[Txid],
        activate_txids: &[ActivatedWithTxid],
        activate_outpoints: &[ActivatedWithOutpoint],
    ) -> Result<u32, BridgeError> {
        let signed_tx_hex = consensus::encode::serialize_hex(signed_tx);

        let req = InsertTryToSendParams {
            tx_metadata,
            signed_tx_hex,
            fee_paying_type,
            rbf_signing_info,
            cancel_outpoints: cancel_outpoints.to_vec(),
            cancel_txids: cancel_txids.to_vec(),
            activate_txids: activate_txids.to_vec(),
            activate_outpoints: activate_outpoints.to_vec(),
        };

        self.inner
            .request::<u32, _>("send_tx", rpc_params![req])
            .await
            .map_err(|e| BridgeError::Eyre(e.into()))
    }
}
