use std::net::SocketAddr;

use bitcoin::consensus;
use bitcoin::{Transaction, Txid};
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{server::Server, RpcModule};
use serde::{Deserialize, Serialize};

use crate::client::TxSenderClient;
use crate::{ActivatedWithOutpoint, ActivatedWithTxid};
use clementine_errors::BridgeError;
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};

const JSONRPC_INTERNAL_ERROR_CODE: i32 = -32_000;

fn jsonrpc_err(message: impl ToString) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(JSONRPC_INTERNAL_ERROR_CODE, message.to_string(), None::<()>)
}

#[derive(Debug, Clone)]
pub struct TxSenderJsonRpcServer {
    handle: ServerHandle,
    local_addr: SocketAddr,
}

impl TxSenderJsonRpcServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(self) -> ServerHandle {
        self.handle
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertTryToSendParams {
    pub tx_metadata: Option<TxMetadata>,
    /// Signed tx encoded as hex.
    pub signed_tx_hex: String,
    pub fee_paying_type: FeePayingType,
    pub rbf_signing_info: Option<RbfSigningInfo>,
    pub cancel_outpoints: Vec<bitcoin::OutPoint>,
    pub cancel_txids: Vec<Txid>,
    pub activate_txids: Vec<ActivatedWithTxid>,
    pub activate_outpoints: Vec<ActivatedWithOutpoint>,
}

/// Starts a JSON-RPC server exposing only `send_tx`.
///
/// The method is transactional: it begins a DB transaction, calls
/// `TxSenderClient::insert_try_to_send`, and commits on success.
pub async fn start_jsonrpc_server(
    tx_sender_client: TxSenderClient,
    bind_addr: SocketAddr,
) -> Result<TxSenderJsonRpcServer, BridgeError> {
    let server: Server = ServerBuilder::default()
        .build(bind_addr)
        .await
        .map_err(|e| BridgeError::Eyre(e.into()))?;

    let local_addr = server
        .local_addr()
        .map_err(|e| BridgeError::Eyre(e.into()))?;

    let mut module = RpcModule::new(tx_sender_client.clone());
    module
        .register_async_method("send_tx", |params, client, _| async move {
            let req: InsertTryToSendParams = params.one().map_err(jsonrpc_err)?;

            let raw_tx = hex::decode(&req.signed_tx_hex).map_err(jsonrpc_err)?;
            let signed_tx: Transaction = consensus::deserialize(&raw_tx).map_err(jsonrpc_err)?;

            let mut dbtx = client.db.begin_transaction().await.map_err(jsonrpc_err)?;

            let try_to_send_id = client
                .insert_try_to_send(
                    &mut dbtx,
                    req.tx_metadata,
                    &signed_tx,
                    req.fee_paying_type,
                    req.rbf_signing_info,
                    &req.cancel_outpoints,
                    &req.cancel_txids,
                    &req.activate_txids,
                    &req.activate_outpoints,
                )
                .await
                .map_err(jsonrpc_err)?;

            client
                .db
                .commit_transaction(dbtx)
                .await
                .map_err(jsonrpc_err)?;

            Ok::<u32, ErrorObjectOwned>(try_to_send_id)
        })
        .map_err(|e| BridgeError::Eyre(e.into()))?;

    let handle = server.start(module);

    Ok(TxSenderJsonRpcServer { handle, local_addr })
}
