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

#[cfg(feature = "citrea")]
use crate::citrea::RawTxData;

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

/// Parameters for inserting a Citrea DA transaction request.
#[cfg(feature = "citrea")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertCitreaRawTxParams {
    /// Opaque DA payload to be inscribed on Bitcoin.
    pub raw_tx_data: RawTxData,
}

/// Starts a JSON-RPC server exposing `send_tx` and `send_citrea_tx` methods.
/// `send_tx` and `send_citrea_tx` are transactional: it begins a DB transaction, calls
/// `TxSenderClient::insert_try_to_send` or `TxSenderClient::send_citrea_tx`, and commits on success.
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

    // Citrea-specific RPCs.
    #[cfg(feature = "citrea")]
    {
        module
            .register_async_method("send_citrea_tx", |params, client, _| async move {
                let req: InsertCitreaRawTxParams = params.one().map_err(jsonrpc_err)?;

                client
                    .send_citrea_tx(req.raw_tx_data)
                    .await
                    .map_err(jsonrpc_err)?;

                Ok::<(), ErrorObjectOwned>(())
            })
            .map_err(|e| BridgeError::Eyre(e.into()))?;
    }

    let handle = server.start(module);

    Ok(TxSenderJsonRpcServer { handle, local_addr })
}

#[cfg(test)]
mod tests {
    use crate::test_utils::create_test_environment;
    use crate::TxSenderDb;

    use super::*;

    #[tokio::test]
    async fn test_jsonrpc_txsender_insert_try_to_send() -> Result<(), BridgeError> {
        use std::time::{Duration, Instant};

        use crate::jsonrpc::client::JsonRpcTxSenderClient;
        use crate::task::spawn_txsender_loop_with_free_localhost_jsonrpc_port;
        use bitcoin::absolute;
        use bitcoin::hashes::Hash as _;
        use bitcoin::transaction::Version;
        use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

        let (config, db, rpc) = create_test_environment(true, true).await;
        let rpc = rpc.unwrap();
        let db = db.unwrap();
        rpc.rpc().mine_blocks(1).await.unwrap();

        // Start standalone txsender with JSON-RPC enabled on a free port.
        let tx_sender_cfg = config.clone();
        let (addr, handle) = spawn_txsender_loop_with_free_localhost_jsonrpc_port(tx_sender_cfg);
        let url = format!("http://{addr}");
        let client = JsonRpcTxSenderClient::new(&url)?;

        // A minimal syntactically-valid transaction (doesn't need to be mineable for enqueueing).
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // Wait for server to come up (spawn loop initializes asynchronously).
        let start = Instant::now();
        let try_to_send_id = loop {
            match client
                .insert_try_to_send(None, &tx, FeePayingType::CPFP, None, &[], &[], &[], &[])
                .await
            {
                Ok(id) => break id,
                Err(e) => {
                    if start.elapsed() > Duration::from_secs(10) {
                        return Err(BridgeError::Eyre(eyre::eyre!(
                            "Timed out waiting for txsender JSON-RPC to start: {e:?}"
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };

        // Verify persisted in DB.
        let tx_sender_db = TxSenderDb::from_pool(db.pool().clone());
        let (_meta, stored_tx, fee_paying_type, _seen_at_height, _rbf) = tx_sender_db
            .get_try_to_send_tx(None, try_to_send_id)
            .await?;
        assert_eq!(fee_paying_type, FeePayingType::CPFP);
        assert_eq!(stored_tx.compute_txid(), tx.compute_txid());

        // Stop background loop.
        handle.abort();
        let _ = handle.await;

        Ok(())
    }
}
