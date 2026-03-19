use std::net::SocketAddr;

use bitcoin::consensus;
use bitcoin::Transaction;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{server::Server, RpcModule};

use crate::{TxSenderClient, TxSenderTracker};
use clementine_errors::BridgeError;
use tx_sender_types::clementine::InsertTryToSendParams;
use tx_sender_types::tracking::{TrackRequest, TrackResponse};

#[cfg(feature = "citrea")]
use tx_sender_types::citrea::InsertCitreaRawTxParams;

const JSONRPC_INTERNAL_ERROR_CODE: i32 = -32_000;

fn jsonrpc_err(message: impl ToString) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(JSONRPC_INTERNAL_ERROR_CODE, message.to_string(), None::<()>)
}

#[derive(Debug, Clone)]
pub struct TxSenderJsonRpcServer {
    handle: ServerHandle,
    local_addr: SocketAddr,
}

#[derive(Clone)]
struct JsonRpcContext {
    client: TxSenderClient,
    tracker: TxSenderTracker,
}

impl TxSenderJsonRpcServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(self) -> ServerHandle {
        self.handle
    }
}

/// Starts a JSON-RPC server exposing `send_tx` and `send_citrea_tx` methods.
/// `send_tx` and `send_citrea_tx` are transactional: it begins a DB transaction, calls
/// `TxSenderClient::insert_try_to_send` or `TxSenderClient::send_citrea_tx`, and commits on success.
pub async fn start_jsonrpc_server(
    client: TxSenderClient,
    tracker: TxSenderTracker,
    bind_addr: SocketAddr,
) -> Result<TxSenderJsonRpcServer, BridgeError> {
    let server: Server = ServerBuilder::default()
        .max_request_body_size(10 * 1024 * 1024) // 10 MB
        .build(bind_addr)
        .await
        .map_err(|e| BridgeError::Eyre(e.into()))?;

    let local_addr = server
        .local_addr()
        .map_err(|e| BridgeError::Eyre(e.into()))?;

    let mut module = RpcModule::new(JsonRpcContext { client, tracker });
    module
        .register_async_method("send_tx", |params, ctx, _| async move {
            let req: InsertTryToSendParams = params.one().map_err(jsonrpc_err)?;

            let raw_tx = hex::decode(&req.signed_tx_hex).map_err(jsonrpc_err)?;
            let signed_tx: Transaction = consensus::deserialize(&raw_tx).map_err(jsonrpc_err)?;

            let mut dbtx = ctx
                .client
                .db
                .begin_transaction()
                .await
                .map_err(jsonrpc_err)?;

            let try_to_send_id = ctx
                .client
                .insert_try_to_send(
                    &mut dbtx,
                    req.tx_metadata,
                    &signed_tx,
                    req.fee_paying_type,
                    req.rbf_signing_info,
                    &req.activate_txids,
                )
                .await
                .map_err(jsonrpc_err)?;

            ctx.client
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
            .register_async_method("send_citrea_tx", |params, ctx, _| async move {
                let req: InsertCitreaRawTxParams = params.one().map_err(jsonrpc_err)?;

                let insertion_id = ctx
                    .client
                    .send_citrea_tx(req.citrea_tx_request)
                    .await
                    .map_err(jsonrpc_err)?;

                Ok::<i64, ErrorObjectOwned>(insertion_id)
            })
            .map_err(|e| BridgeError::Eyre(e.into()))?;
    }

    module
        .register_async_method("track_tx", |params, ctx, _| async move {
            let req: TrackRequest = params.one().map_err(jsonrpc_err)?;
            let response: TrackResponse =
                ctx.tracker.track_request(req).await.map_err(jsonrpc_err)?;
            Ok::<TrackResponse, ErrorObjectOwned>(response)
        })
        .map_err(|e| BridgeError::Eyre(e.into()))?;

    let handle = server.start(module);

    Ok(TxSenderJsonRpcServer { handle, local_addr })
}

#[cfg(test)]
mod tests {
    use crate::test_utils::create_test_environment;
    use crate::TxSenderDb;
    use bitcoin::absolute;
    use bitcoin::hashes::Hash as _;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use clementine_utils::FeePayingType;
    use tx_sender_types::{
        ActivationBlockerReason, ActivationState, TrackRequest, TrackResponse, TrackStatus,
    };

    use super::*;

    fn make_test_tx(input_vout: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: input_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[tokio::test]
    async fn test_jsonrpc_txsender_insert_try_to_send() -> Result<(), BridgeError> {
        use std::time::{Duration, Instant};

        use crate::jsonrpc::client::JsonRpcTxSenderClient;
        use crate::task::spawn_txsender_loop_with_free_localhost_jsonrpc_port;

        let (config, db, rpc) = create_test_environment(true, true).await;
        let rpc = rpc.unwrap();
        let db = db.unwrap();
        rpc.rpc().mine_blocks(1).await.unwrap();

        // Start standalone txsender with JSON-RPC enabled on a free port.
        let tx_sender_cfg = config.clone();
        let (addr, handle) = spawn_txsender_loop_with_free_localhost_jsonrpc_port(tx_sender_cfg);
        let url = format!("http://{addr}");
        let client =
            JsonRpcTxSenderClient::new(&url).map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

        // A minimal syntactically-valid transaction (doesn't need to be mineable for enqueueing).
        let tx = make_test_tx(0);

        // Wait for server to come up (spawn loop initializes asynchronously).
        let start = Instant::now();
        let try_to_send_id = loop {
            match client
                .insert_try_to_send(None, &tx, FeePayingType::CPFP, None, &[])
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

    #[tokio::test]
    async fn test_jsonrpc_txsender_track_try_to_send_lifecycle() -> Result<(), BridgeError> {
        use std::time::{Duration, Instant};

        use crate::jsonrpc::client::JsonRpcTxSenderClient;
        use crate::task::spawn_txsender_loop_with_free_localhost_jsonrpc_port;

        let (config, db, rpc) = create_test_environment(true, true).await;
        let rpc = rpc.unwrap();
        let db = db.unwrap();
        rpc.rpc().mine_blocks(1).await.unwrap();

        let tx_sender_cfg = config.clone();
        let (addr, handle) = spawn_txsender_loop_with_free_localhost_jsonrpc_port(tx_sender_cfg);
        let url = format!("http://{addr}");
        let client =
            JsonRpcTxSenderClient::new(&url).map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

        let tx = make_test_tx(0);

        let start = Instant::now();
        let try_to_send_id = loop {
            match client
                .insert_try_to_send(None, &tx, FeePayingType::NoFunding, None, &[])
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

        let tx_sender_db = TxSenderDb::from_pool(db.pool().clone());

        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::Pending);
                assert!(matches!(track.activation, ActivationState::Waiting { .. }));
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        tx_sender_db
            .update_tx_debug_sending_state(try_to_send_id, "no_funding_send_success", true)
            .await?;
        sqlx::query("UPDATE tx_sender_try_to_send_txs SET effective_fee_rate = $2 WHERE id = $1")
            .bind(i32::try_from(try_to_send_id).expect("id fits in i32"))
            .bind(2500_i64)
            .execute(db.pool())
            .await?;
        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::Pending);
                assert_eq!(track.fee_sat_kvb, Some(2500));
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        match client
            .track_tx(TrackRequest::ByTxid {
                txid: tx.compute_txid().to_string(),
            })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.tx_info.txid, tx.compute_txid().to_string());
                assert_eq!(track.fee_sat_kvb, Some(2500));
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        tx_sender_db
            .set_try_to_send_seen_at_height(None, try_to_send_id, Some(123))
            .await?;
        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::Mined);
                assert_eq!(track.tx_info.mined_at_height, Some(123));
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        tx_sender_db
            .set_try_to_send_finalized(None, try_to_send_id, true)
            .await?;
        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::Finalized);
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        let failed_tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 1,
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

        let failed_id = client
            .insert_try_to_send(None, &failed_tx, FeePayingType::NoFunding, None, &[])
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;
        sqlx::query(
            "UPDATE tx_sender_try_to_send_txs SET input_unspent_timed_out = TRUE WHERE id = $1",
        )
        .bind(i32::try_from(failed_id).expect("failed_id fits in i32"))
        .execute(db.pool())
        .await?;

        match client
            .track_tx(TrackRequest::TryToSend {
                try_to_send_id: failed_id,
            })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::Cancelled);
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        handle.abort();
        let _ = handle.await;

        Ok(())
    }

    #[tokio::test]
    async fn test_jsonrpc_txsender_track_by_rbf_txid() -> Result<(), BridgeError> {
        use std::time::{Duration, Instant};

        use crate::jsonrpc::client::JsonRpcTxSenderClient;
        use crate::task::spawn_txsender_loop_with_free_localhost_jsonrpc_port;

        let (config, db, rpc) = create_test_environment(true, true).await;
        let rpc = rpc.unwrap();
        let db = db.unwrap();
        rpc.rpc().mine_blocks(1).await.unwrap();

        let (addr, handle) = spawn_txsender_loop_with_free_localhost_jsonrpc_port(config);
        let client = JsonRpcTxSenderClient::new(&format!("http://{addr}"))
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

        let tx = make_test_tx(0);
        let bumped_tx = make_test_tx(1);

        let start = Instant::now();
        let try_to_send_id = loop {
            match client
                .insert_try_to_send(None, &tx, FeePayingType::RBF, None, &[])
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

        let tx_sender_db = TxSenderDb::from_pool(db.pool().clone());
        let bumped_txid = bumped_tx.compute_txid();
        tx_sender_db
            .save_rbf_txid(None, try_to_send_id, bumped_txid)
            .await?;

        match client
            .track_tx(TrackRequest::ByTxid {
                txid: bumped_txid.to_string(),
            })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::Pending);
                assert_eq!(track.tx_info.txid, bumped_txid.to_string());
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        handle.abort();
        let _ = handle.await;

        Ok(())
    }

    #[tokio::test]
    async fn test_jsonrpc_txsender_tracking_ignores_evicted_fee_payers() -> Result<(), BridgeError>
    {
        use std::time::{Duration, Instant};

        use crate::jsonrpc::client::JsonRpcTxSenderClient;
        use crate::task::spawn_txsender_loop_with_free_localhost_jsonrpc_port;

        let (config, db, rpc) = create_test_environment(true, true).await;
        let rpc = rpc.unwrap();
        let db = db.unwrap();
        rpc.rpc().mine_blocks(1).await.unwrap();

        let (addr, handle) = spawn_txsender_loop_with_free_localhost_jsonrpc_port(config);
        let client = JsonRpcTxSenderClient::new(&format!("http://{addr}"))
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

        let tx = make_test_tx(0);
        let fee_payer_txid = make_test_tx(2).compute_txid();

        let start = Instant::now();
        let try_to_send_id = loop {
            match client
                .insert_try_to_send(None, &tx, FeePayingType::CPFP, None, &[])
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

        let tx_sender_db = TxSenderDb::from_pool(db.pool().clone());
        tx_sender_db
            .save_fee_payer_tx(
                None,
                try_to_send_id,
                fee_payer_txid,
                0,
                bitcoin::Amount::from_sat(1),
                None,
            )
            .await?;

        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::InProgress);
                assert_eq!(track.fee_payer_txs.len(), 1);
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        let fee_payer_row_id = tx_sender_db
            .get_unconfirmed_fee_payer_txs(None, try_to_send_id)
            .await?
            .into_iter()
            .next()
            .expect("saved fee payer tx should exist")
            .0;
        tx_sender_db
            .mark_fee_payer_utxo_as_evicted(None, fee_payer_row_id)
            .await?;

        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::Pending);
                assert!(track.fee_payer_txs.is_empty());
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        handle.abort();
        let _ = handle.await;

        Ok(())
    }

    #[tokio::test]
    async fn test_jsonrpc_txsender_track_activation_blockers() -> Result<(), BridgeError> {
        use std::time::{Duration, Instant};

        use crate::jsonrpc::client::JsonRpcTxSenderClient;
        use crate::task::spawn_txsender_loop_with_free_localhost_jsonrpc_port;
        let (config, db, rpc) = create_test_environment(true, true).await;
        let rpc = rpc.unwrap();
        let db = db.unwrap();
        rpc.rpc().mine_blocks(1).await.unwrap();

        let tx_sender_cfg = config.clone();
        let (addr, handle) = spawn_txsender_loop_with_free_localhost_jsonrpc_port(tx_sender_cfg);
        let url = format!("http://{addr}");
        let client =
            JsonRpcTxSenderClient::new(&url).map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

        let blocker_txid = Txid::from_slice(&[1u8; 32]).expect("valid blocker txid");
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: blocker_txid,
                    vout: 7,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(3),
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let start = Instant::now();
        let try_to_send_id = loop {
            match client
                .insert_try_to_send(
                    None,
                    &tx,
                    FeePayingType::NoFunding,
                    None,
                    &[],
                )
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

        let tx_sender_db = TxSenderDb::from_pool(db.pool().clone());

        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => match track.activation {
                ActivationState::Waiting { blockers } => {
                    assert_eq!(blockers.len(), 1);
                    assert_eq!(blockers[0].txid, blocker_txid.to_string());
                    assert!(matches!(
                        blockers[0].reason,
                        ActivationBlockerReason::Missing
                    ));
                }
                other => panic!("expected waiting activation, got {other:?}"),
            },
            other => panic!("unexpected tracking response: {other:?}"),
        }

        let current_tip_height = rpc.rpc().get_current_chain_height().await.unwrap();
        tx_sender_db
            .set_activate_txid_seen_at_height(
                None,
                try_to_send_id,
                blocker_txid,
                Some(current_tip_height),
            )
            .await?;

        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => match track.activation {
                ActivationState::Waiting { blockers } => {
                    assert_eq!(blockers.len(), 1);
                    assert_eq!(blockers[0].txid, blocker_txid.to_string());
                    assert!(matches!(
                        blockers[0].reason,
                        ActivationBlockerReason::Timelocked {
                            mined_at_height,
                            required_blocks: 3,
                            remaining_blocks: 3,
                        } if mined_at_height == current_tip_height
                    ));
                }
                other => panic!("expected waiting activation, got {other:?}"),
            },
            other => panic!("unexpected tracking response: {other:?}"),
        }

        rpc.rpc().mine_blocks(3).await.unwrap();

        match client
            .track_tx(TrackRequest::TryToSend { try_to_send_id })
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
        {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::Pending);
                assert_eq!(track.activation, ActivationState::Active);
            }
            other => panic!("unexpected tracking response: {other:?}"),
        }

        handle.abort();
        let _ = handle.await;

        Ok(())
    }
}
