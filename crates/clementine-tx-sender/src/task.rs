use crate::config::TxSenderConfig;
use crate::TxSender;
use clementine_errors::BridgeError;
use std::time::Duration;

#[derive(Debug)]
pub struct TxSenderTaskInternal {
    pub current_tip_height: u32,
    pub last_processed_tip_height: u32,
    pub inner: TxSender,
}

impl TxSenderTaskInternal {
    pub fn new(inner: TxSender) -> Self {
        Self {
            current_tip_height: 0,
            last_processed_tip_height: 0,
            inner,
        }
    }

    #[tracing::instrument(skip(self), name = "tx_sender_task")]
    pub async fn run_once(&mut self) -> Result<bool, BridgeError> {
        // Get current tip height from Bitcoin RPC, then sync confirmations/spent tracking.
        self.current_tip_height = self
            .inner
            .rpc
            .get_current_chain_height()
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

        tracing::debug!("TXSENDER: Getting fee rate");
        let fee_rate = self.inner.get_fee_rate().await?;
        tracing::debug!("TXSENDER: Fee rate result: {fee_rate:?}");

        #[cfg(feature = "citrea")]
        self.inner.sync_citrea_txs(fee_rate).await?;
        // No need for db transaction as it doesn't matter if it fails midway, we resync from rpc continuously
        self.inner
            .sync_transaction_confirmations_via_rpc(None)
            .await?;

        self.inner
            .try_to_send_unconfirmed_txs(
                fee_rate,
                self.current_tip_height,
                self.last_processed_tip_height != self.current_tip_height,
            )
            .await?;
        self.last_processed_tip_height = self.current_tip_height;

        self.inner
            .db
            .update_synced_height(self.current_tip_height)
            .await?;

        Ok(false)
    }
}

/// Spawns a tokio task that runs txsender indefinitely.
///
/// This is a standalone loop helper (no dependency on `clementine-core` task framework).
pub fn spawn_txsender_loop(config: TxSenderConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let poll_delay = Duration::from_millis(config.poll_delay_ms);
        #[cfg(feature = "json-rpc")]
        let mut jsonrpc_handle: Option<crate::jsonrpc::server::TxSenderJsonRpcServer> = None;

        loop {
            let init_res: Result<TxSender, BridgeError> = async {
                let tx_sender = TxSender::new(config.clone()).await?;

                // Standalone deployments own their txsender schema.
                // In clementine-core deployments, schema/migrations are owned by core.
                #[cfg(feature = "standalone")]
                tx_sender.db.run_migrations().await?;

                #[cfg(feature = "json-rpc")]
                if let Some(rpc_cfg) = config.jsonrpc.clone() {
                    // If we previously had a server, stop it before re-binding.
                    if let Some(old) = jsonrpc_handle.take() {
                        let handle = old.stop();
                        let _ = handle.stop();
                    }

                    let bind: std::net::IpAddr = rpc_cfg.bind.parse().map_err(|e| {
                        BridgeError::ConfigError(format!("Invalid TX_SENDER_JSONRPC_BIND: {e}"))
                    })?;
                    let addr = std::net::SocketAddr::new(bind, rpc_cfg.port);

                    let server = crate::jsonrpc::server::start_jsonrpc_server(
                        tx_sender.client(),
                        tx_sender.tracker(),
                        addr,
                    )
                    .await?;
                    jsonrpc_handle = Some(server);
                }

                Ok(tx_sender)
            }
            .await;

            let tx_sender = match init_res {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!("txsender init failed (will retry): {e:?}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut internal = TxSenderTaskInternal::new(tx_sender);
            loop {
                if let Err(e) = internal.run_once().await {
                    tracing::error!("txsender loop iteration failed: {e:?}");
                }
                tokio::time::sleep(poll_delay).await;
            }
        }
    })
}
