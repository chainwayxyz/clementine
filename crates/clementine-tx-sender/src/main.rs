#[cfg(all(feature = "standalone", feature = "json-rpc"))]
#[tokio::main]
async fn main() -> Result<(), eyre::Report> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config: clementine_tx_sender::config::TxSenderConfig = clementine_tx_sender::config::TxSenderConfig::from_env()?;

    if config.jsonrpc.is_none() {
        return Err(eyre::eyre!(
            "TX_SENDER_JSONRPC_PORT must be set to start the JSON-RPC server"
        ));
    }

    let handle = clementine_tx_sender::task::spawn_txsender_loop(config);

    // Wait until Ctrl-C, then abort the background loop.
    tokio::signal::ctrl_c().await?;
    tracing::info!("Received Ctrl-C, shutting down txsender");
    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[cfg(not(all(feature = "standalone", feature = "json-rpc")))]
fn main() {
    eprintln!(
        "This binary requires `--features \"standalone\"`.\n\
         Example:\n\
         cargo run -p clementine-tx-sender --features \"standalone\""
    );
}
