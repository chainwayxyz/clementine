use clementine_core::{
    cli, extended_rpc::ExtendedRpc, servers::create_verifier_server,
    traits::bitcoin_rpc::BitcoinRPC,
};

#[tokio::main]
async fn main() {
    let config = cli::get_configuration();

    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    );

    create_verifier_server(config, rpc)
        .await
        .unwrap()
        .1
        .stopped()
        .await;
}
