use clementine_core::{
    cli, extended_rpc::ExtendedRpc, servers::create_operator_server,
    traits::bitcoin_rpc::BitcoinRPC,
};

#[tokio::main]
async fn main() {
    let config = cli::get_configuration();

    let verifier_endpoints = config.verifier_endpoints.clone().unwrap();

    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    );

    create_operator_server(config, rpc, verifier_endpoints)
        .await
        .unwrap()
        .1
        .stopped()
        .await;
}
