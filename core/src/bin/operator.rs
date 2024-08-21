use clementine_core::{cli, extended_rpc::ExtendedRpc, servers::create_operator_server};

#[tokio::main]
async fn main() {
    let config = cli::get_configuration();
    let rpc = ExtendedRpc::<bitcoincore_rpc::Client>::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    );

    create_operator_server(config, rpc)
        .await
        .unwrap()
        .1
        .stopped()
        .await;
}
