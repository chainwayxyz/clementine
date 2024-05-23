use clementine_core::{cli, create_operator_server};

#[tokio::main]
async fn main() {
    let config = cli::get_configuration();
    let verifier_endpoints = config.verifier_endpoints.clone().unwrap();

    create_operator_server(config, verifier_endpoints)
        .await
        .unwrap()
        .1
        .stopped()
        .await;
}
