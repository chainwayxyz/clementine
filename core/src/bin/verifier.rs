use clementine_core::{cli, create_verifier_server};

#[tokio::main]
async fn main() {
    let config = cli::get_configuration();

    create_verifier_server(config)
        .await
        .unwrap()
        .1
        .stopped()
        .await;
}
