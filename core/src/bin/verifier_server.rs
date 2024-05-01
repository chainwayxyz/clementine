use clementine_core::create_verifier_server;

#[tokio::main]
async fn main() {
    create_verifier_server(None, None, Some("./configs/keys0.json".to_string()))
        .await
        .unwrap()
        .1
        .stopped()
        .await;
}
