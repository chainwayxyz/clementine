#[cfg(feature = "aggregator_server")]
use clementine_core::servers::create_aggregator_server;

#[cfg(feature = "operator_server")]
use clementine_core::servers::create_operator_server;

#[cfg(feature = "verifier_server")]
use clementine_core::servers::create_verifier_server;

#[tokio::main]
async fn main() {
    #[cfg(any(
        feature = "verifier_server",
        feature = "operator_server",
        feature = "aggregator_server"
    ))]
    {
        use clementine_core::{cli, database::common::Database, extended_rpc::ExtendedRpc};

        let mut config = cli::get_configuration();
        let rpc = ExtendedRpc::<bitcoincore_rpc::Client>::new(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        );

        let database = Database::new(config.clone()).await.unwrap();
        database.init_from_schema().await.unwrap();
        database.close().await;

        let mut handles = vec![];

        #[cfg(feature = "verifier_server")]
        {
            handles.push(
                create_verifier_server(config.clone(), rpc.clone())
                    .await
                    .unwrap()
                    .1
                    .stopped(),
            );
            config.port += 1;
        }

        #[cfg(feature = "operator_server")]
        {
            handles.push(
                create_operator_server(config.clone(), rpc.clone())
                    .await
                    .unwrap()
                    .1
                    .stopped(),
            );
            config.port += 1;
        }

        #[cfg(feature = "aggregator_server")]
        handles.push(create_aggregator_server(config).await.unwrap().1.stopped());

        futures::future::join_all(handles).await;
    }

    #[cfg(not(any(
        feature = "verifier_server",
        feature = "operator_server",
        feature = "aggregator_server"
    )))]
    {
        println!("No server features are enabled. Exiting...");
    }
}
