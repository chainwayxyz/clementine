use clementine_core::servers::create_aggregator_server;
use clementine_core::servers::create_operator_server;
use clementine_core::servers::create_verifier_server;
use clementine_core::{cli, database::common::Database, extended_rpc::ExtendedRpc};
use std::process::exit;

#[tokio::main]
async fn main() {
    let args = match cli::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };

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

    if args.verifier_server {
        handles.push(
            create_verifier_server(config.clone(), rpc.clone())
                .await
                .unwrap()
                .1
                .stopped(),
        );
        config.port += 1;

        tracing::trace!("Verifier servers are started.");
    }

    if args.operator_server {
        handles.push(
            create_operator_server(config.clone(), rpc.clone())
                .await
                .unwrap()
                .1
                .stopped(),
        );
        config.port += 1;

        tracing::trace!("Operator servers are started.");
    }

    if args.aggregator_server {
        handles.push(create_aggregator_server(config).await.unwrap().1.stopped());
    }

    if !args.verifier_server && !args.operator_server && !args.aggregator_server {
        eprintln!("No servers are specified. Please specify one.");
        exit(1);
    }

    futures::future::join_all(handles).await;
}
