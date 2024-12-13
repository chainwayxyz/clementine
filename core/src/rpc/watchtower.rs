use super::clementine::{
    clementine_watchtower_server::ClementineWatchtower, Empty, WatchtowerParams, WinternitzPubkey,
};
use crate::watchtower::Watchtower;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineWatchtower for Watchtower {
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<WatchtowerParams>, Status> {
        let winternitz_pubkeys = self
            .get_winternitz_public_keys()
            .await?
            .into_iter()
            .map(WinternitzPubkey::from_bitvm)
            .collect::<Vec<WinternitzPubkey>>();

        Ok(Response::new(WatchtowerParams {
            watchtower_id: self.config.index,
            winternitz_pubkeys,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config::BridgeConfig,
        create_test_config_with_thread_name,
        database::Database,
        errors::BridgeError,
        extended_rpc::ExtendedRpc,
        initialize_database,
        servers::{
            create_aggregator_grpc_server, create_operator_grpc_server,
            create_verifier_grpc_server, create_watchtower_grpc_server,
        },
        utils::initialize_logger,
    };
    use crate::{
        create_actors,
        rpc::clementine::{clementine_watchtower_server::ClementineWatchtower, Empty},
        watchtower::Watchtower,
    };
    use std::{env, thread};
    use tonic::Request;

    #[tokio::test]
    #[serial_test::serial]
    async fn watchtower_get_params() {
        let mut config = create_test_config_with_thread_name!("test_config.toml", None);
        let (verifiers, operators, _, _watchtowers) = create_actors!(config.clone(), 2);

        config.verifier_endpoints = Some(
            verifiers
                .iter()
                .map(|v| format!("http://{}", v.0))
                .collect(),
        );
        config.operator_endpoints = Some(
            operators
                .iter()
                .map(|o| format!("http://{}", o.0))
                .collect(),
        );
        let watchtower = Watchtower::new(config.clone()).await.unwrap();

        let params = watchtower
            .get_params(Request::new(Empty {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(params.watchtower_id, watchtower.config.index);
        assert!(params.winternitz_pubkeys.len() == config.num_operators * config.num_time_txs);
    }
}
