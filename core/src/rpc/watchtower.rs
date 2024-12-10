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
        let winternitz_pubkeys: Vec<WinternitzPubkey> = self
            .get_winternitz_public_keys()
            .await?
            .into_iter()
            .map(|wpks| WinternitzPubkey {
                digit_pubkey: wpks.iter().map(|inner| inner.to_vec()).collect(),
            })
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
        mock::database::create_test_config_with_thread_name,
        rpc::clementine::{clementine_watchtower_server::ClementineWatchtower, Empty},
        servers::create_actors_grpc,
        watchtower::Watchtower,
    };
    use tonic::Request;

    #[tokio::test]
    #[serial_test::serial]
    async fn watchtower_get_params() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let (verifiers, operators, _, _watchtowers) = create_actors_grpc(config.clone(), 2).await;

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
