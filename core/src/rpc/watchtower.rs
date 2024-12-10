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
            .iter()
            .enumerate()
            .flat_map(|(operator_index, pks)| {
                pks.iter()
                    .enumerate()
                    .map(|(timetx_index, pks)| {
                        let digit_pubkey = pks.iter().map(|m| m.to_vec()).collect();

                        WinternitzPubkey {
                            d: operator_index as u32,
                            n0: timetx_index as u32,
                            digit_pubkey,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        Ok(Response::new(WatchtowerParams {
            watchtower_id: self.index,
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

        assert_eq!(params.watchtower_id, watchtower.index);

        assert!(params.winternitz_pubkeys.len() == config.num_operators * config.num_time_txs);
        assert!(params
            .winternitz_pubkeys
            .iter()
            .all(|pk| pk.d <= config.num_operators as u32 && pk.n0 <= config.num_time_txs as u32));
    }
}
