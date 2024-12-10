use crate::{
    actor::{Actor, WinternitzDerivationPath},
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
    rpc::{
        self,
        clementine::{
            clementine_operator_client::ClementineOperatorClient,
            clementine_verifier_client::ClementineVerifierClient,
        },
    },
};
use bitvm::signatures::winternitz;

#[derive(Debug, Clone)]
pub struct Watchtower {
    _erpc: ExtendedRpc,
    _db: Database,
    pub actor: Actor,
    num_operators: u32,
    num_time_tx: u32,
    pub index: u32,
    pub(crate) _verifier_clients: Vec<ClementineVerifierClient<tonic::transport::Channel>>,
    pub(crate) _operator_clients: Vec<ClementineOperatorClient<tonic::transport::Channel>>,
}

impl Watchtower {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let _erpc = ExtendedRpc::new(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await;
        let _db = Database::new(&config).await?;
        let actor = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.network,
        );

        let verifier_endpoints =
            config
                .verifier_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "Couldn't find operator endpoints in config file!".to_string(),
                ))?;
        let _verifier_clients =
            rpc::get_clients(verifier_endpoints, ClementineVerifierClient::connect).await?;

        let operator_endpoints =
            config
                .operator_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "Couldn't find operator endpoints in config file!".to_string(),
                ))?;
        let _operator_clients =
            rpc::get_clients(operator_endpoints, ClementineOperatorClient::connect).await?;

        Ok(Self {
            _erpc,
            _db,
            actor,
            index: config.index,
            num_operators: config.num_operators as u32,
            num_time_tx: config.num_time_txs as u32,
            _verifier_clients,
            _operator_clients,
        })
    }

    /// Generates Winternitz public keys for every operator and time_tx pair and
    /// returns them.
    ///
    /// # Returns
    ///
    /// - [`Vec<Vec<winternitz::PublicKey>>`]: Winternitz public key for
    ///   operator index row and time_tx index column.
    pub async fn get_winternitz_public_keys(
        &self,
    ) -> Result<Vec<Vec<winternitz::PublicKey>>, BridgeError> {
        let mut winternitz_pubkeys = Vec::new();

        for operator in 0..self.num_operators {
            let mut operator_i = Vec::new();
            for time_tx in 0..self.num_time_tx {
                let path = WinternitzDerivationPath {
                    message_length: 480,
                    log_d: 4,
                    tx_type: crate::actor::TxType::TimeTx,
                    index: None,
                    operator_idx: Some(operator),
                    watchtower_idx: None,
                    time_tx_idx: Some(time_tx),
                };

                operator_i.push(self.actor.derive_winternitz_pk(path)?);
            }

            winternitz_pubkeys.push(operator_i);
        }

        Ok(winternitz_pubkeys)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mock::database::create_test_config_with_thread_name, servers::create_actors_grpc,
        watchtower::Watchtower,
    };

    #[tokio::test]
    #[serial_test::serial]
    async fn new_watchtower() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let (_, _, _, _should_not_panic) = create_actors_grpc(config, 2).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn get_winternitz_public_keys() {
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
        let winternitz_public_keys = watchtower.get_winternitz_public_keys().await.unwrap();

        assert_eq!(winternitz_public_keys.len(), config.num_operators as usize);
        for operator_winternitz_pks in winternitz_public_keys {
            assert_eq!(operator_winternitz_pks.len(), config.num_time_txs as usize);
        }
    }
}
