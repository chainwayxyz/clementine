use crate::{
    actor::{Actor, WinternitzDerivationPath},
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
};
use bitvm::signatures::winternitz;

#[derive(Debug, Clone)]
pub struct Watchtower {
    _erpc: ExtendedRpc,
    _db: Database,
    pub actor: Actor,
    pub config: BridgeConfig,
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

        Ok(Self {
            _erpc,
            _db,
            actor,
            config,
        })
    }

    /// Generates Winternitz public keys for every operator and time_tx pair and
    /// returns them.
    ///
    /// # Returns
    ///
    /// - [`Vec<Vec<winternitz::PublicKey>>`]: Winternitz public key for
    ///   `operator index` row and `time_tx index` column.
    pub async fn get_watchtower_winternitz_public_keys(
        &self,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let mut winternitz_pubkeys = Vec::new();

        for operator in 0..self.config.num_operators as u32 {
            for time_tx in 0..self.config.num_time_txs as u32 {
                let path = WinternitzDerivationPath {
                    message_length: 480,
                    log_d: 4,
                    tx_type: crate::actor::TxType::WatchtowerChallenge,
                    index: None,
                    operator_idx: Some(operator),
                    watchtower_idx: None,
                    time_tx_idx: Some(time_tx),
                    intermediate_step_idx: None,
                };

                winternitz_pubkeys.push(self.actor.derive_winternitz_pk(path)?);
            }
        }

        Ok(winternitz_pubkeys)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::initialize_logger;
    use crate::watchtower::Watchtower;
    use crate::{
        config::BridgeConfig,
        database::Database,
        errors::BridgeError,
        extended_rpc::ExtendedRpc,
        initialize_database,
        servers::{
            create_aggregator_grpc_server, create_operator_grpc_server,
            create_verifier_grpc_server, create_watchtower_grpc_server,
        },
    };
    use crate::{create_actors, create_test_config_with_thread_name};
    use std::{env, thread};

    #[tokio::test]
    #[serial_test::serial]
    async fn new_watchtower() {
        let mut config = create_test_config_with_thread_name!(None);
        let (verifiers, operators, _, _should_not_panic) = create_actors!(config.clone());

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

        let _should_not_panic = Watchtower::new(config.clone()).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn get_watchtower_winternitz_public_keys() {
        let mut config = create_test_config_with_thread_name!(None);
        let (verifiers, operators, _, _watchtowers) = create_actors!(config.clone());

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
        let watchtower_winternitz_public_keys = watchtower
            .get_watchtower_winternitz_public_keys()
            .await
            .unwrap();

        assert_eq!(
            watchtower_winternitz_public_keys.len(),
            config.num_operators * config.num_time_txs
        );
    }
}
