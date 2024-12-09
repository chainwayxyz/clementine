use crate::{
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

#[derive(Debug, Clone)]
pub struct Watchtower {
    rpc: ExtendedRpc,
    db: Database,
    pub(crate) verifier_clients: Vec<ClementineVerifierClient<tonic::transport::Channel>>,
    pub(crate) operator_clients: Vec<ClementineOperatorClient<tonic::transport::Channel>>,
}

impl Watchtower {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let rpc = ExtendedRpc::new(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await;
        let db = Database::new(&config).await?;

        let verifier_endpoints =
            config
                .verifier_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "Couldn't find operator endpoints in config file!".to_string(),
                ))?;
        let verifier_clients =
            rpc::get_clients(verifier_endpoints, ClementineVerifierClient::connect).await?;

        let operator_endpoints =
            config
                .operator_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "Couldn't find operator endpoints in config file!".to_string(),
                ))?;
        let operator_clients =
            rpc::get_clients(operator_endpoints, ClementineOperatorClient::connect).await?;

        Ok(Self {
            rpc,
            db,
            verifier_clients,
            operator_clients,
        })
    }
}
