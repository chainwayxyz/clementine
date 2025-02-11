use crate::constants::{WATCHTOWER_CHALLENGE_MESSAGE_LENGTH, WINTERNITZ_LOG_D};
use crate::musig2::AggregateFromPublicKeys;
use crate::{
    actor::{Actor, WinternitzDerivationPath},
    builder::address::derive_challenge_address_from_xonlypk_and_wpk,
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
};
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitvm::signatures::winternitz;

#[derive(Debug, Clone)]
pub struct Watchtower {
    _erpc: ExtendedRpc,
    pub(crate) db: Database,
    pub signer: Actor,
    pub config: BridgeConfig,
    pub nofn_xonly_pk: XOnlyPublicKey,
}

impl Watchtower {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let _erpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let nofn_xonly_pk =
            XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)?;

        let db = Database::new(&config).await?;
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.network,
        );

        Ok(Self {
            _erpc,
            db,
            signer,
            config,
            nofn_xonly_pk,
        })
    }

    /// Generates Winternitz public keys for every operator and sequential_collateral_tx pair and
    /// returns them.
    ///
    /// # Returns
    ///
    /// - [`Vec<Vec<winternitz::PublicKey>>`]: Winternitz public key for
    ///   `operator index` row and `sequential_collateral_tx index` column.
    pub async fn get_watchtower_winternitz_public_keys(
        &self,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let mut winternitz_pubkeys = Vec::new();

        for operator in 0..self.config.num_operators as u32 {
            for sequential_collateral_tx in 0..self.config.num_sequential_collateral_txs as u32 {
                for kickoff_idx in 0..self.config.num_kickoffs_per_sequential_collateral_tx as u32 {
                    let path = WinternitzDerivationPath {
                        message_length: WATCHTOWER_CHALLENGE_MESSAGE_LENGTH,
                        log_d: WINTERNITZ_LOG_D,
                        tx_type: crate::actor::TxType::WatchtowerChallenge,
                        index: None,
                        operator_idx: Some(operator),
                        watchtower_idx: None,
                        sequential_collateral_tx_idx: Some(sequential_collateral_tx),
                        kickoff_idx: Some(kickoff_idx),
                        intermediate_step_name: None,
                    };

                    winternitz_pubkeys.push(self.signer.derive_winternitz_pk(path)?);
                }
            }
        }

        Ok(winternitz_pubkeys)
    }

    pub async fn get_watchtower_challenge_addresses(&self) -> Result<Vec<ScriptBuf>, BridgeError> {
        let mut challenge_addresses = Vec::new();

        let winternitz_pubkeys = self.get_watchtower_winternitz_public_keys().await?;
        tracing::info!(
            "get_watchtower_challenge_addresses watchtower xonly public key: {:?}",
            self.signer.xonly_public_key
        );
        tracing::info!(
            "get_watchtower_challenge_addresses watchtower taproot public key: {:?}",
            self.signer.address.script_pubkey()
        );
        for winternitz_pubkey in winternitz_pubkeys {
            let challenge_address = derive_challenge_address_from_xonlypk_and_wpk(
                &self.signer.xonly_public_key,
                &winternitz_pubkey,
                self.config.network,
            );
            challenge_addresses.push(challenge_address.script_pubkey());
        }

        Ok(challenge_addresses)
    }
}

#[cfg(test)]
mod tests {
    use crate::create_test_config_with_thread_name;
    use crate::utils::initialize_logger;
    use crate::watchtower::Watchtower;
    use crate::{config::BridgeConfig, database::Database, initialize_database};

    #[tokio::test]
    async fn new_watchtower() {
        let config = create_test_config_with_thread_name!(None);

        let _should_not_panic = Watchtower::new(config.clone()).await.unwrap();
    }

    #[tokio::test]
    async fn get_watchtower_winternitz_public_keys() {
        let config = create_test_config_with_thread_name!(None);

        let watchtower = Watchtower::new(config.clone()).await.unwrap();
        let watchtower_winternitz_public_keys = watchtower
            .get_watchtower_winternitz_public_keys()
            .await
            .unwrap();

        assert_eq!(
            watchtower_winternitz_public_keys.len(),
            config.num_operators
                * config.num_sequential_collateral_txs
                * config.num_kickoffs_per_sequential_collateral_tx
        );
    }
}
