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
use tokio::sync::mpsc::{self, error::SendError};

#[derive(Debug, Clone)]
pub struct Watchtower {
    _erpc: ExtendedRpc,
    _db: Database,
    pub actor: Actor,
    pub config: BridgeConfig,
}

impl Watchtower {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let _erpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

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
                        message_length: 480,
                        log_d: 4,
                        tx_type: crate::actor::TxType::WatchtowerChallenge,
                        index: None,
                        operator_idx: Some(operator),
                        watchtower_idx: None,
                        sequential_collateral_tx_idx: Some(sequential_collateral_tx),
                        kickoff_idx: Some(kickoff_idx),
                        intermediate_step_name: None,
                    };

                    winternitz_pubkeys.push(self.actor.derive_winternitz_pk(path)?);
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
            self.actor.xonly_public_key
        );
        tracing::info!(
            "get_watchtower_challenge_addresses watchtower taproot public key: {:?}",
            self.actor.address.script_pubkey()
        );
        for winternitz_pubkey in winternitz_pubkeys {
            let challenge_address = derive_challenge_address_from_xonlypk_and_wpk(
                &self.actor.xonly_public_key,
                &winternitz_pubkey,
                self.config.network,
            );
            challenge_addresses.push(challenge_address.script_pubkey());
        }

        Ok(challenge_addresses)
    }

    /// Returns id, winteritz public keys and x-only public key of a watchtower.
    ///
    /// # Returns
    ///
    /// - [`u32`]: Id of the current watchtower
    /// - [`mpsc::Receiver`]: Winternitz public keys of the watchtower, in a
    ///   [`tokio`] channel
    /// - [`XOnlyPublicKey`]: X-only public key of the current watchtower
    pub async fn get_params(
        &self,
    ) -> Result<(u32, mpsc::Receiver<winternitz::PublicKey>, XOnlyPublicKey), BridgeError> {
        let watchtower_id = self.config.index;
        let winternitz_public_keys = self.get_watchtower_winternitz_public_keys().await?;
        let xonly_pk = self.actor.xonly_public_key;

        let (wpk_channel_tx, wpk_channel_rx) = mpsc::channel(winternitz_public_keys.len());

        tokio::spawn(async move {
            for wpk in winternitz_public_keys {
                wpk_channel_tx.send(wpk).await?;
            }

            Ok::<(), SendError<_>>(())
        });

        Ok((watchtower_id, wpk_channel_rx, xonly_pk))
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

    #[tokio::test]
    async fn watchtower_get_params() {
        let config = create_test_config_with_thread_name!(None);
        let watchtower = Watchtower::new(config.clone()).await.unwrap();

        let (watchtower_id, mut winternitz_public_keys, xonly_pk) =
            watchtower.get_params().await.unwrap();

        assert_eq!(watchtower_id, watchtower.config.index);
        assert_eq!(xonly_pk, watchtower.actor.xonly_public_key);

        let actual_wpks = watchtower
            .get_watchtower_winternitz_public_keys()
            .await
            .unwrap();
        for (idx, wpk) in winternitz_public_keys.recv().await.into_iter().enumerate() {
            assert_eq!(actual_wpks[idx], wpk);
        }
    }
}
