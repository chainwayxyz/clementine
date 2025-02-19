use crate::constants::WATCHTOWER_CHALLENGE_MESSAGE_LENGTH;
use crate::musig2::AggregateFromPublicKeys;
use crate::{
    actor::{Actor, WinternitzDerivationPath},
    builder::address::derive_challenge_address_from_xonlypk_and_wpk,
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
};
use bitcoin::{ScriptBuf, Txid, XOnlyPublicKey};
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

    /// Generates Winternitz public keys for watchtower challenges for every operator
    /// for a single deposit.
    ///
    /// # Returns
    ///
    /// - [`Vec<Vec<winternitz::PublicKey>>`]: Winternitz public key for
    ///   `operator index`.
    pub fn get_watchtower_winternitz_public_keys(
        &self,
        deposit_txid: Txid,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let mut winternitz_pubkeys = Vec::new();

        for operator in 0..self.config.num_operators as u32 {
            let path = WinternitzDerivationPath::WatchtowerChallenge(operator, deposit_txid);
            winternitz_pubkeys.push(self.signer.derive_winternitz_pk(path)?);
        }

        Ok(winternitz_pubkeys)
    }

    pub async fn get_watchtower_challenge_addresses(
        &self,
        deposit_txid: Txid,
    ) -> Result<Vec<ScriptBuf>, BridgeError> {
        let mut challenge_addresses = Vec::new();

        let winternitz_pubkeys = self.get_watchtower_winternitz_public_keys(deposit_txid)?;
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
                WATCHTOWER_CHALLENGE_MESSAGE_LENGTH,
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
    pub async fn get_params(&self) -> Result<(u32, XOnlyPublicKey), BridgeError> {
        let watchtower_id = self.config.index;
        let xonly_pk = self.signer.xonly_public_key;

        Ok((watchtower_id, xonly_pk))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    use crate::watchtower::Watchtower;

    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    #[tokio::test]
    async fn new_watchtower() {
        let config = create_test_config_with_thread_name(None).await;

        let _should_not_panic = Watchtower::new(config.clone()).await.unwrap();
    }

    #[tokio::test]
    async fn get_watchtower_winternitz_public_keys() {
        let config = create_test_config_with_thread_name(None).await;

        let watchtower = Watchtower::new(config.clone()).await.unwrap();
        let watchtower_winternitz_public_keys = watchtower
            .get_watchtower_winternitz_public_keys(Txid::all_zeros())
            .unwrap();

        assert_eq!(
            watchtower_winternitz_public_keys.len(),
            config.num_operators
        );
    }

    #[tokio::test]
    async fn watchtower_get_params() {
        let config = create_test_config_with_thread_name(None).await;
        let watchtower = Watchtower::new(config.clone()).await.unwrap();

        let (watchtower_id, xonly_pk) = watchtower.get_params().await.unwrap();

        assert_eq!(watchtower_id, watchtower.config.index);
        assert_eq!(xonly_pk, watchtower.signer.xonly_public_key);
    }
}
