use crate::musig2::AggregateFromPublicKeys;
use crate::{
    actor::{Actor, WinternitzDerivationPath},
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
};
use bitcoin::{Txid, XOnlyPublicKey};
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
            config.protocol_paramset().network,
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
            let path = WinternitzDerivationPath::WatchtowerChallenge(
                operator,
                deposit_txid,
                self.config.protocol_paramset(),
            );
            winternitz_pubkeys.push(self.signer.derive_winternitz_pk(path)?);
        }

        Ok(winternitz_pubkeys)
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
    use crate::test::common::*;

    use crate::watchtower::Watchtower;

    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    #[tokio::test]
    async fn new_watchtower() {
        let config = create_test_config_with_thread_name().await;

        let _should_not_panic = Watchtower::new(config.clone()).await.unwrap();
    }

    #[tokio::test]
    async fn get_watchtower_winternitz_public_keys() {
        let config = create_test_config_with_thread_name().await;

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
        let config = create_test_config_with_thread_name().await;
        let watchtower = Watchtower::new(config.clone()).await.unwrap();

        let (watchtower_id, xonly_pk) = watchtower.get_params().await.unwrap();

        assert_eq!(watchtower_id, watchtower.config.index);
        assert_eq!(xonly_pk, watchtower.signer.xonly_public_key);
    }
}
