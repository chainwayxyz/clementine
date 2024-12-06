use crate::actor::Actor;
use crate::builder;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::{EVMAddress, UTXO};
use bitcoin::{Address, TxOut};
use bitcoin::{Amount, OutPoint};
use bitcoin::{TapSighashType, XOnlyPublicKey};
use secp256k1::schnorr;
use secp256k1::SecretKey;

pub const WITHDRAWAL_EMPTY_UTXO_SATS: Amount = Amount::from_sat(550);

#[derive(Debug)]
pub struct User {
    rpc: ExtendedRpc,
    signer: Actor,
    config: BridgeConfig,
    nofn_xonly_pk: XOnlyPublicKey,
}

impl User {
    /// Creates a new `User`.
    pub fn new(rpc: ExtendedRpc, sk: SecretKey, config: BridgeConfig) -> Self {
        let signer = Actor::new(sk, config.winternitz_secret_key, config.network);

        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_musig2_pks(
            config.verifiers_public_keys.clone(),
            None,
            false,
        );

        User {
            rpc,
            signer,
            config,
            nofn_xonly_pk,
        }
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn deposit_tx(&self, evm_address: EVMAddress) -> Result<OutPoint, BridgeError> {
        let deposit_address = self.get_deposit_address(evm_address)?;

        let deposit_outpoint = self
            .rpc
            .send_to_address(&deposit_address, self.config.bridge_amount_sats)
            .await?;

        Ok(deposit_outpoint)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn get_deposit_address(&self, evm_address: EVMAddress) -> Result<Address, BridgeError> {
        let (deposit_address, _) = builder::address::generate_deposit_address(
            self.nofn_xonly_pk,
            self.signer.address.as_unchecked(),
            evm_address,
            self.config.bridge_amount_sats,
            self.config.network,
            self.config.user_takes_after,
        );

        Ok(deposit_address)
    }

    /// Generates a withdrawal transaction and it's signature.
    ///
    /// # Returns
    ///
    /// - `UTXO`: Dust UTXO
    /// - `TxOut`: Withdrawal transaction output
    /// - `Signature`: Schnorr signature of the withdrawal transaction
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn generate_withdrawal_transaction_and_signature(
        &self,
        withdrawal_address: Address,
        withdrawal_amount: Amount,
    ) -> Result<(UTXO, TxOut, schnorr::Signature), BridgeError> {
        let dust_outpoint = self
            .rpc
            .send_to_address(&self.signer.address, WITHDRAWAL_EMPTY_UTXO_SATS)
            .await?;
        let dust_utxo = UTXO {
            outpoint: dust_outpoint,
            txout: TxOut {
                value: WITHDRAWAL_EMPTY_UTXO_SATS,
                script_pubkey: self.signer.address.script_pubkey(),
            },
        };

        let txins = builder::transaction::create_tx_ins(vec![dust_utxo.outpoint]);
        let txout = TxOut {
            value: withdrawal_amount, // TODO: Change this in the future since Operators should profit from the bridge
            script_pubkey: withdrawal_address.script_pubkey(),
        };
        let txouts = vec![txout.clone()];

        let mut tx = builder::transaction::create_btc_tx(txins, txouts.clone());
        let prevouts = vec![dust_utxo.txout.clone()];

        let sig = self.signer.sign_taproot_pubkey_spend_tx_with_sighash(
            &mut tx,
            &prevouts,
            0,
            Some(TapSighashType::SinglePlusAnyoneCanPay),
        )?;

        Ok((dust_utxo, txout, sig))
    }
}

#[cfg(test)]
mod tests {
    use crate::extended_rpc::ExtendedRpc;
    use crate::mock::database::create_test_config_with_thread_name;
    use crate::user::User;
    use crate::EVMAddress;
    use bitcoincore_rpc::RpcApi;
    use secp256k1::{rand, SecretKey};

    #[tokio::test]
    #[serial_test::parallel]
    async fn deposit_tx() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = ExtendedRpc::new(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await;

        let evm_address = EVMAddress([0x45u8; 20]);
        let sk = SecretKey::new(&mut rand::thread_rng());
        let user = User::new(rpc.clone(), sk, config.clone());

        let deposit_utxo = user.deposit_tx(evm_address).await.unwrap();
        let deposit_txout = rpc
            .client
            .get_raw_transaction(&deposit_utxo.txid, None)
            .await
            .unwrap();

        assert_eq!(
            deposit_txout
                .output
                .get(deposit_utxo.vout as usize)
                .unwrap()
                .value,
            config.bridge_amount_sats
        );

        let deposit_address = user.get_deposit_address(evm_address).unwrap();
        assert_eq!(
            deposit_txout
                .output
                .get(deposit_utxo.vout as usize)
                .unwrap()
                .script_pubkey,
            deposit_address.script_pubkey()
        );
    }
}
