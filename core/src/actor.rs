use crate::errors::BridgeError;
use crate::transaction_builder::TxHandler;
use crate::utils;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::{
    hashes::Hash,
    secp256k1::{schnorr, Keypair, Message, SecretKey, XOnlyPublicKey},
    Address, TapSighash, TapTweakHash,
};
use bitcoin::{TapLeafHash, TapNodeHash, TapSighashType, TxOut};

#[derive(Debug, Clone)]
pub struct Actor {
    pub keypair: Keypair,
    _secret_key: SecretKey,
    pub xonly_public_key: XOnlyPublicKey,
    pub public_key: secp256k1::PublicKey,
    pub address: Address,
}

impl Actor {
    #[tracing::instrument(ret(level = tracing::Level::TRACE))]
    pub fn new(sk: SecretKey, network: bitcoin::Network) -> Self {
        let keypair = Keypair::from_secret_key(&utils::SECP, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&utils::SECP, xonly, None, network);

        Actor {
            keypair,
            _secret_key: keypair.secret_key(),
            xonly_public_key: xonly,
            public_key: keypair.public_key(),
            address,
        }
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_with_tweak(
        &self,
        sighash: TapSighash,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<schnorr::Signature, BridgeError> {
        Ok(utils::SECP.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self.keypair.add_xonly_tweak(
                &utils::SECP,
                &TapTweakHash::from_key_and_tweak(self.xonly_public_key, merkle_root).to_scalar(),
            )?,
        ))
    }

    #[tracing::instrument(skip(self), ret(level = tracing::Level::TRACE))]
    pub fn sign(&self, sighash: TapSighash) -> schnorr::Signature {
        utils::SECP.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self.keypair,
        )
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_taproot_script_spend_tx_new(
        &self,
        tx: &mut TxHandler,
        txin_index: usize,
        script_index: usize,
    ) -> Result<schnorr::Signature, BridgeError> {
        // TODO: if sighash_cache exists in the TxHandler, use it
        // else create a new one and save it to the TxHandler
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx.tx);

        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            &bitcoin::sighash::Prevouts::All(&tx.prevouts),
            TapLeafHash::from_script(
                &tx.scripts[txin_index][script_index],
                LeafVersion::TapScript,
            ),
            bitcoin::sighash::TapSighashType::Default,
        )?;

        Ok(self.sign(sig_hash))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_taproot_pubkey_spend(
        &self,
        tx_handler: &mut TxHandler,
        input_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let mut sighash_cache = SighashCache::new(&mut tx_handler.tx);

        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            input_index,
            &match sighash_type {
                Some(TapSighashType::SinglePlusAnyoneCanPay) => bitcoin::sighash::Prevouts::One(
                    input_index,
                    tx_handler.prevouts[input_index].clone(),
                ),
                _ => bitcoin::sighash::Prevouts::All(&tx_handler.prevouts),
            },
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        self.sign_with_tweak(sig_hash, None)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_taproot_pubkey_spend_tx(
        &self,
        tx: &mut bitcoin::Transaction,
        prevouts: &[TxOut],
        input_index: usize,
    ) -> Result<schnorr::Signature, BridgeError> {
        let mut sighash_cache = SighashCache::new(tx);

        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )?;

        self.sign_with_tweak(sig_hash, None)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_taproot_pubkey_spend_tx_with_sighash(
        &self,
        tx: &mut bitcoin::Transaction,
        prevouts: &[TxOut],
        input_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let mut sighash_cache = SighashCache::new(tx);

        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            input_index,
            &match sighash_type {
                Some(TapSighashType::SinglePlusAnyoneCanPay) => {
                    bitcoin::sighash::Prevouts::One(input_index, prevouts[input_index].clone())
                }
                _ => bitcoin::sighash::Prevouts::All(prevouts),
            },
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        self.sign_with_tweak(sig_hash, None)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_taproot_script_spend_tx_new_tweaked(
        &self,
        tx_handler: &mut TxHandler,
        txin_index: usize,
        script_index: usize,
    ) -> Result<schnorr::Signature, BridgeError> {
        // TODO: if sighash_cache exists in the TxHandler, use it
        // else create a new one and save it to the TxHandler
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx_handler.tx);

        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            &bitcoin::sighash::Prevouts::All(&tx_handler.prevouts),
            TapLeafHash::from_script(
                &tx_handler.scripts[txin_index][script_index],
                LeafVersion::TapScript,
            ),
            bitcoin::sighash::TapSighashType::Default,
        )?;

        self.sign_with_tweak(sig_hash, None)
    }

    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn convert_tx_to_sighash_script_spend(
        tx_handler: &mut TxHandler,
        txin_index: usize,
        script_index: usize,
    ) -> Result<TapSighash, BridgeError> {
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx_handler.tx);

        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            &bitcoin::sighash::Prevouts::All(&tx_handler.prevouts),
            TapLeafHash::from_script(
                &tx_handler.scripts[txin_index][script_index],
                LeafVersion::TapScript,
            ),
            bitcoin::sighash::TapSighashType::Default,
        )?;

        Ok(sig_hash)
    }

    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn convert_tx_to_sighash_pubkey_spend(
        tx: &mut TxHandler,
        txin_index: usize,
    ) -> Result<TapSighash, BridgeError> {
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx.tx);

        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            txin_index,
            &bitcoin::sighash::Prevouts::All(&tx.prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )?;

        Ok(sig_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::Actor;
    use crate::transaction_builder::TxHandler;
    use bitcoin::{
        absolute::Height, transaction::Version, Amount, Network, OutPoint, Transaction, TxIn, TxOut,
    };
    use secp256k1::{rand, Secp256k1, SecretKey};

    /// Returns a valid [`TxHandler`].
    fn create_valid_mock_tx_handler(actor: &Actor) -> TxHandler {
        let mut tx_handler = create_invalid_mock_tx_handler(actor);

        let prev_tx: Transaction = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: tx_handler.prevouts.clone(),
        };

        tx_handler.tx = Transaction {
            version: prev_tx.version,
            lock_time: prev_tx.lock_time,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_tx.compute_txid(),
                    vout: 0,
                },
                script_sig: actor.address.script_pubkey(),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0x1F),
                script_pubkey: actor.address.script_pubkey(),
            }],
        };

        tx_handler
    }
    /// Returns an invalid [`TxHandler`]. Only the tx part is invalid.
    fn create_invalid_mock_tx_handler(actor: &Actor) -> TxHandler {
        let prevouts = vec![TxOut {
            value: Amount::from_sat(0x45),
            script_pubkey: actor.address.script_pubkey(),
        }];

        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(0x1F),
                script_pubkey: actor.address.script_pubkey(),
            }],
        };

        TxHandler {
            tx,
            prevouts,
            scripts: vec![],
            taproot_spend_infos: vec![],
        }
    }

    #[test]
    fn actor_new() {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;

        let actor = Actor::new(sk, network);

        assert_eq!(sk, actor._secret_key);
        assert_eq!(sk.public_key(&secp), actor.public_key);
        assert_eq!(sk.x_only_public_key(&secp).0, actor.xonly_public_key);
    }

    #[test]
    fn sign_taproot_pubkey_spend() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;
        let actor = Actor::new(sk, network);

        // Trying to sign with an invalid transaction will result with an error.
        let mut tx_handler = create_invalid_mock_tx_handler(&actor);
        assert!(actor
            .sign_taproot_pubkey_spend(
                &mut tx_handler,
                0,
                Some(bitcoin::TapSighashType::SinglePlusAnyoneCanPay),
            )
            .is_err());

        // This transaction is matching with prevouts. Therefore signing will
        // be successful.
        tx_handler = create_valid_mock_tx_handler(&actor);
        actor
            .sign_taproot_pubkey_spend(
                &mut tx_handler,
                0,
                Some(bitcoin::TapSighashType::SinglePlusAnyoneCanPay),
            )
            .unwrap();
    }

    #[test]
    fn sign_taproot_pubkey_spend_tx_with_sighash() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;
        let actor = Actor::new(sk, network);

        // Trying to sign with an invalid transaction will result with an error.
        let mut tx_handler = create_invalid_mock_tx_handler(&actor);
        assert!(actor
            .sign_taproot_pubkey_spend_tx_with_sighash(
                &mut tx_handler.tx,
                &tx_handler.prevouts,
                0,
                Some(bitcoin::TapSighashType::SinglePlusAnyoneCanPay),
            )
            .is_err());

        // This transaction is matching with prevouts. Therefore signing will
        // be successful.
        tx_handler = create_valid_mock_tx_handler(&actor);
        actor
            .sign_taproot_pubkey_spend_tx_with_sighash(
                &mut tx_handler.tx,
                &tx_handler.prevouts,
                0,
                Some(bitcoin::TapSighashType::SinglePlusAnyoneCanPay),
            )
            .unwrap();
    }
}
