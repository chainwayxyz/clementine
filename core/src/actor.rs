use crate::builder::transaction::TxHandler;
use crate::errors::BridgeError;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::{
    hashes::Hash,
    secp256k1::{schnorr, Keypair, Message, SecretKey, XOnlyPublicKey},
    Address, TapSighash, TapTweakHash,
};
use bitcoin::{TapLeafHash, TapNodeHash, TapSighashType, TxOut, Witness};
use bitvm::signatures::winternitz::{
    self, BinarysearchVerifier, StraightforwardConverter, Winternitz,
};
use secp256k1::SECP256K1;

/// Available transaction types for [`WinternitzDerivationPath`].
#[derive(Clone, Copy, Debug)]
pub enum TxType {
    TimeTx,
    KickoffTx,
    BitVM,
    OperatorLongestChain,
    WatchtowerChallenge,
}

/// Derivation path specification for Winternitz one time public key generation.
#[derive(Debug, Clone, Copy)]
pub struct WinternitzDerivationPath {
    pub message_length: u32,
    pub log_d: u32,
    pub tx_type: TxType,
    pub index: Option<u32>,
    pub operator_idx: Option<u32>,
    pub watchtower_idx: Option<u32>,
    pub time_tx_idx: Option<u32>,
    pub intermediate_step_idx: Option<u32>,
}
impl WinternitzDerivationPath {
    fn to_vec(self) -> Vec<u8> {
        let index = match self.index {
            None => 0,
            Some(i) => i + 1,
        };
        let operator_idx = match self.operator_idx {
            None => 0,
            Some(i) => i + 1,
        };
        let watchtower_idx = match self.watchtower_idx {
            None => 0,
            Some(i) => i + 1,
        };
        let time_tx_idx = match self.time_tx_idx {
            None => 0,
            Some(i) => i + 1,
        };
        let intermediate_step_idx = match self.intermediate_step_idx {
            None => 0,
            Some(i) => i + 1,
        };

        [
            vec![self.tx_type as u8],
            [
                index.to_be_bytes(),
                operator_idx.to_be_bytes(),
                watchtower_idx.to_be_bytes(),
                time_tx_idx.to_be_bytes(),
                intermediate_step_idx.to_be_bytes(),
            ]
            .concat(),
        ]
        .concat()
    }
}
impl Default for WinternitzDerivationPath {
    fn default() -> Self {
        Self {
            message_length: Default::default(),
            log_d: 4,
            index: Default::default(),
            tx_type: TxType::TimeTx,
            operator_idx: Default::default(),
            watchtower_idx: Default::default(),
            time_tx_idx: Default::default(),
            intermediate_step_idx: Default::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub keypair: Keypair,
    _secret_key: SecretKey,
    winternitz_secret_key: Option<secp256k1::SecretKey>,
    pub xonly_public_key: XOnlyPublicKey,
    pub public_key: secp256k1::PublicKey,
    pub address: Address,
}

impl Actor {
    #[tracing::instrument(ret(level = tracing::Level::TRACE))]
    pub fn new(
        sk: SecretKey,
        winternitz_secret_key: Option<secp256k1::SecretKey>,
        network: bitcoin::Network,
    ) -> Self {
        let keypair = Keypair::from_secret_key(SECP256K1, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(SECP256K1, xonly, None, network);

        Actor {
            keypair,
            _secret_key: keypair.secret_key(),
            winternitz_secret_key,
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
        Ok(SECP256K1.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self.keypair.add_xonly_tweak(
                SECP256K1,
                &TapTweakHash::from_key_and_tweak(self.xonly_public_key, merkle_root).to_scalar(),
            )?,
        ))
    }

    #[tracing::instrument(skip(self), ret(level = tracing::Level::TRACE))]
    pub fn sign(&self, sighash: TapSighash) -> schnorr::Signature {
        SECP256K1.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self.keypair,
        )
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_taproot_script_spend_tx(
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
                &tx.prev_scripts[txin_index][script_index],
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
                &tx_handler.prev_scripts[txin_index][script_index],
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

        let prevouts = bitcoin::sighash::Prevouts::All(&tx_handler.prevouts);
        let leaf_hash = TapLeafHash::from_script(
            tx_handler
                .prev_scripts
                .get(txin_index)
                .ok_or(BridgeError::NoScriptsForTxIn(txin_index))?
                .get(script_index)
                .ok_or(BridgeError::NoScriptAtIndex(script_index))?,
            LeafVersion::TapScript,
        );
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            &prevouts,
            leaf_hash,
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

    /// Returns derivied Winternitz secret key from given path.
    fn get_derived_winternitz_sk(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<winternitz::SecretKey, BridgeError> {
        let wsk = self
            .winternitz_secret_key
            .ok_or(BridgeError::NoWinternitzSecretKey)?;
        Ok([wsk.as_ref().to_vec(), path.to_vec()].concat())
    }

    /// Generates a Winternitz public key for the given path.
    pub fn derive_winternitz_pk(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<winternitz::PublicKey, BridgeError> {
        let winternitz_params = winternitz::Parameters::new(path.message_length, path.log_d);

        let altered_secret_key = self.get_derived_winternitz_sk(path)?;
        let public_key = winternitz::generate_public_key(&winternitz_params, &altered_secret_key);

        Ok(public_key)
    }

    /// Signs given data with Winternitz signature.
    pub fn sign_winternitz_signature(
        &self,
        path: WinternitzDerivationPath,
        data: Vec<u8>,
    ) -> Result<Witness, BridgeError> {
        let winternitz = Winternitz::<BinarysearchVerifier, StraightforwardConverter>::new();
        let winternitz_params = winternitz::Parameters::new(path.message_length, path.log_d);

        let altered_secret_key = self.get_derived_winternitz_sk(path)?;

        let witness = winternitz.sign(&winternitz_params, &altered_secret_key, &data);

        Ok(witness)
    }
}

#[cfg(test)]
mod tests {
    use super::Actor;
    use crate::config::BridgeConfig;
    use crate::utils::initialize_logger;
    use crate::{
        actor::WinternitzDerivationPath, builder::transaction::TxHandler,
        create_test_config_with_thread_name, database::Database, initialize_database,
    };
    use bitcoin::{
        absolute::Height, transaction::Version, Amount, Network, OutPoint, Transaction, TxIn, TxOut,
    };
    use bitvm::{
        execute_script,
        signatures::winternitz::{
            self, BinarysearchVerifier, StraightforwardConverter, Winternitz,
        },
        treepp::script,
    };
    use secp256k1::SECP256K1;
    use secp256k1::{rand, SecretKey};
    use std::env;
    use std::str::FromStr;
    use std::thread;

    /// Returns a valid [`TxHandler`].
    fn create_valid_mock_tx_handler(actor: &Actor) -> TxHandler {
        let mut tx_handler = create_invalid_mock_tx_handler(actor);

        let prev_tx: Transaction = Transaction {
            version: Version(3),
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
            version: Version(3),
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(0x1F),
                script_pubkey: actor.address.script_pubkey(),
            }],
        };

        TxHandler {
            txid: tx.compute_txid(),
            tx,
            prevouts,
            prev_scripts: vec![],
            prev_taproot_spend_infos: vec![],
            out_scripts: vec![],
            out_taproot_spend_infos: vec![],
        }
    }

    #[test]
    fn actor_new() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;

        let actor = Actor::new(sk, None, network);

        assert_eq!(sk, actor._secret_key);
        assert_eq!(sk.public_key(SECP256K1), actor.public_key);
        assert_eq!(sk.x_only_public_key(SECP256K1).0, actor.xonly_public_key);
    }

    #[test]
    fn sign_taproot_pubkey_spend() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;
        let actor = Actor::new(sk, None, network);

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
        let actor = Actor::new(sk, None, network);

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

    #[test]
    fn winternitz_derivation_path_to_vec() {
        let mut params = WinternitzDerivationPath::default();
        assert_eq!(
            params.to_vec(),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        params.index = Some(0);
        assert_eq!(
            params.to_vec(),
            vec![0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        params.operator_idx = Some(1);
        assert_eq!(
            params.to_vec(),
            vec![0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        params.watchtower_idx = Some(2);
        assert_eq!(
            params.to_vec(),
            vec![0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        params.time_tx_idx = Some(3);
        assert_eq!(
            params.to_vec(),
            vec![0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn derive_winternitz_pk_uniqueness() {
        let config = create_test_config_with_thread_name!(None);
        let actor = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            Network::Regtest,
        );

        let mut params = WinternitzDerivationPath::default();
        let pk0 = actor.derive_winternitz_pk(params).unwrap();
        let pk1 = actor.derive_winternitz_pk(params).unwrap();
        assert_eq!(pk0, pk1);

        params.message_length += 1;
        let pk2 = actor.derive_winternitz_pk(params).unwrap();
        assert_ne!(pk0, pk2);
    }

    #[tokio::test]
    async fn derive_winternitz_pk_fixed_pk() {
        let config = create_test_config_with_thread_name!(None);
        let actor = Actor::new(
            config.secret_key,
            Some(
                secp256k1::SecretKey::from_str(
                    "451F451F451F451F451F451F451F451F451F451F451F451F451F451F451F451F",
                )
                .unwrap(),
            ),
            Network::Regtest,
        );

        let params = WinternitzDerivationPath::default();
        let expected_pk = vec![[
            47, 247, 126, 209, 93, 128, 238, 60, 31, 80, 198, 136, 26, 126, 131, 194, 209, 85, 180,
            145,
        ]];
        assert_eq!(actor.derive_winternitz_pk(params).unwrap(), expected_pk);
    }

    #[tokio::test]
    async fn sign_winternitz_signature() {
        let config = create_test_config_with_thread_name!(None);
        let actor = Actor::new(
            config.secret_key,
            Some(
                secp256k1::SecretKey::from_str(
                    "451F451F451F451F451F451F451F451F451F451F451F451F451F451F451F451F",
                )
                .unwrap(),
            ),
            Network::Regtest,
        );

        let data = "iwantporscheasagiftpls".as_bytes().to_vec();
        let path = WinternitzDerivationPath {
            message_length: data.len() as u32,
            log_d: 8,
            ..Default::default()
        };
        let params = winternitz::Parameters::new(path.message_length, path.log_d);

        let witness = actor.sign_winternitz_signature(path, data.clone()).unwrap();
        let pk = actor.derive_winternitz_pk(path).unwrap();

        let winternitz = Winternitz::<BinarysearchVerifier, StraightforwardConverter>::new();
        let check_sig_script = winternitz.checksig_verify(&params, &pk);

        let message_checker = script! {
            for i in 0..path.message_length {
                {data[i as usize]}
                if i == path.message_length - 1 {
                    OP_EQUAL
                } else {
                    OP_EQUALVERIFY
                }
            }
        };

        let script = script!({witness} {check_sig_script} {message_checker});
        let ret = execute_script(script);
        assert!(ret.success);
    }
}
