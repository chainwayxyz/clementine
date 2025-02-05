use crate::builder::transaction::TxHandler;
use crate::errors::BridgeError;
use crate::operator::PublicHash;
use crate::utils::{self, SECP};
use bitcoin::hashes::hash160;
use bitcoin::secp256k1::PublicKey;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    hashes::Hash,
    secp256k1::{schnorr, Keypair, Message, SecretKey, XOnlyPublicKey},
    Address, TapSighash, TapTweakHash,
};
use bitcoin::{TapNodeHash, TapSighashType, TxOut, Witness};
use bitvm::signatures::winternitz::{
    self, BinarysearchVerifier, StraightforwardConverter, Winternitz,
};

/// Available transaction types for [`WinternitzDerivationPath`].
#[derive(Clone, Copy, Debug)]
pub enum TxType {
    SequentialCollateralTx,
    KickoffTx,
    BitVM,
    OperatorLongestChain,
    WatchtowerChallenge,
    OperatorChallengeACK,
}

/// Derivation path specification for Winternitz one time public key generation.
#[derive(Debug, Clone, Copy)]
pub struct WinternitzDerivationPath<'a> {
    pub message_length: u32,
    pub log_d: u32,
    pub tx_type: TxType,
    pub index: Option<u32>,
    pub operator_idx: Option<u32>,
    pub watchtower_idx: Option<u32>,
    pub sequential_collateral_tx_idx: Option<u32>,
    pub kickoff_idx: Option<u32>,
    pub intermediate_step_name: Option<&'a str>,
}
impl WinternitzDerivationPath<'_> {
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
        let sequential_collateral_tx_idx = match self.sequential_collateral_tx_idx {
            None => 0,
            Some(i) => i + 1,
        };
        let kickoff_idx = match self.kickoff_idx {
            None => 0,
            Some(i) => i + 1,
        };
        let intermediate_step_name = match self.intermediate_step_name {
            None => vec![],
            Some(name) => name.as_bytes().to_vec(),
        };

        [
            vec![self.tx_type as u8],
            [
                index.to_be_bytes(),
                operator_idx.to_be_bytes(),
                watchtower_idx.to_be_bytes(),
                sequential_collateral_tx_idx.to_be_bytes(),
                kickoff_idx.to_be_bytes(),
            ]
            .concat(),
            intermediate_step_name,
        ]
        .concat()
    }
}
impl Default for WinternitzDerivationPath<'_> {
    fn default() -> Self {
        Self {
            message_length: Default::default(),
            log_d: 4,
            index: Default::default(),
            tx_type: TxType::SequentialCollateralTx,
            operator_idx: Default::default(),
            watchtower_idx: Default::default(),
            sequential_collateral_tx_idx: Default::default(),
            kickoff_idx: Default::default(),
            intermediate_step_name: Default::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub keypair: Keypair,
    _secret_key: SecretKey,
    winternitz_secret_key: Option<SecretKey>,
    pub xonly_public_key: XOnlyPublicKey,
    pub public_key: PublicKey,
    pub address: Address,
}

impl Actor {
    #[tracing::instrument(ret(level = tracing::Level::TRACE))]
    pub fn new(
        sk: SecretKey,
        winternitz_secret_key: Option<SecretKey>,
        network: bitcoin::Network,
    ) -> Self {
        let keypair = Keypair::from_secret_key(&SECP, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, network);

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
        Ok(utils::SECP.sign_schnorr(
            &Message::from_digest(*sighash.as_byte_array()),
            &self.keypair.add_xonly_tweak(
                &SECP,
                &TapTweakHash::from_key_and_tweak(self.xonly_public_key, merkle_root).to_scalar(),
            )?,
        ))
    }

    #[tracing::instrument(skip(self), ret(level = tracing::Level::TRACE))]
    pub fn sign(&self, sighash: TapSighash) -> schnorr::Signature {
        utils::SECP.sign_schnorr(
            &Message::from_digest(*sighash.as_byte_array()),
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
        let sighash = tx.calculate_script_spend_sighash_indexed(
            txin_index,
            script_index,
            TapSighashType::Default,
        )?;

        Ok(self.sign(sighash))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_taproot_pubkey_spend(
        &self,
        tx_handler: &mut TxHandler,
        input_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let sig_hash = tx_handler.calculate_pubkey_spend_sighash(input_index, sighash_type)?;

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
        let sighash = tx_handler.calculate_script_spend_sighash_indexed(
            txin_index,
            script_index,
            TapSighashType::Default,
        )?;

        self.sign_with_tweak(sighash, None)
    }

    /// Returns derivied Winternitz secret key from given path.
    fn get_derived_winternitz_sk(
        &self,
        path: WinternitzDerivationPath<'_>,
    ) -> Result<winternitz::SecretKey, BridgeError> {
        let wsk = self
            .winternitz_secret_key
            .ok_or(BridgeError::NoWinternitzSecretKey)?;
        Ok([wsk.as_ref().to_vec(), path.to_vec()].concat())
    }

    /// Generates a Winternitz public key for the given path.
    pub fn derive_winternitz_pk(
        &self,
        path: WinternitzDerivationPath<'_>,
    ) -> Result<winternitz::PublicKey, BridgeError> {
        let winternitz_params = winternitz::Parameters::new(path.message_length, path.log_d);

        let altered_secret_key = self.get_derived_winternitz_sk(path)?;
        let public_key = winternitz::generate_public_key(&winternitz_params, &altered_secret_key);

        Ok(public_key)
    }

    /// Signs given data with Winternitz signature.
    pub fn sign_winternitz_signature(
        &self,
        path: WinternitzDerivationPath<'_>,
        data: Vec<u8>,
    ) -> Result<Witness, BridgeError> {
        let winternitz = Winternitz::<BinarysearchVerifier, StraightforwardConverter>::new();
        let winternitz_params = winternitz::Parameters::new(path.message_length, path.log_d);

        let altered_secret_key = self.get_derived_winternitz_sk(path)?;

        let witness = winternitz.sign(&winternitz_params, &altered_secret_key, &data);

        Ok(witness)
    }

    /// Generates the hashes from the preimages. Preimages are constructed using
    /// the Winternitz derivation path and the secret key.
    pub fn generate_public_hash_from_path(
        &self,
        path: WinternitzDerivationPath<'_>,
    ) -> Result<PublicHash, BridgeError> {
        let mut preimage = path.to_vec();
        preimage.extend_from_slice(&self.get_derived_winternitz_sk(path)?);
        let hash = hash160::Hash::hash(&preimage);
        Ok(hash.to_byte_array())
    }
}

#[cfg(test)]
mod tests {
    use super::Actor;
    use crate::builder::address::create_taproot_address;

    use crate::builder::transaction::input::SpendableTxIn;
    use crate::builder::transaction::output::UnspentTxOut;
    use crate::builder::transaction::TxHandlerBuilder;
    use crate::config::BridgeConfig;
    use crate::utils::{initialize_logger, SECP};
    use crate::{
        actor::WinternitzDerivationPath, builder::transaction::TxHandler,
        create_test_config_with_thread_name, database::Database, initialize_database,
    };
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::Sequence;
    use bitcoin::{Amount, Network, OutPoint, TxOut};
    use bitvm::{
        execute_script,
        signatures::winternitz::{
            self, BinarysearchVerifier, StraightforwardConverter, Winternitz,
        },
        treepp::script,
    };
    use secp256k1::rand;
    use std::env;
    use std::str::FromStr;
    use std::thread;

    /// Returns a valid [`TxHandler`].
    fn create_valid_mock_tx_handler(actor: &Actor) -> TxHandler {
        let (op_addr, op_spend) =
            create_taproot_address(&[], Some(actor.xonly_public_key), Network::Regtest);
        let builder = TxHandlerBuilder::new().add_input(
            SpendableTxIn::new(
                OutPoint::default(),
                TxOut {
                    value: Amount::from_sat(1000),
                    script_pubkey: op_addr.script_pubkey(),
                },
                vec![],
                Some(op_spend),
            ),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        );
        builder
            .add_output(UnspentTxOut::new(
                TxOut {
                    value: Amount::from_sat(999),
                    script_pubkey: actor.address.script_pubkey(),
                },
                vec![],
                None,
            ))
            .finalize()
    }

    #[test]
    fn actor_new() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;

        let actor = Actor::new(sk, None, network);

        assert_eq!(sk, actor._secret_key);
        assert_eq!(sk.public_key(&SECP), actor.public_key);
        assert_eq!(sk.x_only_public_key(&SECP).0, actor.xonly_public_key);
    }

    #[test]
    fn sign_taproot_pubkey_spend() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;
        let actor = Actor::new(sk, None, network);

        // This transaction is matching with prevouts. Therefore signing will
        // be successful.
        let mut tx_handler = create_valid_mock_tx_handler(&actor);
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

        // This transaction is matching with prevouts. Therefore signing will
        // be successful.
        let tx_handler = create_valid_mock_tx_handler(&actor);
        let x = tx_handler.calculate_pubkey_spend_sighash(0, None).unwrap();
        actor.sign_with_tweak(x, None).unwrap();
    }

    #[test]
    fn winternitz_derivation_path_to_vec() {
        let mut params = WinternitzDerivationPath::default();
        assert_eq!(
            params.to_vec(),
            [
                vec![0],
                vec![0; 4],
                vec![0; 4],
                vec![0; 4],
                vec![0; 4],
                vec![0; 4],
            ]
            .concat()
        );

        params.index = Some(0);
        assert_eq!(
            params.to_vec(),
            [
                vec![0],
                1u32.to_be_bytes().to_vec(),
                vec![0; 4],
                vec![0; 4],
                vec![0; 4],
                vec![0; 4],
            ]
            .concat()
        );

        params.operator_idx = Some(1);
        assert_eq!(
            params.to_vec(),
            [
                vec![0],
                1u32.to_be_bytes().to_vec(),
                2u32.to_be_bytes().to_vec(),
                vec![0; 4],
                vec![0; 4],
                vec![0; 4],
            ]
            .concat()
        );

        params.watchtower_idx = Some(2);
        assert_eq!(
            params.to_vec(),
            [
                vec![0],
                1u32.to_be_bytes().to_vec(),
                2u32.to_be_bytes().to_vec(),
                3u32.to_be_bytes().to_vec(),
                vec![0; 4],
                vec![0; 4],
            ]
            .concat()
        );

        params.sequential_collateral_tx_idx = Some(3);
        assert_eq!(
            params.to_vec(),
            [
                vec![0],
                1u32.to_be_bytes().to_vec(),
                2u32.to_be_bytes().to_vec(),
                3u32.to_be_bytes().to_vec(),
                4u32.to_be_bytes().to_vec(),
                vec![0; 4],
            ]
            .concat()
        );

        params.kickoff_idx = Some(4);
        assert_eq!(
            params.to_vec(),
            [
                vec![0],
                1u32.to_be_bytes().to_vec(),
                2u32.to_be_bytes().to_vec(),
                3u32.to_be_bytes().to_vec(),
                4u32.to_be_bytes().to_vec(),
                5u32.to_be_bytes().to_vec(),
            ]
            .concat()
        );

        params.intermediate_step_name = Some("step5");
        assert_eq!(
            params.to_vec(),
            [
                vec![0],
                1u32.to_be_bytes().to_vec(),
                2u32.to_be_bytes().to_vec(),
                3u32.to_be_bytes().to_vec(),
                4u32.to_be_bytes().to_vec(),
                5u32.to_be_bytes().to_vec(),
                "step5".as_bytes().to_vec()
            ]
            .concat()
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
                SecretKey::from_str(
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
                SecretKey::from_str(
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
