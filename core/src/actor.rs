use crate::builder::script::SpendPath;
use crate::builder::transaction::input::SpentTxIn;
use crate::builder::transaction::TxHandler;
use crate::errors::BridgeError;
use crate::errors::BridgeError::NotOwnKeyPath;
use crate::operator::PublicHash;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::TaggedSignature;
use crate::utils::{self, SECP};
use bitcoin::hashes::hash160;
use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot::{LeafVersion, TaprootSpendInfo};
use bitcoin::{
    hashes::Hash,
    secp256k1::{schnorr, Keypair, Message, SecretKey, XOnlyPublicKey},
    Address, ScriptBuf, TapSighash, TapTweakHash,
};
use bitcoin::{TapNodeHash, Witness};
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

    fn get_saved_signature(
        signature_id: SignatureId,
        signatures: &[TaggedSignature],
    ) -> Option<schnorr::Signature> {
        signatures
            .iter()
            .find(|sig| {
                sig.signature_id
                    .map(|id| id == signature_id)
                    .unwrap_or(false)
            })
            .and_then(|sig| schnorr::Signature::from_slice(sig.signature.as_ref()).ok())
    }

    fn add_script_path_to_witness(
        witness: &mut Witness,
        script: &ScriptBuf,
        spend_info: &TaprootSpendInfo,
    ) -> Result<(), BridgeError> {
        let spend_control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(BridgeError::ControlBlockError)?;
        witness.push(script.clone());
        witness.push(spend_control_block.serialize());
        Ok(())
    }

    pub fn tx_sign_preimage(
        &self,
        txhandler: &mut TxHandler,
        data: impl AsRef<[u8]>,
    ) -> Result<(), BridgeError> {
        let mut signed_preimage = false;

        let data = data.as_ref();
        let signer =
            move |_: usize,
                  spt: &SpentTxIn,
                  calc_sighash: Box<dyn FnOnce() -> Result<TapSighash, BridgeError> + '_>|
                  -> Result<Option<Witness>, BridgeError> {
                let spendinfo = spt
                    .get_spendable()
                    .get_spend_info()
                    .as_ref()
                    .ok_or(BridgeError::MissingSpendInfo)?;
                match spt.get_spend_path() {
                    SpendPath::ScriptSpend(script_idx) => {
                        let script = spt
                            .get_spendable()
                            .get_scripts()
                            .get(script_idx)
                            .ok_or(BridgeError::NoScriptAtIndex(script_idx))?;

                        use crate::builder::script::ScriptKind as Kind;

                        let mut witness = match script.kind() {
                            Kind::PreimageRevealScript(script) => {
                                if script.0 != self.xonly_public_key {
                                    return Err(BridgeError::NotOwnedScriptPath);
                                }
                                script.generate_script_inputs(data, &self.sign(calc_sighash()?))
                            }
                            Kind::WinternitzCommit(_)
                            | Kind::CheckSig(_)
                            | Kind::Other(_)
                            | Kind::DepositScript(_)
                            | Kind::TimelockScript(_)
                            | Kind::WithdrawalScript(_) => return Ok(None),
                        };

                        if signed_preimage {
                            return Err(BridgeError::MultiplePreimageRevealScripts);
                        }

                        signed_preimage = true;

                        Self::add_script_path_to_witness(
                            &mut witness,
                            &script.to_script_buf(),
                            spendinfo,
                        )?;

                        Ok(Some(witness))
                    }
                    SpendPath::KeySpend => Ok(None),
                    SpendPath::Unknown => Err(BridgeError::SpendPathNotSpecified),
                }
            };

        txhandler.sign_txins(signer)?;
        Ok(())
    }
    pub fn tx_sign_winternitz(
        &self,
        txhandler: &mut TxHandler,
        data: &Vec<u8>,
        path: WinternitzDerivationPath,
    ) -> Result<(), BridgeError> {
        let mut signed_winternitz = false;

        let signer =
            move |_: usize,
                  spt: &SpentTxIn,
                  calc_sighash: Box<dyn FnOnce() -> Result<TapSighash, BridgeError> + '_>|
                  -> Result<Option<Witness>, BridgeError> {
                let spendinfo = spt
                    .get_spendable()
                    .get_spend_info()
                    .as_ref()
                    .ok_or(BridgeError::MissingSpendInfo)?;
                match spt.get_spend_path() {
                    SpendPath::ScriptSpend(script_idx) => {
                        let script = spt
                            .get_spendable()
                            .get_scripts()
                            .get(script_idx)
                            .ok_or(BridgeError::NoScriptAtIndex(script_idx))?;

                        use crate::builder::script::ScriptKind as Kind;

                        let mut witness = match script.kind() {
                            Kind::WinternitzCommit(script) => {
                                if script.1 != self.xonly_public_key {
                                    return Err(BridgeError::NotOwnedScriptPath);
                                }
                                script.generate_script_inputs(
                                    data,
                                    &self.get_derived_winternitz_sk(path)?,
                                    &self.sign(calc_sighash()?),
                                )
                            }
                            Kind::PreimageRevealScript(_)
                            | Kind::CheckSig(_)
                            | Kind::Other(_)
                            | Kind::DepositScript(_)
                            | Kind::TimelockScript(_)
                            | Kind::WithdrawalScript(_) => return Ok(None),
                        };

                        if signed_winternitz {
                            return Err(BridgeError::MultipleWinternitzScripts);
                        }

                        signed_winternitz = true;

                        Self::add_script_path_to_witness(
                            &mut witness,
                            &script.to_script_buf(),
                            spendinfo,
                        )?;

                        Ok(Some(witness))
                    }
                    SpendPath::KeySpend => Ok(None),
                    SpendPath::Unknown => Err(BridgeError::SpendPathNotSpecified),
                }
            };

        txhandler.sign_txins(signer)?;
        Ok(())
    }

    pub fn tx_sign_and_fill_sigs(
        &self,
        txhandler: &mut TxHandler,
        signatures: &[TaggedSignature],
    ) -> Result<(), BridgeError> {
        let signer = move |_,
                           spt: &SpentTxIn,
                           calc_sighash: Box<
            dyn for<'a> FnOnce() -> Result<TapSighash, BridgeError> + '_,
        >|
              -> Result<Option<Witness>, BridgeError> {
            let spendinfo = spt
                .get_spendable()
                .get_spend_info()
                .as_ref()
                .ok_or_else(|| BridgeError::MissingSpendInfo)?;

            match spt.get_spend_path() {
                SpendPath::ScriptSpend(script_idx) => {
                    let script = spt
                        .get_spendable()
                        .get_scripts()
                        .get(script_idx)
                        .ok_or_else(|| BridgeError::NoScriptAtIndex(script_idx))?;
                    let sig = Self::get_saved_signature(spt.get_signature_id(), signatures);
                    use crate::builder::script::ScriptKind as Kind;

                    // Set the script inputs of the witness
                    let mut witness: Witness = match script.kind() {
                        Kind::DepositScript(script) => {
                            match (sig, script.0 == self.xonly_public_key) {
                                (Some(sig), _) => script.generate_script_inputs(&sig),
                                (None, true) => {
                                    script.generate_script_inputs(&self.sign(calc_sighash()?))
                                }
                                (None, false) => return Err(BridgeError::SignatureNotFound),
                            }
                        }
                        Kind::TimelockScript(script) => match (sig, script.0) {
                            (Some(sig), Some(_)) => script.generate_script_inputs(Some(&sig)),
                            (None, Some(xonly_key)) if xonly_key == self.xonly_public_key => {
                                script.generate_script_inputs(Some(&self.sign(calc_sighash()?)))
                            }
                            (None, Some(_)) => return Err(BridgeError::SignatureNotFound),
                            (_, None) => Witness::new(),
                        },
                        Kind::CheckSig(script) => match (sig, script.0 == self.xonly_public_key) {
                            (Some(sig), _) => script.generate_script_inputs(&sig),
                            (None, true) => {
                                script.generate_script_inputs(&self.sign(calc_sighash()?))
                            }
                            (None, false) => return Err(BridgeError::SignatureNotFound),
                        },
                        Kind::WinternitzCommit(_)
                        | Kind::PreimageRevealScript(_)
                        | Kind::Other(_)
                        | Kind::WithdrawalScript(_) => return Ok(None),
                    };

                    // Add P2TR elements (control block and script) to the witness
                    Self::add_script_path_to_witness(
                        &mut witness,
                        &script.to_script_buf(),
                        spendinfo,
                    )?;
                    Ok(Some(witness))
                }
                SpendPath::KeySpend => {
                    let xonly_public_key = spendinfo.internal_key();

                    if xonly_public_key == self.xonly_public_key {
                        let sighash = calc_sighash()?;
                        // TODO: get Schnorr sigs, not Vec<TaggedSignature>, pref in HashMap
                        let sig = Self::get_saved_signature(spt.get_signature_id(), signatures);
                        let sig = match sig {
                            Some(sig) => sig,
                            None => self.sign_with_tweak(sighash, spendinfo.merkle_root())?,
                        };
                        return Ok(Some(Witness::from_slice(&[&sig.serialize()])));
                    }
                    Err(NotOwnKeyPath)
                }
                SpendPath::Unknown => Err(BridgeError::SpendPathNotSpecified),
            }
        };

        txhandler.sign_txins(signer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Actor;
    use crate::builder::address::create_taproot_address;

    use super::*;
    use crate::builder::script::{CheckSig, SpendPath, SpendableScript};
    use crate::builder::transaction::input::SpendableTxIn;
    use crate::builder::transaction::output::UnspentTxOut;
    use crate::builder::transaction::{TxHandler, TxHandlerBuilder};
    use crate::config::BridgeConfig;
    use crate::rpc::clementine::NormalSignatureKind;
    use crate::utils::{initialize_logger, SECP};
    use crate::{
        actor::WinternitzDerivationPath, create_test_config_with_thread_name, database::Database,
        initialize_database,
    };
    use bitcoin::secp256k1::{schnorr, Message, SecretKey};

    use bitcoin::sighash::TapSighashType;
    use bitcoin::transaction::Transaction;

    use bitcoin::{Amount, Network, OutPoint};
    use bitvm::{
        execute_script,
        signatures::winternitz::{
            self, BinarysearchVerifier, StraightforwardConverter, Winternitz,
        },
        treepp::script,
    };
    use rand::thread_rng;
    use secp256k1::rand;
    use std::str::FromStr;
    use std::sync::Arc;

    // Helper: create a TxHandler with a single key spend input.
    fn create_key_spend_tx_handler(actor: &Actor) -> (bitcoin::TxOut, TxHandler) {
        let (tap_addr, spend_info) =
            create_taproot_address(&[], Some(actor.xonly_public_key), Network::Regtest);
        // Build a transaction with one input that expects a key spend signature.
        let prevtxo = bitcoin::TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: tap_addr.script_pubkey(),
        };
        let builder = TxHandlerBuilder::new().add_input(
            NormalSignatureKind::AlreadyDisproved1,
            SpendableTxIn::new(
                OutPoint::default(),
                prevtxo.clone(),
                vec![],
                Some(spend_info),
            ),
            SpendPath::KeySpend,
            bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        );

        (
            prevtxo,
            builder
                .add_output(UnspentTxOut::new(
                    bitcoin::TxOut {
                        value: Amount::from_sat(999),
                        script_pubkey: actor.address.script_pubkey(),
                    },
                    vec![],
                    None,
                ))
                .finalize(),
        )
    }

    // Helper: create a dummy CheckSig script for script spend.
    fn create_dummy_checksig_script(actor: &Actor) -> CheckSig {
        // Use a trivial script that is expected to be spent via a signature.
        // In production this would be a proper P2TR script.
        CheckSig(actor.xonly_public_key)
    }

    // Helper: create a TxHandler with a single script spend input using CheckSig.
    fn create_script_spend_tx_handler(actor: &Actor) -> (bitcoin::TxOut, TxHandler) {
        // Create a dummy spendable input that carries a script.
        // Here we simulate that the spendable has one script: a CheckSig script.
        let script = create_dummy_checksig_script(actor);

        let (tap_addr, spend_info) = create_taproot_address(
            &[script.to_script_buf()],
            Some(actor.xonly_public_key),
            Network::Regtest,
        );

        let prevutxo = bitcoin::TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: tap_addr.script_pubkey(),
        };
        let spendable_input = SpendableTxIn::new(
            OutPoint::default(),
            prevutxo.clone(),
            vec![Arc::new(script)],
            Some(spend_info),
        );

        let builder = TxHandlerBuilder::new().add_input(
            NormalSignatureKind::AlreadyDisproved1,
            spendable_input,
            SpendPath::ScriptSpend(0),
            bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        );

        (
            prevutxo,
            builder
                .add_output(UnspentTxOut::new(
                    bitcoin::TxOut {
                        value: Amount::from_sat(999),
                        script_pubkey: actor.address.script_pubkey(),
                    },
                    vec![],
                    None,
                ))
                .finalize(),
        )
    }

    #[test]
    fn test_actor_key_spend_verification() {
        let sk = SecretKey::new(&mut thread_rng());
        let actor = Actor::new(sk, None, Network::Regtest);
        let (utxo, mut txhandler) = create_key_spend_tx_handler(&actor);

        // Actor signs the key spend input.
        actor
            .tx_sign_and_fill_sigs(&mut txhandler, &[])
            .expect("Key spend signature should succeed");

        // Retrieve the cached transaction from the txhandler.
        let tx: &Transaction = txhandler.get_cached_tx();

        tx.verify(|_| Some(utxo.clone()))
            .expect("Expected valid signature for key spend");
    }

    #[test]
    fn test_actor_script_spend_tx_valid() {
        let sk = SecretKey::new(&mut thread_rng());
        let actor = Actor::new(sk, None, Network::Regtest);
        let (prevutxo, mut txhandler) = create_script_spend_tx_handler(&actor);

        // Actor performs a partial sign for script spend.
        // Using an empty signature slice since our dummy CheckSig uses actor signature.
        let signatures: Vec<_> = vec![];
        actor
            .tx_sign_and_fill_sigs(&mut txhandler, &signatures)
            .expect("Script spend partial sign should succeed");

        // Retrieve the cached transaction.
        let tx: &Transaction = txhandler.get_cached_tx();

        tx.verify(|_| Some(prevutxo.clone()))
            .expect("Invalid transaction");
    }

    #[test]
    fn test_actor_script_spend_sig_valid() {
        let sk = SecretKey::new(&mut thread_rng());
        let actor = Actor::new(sk, None, Network::Regtest);
        let (_, mut txhandler) = create_script_spend_tx_handler(&actor);

        // Actor performs a partial sign for script spend.
        // Using an empty signature slice since our dummy CheckSig uses actor signature.
        let signatures: Vec<_> = vec![];
        actor
            .tx_sign_and_fill_sigs(&mut txhandler, &signatures)
            .expect("Script spend partial sign should succeed");

        // Retrieve the cached transaction.
        let tx: &Transaction = txhandler.get_cached_tx();

        // For script spend, we extract the witness from the corresponding input.
        // Our dummy witness is expected to contain the signature.
        let witness = &tx.input[0].witness;
        assert!(!witness.is_empty(), "Witness should not be empty");
        let sig = schnorr::Signature::from_slice(&witness[0])
            .expect("Failed to parse Schnorr signature from witness");

        // Compute the sighash expected for a pubkey spend (similar to key spend).
        let sighash = txhandler
            .calculate_script_spend_sighash_indexed(0, 0, TapSighashType::Default)
            .expect("Sighash computed");

        let message = Message::from_digest(*sighash.as_byte_array());
        SECP.verify_schnorr(&sig, &message, &actor.xonly_public_key)
            .expect("Script spend signature verification failed");
    }

    // #[test]
    // fn verify_cached_tx() {
    //     let sk = SecretKey::new(&mut rand::thread_rng());
    //     let network = Network::Regtest;
    //     let actor = Actor::new(sk, None, network);

    //     let mut txhandler = create_valid_mock_tx_handler(&actor);

    //     // Sign the transaction
    //     actor
    //         .sign_taproot_pubkey_spend(&mut txhandler, 0, None)
    //         .unwrap();

    //     // Add witness to the transaction
    //     let sig = actor
    //         .sign_taproot_pubkey_spend(&mut txhandler, 0, None)
    //         .unwrap();
    //     txhandler.get_cached_tx().input[0].witness = Witness::p2tr_key_spend(&sig);

    //     // Verify the cached transaction
    //     let cached_tx = txhandler.get_cached_tx();
    //     cached_tx.verify().expect("Transaction verification failed");
    // }

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
        let tx_handler = create_key_spend_tx_handler(&actor).1;
        let sighash = tx_handler
            .calculate_pubkey_spend_sighash(0, bitcoin::TapSighashType::Default)
            .expect("calculating pubkey spend sighash");

        let signature = actor.sign(sighash);

        let message = Message::from_digest(*sighash.as_byte_array());
        SECP.verify_schnorr(&signature, &message, &actor.xonly_public_key)
            .expect("invalid signature");
    }

    #[test]
    fn sign_taproot_pubkey_spend_tx_with_sighash() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;
        let actor = Actor::new(sk, None, network);

        // This transaction is matching with prevouts. Therefore signing will
        // be successful.
        let tx_handler = create_key_spend_tx_handler(&actor).1;
        let x = tx_handler
            .calculate_pubkey_spend_sighash(0, TapSighashType::Default)
            .unwrap();
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
