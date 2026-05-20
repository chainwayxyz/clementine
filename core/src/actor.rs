use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash as StdHash;

use crate::bitvm_client::{self, ClementineBitVMPublicKeys, SECP};
use crate::config::protocol::ProtocolParamset;
use alloy::signers::k256;
use alloy::signers::local::PrivateKeySigner;
use bitcoin::hashes::{hash160, Hash as BitcoinHash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot;
use bitcoin::{
    secp256k1::{schnorr, Keypair, Message, SecretKey, XOnlyPublicKey},
    Address, TapSighash, TapTweakHash,
};
use bitcoin::{Network, OutPoint, TapNodeHash};
use bitvm::signatures::winternitz;
use clementine_errors::BridgeError;
use clementine_errors::TxError;
use clementine_primitives::EVMAddress;
use clementine_primitives::{BridgeRound, PublicHash};
use clementine_utils::sign::TapTweakData;
use eyre::Context;
use hkdf::Hkdf;
use sha2::Sha256;
use tx_builder::script::ScriptLeaf;
use tx_builder::scripts::WinternitzCommit;
use tx_builder::spec::SpendSpec;
use tx_builder::txhandler::TxHandler;
use tx_builder::witness::{WinternitzCommitInput, WitnessInput};
use tx_builder::witness_material::{
    insert_witness_material, WitnessMaterialExt, WitnessMaterialMap,
};

pub use clementine_errors::VerificationError;

#[derive(Debug, Clone)]
pub enum WinternitzDerivationPath {
    /// round_idx, kickoff_idx
    /// Message length is fixed KICKOFF_BLOCKHASH_COMMIT_LENGTH
    Kickoff(BridgeRound, u32, &'static ProtocolParamset),
    /// message_length, pk_type_idx, pk_idx, deposit_outpoint
    BitvmAssert(u32, u32, u32, OutPoint, &'static ProtocolParamset),
    /// watchtower_idx, deposit_outpoint
    /// message length is fixed to 1 (because its for one hash)
    ChallengeAckHash(u32, OutPoint, &'static ProtocolParamset),
}

impl WinternitzDerivationPath {
    fn get_type_id(&self) -> u8 {
        match self {
            WinternitzDerivationPath::Kickoff(..) => 0u8,
            WinternitzDerivationPath::BitvmAssert(..) => 1u8,
            WinternitzDerivationPath::ChallengeAckHash(..) => 2u8,
        }
    }

    fn get_network_prefix(&self) -> u8 {
        let paramset = match self {
            WinternitzDerivationPath::Kickoff(.., paramset) => paramset,
            WinternitzDerivationPath::BitvmAssert(.., paramset) => paramset,
            WinternitzDerivationPath::ChallengeAckHash(.., paramset) => paramset,
        };
        match paramset.network {
            Network::Regtest => 0u8,
            Network::Testnet4 => 1u8,
            Network::Signet => 2u8,
            Network::Bitcoin => 3u8,
            // currently only testnet is unsupported
            _ => panic!("Unsupported network {:?}", paramset.network),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let type_id = self.get_type_id();
        let mut bytes = vec![type_id, self.get_network_prefix()];

        match self {
            WinternitzDerivationPath::Kickoff(round_idx, kickoff_idx, _) => {
                bytes.extend_from_slice(&round_idx.to_index().to_be_bytes());
                bytes.extend_from_slice(&kickoff_idx.to_be_bytes());
            }
            WinternitzDerivationPath::BitvmAssert(
                message_length,
                pk_type_idx,
                pk_idx,
                deposit_outpoint,
                _,
            ) => {
                bytes.extend_from_slice(&message_length.to_be_bytes());
                bytes.extend_from_slice(&pk_type_idx.to_be_bytes());
                bytes.extend_from_slice(&pk_idx.to_be_bytes());
                bytes.extend_from_slice(&deposit_outpoint.txid.to_byte_array());
                bytes.extend_from_slice(&deposit_outpoint.vout.to_be_bytes());
            }
            WinternitzDerivationPath::ChallengeAckHash(watchtower_idx, deposit_outpoint, _) => {
                bytes.extend_from_slice(&watchtower_idx.to_be_bytes());
                bytes.extend_from_slice(&deposit_outpoint.txid.to_byte_array());
                bytes.extend_from_slice(&deposit_outpoint.vout.to_be_bytes());
            }
        }

        bytes
    }

    /// Returns the parameters for the Winternitz signature.
    pub fn get_params(&self) -> winternitz::Parameters {
        match self {
            WinternitzDerivationPath::Kickoff(_, _, paramset) => winternitz::Parameters::new(
                paramset.kickoff_blockhash_commit_length,
                paramset.winternitz_log_d,
            ),
            WinternitzDerivationPath::BitvmAssert(message_length, _, _, _, paramset) => {
                winternitz::Parameters::new(*message_length, paramset.winternitz_log_d)
            }
            WinternitzDerivationPath::ChallengeAckHash(_, _, paramset) => {
                winternitz::Parameters::new(1, paramset.winternitz_log_d)
            }
        }
    }
}

fn calc_tweaked_keypair(
    keypair: &Keypair,
    merkle_root: Option<TapNodeHash>,
) -> Result<Keypair, BridgeError> {
    Ok(keypair
        .add_xonly_tweak(
            &SECP,
            &TapTweakHash::from_key_and_tweak(keypair.x_only_public_key().0, merkle_root)
                .to_scalar(),
        )
        .wrap_err("Failed to add tweak to keypair")?)
}

fn calc_tweaked_xonly_pk(
    pubkey: XOnlyPublicKey,
    merkle_root: Option<TapNodeHash>,
) -> Result<XOnlyPublicKey, BridgeError> {
    Ok(pubkey
        .add_tweak(
            &SECP,
            &TapTweakHash::from_key_and_tweak(pubkey, merkle_root).to_scalar(),
        )
        .wrap_err("Failed to add tweak to xonly_pk")?
        .0)
}

#[derive(Debug, Clone, Default)]
// A cache that holds tweaked keys so that we do not need to repeatedly calculate them.
// This cache will hold data for only one deposit generally because we need to clone the holder of Actor(owner or verifier)
// to spawned threads during deposit and jn general is immutable.
// (Because all grpc functions have &self, we also need to clone Actor to a mutable instance
// to modify the caches)
pub struct TweakCache {
    tweaked_key_cache: HashMap<(XOnlyPublicKey, Option<TapNodeHash>), XOnlyPublicKey>,
    // A cache to hold actors own tweaked keys.
    tweaked_keypair_cache: HashMap<(XOnlyPublicKey, Option<TapNodeHash>), Keypair>,
}

impl TweakCache {
    fn get_tweaked_keypair(
        &mut self,
        keypair: &Keypair,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<&Keypair, BridgeError> {
        match self
            .tweaked_keypair_cache
            .entry((keypair.x_only_public_key().0, merkle_root))
        {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => Ok(entry.insert(calc_tweaked_keypair(keypair, merkle_root)?)),
        }
    }

    fn get_tweaked_xonly_key(
        &mut self,
        pubkey: XOnlyPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<XOnlyPublicKey, BridgeError> {
        match self.tweaked_key_cache.entry((pubkey, merkle_root)) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => Ok(*entry.insert(calc_tweaked_xonly_pk(pubkey, merkle_root)?)),
        }
    }
}

pub fn verify_schnorr(
    signature: &schnorr::Signature,
    sighash: &Message,
    pubkey: XOnlyPublicKey,
    tweak_data: TapTweakData,
    tweak_cache: Option<&mut TweakCache>,
) -> Result<(), BridgeError> {
    let pubkey = match tweak_data {
        TapTweakData::KeyPath(merkle_root) => match tweak_cache {
            Some(cache) => cache.get_tweaked_xonly_key(pubkey, merkle_root)?,
            None => calc_tweaked_xonly_pk(pubkey, merkle_root)?,
        },
        TapTweakData::ScriptPath => pubkey,
        TapTweakData::Unknown => return Err(eyre::eyre!("Spend Path Unknown").into()),
    };
    SECP.verify_schnorr(signature, sighash, &pubkey)
        .map_err(|_| eyre::eyre!("Failed to verify Schnorr signature").into())
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub keypair: Keypair,
    pub xonly_public_key: XOnlyPublicKey,
    pub public_key: PublicKey,
    pub address: Address,
}

impl Actor {
    pub fn new(sk: SecretKey, network: bitcoin::Network) -> Self {
        let keypair = Keypair::from_secret_key(&SECP, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, network);

        Actor {
            keypair,
            xonly_public_key: xonly,
            public_key: keypair.public_key(),
            address,
        }
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR))]
    fn sign_with_tweak(
        &self,
        sighash: TapSighash,
        merkle_root: Option<TapNodeHash>,
        tweak_cache: Option<&mut TweakCache>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let keypair;
        let keypair_ref = match tweak_cache {
            Some(cache) => cache.get_tweaked_keypair(&self.keypair, merkle_root)?,
            None => {
                keypair = calc_tweaked_keypair(&self.keypair, merkle_root)?;
                &keypair
            }
        };

        Ok(bitvm_client::SECP
            .sign_schnorr(&Message::from_digest(*sighash.as_byte_array()), keypair_ref))
    }

    #[tracing::instrument(skip(self))]
    fn sign(&self, sighash: TapSighash) -> schnorr::Signature {
        bitvm_client::SECP.sign_schnorr(
            &Message::from_digest(*sighash.as_byte_array()),
            &self.keypair,
        )
    }

    pub fn sign_with_tweak_data(
        &self,
        sighash: TapSighash,
        tweak_data: TapTweakData,
        tweak_cache: Option<&mut TweakCache>,
    ) -> Result<schnorr::Signature, BridgeError> {
        match tweak_data {
            TapTweakData::KeyPath(merkle_root) => {
                self.sign_with_tweak(sighash, merkle_root, tweak_cache)
            }
            TapTweakData::ScriptPath => Ok(self.sign(sighash)),
            TapTweakData::Unknown => Err(eyre::eyre!("Spend Data Unknown").into()),
        }
    }

    pub fn get_evm_address(&self) -> Result<EVMAddress, BridgeError> {
        let x =
            k256::ecdsa::SigningKey::from_bytes(&self.keypair.secret_key().secret_bytes().into())
                .wrap_err("Failed to convert secret key to signing key")?;
        let key: PrivateKeySigner = x.into();
        let wallet_address = key.address();

        Ok(EVMAddress(wallet_address.into_array()))
    }

    /// Returns derivied Winternitz secret key from given path.
    pub fn get_derived_winternitz_sk(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<winternitz::SecretKey, BridgeError> {
        let hk = Hkdf::<Sha256>::new(None, self.keypair.secret_key().as_ref());
        let path_bytes = path.to_bytes();
        let mut derived_key = vec![0u8; 32];
        hk.expand(&path_bytes, &mut derived_key)
            .map_err(|e| eyre::eyre!("Key derivation failed: {:?}", e))?;

        Ok(derived_key)
    }

    /// Generates a Winternitz public key for the given path.
    pub fn derive_winternitz_pk(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<winternitz::PublicKey, BridgeError> {
        let winternitz_params = path.get_params();

        let altered_secret_key = self.get_derived_winternitz_sk(path)?;
        let public_key = winternitz::generate_public_key(&winternitz_params, &altered_secret_key);

        Ok(public_key)
    }

    pub fn generate_preimage_from_path(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<PublicHash, BridgeError> {
        let first_preimage = self.get_derived_winternitz_sk(path)?;
        let second_preimage = <hash160::Hash as BitcoinHash>::hash(&first_preimage);
        Ok(second_preimage.to_byte_array())
    }

    /// Generates the hashes from the preimages. Preimages are constructed using
    /// the Winternitz derivation path and the secret key.
    pub fn generate_public_hash_from_path(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<PublicHash, BridgeError> {
        let preimage = self.generate_preimage_from_path(path)?;
        let hash = <hash160::Hash as BitcoinHash>::hash(&preimage);
        Ok(hash.to_byte_array())
    }

    pub fn generate_bitvm_pks_for_deposit(
        &self,
        deposit_outpoint: OutPoint,
        paramset: &'static ProtocolParamset,
    ) -> Result<ClementineBitVMPublicKeys, BridgeError> {
        let mut pks = ClementineBitVMPublicKeys::create_replacable();
        let pk_vec = self.derive_winternitz_pk(
            ClementineBitVMPublicKeys::get_latest_blockhash_derivation(deposit_outpoint, paramset),
        )?;
        pks.latest_blockhash_pk = ClementineBitVMPublicKeys::vec_to_array::<43>(&pk_vec);
        let pk_vec = self.derive_winternitz_pk(
            ClementineBitVMPublicKeys::get_challenge_sending_watchtowers_derivation(
                deposit_outpoint,
                paramset,
            ),
        )?;
        pks.challenge_sending_watchtowers_pk =
            ClementineBitVMPublicKeys::vec_to_array::<43>(&pk_vec);
        for i in 0..pks.bitvm_pks.0.len() {
            let pk_vec = self.derive_winternitz_pk(WinternitzDerivationPath::BitvmAssert(
                64,
                3,
                i as u32,
                deposit_outpoint,
                paramset,
            ))?;
            pks.bitvm_pks.0[i] = ClementineBitVMPublicKeys::vec_to_array::<67>(&pk_vec);
        }
        for i in 0..pks.bitvm_pks.1.len() {
            let pk_vec = self.derive_winternitz_pk(WinternitzDerivationPath::BitvmAssert(
                64,
                4,
                i as u32,
                deposit_outpoint,
                paramset,
            ))?;
            pks.bitvm_pks.1[i] = ClementineBitVMPublicKeys::vec_to_array::<67>(&pk_vec);
        }
        for i in 0..pks.bitvm_pks.2.len() {
            let pk_vec = self.derive_winternitz_pk(WinternitzDerivationPath::BitvmAssert(
                32,
                5,
                i as u32,
                deposit_outpoint,
                paramset,
            ))?;
            pks.bitvm_pks.2[i] = ClementineBitVMPublicKeys::vec_to_array::<35>(&pk_vec);
        }

        Ok(pks)
    }

    pub fn sign_schnorr<Tx, Input, Output, Leaf, ActorId>(
        &self,
        txhandler: &mut TxHandler<Tx, Input, Output, Leaf, ActorId>,
        mut tweak_cache: Option<&mut TweakCache>,
    ) -> Result<(), BridgeError>
    where
        Tx: Clone,
        Input: Clone + Eq + StdHash + Debug,
        Output: Clone + Eq + StdHash + Debug,
        Leaf: Clone + Debug + PartialEq,
        ActorId: Clone + Debug,
    {
        let mut materials = WitnessMaterialMap::new();

        for input_idx in 0..txhandler.input_count() {
            let input_id = txhandler.input_for_index(input_idx)?;
            if txhandler.input_has_witness(input_id.clone())? {
                continue;
            }
            let spend = txhandler.spend(input_id.clone())?;
            let spendable = txhandler.spendable_for_input(input_id.clone())?;
            let spendinfo_binding = spendable.get_spend_info();
            let spendinfo = spendinfo_binding
                .as_ref()
                .ok_or(TxError::MissingSpendInfo)?;
            let sighash_type = txhandler.sighash_type_for_input(input_id.clone())?;

            let sighash = txhandler.tap_sighash_for_input(input_id.clone())?;
            match &spend {
                SpendSpec::NamedLeaf { leaf, .. } => {
                    let script = txhandler
                        .named_leaf_script_for_input(input_id.clone())?
                        .ok_or_else(|| {
                            eyre::eyre!("Named leaf {:?} not found on input {:?}", leaf, input_id)
                        })?;

                    let material = match script {
                        ScriptLeaf::Timelock(script) if script.pk.is_none() => {
                            Some(input_id.witness_input(WitnessInput::Timelock(None)))
                        }
                        ScriptLeaf::WinternitzCommit(_)
                        | ScriptLeaf::PreimageReveal(_)
                        | ScriptLeaf::Multisig(_)
                        | ScriptLeaf::Other(_) => None,
                        _ => {
                            let xonly_public_key = script.sig_owner_key().ok_or_else(|| {
                                TxError::Other(eyre::eyre!(
                                    "Missing sig owner key for keyed single-signature leaf {} on input {:?}",
                                    script.kind_name(),
                                    input_id
                                ))
                            })?;
                            if xonly_public_key != self.xonly_public_key {
                                continue;
                            }
                            Some(input_id.signature(self.sign(sighash)))
                        }
                    };

                    if let Some(material) = material {
                        insert_witness_material(&mut materials, material)?;
                    }
                }
                SpendSpec::KeySpend { .. } => {
                    let xonly_public_key = spendinfo.internal_key();
                    if xonly_public_key != self.xonly_public_key {
                        continue;
                    }
                    let sig = taproot::Signature {
                        signature: self.sign_with_tweak(
                            sighash,
                            spendinfo.merkle_root(),
                            tweak_cache.as_deref_mut(),
                        )?,
                        sighash_type,
                    };

                    insert_witness_material(&mut materials, input_id.signature(sig.signature))?;
                }
                SpendSpec::RevealRequired { .. } => continue,
            }
        }

        txhandler.fill_witnesses(&materials)
    }

    pub fn sign_preimage<Tx, Input, Output, Leaf, ActorId>(
        &self,
        txhandler: &mut TxHandler<Tx, Input, Output, Leaf, ActorId>,
        data: impl AsRef<[u8]>,
    ) -> Result<(), BridgeError>
    where
        Tx: Clone,
        Input: Clone + Eq + StdHash + Debug,
        Output: Clone + Eq + StdHash + Debug,
        Leaf: Clone + Debug + PartialEq,
        ActorId: Clone + Debug,
    {
        let mut materials = WitnessMaterialMap::new();
        let mut signed_preimage = false;
        let data = data.as_ref();

        for input_idx in 0..txhandler.input_count() {
            let input_id = txhandler.input_for_index(input_idx)?;
            if txhandler.input_has_witness(input_id.clone())? {
                continue;
            }
            let spend = txhandler.spend(input_id.clone())?;
            match &spend {
                SpendSpec::NamedLeaf { leaf, .. } => {
                    let script = txhandler
                        .named_leaf_script_for_input(input_id.clone())?
                        .ok_or_else(|| {
                            eyre::eyre!("Named leaf {:?} not found on input {:?}", leaf, input_id)
                        })?;
                    let signature = match script {
                        ScriptLeaf::PreimageReveal(script) => {
                            if script.pk != self.xonly_public_key {
                                return Err(TxError::NotOwnedScriptPath.into());
                            }
                            self.sign(txhandler.tap_sighash_for_input(input_id.clone())?)
                        }
                        ScriptLeaf::WinternitzCommit(_)
                        | ScriptLeaf::CheckSig(_)
                        | ScriptLeaf::Multisig(_)
                        | ScriptLeaf::Other(_)
                        | ScriptLeaf::BaseDeposit(_)
                        | ScriptLeaf::ReplacementDeposit(_)
                        | ScriptLeaf::Timelock(_) => continue,
                    };

                    if signed_preimage {
                        return Err(eyre::eyre!("Encountered multiple preimage reveal scripts when attempting to commit to only one.").into());
                    }
                    signed_preimage = true;

                    insert_witness_material(
                        &mut materials,
                        input_id.preimage_reveal(signature, data.to_vec()),
                    )?;
                }
                SpendSpec::KeySpend { .. } => {}
                SpendSpec::RevealRequired { .. } => continue,
            }
        }

        txhandler.fill_witnesses(&materials)
    }

    pub fn sign_winternitz<Tx, Input, Output, Leaf, ActorId>(
        &self,
        txhandler: &mut TxHandler<Tx, Input, Output, Leaf, ActorId>,
        data: &[(Vec<u8>, WinternitzDerivationPath)],
    ) -> Result<(), BridgeError>
    where
        Tx: Clone,
        Input: Clone + Eq + StdHash + Debug,
        Output: Clone + Eq + StdHash + Debug,
        Leaf: Clone + Debug + PartialEq,
        ActorId: Clone + Debug,
    {
        let mut materials = WitnessMaterialMap::new();
        let mut signed_winternitz = false;

        for input_idx in 0..txhandler.input_count() {
            let input_id = txhandler.input_for_index(input_idx)?;
            if txhandler.input_has_witness(input_id.clone())? {
                continue;
            }
            let spend = txhandler.spend(input_id.clone())?;
            match &spend {
                SpendSpec::NamedLeaf { leaf, .. } => {
                    let script = txhandler
                        .named_leaf_script_for_input(input_id.clone())?
                        .ok_or_else(|| {
                            eyre::eyre!("Named leaf {:?} not found on input {:?}", leaf, input_id)
                        })?;
                    let witness_input = match script {
                        ScriptLeaf::WinternitzCommit(script) => {
                            WitnessInput::WinternitzCommit(self.build_winternitz_commit_input(
                                script,
                                txhandler.tap_sighash_for_input(input_id.clone())?,
                                txhandler.sighash_type_for_input(input_id.clone())?,
                                data,
                            )?)
                        }
                        ScriptLeaf::PreimageReveal(_)
                        | ScriptLeaf::CheckSig(_)
                        | ScriptLeaf::Multisig(_)
                        | ScriptLeaf::Other(_)
                        | ScriptLeaf::BaseDeposit(_)
                        | ScriptLeaf::ReplacementDeposit(_)
                        | ScriptLeaf::Timelock(_) => continue,
                    };

                    if signed_winternitz {
                        return Err(eyre::eyre!("Encountered multiple winternitz scripts when attempting to commit to only one.").into());
                    }
                    signed_winternitz = true;

                    insert_witness_material(&mut materials, input_id.witness_input(witness_input))?;
                }
                SpendSpec::KeySpend { .. } => {}
                SpendSpec::RevealRequired { .. } => continue,
            }
        }

        txhandler.fill_witnesses(&materials)
    }

    pub fn build_winternitz_commit_input(
        &self,
        script: &WinternitzCommit,
        sighash: TapSighash,
        sighash_type: bitcoin::TapSighashType,
        data: &[(Vec<u8>, WinternitzDerivationPath)],
    ) -> Result<WinternitzCommitInput, BridgeError> {
        if script.checksig_pubkey != self.xonly_public_key {
            return Err(TxError::NotOwnedScriptPath.into());
        }

        let mut stack_items = Vec::new();
        for (index, (data, path)) in data.iter().enumerate().rev() {
            let secret_key = self.get_derived_winternitz_sk(path.clone())?;
            let witness = bitvm::signatures::signing_winternitz::WINTERNITZ_MESSAGE_VERIFIER.sign(
                &script.get_params(index),
                &secret_key,
                data,
            );
            stack_items.extend(witness.iter().map(|item| item.to_vec()));
        }

        Ok(WinternitzCommitInput {
            signature: taproot::Signature {
                signature: self.sign(sighash),
                sighash_type,
            },
            stack_items,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Actor;
    use crate::builder::address::create_taproot_address;
    use crate::builder::transaction::custom::{
        builder as custom_builder, current_tx as custom_current_tx, input as custom_input,
        named_leaf_descriptor, output as custom_output, output_from_script_leaves,
        sign_with_actor as sign_custom_with_actor, spendable_from_script_leaves, CustomTxHandler,
    };
    use crate::config::protocol::ProtocolParamsetName;

    use super::*;
    use crate::builder::transaction::{TxHandler, TxHandlerBuilder};
    use crate::protocol::ids::TransactionType;
    use crate::protocol::spec::SpendSpec;
    use crate::protocol::tx::{
        challenge::ChallengeInput, move_to_vault::MoveToVaultOutput, reimburse::ReimburseInput,
    };

    use crate::bitvm_client::SECP;
    use crate::{actor::WinternitzDerivationPath, test::common::*};
    use bitcoin::secp256k1::{schnorr, Message, SecretKey};

    use bitcoin::sighash::TapSighashType;
    use bitcoin::transaction::Transaction;

    use bitcoin::secp256k1::rand;
    use bitcoin::{Amount, Network, OutPoint, Txid};
    use bitcoincore_rpc::RpcApi;
    use bitvm::{
        execute_script,
        signatures::winternitz::{self, BinarysearchVerifier, ToBytesConverter, Winternitz},
        treepp::script,
    };
    use rand::thread_rng;
    use std::str::FromStr;
    use tx_builder::script::ScriptLeaf as RuntimeScriptLeaf;
    use tx_builder::scripts::CheckSig as RuntimeCheckSig;

    // Helper: create a TxHandler with a single key spend input.
    fn create_key_spend_tx_handler(actor: &Actor) -> (bitcoin::TxOut, TxHandler) {
        let (tap_addr, spend_info) =
            create_taproot_address(&[], Some(actor.xonly_public_key), Network::Regtest);
        // Build a transaction with one input that expects a key spend signature.
        let prevtxo = bitcoin::TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: tap_addr.script_pubkey(),
        };
        let builder = TxHandlerBuilder::new(TransactionType::MoveToVault).add_input(
            ReimburseInput::ReimburseInKickoff,
            crate::builder::transaction::spendable_txin(
                OutPoint::default(),
                prevtxo.clone(),
                vec![],
                vec![],
                Some(spend_info),
            ),
            bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            crate::builder::transaction::input_descriptor(SpendSpec::key_spend()),
        );

        (
            prevtxo,
            builder
                .add_output(
                    MoveToVaultOutput::DepositInMove,
                    crate::builder::transaction::unspent_txout(
                        bitcoin::TxOut {
                            value: Amount::from_sat(999),
                            script_pubkey: actor.address.script_pubkey(),
                        },
                        vec![],
                        vec![],
                        None,
                    ),
                )
                .finalize(),
        )
    }

    fn create_custom_script_spend_tx_handler(actor: &Actor) -> (bitcoin::TxOut, CustomTxHandler) {
        let script = RuntimeScriptLeaf::CheckSig(RuntimeCheckSig::new(actor.xonly_public_key));
        let spendable_input = spendable_from_script_leaves(
            0,
            OutPoint::default(),
            Amount::from_sat(1000),
            vec![script.clone()],
            Some(actor.xonly_public_key),
            Network::Regtest,
        );
        let prevutxo = spendable_input.get_prevout().clone();
        let (_, output) = output_from_script_leaves(
            0,
            Amount::from_sat(999),
            vec![script],
            Some(actor.xonly_public_key),
            Network::Regtest,
        );

        let txhandler = custom_builder(0)
            .add_input(
                custom_input(0),
                spendable_input,
                bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                named_leaf_descriptor(0, 0, TapSighashType::Default),
            )
            .add_output(custom_output(0), output)
            .finalize();

        (prevutxo, txhandler)
    }

    #[test]
    fn test_actor_key_spend_verification() {
        let sk = SecretKey::new(&mut thread_rng());
        let actor = Actor::new(sk, Network::Regtest);
        let (utxo, mut txhandler) = create_key_spend_tx_handler(&actor);

        // Actor signs the key spend input.
        crate::builder::transaction::sign::apply_schnorr_signatures(
            &actor,
            &mut txhandler,
            &[],
            None,
        )
        .expect("Key spend signature should succeed");

        // Retrieve the cached transaction from the txhandler.
        let tx: &Transaction = txhandler.transaction();

        tx.verify(|_| Some(utxo.clone()))
            .expect("Expected valid signature for key spend");
    }

    #[test]
    fn test_actor_script_spend_tx_valid() {
        let sk = SecretKey::new(&mut thread_rng());
        let actor = Actor::new(sk, Network::Regtest);
        let (prevutxo, mut txhandler) = create_custom_script_spend_tx_handler(&actor);

        sign_custom_with_actor(&actor, &mut txhandler)
            .expect("Script spend partial sign should succeed");

        let tx = custom_current_tx(&txhandler);

        tx.verify(|_| Some(prevutxo.clone()))
            .expect("Invalid transaction");
    }

    #[test]
    fn test_actor_script_spend_sig_valid() {
        let sk = SecretKey::new(&mut thread_rng());
        let actor = Actor::new(sk, Network::Regtest);
        let (_, mut txhandler) = create_custom_script_spend_tx_handler(&actor);

        sign_custom_with_actor(&actor, &mut txhandler)
            .expect("Script spend partial sign should succeed");

        let tx = custom_current_tx(&txhandler);

        // For script spend, we extract the witness from the corresponding input.
        // Our dummy witness is expected to contain the signature.
        let witness = &tx.input[0].witness;
        assert!(!witness.is_empty(), "Witness should not be empty");
        let sig = schnorr::Signature::from_slice(&witness[0])
            .expect("Failed to parse Schnorr signature from witness");

        // Compute the sighash expected for a pubkey spend (similar to key spend).
        let sighash = txhandler
            .sighash_for_input(custom_input(0))
            .expect("Sighash computed");

        let message = Message::from_digest(sighash);
        SECP.verify_schnorr(&sig, &message, &actor.xonly_public_key)
            .expect("Script spend signature verification failed");
    }

    #[test]
    fn sign_schnorr_skips_foreign_inputs() {
        let actor = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let foreign = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let (_, mut txhandler) = create_key_spend_tx_handler(&foreign);

        actor
            .sign_schnorr(&mut txhandler, None)
            .expect("foreign inputs should be ignored");

        assert!(
            txhandler
                .witness_for_input(ReimburseInput::ReimburseInKickoff)
                .expect("witness lookup")
                .is_none(),
            "foreign input should not be signed"
        );
    }

    #[test]
    fn actor_new() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;

        let actor = Actor::new(sk, network);

        assert_eq!(sk.public_key(&SECP), actor.public_key);
        assert_eq!(sk.x_only_public_key(&SECP).0, actor.xonly_public_key);
    }

    #[test]
    fn sign_taproot_pubkey_spend() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = Network::Regtest;
        let actor = Actor::new(sk, network);

        // This transaction is matching with prevouts. Therefore signing will
        // be successful.
        let tx_handler = create_key_spend_tx_handler(&actor).1;
        let sighash = tx_handler
            .tap_sighash_for_input(ReimburseInput::ReimburseInKickoff)
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
        let actor = Actor::new(sk, network);

        // This transaction is matching with prevouts. Therefore signing will
        // be successful.
        let tx_handler = create_key_spend_tx_handler(&actor).1;
        let x = tx_handler
            .tap_sighash_for_input(ReimburseInput::ReimburseInKickoff)
            .unwrap();
        actor.sign_with_tweak(x, None, None).unwrap();
    }

    #[tokio::test]
    async fn derive_winternitz_pk_uniqueness() {
        let paramset: &'static ProtocolParamset = ProtocolParamsetName::Regtest.into();
        let config = create_test_config_with_thread_name().await;
        let actor = Actor::new(config.secret_key, Network::Regtest);

        let mut params = WinternitzDerivationPath::Kickoff(BridgeRound::Round(0), 0, paramset);
        let pk0 = actor.derive_winternitz_pk(params.clone()).unwrap();
        let pk1 = actor.derive_winternitz_pk(params).unwrap();
        assert_eq!(pk0, pk1);

        params = WinternitzDerivationPath::Kickoff(BridgeRound::Round(0), 1, paramset);
        let pk2 = actor.derive_winternitz_pk(params).unwrap();
        assert_ne!(pk0, pk2);
    }

    impl TweakCache {
        fn get_tweaked_xonly_key_cache_size(&self) -> usize {
            self.tweaked_key_cache.len()
        }
        fn get_tweaked_keypair_cache_size(&self) -> usize {
            self.tweaked_keypair_cache.len()
        }
    }

    #[tokio::test]
    async fn test_tweak_cache() {
        let mut tweak_cache = TweakCache::default();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let keypair = Keypair::from_secret_key(&SECP, &sk);
        let sk2 = SecretKey::new(&mut rand::thread_rng());
        let keypair2 = Keypair::from_secret_key(&SECP, &sk2);
        let sk3 = SecretKey::new(&mut rand::thread_rng());
        let keypair3 = Keypair::from_secret_key(&SECP, &sk3);

        tweak_cache.get_tweaked_keypair(&keypair, None).unwrap();
        assert!(tweak_cache.get_tweaked_keypair_cache_size() == 1);
        tweak_cache
            .get_tweaked_keypair(&keypair, Some(TapNodeHash::assume_hidden([0x55; 32])))
            .unwrap();
        assert!(tweak_cache.get_tweaked_keypair_cache_size() == 2);
        tweak_cache
            .get_tweaked_keypair(&keypair, Some(TapNodeHash::assume_hidden([0x56; 32])))
            .unwrap();
        assert!(tweak_cache.get_tweaked_keypair_cache_size() == 3);
        tweak_cache
            .get_tweaked_keypair(&keypair, Some(TapNodeHash::assume_hidden([0x57; 32])))
            .unwrap();
        assert!(tweak_cache.get_tweaked_keypair_cache_size() == 4);
        tweak_cache
            .get_tweaked_keypair(&keypair, Some(TapNodeHash::assume_hidden([0x55; 32])))
            .unwrap();
        tweak_cache.get_tweaked_keypair(&keypair, None).unwrap();
        assert!(tweak_cache.get_tweaked_keypair_cache_size() == 4);
        tweak_cache.get_tweaked_keypair(&keypair2, None).unwrap();
        assert!(tweak_cache.get_tweaked_keypair_cache_size() == 5);
        let xonly_pk1 = keypair.x_only_public_key();
        let xonly_pk2 = keypair2.x_only_public_key();
        let xonly_pk3 = keypair3.x_only_public_key();

        // Test for get_tweaked_xonly_key
        tweak_cache
            .get_tweaked_xonly_key(xonly_pk1.0, None)
            .unwrap();
        assert!(tweak_cache.get_tweaked_xonly_key_cache_size() == 1);
        tweak_cache
            .get_tweaked_xonly_key(xonly_pk1.0, Some(TapNodeHash::assume_hidden([0x55; 32])))
            .unwrap();
        assert!(tweak_cache.get_tweaked_xonly_key_cache_size() == 2);
        tweak_cache
            .get_tweaked_xonly_key(xonly_pk2.0, Some(TapNodeHash::assume_hidden([0x55; 32])))
            .unwrap();
        assert!(tweak_cache.get_tweaked_xonly_key_cache_size() == 3);
        tweak_cache
            .get_tweaked_xonly_key(xonly_pk3.0, Some(TapNodeHash::assume_hidden([0x55; 32])))
            .unwrap();
        assert!(tweak_cache.get_tweaked_xonly_key_cache_size() == 4);
        tweak_cache
            .get_tweaked_xonly_key(xonly_pk1.0, None)
            .unwrap();
        tweak_cache
            .get_tweaked_xonly_key(xonly_pk3.0, Some(TapNodeHash::assume_hidden([0x55; 32])))
            .unwrap();
        assert!(tweak_cache.get_tweaked_xonly_key_cache_size() == 4);
    }

    #[tokio::test]
    async fn derive_winternitz_pk_fixed_pk() {
        let paramset: &'static ProtocolParamset = ProtocolParamsetName::Regtest.into();
        let actor = Actor::new(
            SecretKey::from_str("451F451F451F451F451F451F451F451F451F451F451F451F451F451F451F451F")
                .unwrap(),
            Network::Regtest,
        );
        // Test so that same path always returns the same public key (to not change it accidentally)
        // check only first digit
        let params = WinternitzDerivationPath::Kickoff(BridgeRound::Round(0), 1, paramset);
        let expected_pk = vec![
            101, 197, 179, 64, 250, 67, 109, 29, 241, 138, 5, 24, 94, 33, 175, 150, 152, 91, 168,
            177,
        ];
        assert_eq!(
            actor.derive_winternitz_pk(params).unwrap()[0].to_vec(),
            expected_pk
        );

        let deposit_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 1,
        };

        let params = WinternitzDerivationPath::BitvmAssert(3, 0, 0, deposit_outpoint, paramset);
        let expected_pk = vec![
            175, 225, 87, 0, 121, 25, 91, 88, 22, 210, 26, 117, 146, 84, 228, 150, 199, 181, 186,
            33,
        ];
        assert_eq!(
            actor.derive_winternitz_pk(params).unwrap()[0].to_vec(),
            expected_pk
        );

        let params = WinternitzDerivationPath::ChallengeAckHash(0, deposit_outpoint, paramset);
        let expected_pk = vec![
            247, 46, 220, 228, 70, 245, 147, 30, 64, 207, 189, 137, 222, 217, 244, 96, 68, 114,
            243, 13,
        ];
        assert_eq!(
            actor.derive_winternitz_pk(params).unwrap()[0].to_vec(),
            expected_pk
        );
    }

    #[tokio::test]
    async fn sign_winternitz_signature() {
        let config = create_test_config_with_thread_name().await;
        let actor = Actor::new(config.secret_key, Network::Regtest);

        let data = "iwantporscheasagiftpls".as_bytes().to_vec();
        let message_len = data.len() as u32 * 2;
        let paramset: &'static ProtocolParamset = ProtocolParamsetName::Regtest.into();

        let deposit_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 1,
        };

        let path =
            WinternitzDerivationPath::BitvmAssert(message_len, 0, 0, deposit_outpoint, paramset);
        let params = winternitz::Parameters::new(message_len, paramset.winternitz_log_d);

        let winternitz = Winternitz::<BinarysearchVerifier, ToBytesConverter>::new();
        let secret_key = actor.get_derived_winternitz_sk(path.clone()).unwrap();
        let witness = winternitz.sign(&params, &secret_key, &data);
        let pk = actor.derive_winternitz_pk(path.clone()).unwrap();

        let check_sig_script = winternitz.checksig_verify(&params, &pk);

        let message_checker = script! {
            for i in 0..message_len / 2 {
                {data[i as usize]}
                if i == message_len / 2 - 1 {
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

    #[tokio::test]
    async fn test_key_spend_signing() {
        // Setup test node and actor
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();
        let sk = SecretKey::new(&mut thread_rng());
        let actor = Actor::new(sk, Network::Regtest);

        // Create a UTXO controlled by the actor's key spend path
        let (tap_addr, spend_info) =
            create_taproot_address(&[], Some(actor.xonly_public_key), Network::Regtest);
        let prevtxo = bitcoin::TxOut {
            value: Amount::from_sat(50000), // Use a reasonable amount
            script_pubkey: tap_addr.script_pubkey(),
        };

        // Fund the address (required for testmempoolaccept)
        let outpoint = rpc
            .send_to_address(&tap_addr, Amount::from_sat(50000))
            .await
            .unwrap();

        rpc.mine_blocks(1).await.unwrap(); // Confirm the funding transaction

        // Build a transaction spending the UTXO with TapSighashType::SinglePlusAnyoneCanPay
        let mut builder = TxHandlerBuilder::new(TransactionType::MoveToVault)
            // Use Challenge which maps to NofnSharedDeposit(TapSighashType::SinglePlusAnyoneCanPay)
            .add_input(
                ChallengeInput::Challenge,
                crate::builder::transaction::spendable_txin(
                    outpoint,
                    prevtxo.clone(),
                    vec![],
                    vec![],
                    Some(spend_info.clone()),
                ),
                bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                crate::builder::transaction::input_descriptor(SpendSpec::key_spend()),
            );

        // Add a dummy output
        builder = builder.add_output(
            MoveToVaultOutput::DepositInMove,
            crate::builder::transaction::unspent_txout(
                bitcoin::TxOut {
                    value: Amount::from_sat(49000), // Account for fee
                    script_pubkey: actor.address.script_pubkey(),
                },
                vec![],
                vec![],
                None,
            ),
        );

        let mut txhandler = builder.finalize();

        // Actor signs the key spend input using the non-default sighash type
        crate::builder::transaction::sign::apply_schnorr_signatures(
            &actor,
            &mut txhandler,
            &[],
            None,
        )
        .expect("Key spend signature with SighashNone should succeed");

        // Retrieve the signed transaction
        let tx: &Transaction = txhandler.transaction();

        // Use testmempoolaccept to verify the transaction is valid by consensus rules
        let mempool_accept_result = rpc.test_mempool_accept(&[tx]).await.unwrap();

        assert!(
            mempool_accept_result[0].allowed.unwrap(),
            "Transaction should be allowed in mempool. Rejection reason: {:?}",
            mempool_accept_result[0].reject_reason.as_ref().unwrap()
        );

        // Build a transaction spending the UTXO with TapSighashType::Default
        let mut builder = TxHandlerBuilder::new(TransactionType::MoveToVault)
            // Use Reimburse2 which maps to NofnSharedDeposit(TapSighashType::Default)
            .add_input(
                ReimburseInput::ReimburseInKickoff,
                crate::builder::transaction::spendable_txin(
                    outpoint,
                    prevtxo.clone(),
                    vec![],
                    vec![],
                    Some(spend_info.clone()),
                ),
                bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                crate::builder::transaction::input_descriptor(SpendSpec::key_spend()),
            );

        // Add a dummy output
        builder = builder.add_output(
            MoveToVaultOutput::DepositInMove,
            crate::builder::transaction::unspent_txout(
                bitcoin::TxOut {
                    value: Amount::from_sat(39000), // Account for fee
                    script_pubkey: actor.address.script_pubkey(),
                },
                vec![],
                vec![],
                None,
            ),
        );

        let mut txhandler = builder.finalize();

        // Actor signs the key spend input using the non-default sighash type
        crate::builder::transaction::sign::apply_schnorr_signatures(
            &actor,
            &mut txhandler,
            &[],
            None,
        )
        .expect("Key spend signature with SighashDefault should succeed");

        // Retrieve the signed transaction
        let tx: &Transaction = txhandler.transaction();

        // Use testmempoolaccept to verify the transaction is valid by consensus rules
        let mempool_accept_result = rpc.test_mempool_accept(&[tx]).await.unwrap();

        assert!(
            mempool_accept_result[0].allowed.unwrap(),
            "Transaction should be allowed in mempool. Rejection reason: {:?}",
            mempool_accept_result[0].reject_reason.as_ref().unwrap()
        );
    }
}
