use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::bitvm_client::{self, ClementineBitVMPublicKeys, SECP};
use crate::builder::script::SpendPath;
use crate::builder::sighash::TapTweakData;
use crate::builder::transaction::input::SpentTxIn;
use crate::builder::transaction::{SighashCalculator, TxHandler};
use crate::config::protocol::ProtocolParamset;
use crate::errors::{BridgeError, TxError};
use crate::operator::PublicHash;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::TaggedSignature;
use bitcoin::hashes::hash160;
use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot::{self, LeafVersion, TaprootSpendInfo};
use bitcoin::{
    hashes::Hash,
    secp256k1::{schnorr, Keypair, Message, SecretKey, XOnlyPublicKey},
    Address, ScriptBuf, TapSighash, TapTweakHash,
};
use bitcoin::{OutPoint, TapNodeHash, TapSighashType, Witness};
use bitvm::signatures::winternitz::{self, BinarysearchVerifier, ToBytesConverter, Winternitz};
use eyre::OptionExt;

#[derive(Debug, Clone)]
pub enum WinternitzDerivationPath {
    /// round_idx, kickoff_idx
    /// Message length is fixed KICKOFF_BLOCKHASH_COMMIT_LENGTH
    Kickoff(u32, u32, &'static ProtocolParamset),
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

    fn to_bytes(&self) -> Vec<u8> {
        let type_id = self.get_type_id();
        let mut bytes = vec![type_id];

        match self {
            WinternitzDerivationPath::Kickoff(seq_collat_idx, kickoff_idx, _) => {
                bytes.extend_from_slice(&seq_collat_idx.to_be_bytes());
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
    keypair
        .add_xonly_tweak(
            &SECP,
            &TapTweakHash::from_key_and_tweak(keypair.x_only_public_key().0, merkle_root)
                .to_scalar(),
        )
        .map_err(|e| BridgeError::Error(format!("Failed to add tweak to keypair: {}", e)))
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
        .map_err(|e| BridgeError::Error(format!("Failed to add tweak to xonly_pk: {}", e)))?
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
        TapTweakData::Unknown => return Err(BridgeError::Error("Spend Path Unknown".to_string())),
    };
    SECP.verify_schnorr(signature, sighash, &pubkey)
        .map_err(|_| BridgeError::Error("Failed to verify Schnorr signature".to_string()))
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

    #[tracing::instrument(skip(self), ret(level = tracing::Level::TRACE))]
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
            TapTweakData::Unknown => Err(BridgeError::Error("Spend Data Unknown".to_string())),
        }
    }

    /// Returns derivied Winternitz secret key from given path.
    pub fn get_derived_winternitz_sk(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<winternitz::SecretKey, BridgeError> {
        let wsk = self
            .winternitz_secret_key
            .ok_or_eyre("Root Winternitz secret key is not provided in configuration file")?;
        Ok([wsk.as_ref().to_vec(), path.to_bytes()].concat())
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

    /// Signs given data with Winternitz signature.
    pub fn sign_winternitz_signature(
        &self,
        path: WinternitzDerivationPath,
        data: Vec<u8>,
    ) -> Result<Witness, BridgeError> {
        let winternitz = Winternitz::<BinarysearchVerifier, ToBytesConverter>::new();

        let winternitz_params = path.get_params();

        let altered_secret_key = self.get_derived_winternitz_sk(path)?;

        let witness = winternitz.sign(&winternitz_params, &altered_secret_key, &data);

        Ok(witness)
    }

    pub fn generate_preimage_from_path(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<PublicHash, BridgeError> {
        let first_preimage = self.get_derived_winternitz_sk(path)?;
        let second_preimage = hash160::Hash::hash(&first_preimage);
        Ok(second_preimage.to_byte_array())
    }

    /// Generates the hashes from the preimages. Preimages are constructed using
    /// the Winternitz derivation path and the secret key.
    pub fn generate_public_hash_from_path(
        &self,
        path: WinternitzDerivationPath,
    ) -> Result<PublicHash, BridgeError> {
        let preimage = self.generate_preimage_from_path(path)?;
        let hash = hash160::Hash::hash(&preimage);
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
        pks.latest_blockhash_pk = ClementineBitVMPublicKeys::vec_to_array::<44>(&pk_vec);
        let pk_vec = self.derive_winternitz_pk(
            ClementineBitVMPublicKeys::get_challenge_sending_watchtowers_derivation(
                deposit_outpoint,
                paramset,
            ),
        )?;
        pks.challenge_sending_watchtowers_pk =
            ClementineBitVMPublicKeys::vec_to_array::<44>(&pk_vec);
        for i in 0..pks.bitvm_pks.0.len() {
            let pk_vec = self.derive_winternitz_pk(WinternitzDerivationPath::BitvmAssert(
                64,
                3,
                i as u32,
                deposit_outpoint,
                paramset,
            ))?;
            pks.bitvm_pks.0[i] = ClementineBitVMPublicKeys::vec_to_array::<68>(&pk_vec);
        }
        for i in 0..pks.bitvm_pks.1.len() {
            let pk_vec = self.derive_winternitz_pk(WinternitzDerivationPath::BitvmAssert(
                64,
                4,
                i as u32,
                deposit_outpoint,
                paramset,
            ))?;
            pks.bitvm_pks.1[i] = ClementineBitVMPublicKeys::vec_to_array::<68>(&pk_vec);
        }
        for i in 0..pks.bitvm_pks.2.len() {
            let pk_vec = self.derive_winternitz_pk(WinternitzDerivationPath::BitvmAssert(
                32,
                5,
                i as u32,
                deposit_outpoint,
                paramset,
            ))?;
            pks.bitvm_pks.2[i] = ClementineBitVMPublicKeys::vec_to_array::<36>(&pk_vec);
        }

        Ok(pks)
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

    pub fn add_script_path_to_witness(
        witness: &mut Witness,
        script: &ScriptBuf,
        spend_info: &TaprootSpendInfo,
    ) -> Result<(), BridgeError> {
        let spend_control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or_eyre("Failed to find control block for script")?;
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
        let signer = move |_: usize,
                           spt: &SpentTxIn,
                           calc_sighash: SighashCalculator<'_>|
              -> Result<Option<Witness>, BridgeError> {
            let spendinfo = spt
                .get_spendable()
                .get_spend_info()
                .as_ref()
                .ok_or(TxError::MissingSpendInfo)?;
            match spt.get_spend_path() {
                SpendPath::ScriptSpend(script_idx) => {
                    let script = spt
                        .get_spendable()
                        .get_scripts()
                        .get(script_idx)
                        .ok_or(TxError::NoScriptAtIndex(script_idx))?;
                    let sighash_type = spt
                        .get_signature_id()
                        .get_deposit_sig_owner()
                        .map(|s| s.sighash_type())?
                        .unwrap_or(TapSighashType::Default);

                    use crate::builder::script::ScriptKind as Kind;

                    let mut witness = match script.kind() {
                        Kind::PreimageRevealScript(script) => {
                            if script.0 != self.xonly_public_key {
                                return Err(TxError::NotOwnedScriptPath.into());
                            }
                            let signature = self.sign(calc_sighash(sighash_type)?);
                            script.generate_script_inputs(
                                data,
                                &taproot::Signature {
                                    signature,
                                    sighash_type,
                                },
                            )
                        }
                        Kind::WinternitzCommit(_)
                        | Kind::CheckSig(_)
                        | Kind::Other(_)
                        | Kind::BaseDepositScript(_)
                        | Kind::ReplacementDepositScript(_)
                        | Kind::TimelockScript(_)
                        | Kind::WithdrawalScript(_) => return Ok(None),
                    };

                    if signed_preimage {
                        return Err(eyre::eyre!("Encountered multiple preimage reveal scripts when attempting to commit to only one.").into());
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
                SpendPath::Unknown => Err(TxError::SpendPathNotSpecified.into()),
            }
        };

        txhandler.sign_txins(signer)?;
        Ok(())
    }
    pub fn tx_sign_winternitz(
        &self,
        txhandler: &mut TxHandler,
        data: &[(Vec<u8>, WinternitzDerivationPath)],
    ) -> Result<(), BridgeError> {
        let mut signed_winternitz = false;

        let signer = move |_: usize,
                           spt: &SpentTxIn,
                           calc_sighash: SighashCalculator<'_>|
              -> Result<Option<Witness>, BridgeError> {
            let spendinfo = spt
                .get_spendable()
                .get_spend_info()
                .as_ref()
                .ok_or(TxError::MissingSpendInfo)?;
            match spt.get_spend_path() {
                SpendPath::ScriptSpend(script_idx) => {
                    let script = spt
                        .get_spendable()
                        .get_scripts()
                        .get(script_idx)
                        .ok_or(TxError::NoScriptAtIndex(script_idx))?;
                    let sighash_type = spt
                        .get_signature_id()
                        .get_deposit_sig_owner()
                        .map(|s| s.sighash_type())?
                        .unwrap_or(TapSighashType::Default);

                    use crate::builder::script::ScriptKind as Kind;

                    let mut witness = match script.kind() {
                        Kind::WinternitzCommit(script) => {
                            if script.checksig_pubkey != self.xonly_public_key {
                                return Err(TxError::NotOwnedScriptPath.into());
                            }

                            let mut script_data = Vec::with_capacity(data.len());
                            for (data, path) in data {
                                let secret_key = self.get_derived_winternitz_sk(path.clone())?;
                                script_data.push((data.clone(), secret_key));
                            }
                            script.generate_script_inputs(
                                &script_data,
                                &taproot::Signature {
                                    signature: self.sign(calc_sighash(sighash_type)?),
                                    sighash_type,
                                },
                            )
                        }
                        Kind::PreimageRevealScript(_)
                        | Kind::CheckSig(_)
                        | Kind::Other(_)
                        | Kind::BaseDepositScript(_)
                        | Kind::ReplacementDepositScript(_)
                        | Kind::TimelockScript(_)
                        | Kind::WithdrawalScript(_) => return Ok(None),
                    };

                    if signed_winternitz {
                        return Err(eyre::eyre!("Encountered multiple winternitz scripts when attempting to commit to only one.").into());
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
                SpendPath::Unknown => Err(TxError::SpendPathNotSpecified.into()),
            }
        };

        txhandler.sign_txins(signer)?;
        Ok(())
    }

    pub fn tx_sign_and_fill_sigs(
        &self,
        txhandler: &mut TxHandler,
        signatures: &[TaggedSignature],
        mut tweak_cache: Option<&mut TweakCache>,
    ) -> Result<(), BridgeError> {
        let tx_type = txhandler.get_transaction_type();
        let signer = move |_,
                           spt: &SpentTxIn,
                           calc_sighash: SighashCalculator<'_>|
              -> Result<Option<Witness>, BridgeError> {
            let spendinfo = spt
                .get_spendable()
                .get_spend_info()
                .as_ref()
                .ok_or(TxError::MissingSpendInfo)?;
            let sighash_type = spt
                .get_signature_id()
                .get_deposit_sig_owner()
                .map(|s| s.sighash_type())?
                .unwrap_or(TapSighashType::Default);
            match spt.get_spend_path() {
                SpendPath::ScriptSpend(script_idx) => {
                    let script = spt
                        .get_spendable()
                        .get_scripts()
                        .get(script_idx)
                        .ok_or(TxError::NoScriptAtIndex(script_idx))?;
                    let sig = Self::get_saved_signature(spt.get_signature_id(), signatures);

                    let sig = sig.map(|sig| taproot::Signature {
                        signature: sig,
                        sighash_type,
                    });

                    use crate::builder::script::ScriptKind as Kind;

                    // Set the script inputs of the witness
                    let mut witness: Witness = match script.kind() {
                        Kind::BaseDepositScript(script) => {
                            match (sig, script.0 == self.xonly_public_key) {
                                (Some(sig), _) => script.generate_script_inputs(&sig),
                                (None, true) => {
                                    script.generate_script_inputs(&taproot::Signature {
                                        signature: self.sign(calc_sighash(sighash_type)?),
                                        sighash_type,
                                    })
                                }
                                (None, false) => {
                                    return Err(TxError::SignatureNotFound(tx_type).into())
                                }
                            }
                        }
                        Kind::ReplacementDepositScript(script) => {
                            match (sig, script.0 == self.xonly_public_key) {
                                (Some(sig), _) => script.generate_script_inputs(&sig),
                                (None, true) => {
                                    script.generate_script_inputs(&taproot::Signature {
                                        signature: self.sign(calc_sighash(sighash_type)?),
                                        sighash_type,
                                    })
                                }
                                (None, false) => {
                                    return Err(TxError::SignatureNotFound(tx_type).into());
                                }
                            }
                        }
                        Kind::TimelockScript(script) => match (sig, script.0) {
                            (Some(sig), Some(_)) => script.generate_script_inputs(Some(&sig)),
                            (None, Some(xonly_key)) if xonly_key == self.xonly_public_key => script
                                .generate_script_inputs(Some(&taproot::Signature {
                                    signature: self.sign(calc_sighash(sighash_type)?),
                                    sighash_type,
                                })),
                            (None, Some(_)) => {
                                return Err(TxError::SignatureNotFound(tx_type).into())
                            }
                            (_, None) => Witness::new(),
                        },
                        Kind::CheckSig(script) => match (sig, script.0 == self.xonly_public_key) {
                            (Some(sig), _) => script.generate_script_inputs(&sig),

                            (None, true) => script.generate_script_inputs(&taproot::Signature {
                                signature: self.sign(calc_sighash(sighash_type)?),
                                sighash_type,
                            }),
                            (None, false) => return Err(TxError::SignatureNotFound(tx_type).into()),
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

                    let sighash = calc_sighash(sighash_type)?;
                    let sig = Self::get_saved_signature(spt.get_signature_id(), signatures);
                    let sig = match sig {
                        Some(sig) => sig,
                        None => {
                            if xonly_public_key == self.xonly_public_key {
                                self.sign_with_tweak(
                                    sighash,
                                    spendinfo.merkle_root(),
                                    tweak_cache.as_deref_mut(),
                                )?
                            } else {
                                return Err(TxError::NotOwnKeyPath.into());
                            }
                        }
                    };
                    Ok(Some(Witness::from_slice(&[&sig.serialize()])))
                }
                SpendPath::Unknown => Err(TxError::SpendPathNotSpecified.into()),
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
    use crate::config::protocol::ProtocolParamsetName;

    use super::*;
    use crate::builder::script::{CheckSig, SpendPath, SpendableScript};
    use crate::builder::transaction::input::SpendableTxIn;
    use crate::builder::transaction::output::UnspentTxOut;
    use crate::builder::transaction::{TransactionType, TxHandler, TxHandlerBuilder};

    use crate::bitvm_client::SECP;
    use crate::rpc::clementine::NormalSignatureKind;
    use crate::{actor::WinternitzDerivationPath, test::common::*};
    use bitcoin::secp256k1::{schnorr, Message, SecretKey};

    use bitcoin::sighash::TapSighashType;
    use bitcoin::transaction::Transaction;

    use bitcoin::{Amount, Network, OutPoint, Txid};
    use bitvm::{
        execute_script,
        signatures::winternitz::{self, BinarysearchVerifier, ToBytesConverter, Winternitz},
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
        let builder = TxHandlerBuilder::new(TransactionType::Dummy).add_input(
            NormalSignatureKind::Reimburse2,
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

        let builder = TxHandlerBuilder::new(TransactionType::Dummy).add_input(
            NormalSignatureKind::KickoffNotFinalized1,
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
            .tx_sign_and_fill_sigs(&mut txhandler, &[], None)
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
            .tx_sign_and_fill_sigs(&mut txhandler, &signatures, None)
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
            .tx_sign_and_fill_sigs(&mut txhandler, &signatures, None)
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
        actor.sign_with_tweak(x, None, None).unwrap();
    }

    #[tokio::test]
    async fn derive_winternitz_pk_uniqueness() {
        let paramset: &'static ProtocolParamset = ProtocolParamsetName::Regtest.into();
        let config = create_test_config_with_thread_name().await;
        let actor = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            Network::Regtest,
        );

        let mut params = WinternitzDerivationPath::Kickoff(0, 0, paramset);
        let pk0 = actor.derive_winternitz_pk(params.clone()).unwrap();
        let pk1 = actor.derive_winternitz_pk(params).unwrap();
        assert_eq!(pk0, pk1);

        params = WinternitzDerivationPath::Kickoff(0, 1, paramset);
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
        let config = create_test_config_with_thread_name().await;
        let paramset: &'static ProtocolParamset = ProtocolParamsetName::Regtest.into();
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
        // Test so that same path always returns the same public key (to not change it accidentally)
        // check only first digit
        let params = WinternitzDerivationPath::Kickoff(0, 1, paramset);
        let expected_pk = vec![
            173, 204, 163, 206, 248, 61, 42, 248, 42, 163, 51, 172, 127, 111, 1, 82, 142, 151, 78,
            6,
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
            109, 153, 145, 11, 185, 140, 236, 205, 105, 93, 80, 123, 62, 218, 228, 193, 124, 151,
            200, 208,
        ];
        assert_eq!(
            actor.derive_winternitz_pk(params).unwrap()[0].to_vec(),
            expected_pk
        );

        let params = WinternitzDerivationPath::ChallengeAckHash(0, deposit_outpoint, paramset);
        let expected_pk = vec![
            113, 255, 129, 122, 93, 181, 207, 47, 113, 140, 166, 79, 160, 116, 58, 199, 27, 162,
            163, 142,
        ];
        assert_eq!(
            actor.derive_winternitz_pk(params).unwrap()[0].to_vec(),
            expected_pk
        );
    }

    #[tokio::test]
    async fn sign_winternitz_signature() {
        let config = create_test_config_with_thread_name().await;
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
        let message_len = data.len() as u32 * 2;
        let paramset: &'static ProtocolParamset = ProtocolParamsetName::Regtest.into();

        let deposit_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 1,
        };

        let path =
            WinternitzDerivationPath::BitvmAssert(message_len, 0, 0, deposit_outpoint, paramset);
        let params = winternitz::Parameters::new(message_len, paramset.winternitz_log_d);

        let witness = actor
            .sign_winternitz_signature(path.clone(), data.clone())
            .unwrap();
        let pk = actor.derive_winternitz_pk(path.clone()).unwrap();

        let winternitz = Winternitz::<BinarysearchVerifier, ToBytesConverter>::new();
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
}
