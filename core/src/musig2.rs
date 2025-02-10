//! # MuSig2
//!
//! Helper functions for the MuSig2 signature scheme.

use crate::{errors::BridgeError, utils::SECP};
use bitcoin::{
    hashes::Hash,
    key::Keypair,
    secp256k1::{schnorr, Message, PublicKey, SecretKey},
    TapNodeHash, XOnlyPublicKey,
};
use lazy_static::lazy_static;
use secp256k1::{
    musig::{
        new_musig_nonce_pair, MusigAggNonce, MusigKeyAggCache, MusigPartialSignature,
        MusigPubNonce, MusigSecNonce, MusigSecRand, MusigSession,
    },
    rand::Rng,
    Scalar, SECP256K1,
};
use sha2::{Digest, Sha256};

pub type MuSigNoncePair = (MusigSecNonce, MusigPubNonce);

pub fn from_secp_xonly(xpk: secp256k1::XOnlyPublicKey) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&xpk.serialize()).expect("serialized pubkey is valid")
}

pub fn to_secp_pk(pk: PublicKey) -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_slice(&pk.serialize()).expect("serialized pubkey is valid")
}
pub fn from_secp_pk(pk: secp256k1::PublicKey) -> PublicKey {
    PublicKey::from_slice(&pk.serialize()).expect("serialized pubkey is valid")
}

pub fn to_secp_sk(sk: SecretKey) -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&sk.secret_bytes()).expect("serialized secret key is valid")
}

pub fn to_secp_kp(kp: &Keypair) -> secp256k1::Keypair {
    secp256k1::Keypair::from_seckey_slice(SECP256K1, &kp.secret_bytes())
        .expect("serialized secret key is valid")
}
pub fn from_secp_kp(kp: &secp256k1::Keypair) -> Keypair {
    Keypair::from_seckey_slice(&SECP, &kp.secret_bytes()).expect("serialized secret key is valid")
}

pub fn from_secp_sig(sig: secp256k1::schnorr::Signature) -> schnorr::Signature {
    schnorr::Signature::from_slice(&sig.to_byte_array()).expect("serialized signature is valid")
}

pub fn to_secp_msg(msg: &Message) -> secp256k1::Message {
    secp256k1::Message::from_digest(*msg.as_ref())
}

/// Possible Musig2 modes.
#[derive(Debug, Clone, Copy)]
pub enum Musig2Mode {
    /// No taproot tweak.
    ScriptSpend,
    /// Taproot tweak with aggregated public key.
    OnlyKeySpend,
    /// Taproot tweak with tweaked aggregated public key.
    KeySpendWithScript(TapNodeHash),
}

/// sha256(b"TapTweak")
const TAPROOT_TWEAK_TAG_DIGEST: [u8; 32] = [
    0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50, 0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
    0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb, 0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57, 0xc5, 0xe9,
];

lazy_static! {
    pub static ref TAPROOT_TWEAK_TAGGED_HASH: Sha256 = Sha256::new()
        .chain_update(TAPROOT_TWEAK_TAG_DIGEST)
        .chain_update(TAPROOT_TWEAK_TAG_DIGEST);
}

fn create_key_agg_cache(
    public_keys: impl AsRef<[PublicKey]>,
    mode: Option<Musig2Mode>,
) -> Result<MusigKeyAggCache, BridgeError> {
    let secp_pubkeys: Vec<secp256k1::PublicKey> = public_keys
        .as_ref()
        .iter()
        .map(|pk| to_secp_pk(*pk))
        .collect();
    let pubkeys_ref: Vec<&secp256k1::PublicKey> = secp_pubkeys.iter().collect();
    let pubkeys_ref = pubkeys_ref.as_slice();

    let mut musig_key_agg_cache = MusigKeyAggCache::new(SECP256K1, pubkeys_ref);
    let agg_key = musig_key_agg_cache.agg_pk();

    if let Some(mode) = mode {
        match mode {
            Musig2Mode::ScriptSpend => (),
            Musig2Mode::OnlyKeySpend => {
                // sha256(C, C, IPK) where C = sha256("TapTweak")
                let xonly_tweak = TAPROOT_TWEAK_TAGGED_HASH
                    .clone()
                    .chain_update(agg_key.serialize())
                    .finalize();

                musig_key_agg_cache.pubkey_xonly_tweak_add(
                    SECP256K1,
                    &Scalar::from_be_bytes(xonly_tweak.into())?,
                )?;
            }
            Musig2Mode::KeySpendWithScript(merkle_root) => {
                // sha256(C, C, IPK, s) where C = sha256("TapTweak")
                let xonly_tweak = TAPROOT_TWEAK_TAGGED_HASH
                    .clone()
                    .chain_update(agg_key.serialize())
                    .chain_update(merkle_root.to_raw_hash().to_byte_array())
                    .finalize();

                musig_key_agg_cache
                    .pubkey_ec_tweak_add(SECP256K1, &Scalar::from_be_bytes(xonly_tweak.into())?)?;
            }
        }
    };

    Ok(musig_key_agg_cache)
}

pub trait AggregateFromPublicKeys {
    fn from_musig2_pks(
        pks: Vec<PublicKey>,
        tweak: Option<Musig2Mode>,
    ) -> Result<XOnlyPublicKey, BridgeError>;
}

impl AggregateFromPublicKeys for XOnlyPublicKey {
    fn from_musig2_pks(
        pks: Vec<PublicKey>,
        tweak: Option<Musig2Mode>,
    ) -> Result<XOnlyPublicKey, BridgeError> {
        let musig_key_agg_cache = create_key_agg_cache(pks, tweak)?;

        Ok(XOnlyPublicKey::from_slice(
            &musig_key_agg_cache.agg_pk().serialize(),
        )?)
    }
}

// Aggregates the public nonces into a single aggregated nonce.
pub fn aggregate_nonces(pub_nonces: &[&MusigPubNonce]) -> MusigAggNonce {
    MusigAggNonce::new(SECP256K1, pub_nonces)
}

// Aggregates the partial signatures into a single aggregated signature.
pub fn aggregate_partial_signatures(
    pks: &[PublicKey],
    tweak: Option<Musig2Mode>,
    agg_nonce: MusigAggNonce,
    partial_sigs: &[MusigPartialSignature],
    message: Message,
) -> Result<schnorr::Signature, BridgeError> {
    let musig_key_agg_cache: MusigKeyAggCache = create_key_agg_cache(pks, tweak)?;
    let secp_message = to_secp_msg(&message);

    let session = MusigSession::new(SECP256K1, &musig_key_agg_cache, agg_nonce, secp_message);

    let partial_sigs: Vec<&MusigPartialSignature> = partial_sigs.iter().collect();
    let final_sig = session.partial_sig_agg(&partial_sigs);

    SECP256K1.verify_schnorr(
        &final_sig,
        secp_message.as_ref(),
        &musig_key_agg_cache.agg_pk(),
    )?;

    Ok(from_secp_sig(session.partial_sig_agg(&partial_sigs)))
}

/// Generates a pair of nonces, one secret and one public. Be careful,
/// DO NOT REUSE the same pair of nonces for multiple transactions. It will cause
/// you to leak your secret key. For more information. See:
/// https://medium.com/blockstream/musig-dn-schnorr-multisignatures-with-verifiably-deterministic-nonces-27424b5df9d6#e3b6.
pub fn nonce_pair(
    keypair: &Keypair,
    mut rng: &mut impl Rng,
) -> Result<(MusigSecNonce, MusigPubNonce), BridgeError> {
    let musig_session_sec_rand = MusigSecRand::new(&mut rng);

    Ok(new_musig_nonce_pair(
        SECP256K1,
        musig_session_sec_rand,
        None,
        None,
        to_secp_kp(keypair).public_key(),
        None,
        None,
    )?)
}

pub fn partial_sign(
    pks: impl AsRef<[PublicKey]>,
    // Aggregated tweak, if there is any. This is useful for
    // Taproot key-spends, since we might have script-spend conditions.
    tweak: Option<Musig2Mode>,
    sec_nonce: MusigSecNonce,
    agg_nonce: MusigAggNonce,
    keypair: Keypair,
    sighash: Message,
) -> Result<MusigPartialSignature, BridgeError> {
    let musig_key_agg_cache = create_key_agg_cache(pks, tweak)?;

    let session = MusigSession::new(
        SECP256K1,
        &musig_key_agg_cache,
        agg_nonce,
        to_secp_msg(&sighash),
    );

    Ok(session.partial_sign(
        SECP256K1,
        sec_nonce,
        &to_secp_kp(&keypair),
        &musig_key_agg_cache,
    )?)
}

#[cfg(test)]
mod tests {
    use super::{nonce_pair, MuSigNoncePair, Musig2Mode};
    use crate::builder::script::{CheckSig, OtherSpendable, SpendableScript};
    use crate::builder::transaction::DEFAULT_SEQUENCE;
    use crate::rpc::clementine::NormalSignatureKind;
    use crate::{
        builder::{
            self,
            transaction::{input::SpendableTxIn, output::UnspentTxOut, TxHandlerBuilder},
        },
        errors::BridgeError,
        musig2::{
            aggregate_nonces, aggregate_partial_signatures, create_key_agg_cache, from_secp_xonly,
            partial_sign, AggregateFromPublicKeys,
        },
        utils::{self, SECP},
    };
    use bitcoin::{
        hashes::Hash,
        key::Keypair,
        script,
        secp256k1::{schnorr, Message, PublicKey},
        Amount, OutPoint, TapNodeHash, TapSighashType, TxOut, Txid, XOnlyPublicKey,
    };
    use secp256k1::{musig::MusigPartialSignature, rand::Rng};
    use std::sync::Arc;
    use std::vec;

    /// Generates random key and nonce pairs for a given number of signers.
    fn create_key_and_nonce_pairs(num_signers: usize) -> (Vec<Keypair>, Vec<MuSigNoncePair>) {
        let mut key_pairs = Vec::new();
        let mut nonce_pairs = Vec::new();

        for _ in 0..num_signers {
            let key_pair = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
            let nonce_pair =
                nonce_pair(&key_pair, &mut bitcoin::secp256k1::rand::thread_rng()).unwrap();

            key_pairs.push(key_pair);
            nonce_pairs.push(nonce_pair);
        }

        (key_pairs, nonce_pairs)
    }

    #[test]
    fn musig2_raw_without_a_tweak() {
        let (key_pairs, nonce_pairs) = create_key_and_nonce_pairs(3);
        let message = Message::from_digest(secp256k1::rand::thread_rng().gen());

        let public_keys = key_pairs
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<PublicKey>>();
        let agg_pk = XOnlyPublicKey::from_musig2_pks(public_keys.clone(), None).unwrap();

        let aggregated_nonce = super::aggregate_nonces(
            nonce_pairs
                .iter()
                .map(|(_, musig_pub_nonce)| musig_pub_nonce)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let partial_sigs = key_pairs
            .into_iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    public_keys.clone(),
                    None,
                    nonce_pair.0,
                    aggregated_nonce,
                    kp,
                    message,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let final_signature = super::aggregate_partial_signatures(
            &public_keys,
            None,
            aggregated_nonce,
            &partial_sigs,
            message,
        )
        .unwrap();

        SECP.verify_schnorr(&final_signature, &message, &agg_pk)
            .unwrap();
    }

    #[test]
    fn musig2_raw_fail_if_partial_sigs_invalid() {
        let kp_0 = Keypair::new(&SECP, &mut secp256k1::rand::thread_rng());
        let kp_1 = Keypair::new(&SECP, &mut secp256k1::rand::thread_rng());
        let kp_2 = Keypair::new(&SECP, &mut secp256k1::rand::thread_rng());

        let message = Message::from_digest(secp256k1::rand::thread_rng().gen());

        let pks = vec![kp_0.public_key(), kp_1.public_key(), kp_2.public_key()];

        let (sec_nonce_0, pub_nonce_0) =
            super::nonce_pair(&kp_0, &mut secp256k1::rand::thread_rng()).unwrap();
        let (sec_nonce_1, pub_nonce_1) =
            super::nonce_pair(&kp_1, &mut secp256k1::rand::thread_rng()).unwrap();
        let (sec_nonce_2, pub_nonce_2) =
            super::nonce_pair(&kp_2, &mut secp256k1::rand::thread_rng()).unwrap();

        let agg_nonce = super::aggregate_nonces(&[&pub_nonce_0, &pub_nonce_1, &pub_nonce_2]);

        let partial_sig_0 =
            super::partial_sign(pks.clone(), None, sec_nonce_0, agg_nonce, kp_0, message).unwrap();
        let partial_sig_1 =
            super::partial_sign(pks.clone(), None, sec_nonce_1, agg_nonce, kp_1, message).unwrap();
        // Oops, a verifier accidentally added some tweak!
        let partial_sig_2 = super::partial_sign(
            pks.clone(),
            Some(Musig2Mode::KeySpendWithScript(
                TapNodeHash::from_slice(&[1u8; 32]).unwrap(),
            )),
            sec_nonce_2,
            agg_nonce,
            kp_2,
            message,
        )
        .unwrap();
        let partial_sigs = vec![partial_sig_0, partial_sig_1, partial_sig_2];

        let final_signature: Result<schnorr::Signature, BridgeError> =
            super::aggregate_partial_signatures(&pks, None, agg_nonce, &partial_sigs, message);

        assert!(final_signature.is_err());
    }

    #[test]
    fn musig2_sig_with_tweak() {
        let (key_pairs, nonce_pairs) = create_key_and_nonce_pairs(3);
        let message = Message::from_digest(secp256k1::rand::thread_rng().gen());
        let tweak: [u8; 32] = secp256k1::rand::thread_rng().gen();

        let public_keys = key_pairs
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<PublicKey>>();
        let aggregated_pk: XOnlyPublicKey = XOnlyPublicKey::from_musig2_pks(
            public_keys.clone(),
            Some(Musig2Mode::KeySpendWithScript(
                TapNodeHash::from_slice(&tweak).unwrap(),
            )),
        )
        .unwrap();

        let aggregated_nonce = super::aggregate_nonces(
            nonce_pairs
                .iter()
                .map(|(_, musig_pub_nonce)| musig_pub_nonce)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let partial_sigs = key_pairs
            .into_iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    public_keys.clone(),
                    Some(Musig2Mode::KeySpendWithScript(
                        TapNodeHash::from_slice(&tweak).unwrap(),
                    )),
                    nonce_pair.0,
                    aggregated_nonce,
                    kp,
                    message,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let final_signature = super::aggregate_partial_signatures(
            &public_keys,
            Some(Musig2Mode::KeySpendWithScript(
                TapNodeHash::from_slice(&tweak).unwrap(),
            )),
            aggregated_nonce,
            &partial_sigs,
            message,
        )
        .unwrap();

        SECP.verify_schnorr(&final_signature, &message, &aggregated_pk)
            .unwrap();
    }

    #[test]
    fn musig2_tweak_fail() {
        let kp_0 = Keypair::new(&SECP, &mut secp256k1::rand::thread_rng());
        let kp_1 = Keypair::new(&SECP, &mut secp256k1::rand::thread_rng());
        let kp_2 = Keypair::new(&SECP, &mut secp256k1::rand::thread_rng());

        let message = Message::from_digest(secp256k1::rand::thread_rng().gen::<[u8; 32]>());

        let tweak: [u8; 32] = secp256k1::rand::thread_rng().gen();

        let pks = vec![kp_0.public_key(), kp_1.public_key(), kp_2.public_key()];

        let (sec_nonce_0, pub_nonce_0) =
            super::nonce_pair(&kp_0, &mut secp256k1::rand::thread_rng()).unwrap();
        let (sec_nonce_1, pub_nonce_1) =
            super::nonce_pair(&kp_1, &mut secp256k1::rand::thread_rng()).unwrap();
        let (sec_nonce_2, pub_nonce_2) =
            super::nonce_pair(&kp_2, &mut secp256k1::rand::thread_rng()).unwrap();

        let agg_nonce = super::aggregate_nonces(&[&pub_nonce_0, &pub_nonce_1, &pub_nonce_2]);

        let partial_sig_0 = super::partial_sign(
            pks.clone(),
            Some(Musig2Mode::KeySpendWithScript(
                TapNodeHash::from_slice(&tweak).unwrap(),
            )),
            sec_nonce_0,
            agg_nonce,
            kp_0,
            message,
        )
        .unwrap();
        let partial_sig_1 = super::partial_sign(
            pks.clone(),
            Some(Musig2Mode::KeySpendWithScript(
                TapNodeHash::from_slice(&tweak).unwrap(),
            )),
            sec_nonce_1,
            agg_nonce,
            kp_1,
            message,
        )
        .unwrap();
        // Oops, a verifier accidentally forgot to put the tweak!
        let partial_sig_2 =
            super::partial_sign(pks.clone(), None, sec_nonce_2, agg_nonce, kp_2, message).unwrap();
        let partial_sigs = vec![partial_sig_0, partial_sig_1, partial_sig_2];

        let final_signature = super::aggregate_partial_signatures(
            &pks,
            Some(Musig2Mode::KeySpendWithScript(
                TapNodeHash::from_slice(&tweak).unwrap(),
            )),
            agg_nonce,
            &partial_sigs,
            message,
        );

        assert!(final_signature.is_err());
    }

    #[test]
    fn musig2_key_spend() {
        let (key_pairs, nonce_pairs) = create_key_and_nonce_pairs(2);
        let public_keys = key_pairs
            .iter()
            .map(|key_pair| key_pair.public_key())
            .collect::<Vec<PublicKey>>();

        let untweaked_xonly_pubkey =
            XOnlyPublicKey::from_musig2_pks(public_keys.clone(), None).unwrap();

        let agg_nonce = super::aggregate_nonces(
            nonce_pairs
                .iter()
                .map(|(_, musig_pub_nonce)| musig_pub_nonce)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let dummy_script = script::Builder::new().push_int(1).into_script();
        let scripts: Vec<Arc<dyn SpendableScript>> =
            vec![Arc::new(OtherSpendable::new(dummy_script))];
        let receiving_address = bitcoin::Address::p2tr(
            &SECP,
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            None,
            bitcoin::Network::Regtest,
        );
        let (sending_address, sending_address_spend_info) =
            builder::address::create_taproot_address(
                &scripts
                    .iter()
                    .map(|a| a.to_script_buf())
                    .collect::<Vec<_>>(),
                Some(untweaked_xonly_pubkey),
                bitcoin::Network::Regtest,
            );

        let prevout = TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: sending_address.script_pubkey(),
        };
        let utxo = OutPoint {
            txid: Txid::from_byte_array([0u8; 32]),
            vout: 0,
        };

        let mut builder = TxHandlerBuilder::new();
        builder = builder
            .add_input(
                NormalSignatureKind::NotStored,
                SpendableTxIn::new(
                    utxo,
                    prevout.clone(),
                    scripts.clone(),
                    Some(sending_address_spend_info.clone()),
                ),
                builder::script::SpendPath::Unknown,
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(TxOut {
                value: Amount::from_sat(99_000_000),
                script_pubkey: receiving_address.script_pubkey(),
            }));

        let tx_details = builder.finalize();

        let message = Message::from_digest(
            tx_details
                .calculate_pubkey_spend_sighash(0, TapSighashType::Default)
                .unwrap()
                .to_byte_array(),
        );
        let merkle_root = sending_address_spend_info.merkle_root().unwrap();

        let partial_sigs: Vec<MusigPartialSignature> = key_pairs
            .into_iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    public_keys.clone(),
                    Some(Musig2Mode::KeySpendWithScript(merkle_root)),
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    message,
                )
                .unwrap()
            })
            .collect();

        let final_signature = super::aggregate_partial_signatures(
            &public_keys,
            Some(Musig2Mode::KeySpendWithScript(merkle_root)),
            agg_nonce,
            &partial_sigs,
            message,
        )
        .unwrap();

        let musig_agg_xonly_pubkey = XOnlyPublicKey::from_musig2_pks(
            public_keys,
            Some(Musig2Mode::KeySpendWithScript(merkle_root)),
        )
        .unwrap();

        SECP.verify_schnorr(&final_signature, &message, &musig_agg_xonly_pubkey)
            .unwrap();
    }

    #[test]
    fn musig2_script_spend() {
        let (key_pairs, nonce_pairs) = create_key_and_nonce_pairs(2);
        let public_keys = key_pairs
            .iter()
            .map(|key_pair| key_pair.public_key())
            .collect::<Vec<PublicKey>>();

        let agg_nonce = super::aggregate_nonces(
            nonce_pairs
                .iter()
                .map(|x| &x.1)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let musig_agg_xonly_pubkey_wrapped =
            XOnlyPublicKey::from_musig2_pks(public_keys.clone(), None).unwrap();

        let scripts: Vec<Arc<dyn SpendableScript>> =
            vec![Arc::new(CheckSig::new(musig_agg_xonly_pubkey_wrapped))];

        let receiving_address = bitcoin::Address::p2tr(
            &SECP,
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            None,
            bitcoin::Network::Regtest,
        );
        let (sending_address, sending_address_spend_info) =
            builder::address::create_taproot_address(
                &scripts
                    .iter()
                    .map(|a| a.to_script_buf())
                    .collect::<Vec<_>>(),
                None,
                bitcoin::Network::Regtest,
            );

        let prevout = TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: sending_address.script_pubkey(),
        };
        let utxo = OutPoint {
            txid: Txid::from_byte_array([0u8; 32]),
            vout: 0,
        };

        let tx_details = TxHandlerBuilder::new()
            .add_input(
                NormalSignatureKind::NotStored,
                SpendableTxIn::new(
                    utxo,
                    prevout,
                    scripts,
                    Some(sending_address_spend_info.clone()),
                ),
                builder::script::SpendPath::Unknown,
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(TxOut {
                value: Amount::from_sat(99_000_000),
                script_pubkey: receiving_address.script_pubkey(),
            }))
            .finalize();

        let message = Message::from_digest(
            tx_details
                .calculate_script_spend_sighash_indexed(0, 0, bitcoin::TapSighashType::Default)
                .unwrap()
                .to_byte_array(),
        );

        let partial_sigs: Vec<MusigPartialSignature> = key_pairs
            .into_iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    public_keys.clone(),
                    None,
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    message,
                )
                .unwrap()
            })
            .collect();

        let final_signature = super::aggregate_partial_signatures(
            &public_keys,
            None,
            agg_nonce,
            &partial_sigs,
            message,
        )
        .unwrap();

        SECP.verify_schnorr(&final_signature, &message, &musig_agg_xonly_pubkey_wrapped)
            .unwrap();
    }

    #[test]
    fn different_aggregated_keys_for_different_musig2_modes() {
        let kp1 = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
        let kp2 = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
        let public_keys = vec![kp1.public_key(), kp2.public_key()];

        let key_agg_cache = create_key_agg_cache(public_keys.clone(), None).unwrap();
        let agg_pk_no_tweak = from_secp_xonly(key_agg_cache.agg_pk());

        let key_agg_cache =
            create_key_agg_cache(public_keys.clone(), Some(Musig2Mode::ScriptSpend)).unwrap();
        let agg_pk_script_spend = from_secp_xonly(key_agg_cache.agg_pk());

        let key_agg_cache =
            create_key_agg_cache(public_keys.clone(), Some(Musig2Mode::OnlyKeySpend)).unwrap();
        let agg_pk_key_tweak = from_secp_xonly(key_agg_cache.agg_pk());

        let key_agg_cache = create_key_agg_cache(
            public_keys.clone(),
            Some(Musig2Mode::KeySpendWithScript(
                TapNodeHash::from_slice(&[1u8; 32]).unwrap(),
            )),
        )
        .unwrap();
        let agg_pk_script_tweak = from_secp_xonly(key_agg_cache.agg_pk());

        assert_eq!(agg_pk_no_tweak, agg_pk_script_spend);

        assert_ne!(agg_pk_no_tweak, agg_pk_script_tweak);
        assert_ne!(agg_pk_no_tweak, agg_pk_key_tweak);
        assert_ne!(agg_pk_script_tweak, agg_pk_key_tweak);
        assert_ne!(agg_pk_script_tweak, agg_pk_script_spend);
        assert_ne!(agg_pk_key_tweak, agg_pk_script_spend);
    }

    #[test]
    fn signing_checks_for_different_musig2_modes() {
        let kp1 = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
        let kp2 = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
        let public_keys = vec![kp1.public_key(), kp2.public_key()];

        let message = Message::from_digest(secp256k1::rand::thread_rng().gen());
        let key_spend_with_script_tweak =
            Musig2Mode::KeySpendWithScript(TapNodeHash::from_slice(&[0x45u8; 32]).unwrap());

        let key_agg_cache =
            create_key_agg_cache(public_keys.clone(), Some(key_spend_with_script_tweak)).unwrap();
        let agg_pk_script_tweak = from_secp_xonly(key_agg_cache.agg_pk());

        let (sec_nonce1, pub_nonce1) =
            nonce_pair(&kp1, &mut bitcoin::secp256k1::rand::thread_rng()).unwrap();
        let (sec_nonce2, pub_nonce2) =
            nonce_pair(&kp2, &mut bitcoin::secp256k1::rand::thread_rng()).unwrap();
        let agg_nonce = aggregate_nonces(&[&pub_nonce1, &pub_nonce2]);

        let partial_sig1 = partial_sign(
            public_keys.clone(),
            Some(key_spend_with_script_tweak),
            sec_nonce1,
            agg_nonce,
            kp1,
            message,
        )
        .unwrap();
        let partial_sig2 = partial_sign(
            public_keys.clone(),
            Some(key_spend_with_script_tweak),
            sec_nonce2,
            agg_nonce,
            kp2,
            message,
        )
        .unwrap();

        let final_sig = aggregate_partial_signatures(
            &public_keys,
            Some(key_spend_with_script_tweak),
            agg_nonce,
            &[partial_sig1, partial_sig2],
            message,
        )
        .unwrap();

        SECP.verify_schnorr(&final_sig, &message, &agg_pk_script_tweak)
            .unwrap();

        // Verification will fail with a untweaked aggregate public key against
        // a signature created with a tweaked aggregate public key.
        let key_agg_cache = create_key_agg_cache(public_keys.clone(), None).unwrap();
        let agg_pk_no_tweak = from_secp_xonly(key_agg_cache.agg_pk());
        assert!(SECP
            .verify_schnorr(&final_sig, &message, &agg_pk_no_tweak)
            .is_err());
    }
}
