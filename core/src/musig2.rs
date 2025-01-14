//! # MuSig2
//!
//! Helper functions for the MuSig2 signature scheme.

use crate::{errors::BridgeError, utils::SECP, ByteArray64};
use bitcoin::{
    hashes::Hash,
    key::Keypair,
    secp256k1::{schnorr, Message, PublicKey, SecretKey},
    TapNodeHash, XOnlyPublicKey,
};
use secp256k1::{
    musig::{
        new_musig_nonce_pair, MusigAggNonce, MusigKeyAggCache, MusigPartialSignature,
        MusigPubNonce, MusigSecNonce, MusigSecRand, MusigSession,
    },
    rand::Rng,
    Scalar, SECP256K1,
};

// We can directly use the musig2 crate for this
// No need for extra types etc.
// MuSigPubNonce consists of two curve points, so it's 66 bytes (compressed).
// pub type MuSigPubNonce = ByteArray66;
// MuSigSecNonce consists of two scalars, so it's 64 bytes.
// pub type MuSigSecNonce = ByteArray64;
// MuSigAggNonce is a scalar, so it's 32 bytes.
// pub type MuSigAggNonce = ByteArray66;
// MusigPartialSignature is a scalar, so it's 32 bytes.
// pub type MusigPartialSignature = ByteArray32;
// MuSigFinalSignature is a Schnorr signature, so it's 64 bytes.
pub type MuSigFinalSignature = ByteArray64;
// SigHash used for MuSig2 operations.
// pub type MuSigSigHash = ByteArray32;
pub type MuSigNoncePair = (MusigSecNonce, MusigPubNonce);

pub trait AggregateFromPublicKeys {
    fn from_musig2_pks(
        pks: Vec<PublicKey>,
        tweak: Option<TapNodeHash>,
        tweak_flag: bool,
    ) -> XOnlyPublicKey;
}

pub fn from_secp_xonly(xpk: secp256k1::XOnlyPublicKey) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&xpk.serialize()).unwrap()
}

pub fn to_secp_pk(pk: PublicKey) -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn from_secp_pk(pk: secp256k1::PublicKey) -> PublicKey {
    PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn to_secp_sk(sk: SecretKey) -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&sk.secret_bytes()).unwrap()
}

pub fn to_secp_kp(kp: &Keypair) -> secp256k1::Keypair {
    secp256k1::Keypair::from_seckey_slice(SECP256K1, &kp.secret_bytes()).unwrap()
}

pub fn from_secp_kp(kp: &secp256k1::Keypair) -> Keypair {
    Keypair::from_seckey_slice(&SECP, &kp.secret_bytes()).unwrap()
}

pub fn from_secp_sig(sig: secp256k1::schnorr::Signature) -> schnorr::Signature {
    schnorr::Signature::from_slice(&sig.to_byte_array()).unwrap()
}

pub fn to_secp_msg(msg: &Message) -> secp256k1::Message {
    secp256k1::Message::from_digest(*msg.as_ref())
}

impl AggregateFromPublicKeys for XOnlyPublicKey {
    #[tracing::instrument(ret(level = tracing::Level::TRACE))]
    fn from_musig2_pks(
        pks: Vec<PublicKey>,
        tweak: Option<TapNodeHash>,
        tweak_flag: bool,
    ) -> XOnlyPublicKey {
        let secp_pubkeys: Vec<secp256k1::PublicKey> =
            pks.iter().map(|pk| to_secp_pk(*pk)).collect();
        let pubkeys_ref: Vec<&secp256k1::PublicKey> = secp_pubkeys.iter().collect();
        let pubkeys_ref = pubkeys_ref.as_slice();

        let mut musig_key_agg_cache = MusigKeyAggCache::new(SECP256K1, pubkeys_ref);

        let ret = if let Some(tweak) = tweak {
            let xonly_tweak = Scalar::from_be_bytes(tweak.to_raw_hash().to_byte_array()).unwrap();
            let _tweaked_agg_pk = musig_key_agg_cache
                .pubkey_xonly_tweak_add(SECP256K1, &xonly_tweak)
                .unwrap();

            musig_key_agg_cache.agg_pk()
        } else {
            musig_key_agg_cache.agg_pk()
        };

        XOnlyPublicKey::from_slice(&ret.serialize()).unwrap()

        // let key_agg_ctx = create_key_agg_ctx(pks, tweak, tweak_flag).unwrap();
        // let musig_agg_pubkey: secp256k1::PublicKey = if tweak_flag {
        //     key_agg_ctx.aggregated_pubkey()
        // } else {
        //     key_agg_ctx.aggregated_pubkey_untweaked()
        // };
        // tracing::debug!("UNTWEAKED AGGREGATED PUBKEY: {:?}", musig_agg_pubkey);
        // let musig_agg_xonly_pubkey = musig_agg_pubkey.x_only_public_key().0;
        // secp256k1::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap()
    }
}

// Aggregates the public nonces into a single aggregated nonce.
pub fn aggregate_nonces(pub_nonces: Vec<MusigPubNonce>) -> MusigAggNonce {
    let pub_nonces = pub_nonces.iter().collect::<Vec<_>>();

    MusigAggNonce::new(SECP256K1, pub_nonces.as_slice())
}

// Aggregates the partial signatures into a single final signature.
#[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
pub fn aggregate_partial_signatures(
    pks: Vec<PublicKey>,
    tweak: Option<TapNodeHash>,
    tweak_flag: bool,
    agg_nonce: MusigAggNonce,
    partial_sigs: Vec<MusigPartialSignature>,
    message: Message,
) -> Result<schnorr::Signature, BridgeError> {
    let secp_pubkeys: Vec<secp256k1::PublicKey> = pks.iter().map(|pk| to_secp_pk(*pk)).collect();
    let pubkeys_ref: Vec<&secp256k1::PublicKey> = secp_pubkeys.iter().collect();
    let pubkeys_ref = pubkeys_ref.as_slice();
    let musig_key_agg_cache = MusigKeyAggCache::new(SECP256K1, pubkeys_ref);

    let session = MusigSession::new(
        SECP256K1,
        &musig_key_agg_cache,
        agg_nonce,
        to_secp_msg(&message),
    );

    let musig_partial_sigs = &partial_sigs[0];

    Ok(from_secp_sig(
        session.partial_sig_agg(&[musig_partial_sigs]),
    ))
}

/// Generates a pair of nonces, one secret and one public. Be careful,
/// DO NOT REUSE the same pair of nonces for multiple transactions. It will cause
/// you to leak your secret key. For more information. See:
/// https://medium.com/blockstream/musig-dn-schnorr-multisignatures-with-verifiably-deterministic-nonces-27424b5df9d6#e3b6.
#[tracing::instrument(skip(rng), ret(level = tracing::Level::TRACE))]
pub fn nonce_pair(
    keypair: &Keypair, // TODO: Remove this field
    mut rng: &mut impl Rng,
) -> (MusigSecNonce, MusigPubNonce) {
    let musig_session_sec_rand = MusigSecRand::new(&mut rng);

    new_musig_nonce_pair(
        SECP256K1,
        musig_session_sec_rand,
        None,
        None,
        to_secp_kp(keypair).public_key(),
        None,
        None,
    )
    .unwrap()
}

#[tracing::instrument(ret(level = tracing::Level::TRACE))]
pub fn partial_sign(
    pks: Vec<PublicKey>,
    // Aggregated tweak, if there is any. This is useful for
    // Taproot key-spends, since we might have script-spend conditions.
    tweak: Option<TapNodeHash>,
    tweak_flag: bool,
    sec_nonce: MusigSecNonce,
    agg_nonce: MusigAggNonce,
    keypair: Keypair,
    sighash: Message,
) -> MusigPartialSignature {
    let secp_pubkeys: Vec<secp256k1::PublicKey> = pks.iter().map(|pk| to_secp_pk(*pk)).collect();
    let pubkeys_ref: Vec<&secp256k1::PublicKey> = secp_pubkeys.iter().collect();
    let pubkeys_ref = pubkeys_ref.as_slice();
    let musig_key_agg_cache = MusigKeyAggCache::new(SECP256K1, pubkeys_ref);

    let session = MusigSession::new(
        SECP256K1,
        &musig_key_agg_cache,
        agg_nonce,
        to_secp_msg(&sighash),
    );

    session
        .partial_sign(
            SECP256K1,
            sec_nonce,
            &to_secp_kp(&keypair),
            &musig_key_agg_cache,
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::{nonce_pair, MuSigNoncePair};
    use crate::{
        actor::Actor,
        builder::{self, transaction::TxHandler},
        errors::BridgeError,
        musig2::AggregateFromPublicKeys,
        utils::{self, SECP},
    };
    use bitcoin::{
        hashes::Hash,
        key::Keypair,
        opcodes::all::OP_CHECKSIG,
        script,
        secp256k1::{schnorr, Message, PublicKey},
        Amount, OutPoint, ScriptBuf, TapNodeHash, TxOut, Txid, XOnlyPublicKey,
    };
    use secp256k1::{musig::MusigPartialSignature, rand::Rng};
    use std::vec;

    /// Generates random key and nonce pairs for a given number of signers.
    fn create_key_and_nonce_pairs(num_signers: usize) -> (Vec<Keypair>, Vec<MuSigNoncePair>) {
        let mut key_pairs = Vec::new();
        let mut nonce_pairs = Vec::new();

        for _ in 0..num_signers {
            let key_pair = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
            let nonce_pair = nonce_pair(&key_pair, &mut bitcoin::secp256k1::rand::thread_rng());

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
        let agg_pk = XOnlyPublicKey::from_musig2_pks(public_keys.clone(), None, false);

        let aggregated_nonce = super::aggregate_nonces(
            nonce_pairs
                .iter()
                .map(|(_, musig_pub_nonce)| *musig_pub_nonce)
                .collect(),
        );

        let partial_sigs = key_pairs
            .into_iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    public_keys.clone(),
                    None,
                    false,
                    nonce_pair.0,
                    aggregated_nonce,
                    kp,
                    message,
                )
            })
            .collect::<Vec<_>>();

        let final_signature = super::aggregate_partial_signatures(
            public_keys.clone(),
            None,
            false,
            aggregated_nonce,
            partial_sigs,
            message,
        )
        .unwrap();

        SECP.verify_schnorr(&final_signature, &message, &agg_pk)
            .unwrap();
    }

    #[test]
    fn musig2_raw_fail_if_partial_sigs_invalid() {
        let kp_0 = Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_1 = Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_2 = Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());

        let message = Message::from_digest(secp256k1::rand::thread_rng().gen());

        let pks = vec![kp_0.public_key(), kp_1.public_key(), kp_2.public_key()];

        let (sec_nonce_0, pub_nonce_0) =
            super::nonce_pair(&kp_0, &mut secp256k1::rand::thread_rng());
        let (sec_nonce_1, pub_nonce_1) =
            super::nonce_pair(&kp_1, &mut secp256k1::rand::thread_rng());
        let (sec_nonce_2, pub_nonce_2) =
            super::nonce_pair(&kp_2, &mut secp256k1::rand::thread_rng());

        let agg_nonce = super::aggregate_nonces(vec![pub_nonce_0, pub_nonce_1, pub_nonce_2]);

        let partial_sig_0 = super::partial_sign(
            pks.clone(),
            None,
            false,
            sec_nonce_0,
            agg_nonce,
            kp_0,
            message,
        );
        let partial_sig_1 = super::partial_sign(
            pks.clone(),
            None,
            false,
            sec_nonce_1,
            agg_nonce,
            kp_1,
            message,
        );
        // Oops, a verifier accidentally added some tweak!
        let partial_sig_2 = super::partial_sign(
            pks.clone(),
            Some(TapNodeHash::from_slice(&[1u8; 32]).unwrap()),
            true,
            sec_nonce_2,
            agg_nonce,
            kp_2,
            message,
        );
        let partial_sigs = vec![partial_sig_0, partial_sig_1, partial_sig_2];

        let final_signature: Result<schnorr::Signature, BridgeError> =
            super::aggregate_partial_signatures(pks, None, false, agg_nonce, partial_sigs, message);

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
        let aggregated_pk = XOnlyPublicKey::from_musig2_pks(
            public_keys.clone(),
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
        );

        let aggregated_nonce = super::aggregate_nonces(
            nonce_pairs
                .iter()
                .map(|(_, musig_pub_nonce)| *musig_pub_nonce)
                .collect(),
        );

        let partial_sigs = key_pairs
            .into_iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    public_keys.clone(),
                    Some(TapNodeHash::from_slice(&tweak).unwrap()),
                    true,
                    nonce_pair.0,
                    aggregated_nonce,
                    kp,
                    message,
                )
            })
            .collect::<Vec<_>>();

        let final_signature = super::aggregate_partial_signatures(
            public_keys,
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
            aggregated_nonce,
            partial_sigs,
            message,
        )
        .unwrap();

        SECP.verify_schnorr(&final_signature, &message, &aggregated_pk)
            .unwrap();
    }

    #[test]
    fn musig2_tweak_fail() {
        let kp_0 = Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_1 = Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_2 = Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());

        let message = Message::from_digest(secp256k1::rand::thread_rng().gen::<[u8; 32]>());
        let tweak: [u8; 32] = secp256k1::rand::thread_rng().gen();

        let pks = vec![kp_0.public_key(), kp_1.public_key(), kp_2.public_key()];

        let (sec_nonce_0, pub_nonce_0) =
            super::nonce_pair(&kp_0, &mut secp256k1::rand::thread_rng());
        let (sec_nonce_1, pub_nonce_1) =
            super::nonce_pair(&kp_1, &mut secp256k1::rand::thread_rng());
        let (sec_nonce_2, pub_nonce_2) =
            super::nonce_pair(&kp_2, &mut secp256k1::rand::thread_rng());

        let agg_nonce = super::aggregate_nonces(vec![pub_nonce_0, pub_nonce_1, pub_nonce_2]);

        let partial_sig_0 = super::partial_sign(
            pks.clone(),
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
            sec_nonce_0,
            agg_nonce,
            kp_0,
            message,
        );
        let partial_sig_1 = super::partial_sign(
            pks.clone(),
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
            sec_nonce_1,
            agg_nonce,
            kp_1,
            message,
        );
        // Oops, a verifier accidentally forgot to put the tweak!
        let partial_sig_2 = super::partial_sign(
            pks.clone(),
            None,
            false,
            sec_nonce_2,
            agg_nonce,
            kp_2,
            message,
        );
        let partial_sigs = vec![partial_sig_0, partial_sig_1, partial_sig_2];

        let final_signature = super::aggregate_partial_signatures(
            pks,
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
            agg_nonce,
            partial_sigs,
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
            XOnlyPublicKey::from_musig2_pks(public_keys.clone(), None, false);

        let agg_nonce = super::aggregate_nonces(
            nonce_pairs
                .iter()
                .map(|(_, musig_pub_nonce)| *musig_pub_nonce)
                .collect(),
        );

        let dummy_script = script::Builder::new().push_int(1).into_script();
        let scripts: Vec<ScriptBuf> = vec![dummy_script];
        let receiving_address = bitcoin::Address::p2tr(
            &utils::SECP,
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            None,
            bitcoin::Network::Regtest,
        );
        let (sending_address, sending_address_spend_info) =
            builder::address::create_taproot_address(
                &scripts.clone(),
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

        let tx_outs = builder::transaction::create_tx_outs(vec![(
            Amount::from_sat(99_000_000),
            receiving_address.script_pubkey(),
        )]);
        let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
        let dummy_tx = builder::transaction::create_btc_tx(tx_ins, tx_outs);
        let mut tx_details = TxHandler {
            txid: dummy_tx.compute_txid(),
            tx: dummy_tx,
            prevouts: vec![prevout],
            prev_scripts: vec![scripts],
            prev_taproot_spend_infos: vec![Some(sending_address_spend_info.clone())],
            out_scripts: vec![vec![]],
            out_taproot_spend_infos: vec![None],
        };

        let message = Message::from_digest(
            Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_details, 0)
                .unwrap()
                .to_byte_array(),
        );
        let merkle_root = sending_address_spend_info.merkle_root();

        let partial_sigs: Vec<MusigPartialSignature> = key_pairs
            .into_iter()
            .zip(nonce_pairs)
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    public_keys.clone(),
                    merkle_root,
                    true,
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    message,
                )
            })
            .collect();

        let final_signature = super::aggregate_partial_signatures(
            public_keys.clone(),
            merkle_root,
            true,
            agg_nonce,
            partial_sigs,
            message,
        )
        .unwrap();

        let musig_agg_xonly_pubkey =
            XOnlyPublicKey::from_musig2_pks(public_keys, merkle_root, true);

        utils::SECP
            .verify_schnorr(&final_signature, &message, &musig_agg_xonly_pubkey)
            .unwrap();
    }

    #[test]
    fn musig2_script_spend() {
        let (key_pairs, nonce_pairs) = create_key_and_nonce_pairs(2);
        let public_keys = key_pairs
            .iter()
            .map(|key_pair| key_pair.public_key())
            .collect::<Vec<PublicKey>>();

        let agg_nonce = super::aggregate_nonces(nonce_pairs.iter().map(|x| x.1).collect());
        let musig_agg_xonly_pubkey_wrapped =
            XOnlyPublicKey::from_musig2_pks(public_keys.clone(), None, false);

        let musig2_script = bitcoin::script::Builder::new()
            .push_x_only_key(&musig_agg_xonly_pubkey_wrapped)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let scripts: Vec<ScriptBuf> = vec![musig2_script];

        let receiving_address = bitcoin::Address::p2tr(
            &utils::SECP,
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            None,
            bitcoin::Network::Regtest,
        );
        let (sending_address, sending_address_spend_info) =
            builder::address::create_taproot_address(
                &scripts.clone(),
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

        let tx_outs = builder::transaction::create_tx_outs(vec![(
            Amount::from_sat(99_000_000),
            receiving_address.script_pubkey(),
        )]);
        let tx_ins = builder::transaction::create_tx_ins(vec![utxo]);
        let dummy_tx = builder::transaction::create_btc_tx(tx_ins, tx_outs);
        let mut tx_details = TxHandler {
            txid: dummy_tx.compute_txid(),
            tx: dummy_tx,
            prevouts: vec![prevout],
            prev_scripts: vec![scripts],
            prev_taproot_spend_infos: vec![Some(sending_address_spend_info.clone())],
            out_scripts: vec![vec![]],
            out_taproot_spend_infos: vec![None],
        };

        let message = Message::from_digest(
            Actor::convert_tx_to_sighash_script_spend(&mut tx_details, 0, 0)
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
                    false,
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    message,
                )
            })
            .collect();

        let final_signature = super::aggregate_partial_signatures(
            public_keys,
            None,
            false,
            agg_nonce,
            partial_sigs,
            message,
        )
        .unwrap();

        utils::SECP
            .verify_schnorr(&final_signature, &message, &musig_agg_xonly_pubkey_wrapped)
            .unwrap();
    }
}
