use crate::{errors::BridgeError, ByteArray32, ByteArray64, ByteArray66};
use bitcoin::hashes::Hash;
use bitcoin::TapNodeHash;
use musig2::{sign_partial, AggNonce, KeyAggContext, SecNonce};
use secp256k1::{rand::Rng, PublicKey};

// We can directly use the musig2 crate for this
// No need for extra types etc.
// MuSigPubNonce consists of two curve points, so it's 66 bytes (compressed).
pub type MuSigPubNonce = ByteArray66;
// MuSigSecNonce consists of two scalars, so it's 64 bytes.
pub type MuSigSecNonce = ByteArray64;
// MuSigAggNonce is a scalar, so it's 32 bytes.
pub type MuSigAggNonce = ByteArray66;
// MuSigPartialSignature is a scalar, so it's 32 bytes.
pub type MuSigPartialSignature = ByteArray32;
// MuSigFinalSignature is a Schnorr signature, so it's 64 bytes.
pub type MuSigFinalSignature = ByteArray64;
// SigHash used for MuSig2 operations.
pub type MuSigSigHash = ByteArray32;
pub type MuSigNoncePair = (MuSigSecNonce, MuSigPubNonce);

pub trait AggregateFromPublicKeys {
    fn from_musig2_pks(
        pks: Vec<PublicKey>,
        tweak: Option<TapNodeHash>,
        tweak_flag: bool,
    ) -> secp256k1::XOnlyPublicKey;
}

impl AggregateFromPublicKeys for secp256k1::XOnlyPublicKey {
    #[tracing::instrument(ret(level = tracing::Level::TRACE))]
    fn from_musig2_pks(
        pks: Vec<PublicKey>,
        tweak: Option<TapNodeHash>,
        tweak_flag: bool,
    ) -> secp256k1::XOnlyPublicKey {
        let key_agg_ctx = create_key_agg_ctx(pks, tweak, tweak_flag).unwrap();
        let musig_agg_pubkey: musig2::secp256k1::PublicKey = if tweak_flag {
            key_agg_ctx.aggregated_pubkey()
        } else {
            key_agg_ctx.aggregated_pubkey_untweaked()
        };
        // tracing::debug!("UNTWEAKED AGGREGATED PUBKEY: {:?}", musig_agg_pubkey);
        let musig_agg_xonly_pubkey = musig_agg_pubkey.x_only_public_key().0;
        secp256k1::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap()
    }
}

// Creates the key aggregation context, with the public keys and the tweak (if any).
// There are two functions to retrieve the aggregated public key, one with the tweak and one without.
#[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
pub fn create_key_agg_ctx(
    pks: Vec<PublicKey>,
    tweak: Option<TapNodeHash>,
    tweak_flag: bool,
) -> Result<KeyAggContext, BridgeError> {
    let musig_pks: Vec<musig2::secp256k1::PublicKey> = pks
        .iter()
        .map(|pk| musig2::secp256k1::PublicKey::from_slice(&pk.serialize()).unwrap())
        .collect::<Vec<musig2::secp256k1::PublicKey>>();
    let key_agg_ctx_raw = KeyAggContext::new(musig_pks)?;
    // tracing::debug!(
    //     "UNTWEAKED AGGREGATED PUBKEY: {:?}",
    //     key_agg_ctx_raw.aggregated_pubkey::<musig2::secp256k1::PublicKey>()
    // );
    if tweak_flag {
        let key_agg_ctx = match tweak {
            Some(scalar) => key_agg_ctx_raw.with_taproot_tweak(&scalar.to_byte_array())?,
            None => key_agg_ctx_raw.with_unspendable_taproot_tweak()?,
        };
        // tracing::debug!(
        //     "TWEAKED AGGREGATED PUBKEY: {:?}",
        //     key_agg_ctx.aggregated_pubkey::<musig2::secp256k1::PublicKey>()
        // );
        Ok(key_agg_ctx)
    } else {
        if tweak.is_some() {
            return Err(BridgeError::VecConversionError); // TODO: Change error handling.
        }
        Ok(key_agg_ctx_raw)
    }
}

// Aggregates the public nonces into a single aggregated nonce. Wrapper for the musig2::AggNonce::sum function.
#[tracing::instrument(ret(level = tracing::Level::TRACE))]
pub fn aggregate_nonces(pub_nonces: Vec<MuSigPubNonce>) -> MuSigAggNonce {
    let musig_pub_nonces: Vec<musig2::PubNonce> = pub_nonces
        .iter()
        .map(|x| musig2::PubNonce::from_bytes(&x.0).unwrap())
        .collect::<Vec<musig2::PubNonce>>();
    let musig_agg_nonce: AggNonce = AggNonce::sum(musig_pub_nonces);
    ByteArray66(musig_agg_nonce.into())
}

// Aggregates the partial signatures into a single final signature. Wrapper for the musig2::aggregate_partial_signatures function.
#[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
pub fn aggregate_partial_signatures(
    pks: Vec<PublicKey>,
    tweak: Option<TapNodeHash>,
    tweak_flag: bool,
    agg_nonce: &MuSigAggNonce,
    partial_sigs: Vec<MuSigPartialSignature>,
    message: MuSigSigHash,
) -> Result<[u8; 64], BridgeError> {
    let key_agg_ctx = create_key_agg_ctx(pks, tweak, tweak_flag)?;
    let musig_partial_sigs: Vec<musig2::PartialSignature> = partial_sigs
        .iter()
        .map(|x| musig2::PartialSignature::from_slice(&x.0).unwrap())
        .collect::<Vec<musig2::PartialSignature>>();
    Ok(musig2::aggregate_partial_signatures(
        &key_agg_ctx,
        &AggNonce::from_bytes(&agg_nonce.0).unwrap(),
        musig_partial_sigs,
        message.0,
    )?)
}

// Generates a pair of nonces, one secret and one public. Wrapper for the musig2::SecNonce::build function. Be careful,
// DO NOT REUSE the same pair of nonces for multiple transactions. It will cause you to leak your secret key. For more information,
// see https://medium.com/blockstream/musig-dn-schnorr-multisignatures-with-verifiably-deterministic-nonces-27424b5df9d6#e3b6.
#[tracing::instrument(skip(rng), ret(level = tracing::Level::TRACE))]
pub fn nonce_pair(
    keypair: &secp256k1::Keypair, // TODO: Remove this field
    rng: &mut impl Rng,
) -> (MuSigSecNonce, MuSigPubNonce) {
    let rnd = rng.gen::<[u8; 32]>();
    let sec_nonce = SecNonce::build(rnd).build();

    let pub_nonce = ByteArray66(sec_nonce.public_nonce().into());
    let sec_nonce: [u8; 64] = sec_nonce.into();

    (ByteArray64(sec_nonce), pub_nonce)
}

// We are creating the key aggregation context manually here, adding the tweaks by hand.
#[tracing::instrument(ret(level = tracing::Level::TRACE))]
pub fn partial_sign(
    pks: Vec<PublicKey>,
    // Aggregated tweak, if there is any. This is useful for
    // Taproot key-spends, since we might have script-spend conditions.
    tweak: Option<TapNodeHash>,
    tweak_flag: bool,
    sec_nonce: MuSigSecNonce,
    agg_nonce: MuSigAggNonce,
    keypair: &secp256k1::Keypair,
    sighash: MuSigSigHash,
) -> MuSigPartialSignature {
    let key_agg_ctx = create_key_agg_ctx(pks, tweak, tweak_flag).unwrap();
    let musig_sec_nonce = SecNonce::from_bytes(&sec_nonce.0).unwrap();
    let musig_agg_nonce = AggNonce::from_bytes(&agg_nonce.0).unwrap();
    let partial_signature: [u8; 32] = sign_partial(
        &key_agg_ctx,
        musig2::secp256k1::SecretKey::from_slice(&keypair.secret_key().secret_bytes()).unwrap(),
        musig_sec_nonce,
        &musig_agg_nonce,
        sighash.0,
    )
    .unwrap();
    ByteArray32(partial_signature)
}

#[cfg(test)]
mod tests {
    use super::{nonce_pair, MuSigNoncePair};
    use crate::{
        actor::Actor,
        builder::{self, transaction::TxHandler},
        errors::BridgeError,
        musig2::{AggregateFromPublicKeys, MuSigPartialSignature},
        utils, ByteArray32,
    };
    use bitcoin::{
        hashes::Hash, opcodes::all::OP_CHECKSIG, script, Amount, OutPoint, ScriptBuf, TapNodeHash,
        TxOut, Txid,
    };
    use secp256k1::{rand::Rng, Keypair, Message, XOnlyPublicKey, SECP256K1};
    use std::vec;

    // Generates a test setup with a given number of signers. Returns a vector of keypairs and a vector of nonce pairs.
    fn generate_test_setup(num_signers: usize) -> (Vec<Keypair>, Vec<MuSigNoncePair>) {
        let mut keypair_vec: Vec<Keypair> = Vec::new();
        for _ in 0..num_signers {
            keypair_vec.push(Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng()));
        }
        let nonce_pair_vec: Vec<MuSigNoncePair> = keypair_vec
            .iter()
            .map(|keypair| nonce_pair(keypair, &mut secp256k1::rand::thread_rng()))
            .collect();
        (keypair_vec, nonce_pair_vec)
    }

    // Test the MuSig2 signature scheme raw (without a tweak).
    #[test]
    fn test_musig2_raw() {
        // Generate a test setup with 3 signers
        let (kp_vec, nonce_pair_vec) = generate_test_setup(3);
        // Generate a random message
        let message: [u8; 32] = secp256k1::rand::thread_rng().gen();
        // Extract the public keys
        let pks = kp_vec
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<secp256k1::PublicKey>>();
        // Create the key aggregation context
        let key_agg_ctx = super::create_key_agg_ctx(pks.clone(), None, false).unwrap();
        // Aggregate the public nonces into the aggregated nonce
        let agg_nonce = super::aggregate_nonces(nonce_pair_vec.iter().map(|x| x.1).collect());
        // Extract the aggregated public key
        let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
        // Calculate the partial signatures
        let partial_sigs: Vec<MuSigPartialSignature> = kp_vec
            .iter()
            .zip(nonce_pair_vec.iter())
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    pks.clone(),
                    None,
                    false,
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    ByteArray32(message),
                )
            })
            .collect();
        // Aggregate the partial signatures into a final signature
        let final_signature: [u8; 64] = super::aggregate_partial_signatures(
            pks,
            None,
            false,
            &agg_nonce,
            partial_sigs,
            ByteArray32(message),
        )
        .unwrap();
        musig2::verify_single(musig_agg_pubkey, final_signature, message)
            .expect("Verification failed!");
        println!("MuSig2 signature verified successfully!");
    }

    // Test that the verification fails if one of the partial signatures is invalid.
    #[test]
    fn test_musig2_raw_fail() {
        let kp_0 = secp256k1::Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
        let kp_1 = secp256k1::Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
        let kp_2 = secp256k1::Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
        let message: [u8; 32] = secp256k1::rand::thread_rng().gen();
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
            &kp_0,
            ByteArray32(message),
        );
        let partial_sig_1 = super::partial_sign(
            pks.clone(),
            None,
            false,
            sec_nonce_1,
            agg_nonce,
            &kp_1,
            ByteArray32(message),
        );
        // Oops, a verifier accidentally added some tweak!
        let partial_sig_2 = super::partial_sign(
            pks.clone(),
            Some(TapNodeHash::from_slice(&[1u8; 32]).unwrap()),
            true,
            sec_nonce_2,
            agg_nonce,
            &kp_2,
            ByteArray32(message),
        );
        let partial_sigs = vec![partial_sig_0, partial_sig_1, partial_sig_2];
        let final_signature: Result<[u8; 64], BridgeError> = super::aggregate_partial_signatures(
            pks,
            None,
            false,
            &agg_nonce,
            partial_sigs,
            ByteArray32(message),
        );
        assert!(final_signature.is_err());
    }

    // Test the MuSig2 signature scheme with a tweak.
    #[test]
    fn test_musig2_tweak() {
        let (kp_vec, nonce_pair_vec) = generate_test_setup(3);
        let message: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let tweak: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let pks = kp_vec
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<secp256k1::PublicKey>>();
        let key_agg_ctx = super::create_key_agg_ctx(
            pks.clone(),
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
        )
        .unwrap();
        let agg_nonce = super::aggregate_nonces(nonce_pair_vec.iter().map(|x| x.1).collect());
        let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
        let partial_sigs: Vec<MuSigPartialSignature> = kp_vec
            .iter()
            .zip(nonce_pair_vec.iter())
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    pks.clone(),
                    Some(TapNodeHash::from_slice(&tweak).unwrap()),
                    true,
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    ByteArray32(message),
                )
            })
            .collect();
        let final_signature: [u8; 64] = super::aggregate_partial_signatures(
            pks,
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
            &agg_nonce,
            partial_sigs,
            ByteArray32(message),
        )
        .unwrap();
        musig2::verify_single(musig_agg_pubkey, final_signature, message)
            .expect("Verification failed!");
        println!("MuSig2 signature verified successfully!");
    }

    #[test]
    fn test_musig2_tweak_fail() {
        let kp_0 = secp256k1::Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
        let kp_1 = secp256k1::Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
        let kp_2 = secp256k1::Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
        let message: [u8; 32] = secp256k1::rand::thread_rng().gen();
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
            &kp_0,
            ByteArray32(message),
        );
        let partial_sig_1 = super::partial_sign(
            pks.clone(),
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
            sec_nonce_1,
            agg_nonce,
            &kp_1,
            ByteArray32(message),
        );
        // Oops, a verifier accidentally forgot to put the tweak!
        let partial_sig_2 = super::partial_sign(
            pks.clone(),
            None,
            false,
            sec_nonce_2,
            agg_nonce,
            &kp_2,
            ByteArray32(message),
        );
        let partial_sigs = vec![partial_sig_0, partial_sig_1, partial_sig_2];
        let final_signature = super::aggregate_partial_signatures(
            pks,
            Some(TapNodeHash::from_slice(&tweak).unwrap()),
            true,
            &agg_nonce,
            partial_sigs,
            ByteArray32(message),
        );
        assert!(final_signature.is_err());
    }

    // Test the MuSig2 signature scheme with a dummy key spend.
    #[test]
    fn test_musig2_dummy_key_spend() {
        let (kp_vec, nonce_pair_vec) = generate_test_setup(2);
        let pks = kp_vec
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<secp256k1::PublicKey>>();
        let key_agg_ctx = super::create_key_agg_ctx(pks.clone(), None, true).unwrap();

        let untweaked_pubkey =
            key_agg_ctx.aggregated_pubkey_untweaked::<musig2::secp256k1::PublicKey>();
        let untweaked_xonly_pubkey: secp256k1::XOnlyPublicKey =
            secp256k1::XOnlyPublicKey::from_slice(
                &untweaked_pubkey.x_only_public_key().0.serialize(),
            )
            .unwrap();
        let agg_nonce = super::aggregate_nonces(nonce_pair_vec.iter().map(|x| x.1).collect());
        let dummy_script = script::Builder::new().push_int(1).into_script();
        let scripts: Vec<ScriptBuf> = vec![dummy_script];
        let receiving_address = bitcoin::Address::p2tr(
            SECP256K1,
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
        let message = Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_details, 0)
            .unwrap()
            .to_byte_array();
        let merkle_root = sending_address_spend_info.merkle_root();
        let partial_sigs: Vec<MuSigPartialSignature> = kp_vec
            .iter()
            .zip(nonce_pair_vec.iter())
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    pks.clone(),
                    merkle_root,
                    true,
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    ByteArray32(message),
                )
            })
            .collect();
        let final_signature: [u8; 64] = super::aggregate_partial_signatures(
            pks.clone(),
            merkle_root,
            true,
            &agg_nonce,
            partial_sigs,
            ByteArray32(message),
        )
        .unwrap();
        let musig_agg_xonly_pubkey_wrapped =
            XOnlyPublicKey::from_musig2_pks(pks, merkle_root, true);
        // musig2::verify_single(musig_agg_pubkey, &final_signature, message)
        //     .expect("Verification failed!");
        SECP256K1
            .verify_schnorr(
                &secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap(),
                &Message::from_digest(message),
                &musig_agg_xonly_pubkey_wrapped,
            )
            .unwrap();
        println!("MuSig2 signature verified successfully!");
    }

    // Test the MuSig2 signature scheme with a dummy script spend.
    #[test]
    fn test_musig2_dummy_script_spend() {
        let (kp_vec, nonce_pair_vec) = generate_test_setup(2);
        let pks = kp_vec
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<secp256k1::PublicKey>>();
        let agg_nonce = super::aggregate_nonces(nonce_pair_vec.iter().map(|x| x.1).collect());
        let musig_agg_xonly_pubkey_wrapped =
            XOnlyPublicKey::from_musig2_pks(pks.clone(), None, false);
        let musig2_script = bitcoin::script::Builder::new()
            .push_x_only_key(&musig_agg_xonly_pubkey_wrapped)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let scripts: Vec<ScriptBuf> = vec![musig2_script];
        let receiving_address = bitcoin::Address::p2tr(
            SECP256K1,
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
        let message = Actor::convert_tx_to_sighash_script_spend(&mut tx_details, 0, 0)
            .unwrap()
            .to_byte_array();

        let partial_sigs: Vec<MuSigPartialSignature> = kp_vec
            .iter()
            .zip(nonce_pair_vec.iter())
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    pks.clone(),
                    None,
                    false,
                    nonce_pair.0,
                    agg_nonce,
                    kp,
                    ByteArray32(message),
                )
            })
            .collect();
        let final_signature: [u8; 64] = super::aggregate_partial_signatures(
            pks,
            None,
            false,
            &agg_nonce,
            partial_sigs,
            ByteArray32(message),
        )
        .unwrap();
        // musig2::verify_single(musig_agg_pubkey, &final_signature, message)
        //     .expect("Verification failed!");
        SECP256K1
            .verify_schnorr(
                &secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap(),
                &Message::from_digest(message),
                &musig_agg_xonly_pubkey_wrapped,
            )
            .unwrap();
        println!("MuSig2 signature verified successfully!");
    }
}
