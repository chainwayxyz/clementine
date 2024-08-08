use musig2::{secp::Scalar, sign_partial, AggNonce, KeyAggContext, SecNonce, SecNonceSpices};
use secp256k1::{rand::Rng, Keypair, PublicKey};

use crate::{errors::BridgeError, ByteArray66};

// We can directly use the musig2 crate for this
// No need for extra types etc.
// MuSigPubNonce consists of two curve points, so it's 66 bytes (compressed).
pub type MuSigPubNonce = ByteArray66;
// MuSigSecNonce consists of two scalars, so it's 64 bytes.
pub type MuSigSecNonce = [u8; 64];
// MuSigAggNonce is a scalar, so it's 32 bytes.
pub type MuSigAggNonce = ByteArray66;
// MuSigPartialSignature is a scalar, so it's 32 bytes.
pub type MuSigPartialSignature = [u8; 32];
pub type MuSigNoncePair = (MuSigSecNonce, MuSigPubNonce);

// Creates the key aggregation context, without any tweaks. Here, tweaks are
// applied later, and on top of the context, instead of individual pubkeys.
pub fn create_key_agg_ctx(
    pks: Vec<PublicKey>,
    tweak: Option<[u8; 32]>,
) -> Result<KeyAggContext, BridgeError> {
    let musig_pks: Vec<musig2::secp256k1::PublicKey> = pks
        .iter()
        .map(|pk| musig2::secp256k1::PublicKey::from_slice(&pk.serialize()).unwrap())
        .collect::<Vec<musig2::secp256k1::PublicKey>>();
    let key_agg_ctx_raw = KeyAggContext::new(musig_pks)?;
    let key_agg_ctx = match tweak {
        Some(scalar) => key_agg_ctx_raw.with_plain_tweak(Scalar::from_slice(&scalar)?)?,
        None => key_agg_ctx_raw,
    };
    Ok(key_agg_ctx)
}

// Returns the aggregated public key, from the key aggregation context. If the key
// aggregation contexts includes any tweaks, then the returned pubkey is affected by them.
pub fn get_agg_pubkey(key_agg_ctx: &KeyAggContext) -> PublicKey {
    PublicKey::from_slice(
        &key_agg_ctx
            .aggregated_pubkey::<musig2::secp256k1::PublicKey>()
            .serialize(),
    )
    .unwrap()
}

pub fn nonce_pair(
    keypair: &secp256k1::Keypair,
    rng: &mut impl Rng,
) -> (MuSigSecNonce, MuSigPubNonce) {
    let musig_pubkey =
        musig2::secp256k1::PublicKey::from_slice(&keypair.public_key().serialize()).unwrap();
    let rnd = rng.gen::<[u8; 32]>();
    let spices = SecNonceSpices::new().with_seckey(
        musig2::secp256k1::SecretKey::from_slice(&keypair.secret_key().secret_bytes()).unwrap(),
    );
    let sec_nonce = SecNonce::build(rnd)
        .with_pubkey(musig_pubkey)
        .with_spices(spices)
        .build();
    let pub_nonce = ByteArray66(sec_nonce.public_nonce().try_into().unwrap());
    (sec_nonce.into(), pub_nonce)
}

// We are creating the key aggregation context manually here, adding the
// tweaks by hand. Instead, we can use the key aggregation as a parameter
// itself, since it must have already been created by the aggregator.
pub fn partial_sign(
    pks: Vec<PublicKey>,
    // Aggregated tweak, if any. Sent by the aggregator. Apparently, it is known by the verifiers
    // because it depends on the transaction that the verifiers are signing (HOW???).
    tweak: Option<[u8; 32]>,
    sec_nonce: MuSigSecNonce,
    agg_nonce: MuSigAggNonce,
    keypair: &secp256k1::Keypair,
    sighash: [u8; 32],
) -> MuSigPartialSignature {
    let key_agg_ctx = create_key_agg_ctx(pks, tweak).unwrap();
    let musig_sec_nonce = SecNonce::from_bytes(&sec_nonce).unwrap();
    let musig_agg_nonce = AggNonce::from_bytes(&agg_nonce.0).unwrap();
    let partial_signature: [u8; 32] = sign_partial(
        &key_agg_ctx,
        musig2::secp256k1::SecretKey::from_slice(&keypair.secret_key().secret_bytes()).unwrap(),
        musig_sec_nonce,
        &musig_agg_nonce,
        &sighash,
    )
    .unwrap();
    partial_signature
}

fn generate_test_setup(num_signers: usize) -> (Vec<Keypair>, Vec<MuSigNoncePair>) {
    let mut keypair_vec: Vec<Keypair> = Vec::new();
    for _ in 0..num_signers {
        keypair_vec.push(Keypair::new(
            &crate::utils::SECP,
            &mut secp256k1::rand::thread_rng(),
        ));
    }
    let nonce_pair_vec: Vec<MuSigNoncePair> = keypair_vec
        .iter()
        .map(|keypair| nonce_pair(keypair, &mut secp256k1::rand::thread_rng()))
        .collect();
    (keypair_vec, nonce_pair_vec)
}

#[cfg(test)]
mod tests {
    use crate::{
        actor::Actor,
        transaction_builder::{CreateTxOutputs, TransactionBuilder},
        utils, ByteArray66,
    };
    use bitcoin::{hashes::Hash, script, Amount, OutPoint, ScriptBuf, TapNodeHash, TxOut, Txid};
    use musig2::{errors::VerifyError, AggNonce, PartialSignature, PubNonce};
    use secp256k1::{rand::Rng, Message};

    #[test]
    fn test_musig2_raw() {
        let (kp_vec, nonce_pair_vec) = super::generate_test_setup(3);
        let message: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let musig_pub_nonces: Vec<PubNonce> = nonce_pair_vec
            .iter()
            .map(|x| musig2::PubNonce::from_bytes(&x.1 .0).unwrap())
            .collect::<Vec<musig2::PubNonce>>();
        let pks = kp_vec
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<secp256k1::PublicKey>>();
        let key_agg_ctx = super::create_key_agg_ctx(pks.clone(), None).unwrap();
        let musig_agg_nonce: AggNonce = AggNonce::sum(musig_pub_nonces);
        let agg_nonce = ByteArray66(musig_agg_nonce.clone().into());
        let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
        let partial_sigs: Vec<[u8; 32]> = kp_vec
            .iter()
            .zip(nonce_pair_vec.iter())
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    pks.clone(),
                    None,
                    nonce_pair.0,
                    agg_nonce.clone(),
                    kp,
                    message,
                )
            })
            .collect();
        let musig_partial_sigs: Vec<PartialSignature> = partial_sigs
            .iter()
            .map(|x| musig2::PartialSignature::from_slice(x).unwrap())
            .collect::<Vec<PartialSignature>>();
        let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
            &key_agg_ctx,
            &musig_agg_nonce,
            musig_partial_sigs,
            message,
        )
        .unwrap();
        musig2::verify_single(musig_agg_pubkey, &final_signature, message)
            .expect("Verification failed!");
        println!("MuSig2 signature verified successfully!");
    }

    #[test]
    fn test_musig2_raw_fail() {
        let kp_0 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_1 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_2 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let message: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let pks = vec![kp_0.public_key(), kp_1.public_key(), kp_2.public_key()];
        let key_agg_ctx = super::create_key_agg_ctx(pks.clone(), None).unwrap();
        let (sec_nonce_0, pub_nonce_0) =
            super::nonce_pair(&kp_0, &mut secp256k1::rand::thread_rng());
        let (sec_nonce_1, pub_nonce_1) =
            super::nonce_pair(&kp_1, &mut secp256k1::rand::thread_rng());
        let (sec_nonce_2, pub_nonce_2) =
            super::nonce_pair(&kp_2, &mut secp256k1::rand::thread_rng());
        let pub_nonces = vec![pub_nonce_0, pub_nonce_1, pub_nonce_2];
        let musig_pub_nonces: Vec<PubNonce> = pub_nonces
            .iter()
            .map(|x| musig2::PubNonce::from_bytes(&x.0).unwrap())
            .collect::<Vec<musig2::PubNonce>>();
        let musig_agg_nonce: AggNonce = AggNonce::sum(musig_pub_nonces);
        let agg_nonce = ByteArray66(musig_agg_nonce.clone().into());
        let partial_sig_0 = super::partial_sign(
            pks.clone(),
            None,
            sec_nonce_0,
            agg_nonce.clone(),
            &kp_0,
            message,
        );
        let partial_sig_1 = super::partial_sign(
            pks.clone(),
            None,
            sec_nonce_1,
            agg_nonce.clone(),
            &kp_1,
            message,
        );
        // Oops, a verifier accidentally added some tweak!
        let partial_sig_2 = super::partial_sign(
            pks.clone(),
            Some([1u8; 32]),
            sec_nonce_2,
            agg_nonce.clone(),
            &kp_2,
            message,
        );
        let partial_sigs = vec![partial_sig_0, partial_sig_1, partial_sig_2];
        let musig_partial_sigs: Vec<PartialSignature> = partial_sigs
            .iter()
            .map(|x| musig2::PartialSignature::from_slice(x).unwrap())
            .collect::<Vec<PartialSignature>>();
        let final_signature: Result<[u8; 64], VerifyError> = musig2::aggregate_partial_signatures(
            &key_agg_ctx,
            &musig_agg_nonce,
            musig_partial_sigs,
            message,
        );
        assert!(final_signature.is_err());
    }

    #[test]
    fn test_musig2_tweak() {
        let (kp_vec, nonce_pair_vec) = super::generate_test_setup(3);
        let message: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let tweak: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let musig_pub_nonces: Vec<PubNonce> = nonce_pair_vec
            .iter()
            .map(|x| musig2::PubNonce::from_bytes(&x.1 .0).unwrap())
            .collect::<Vec<musig2::PubNonce>>();
        let pks = kp_vec
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<secp256k1::PublicKey>>();
        let key_agg_ctx = super::create_key_agg_ctx(pks.clone(), Some(tweak)).unwrap();
        let musig_agg_nonce: AggNonce = AggNonce::sum(musig_pub_nonces);
        let agg_nonce = ByteArray66(musig_agg_nonce.clone().into());
        let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
        let partial_sigs: Vec<[u8; 32]> = kp_vec
            .iter()
            .zip(nonce_pair_vec.iter())
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    pks.clone(),
                    Some(tweak),
                    nonce_pair.0,
                    agg_nonce.clone(),
                    kp,
                    message,
                )
            })
            .collect();
        let musig_partial_sigs: Vec<PartialSignature> = partial_sigs
            .iter()
            .map(|x| musig2::PartialSignature::from_slice(x).unwrap())
            .collect::<Vec<PartialSignature>>();
        let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
            &key_agg_ctx,
            &musig_agg_nonce,
            musig_partial_sigs,
            message,
        )
        .unwrap();
        musig2::verify_single(musig_agg_pubkey, &final_signature, message)
            .expect("Verification failed!");
        println!("MuSig2 signature verified successfully!");
    }

    #[test]
    fn test_musig2_tweak_fail() {
        let kp_0 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_1 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_2 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let message: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let tweak: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let pks = vec![kp_0.public_key(), kp_1.public_key(), kp_2.public_key()];
        let key_agg_ctx = super::create_key_agg_ctx(pks.clone(), None).unwrap();
        let (sec_nonce_0, pub_nonce_0) =
            super::nonce_pair(&kp_0, &mut secp256k1::rand::thread_rng());
        let (sec_nonce_1, pub_nonce_1) =
            super::nonce_pair(&kp_1, &mut secp256k1::rand::thread_rng());
        let (sec_nonce_2, pub_nonce_2) =
            super::nonce_pair(&kp_2, &mut secp256k1::rand::thread_rng());
        let pub_nonces = vec![pub_nonce_0, pub_nonce_1, pub_nonce_2];
        let musig_pub_nonces: Vec<PubNonce> = pub_nonces
            .iter()
            .map(|x| musig2::PubNonce::from_bytes(&x.0).unwrap())
            .collect::<Vec<musig2::PubNonce>>();
        let musig_agg_nonce: AggNonce = AggNonce::sum(musig_pub_nonces);
        let agg_nonce = ByteArray66(musig_agg_nonce.clone().into());
        let partial_sig_0 = super::partial_sign(
            pks.clone(),
            Some(tweak),
            sec_nonce_0,
            agg_nonce.clone(),
            &kp_0,
            message,
        );
        let partial_sig_1 = super::partial_sign(
            pks.clone(),
            Some(tweak),
            sec_nonce_1,
            agg_nonce.clone(),
            &kp_1,
            message,
        );
        // Oops, a verifier accidentally forgot to put the tweak!
        let partial_sig_2 = super::partial_sign(
            pks.clone(),
            None,
            sec_nonce_2,
            agg_nonce.clone(),
            &kp_2,
            message,
        );
        let partial_sigs = vec![partial_sig_0, partial_sig_1, partial_sig_2];
        let musig_partial_sigs: Vec<PartialSignature> = partial_sigs
            .iter()
            .map(|x| musig2::PartialSignature::from_slice(x).unwrap())
            .collect::<Vec<PartialSignature>>();
        let final_signature: Result<[u8; 64], VerifyError> = musig2::aggregate_partial_signatures(
            &key_agg_ctx,
            &musig_agg_nonce,
            musig_partial_sigs,
            message,
        );
        assert!(final_signature.is_err());
    }

    #[test]
    fn test_musig2_key_spend() {
        let (kp_vec, nonce_pair_vec) = super::generate_test_setup(2);
        let pks = kp_vec
            .iter()
            .map(|kp| kp.public_key())
            .collect::<Vec<secp256k1::PublicKey>>();
        let xonly_pks = pks
            .iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect::<Vec<secp256k1::XOnlyPublicKey>>();
        let musig_pub_nonces: Vec<PubNonce> = nonce_pair_vec
            .iter()
            .map(|x| musig2::PubNonce::from_bytes(&x.1 .0).unwrap())
            .collect::<Vec<musig2::PubNonce>>();
        let musig_agg_nonce: AggNonce = AggNonce::sum(musig_pub_nonces);
        let agg_nonce = ByteArray66(musig_agg_nonce.clone().into());
        let dummy_script = script::Builder::new().push_int(1).into_script();
        let scripts: Vec<ScriptBuf> = vec![dummy_script];
        let receiving_address = bitcoin::Address::p2tr(
            &utils::SECP,
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            None,
            bitcoin::Network::Regtest,
        );
        let (sending_address, sending_address_spend_info) =
            TransactionBuilder::create_musig2_taproot_address(
                xonly_pks,
                scripts.clone(),
                bitcoin::Network::Regtest,
            )
            .unwrap();
        let prevout = TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: sending_address.script_pubkey(),
        };
        let utxo = OutPoint {
            txid: Txid::from_byte_array([0u8; 32]),
            vout: 0,
        };
        let tx_outs = TransactionBuilder::create_tx_outs(vec![(
            Amount::from_sat(99_000_000),
            receiving_address.script_pubkey(),
        )]);
        let tx_ins = TransactionBuilder::create_tx_ins(vec![utxo]);
        let dummy_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
        let mut tx_details = CreateTxOutputs {
            tx: dummy_tx,
            prevouts: vec![prevout],
            scripts: vec![scripts],
            taproot_spend_infos: vec![sending_address_spend_info.clone()],
        };
        let message = Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_details, 0)
            .unwrap()
            .to_byte_array();
        let merkle_root = sending_address_spend_info.merkle_root();
        let tweak: [u8; 32] = match merkle_root {
            Some(root) => root.to_byte_array(),
            None => TapNodeHash::all_zeros().to_byte_array(),
        };
        let key_agg_ctx = super::create_key_agg_ctx(pks.clone(), Some(tweak)).unwrap();

        let partial_sigs: Vec<[u8; 32]> = kp_vec
            .iter()
            .zip(nonce_pair_vec.iter())
            .map(|(kp, nonce_pair)| {
                super::partial_sign(
                    pks.clone(),
                    Some(tweak),
                    nonce_pair.0,
                    agg_nonce.clone(),
                    kp,
                    message,
                )
            })
            .collect();
        let musig_partial_sigs: Vec<PartialSignature> = partial_sigs
            .iter()
            .map(|x| musig2::PartialSignature::from_slice(x).unwrap())
            .collect::<Vec<PartialSignature>>();
        let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
            &key_agg_ctx,
            &musig_agg_nonce,
            musig_partial_sigs,
            message,
        )
        .unwrap();
        let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
        let musig_agg_xonly_pubkey = musig_agg_pubkey.x_only_public_key().0;
        let musig_agg_xonly_pubkey_wrapped =
            bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();
        musig2::verify_single(musig_agg_pubkey, &final_signature, message)
            .expect("Verification failed!");
        let res = utils::SECP
            .verify_schnorr(
                &secp256k1::schnorr::Signature::from_slice(&final_signature).unwrap(),
                &Message::from_digest(message),
                &musig_agg_xonly_pubkey_wrapped,
            )
            .unwrap();
        println!("MuSig2 signature verified successfully!");
        println!("secp Verification: {:?}", res);
    }

    #[test]
    fn test_musig2_script_spend() {}
}
