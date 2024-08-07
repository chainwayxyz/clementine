use musig2::{secp::Scalar, sign_partial, AggNonce, KeyAggContext, SecNonce, SecNonceSpices};
use secp256k1::{rand::Rng, PublicKey};

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

// Creates the key aggregation context, without any tweaks. Here, tweaks are
// applied later, and on top of the context, instead of individual pubkeys.
pub fn create_key_agg_ctx_raw(pks: Vec<PublicKey>) -> Result<KeyAggContext, BridgeError> {
    let musig_pks: Vec<musig2::secp256k1::PublicKey> = pks
        .iter()
        .map(|pk| musig2::secp256k1::PublicKey::from_slice(&pk.serialize()).unwrap())
        .collect::<Vec<musig2::secp256k1::PublicKey>>();
    Ok(KeyAggContext::new(musig_pks)?)
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
    // Aggregated tweak, if any. Sent by the aggregator.
    tweak: Option<[u8; 32]>,
    sec_nonce: MuSigSecNonce,
    agg_nonce: MuSigAggNonce,
    keypair: &secp256k1::Keypair,
    sighash: [u8; 32],
) -> MuSigPartialSignature {
    let key_agg_ctx_raw = create_key_agg_ctx_raw(pks).unwrap();
    let key_agg_ctx = if let Some(scalar) = tweak {
        key_agg_ctx_raw
            .with_plain_tweak(Scalar::from_slice(&scalar).unwrap())
            .unwrap()
    } else {
        key_agg_ctx_raw
    };
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

#[cfg(test)]
mod tests {
    use musig2::{AggNonce, PartialSignature, PubNonce};

    use crate::{utils, ByteArray66};

    #[test]
    fn test_musig2() {
        let kp_0 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_1 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let kp_2 = secp256k1::Keypair::new(&utils::SECP, &mut secp256k1::rand::thread_rng());
        let message = [0u8; 32];
        let pks = vec![kp_0.public_key(), kp_1.public_key(), kp_2.public_key()];
        let key_agg_ctx = super::create_key_agg_ctx_raw(pks.clone()).unwrap();
        let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
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
}
