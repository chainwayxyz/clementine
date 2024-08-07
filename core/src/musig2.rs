use musig2::{secp::Scalar, sign_partial, AggNonce, KeyAggContext, SecNonce, SecNonceSpices};
use secp256k1::{rand::Rng, PublicKey};

use crate::{errors::BridgeError, utils, ByteArray66};

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
