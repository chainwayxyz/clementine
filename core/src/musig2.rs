use musig2::{sign_partial, AggNonce, KeyAggContext, SecNonce, SecNonceSpices};
use secp256k1::{rand::Rng, PublicKey};

use crate::{errors::BridgeError, ByteArray66};

// We can directly use the musig2 crate for this
// No need for extra types etc.
// MuSigPubNonce consists of two curve points, so it's 66 bytes (compressed).
pub type MuSigPubNonce = ByteArray66;
// MuSigSecNonce consists of two scalars, so it's 64 bytes.
pub type MuSigSecNonce = [u8; 64];
// MuSigAggNonce is a scalar, so it's 32 bytes.
pub type MuSigAggNonce = [u8; 32];
// MuSigPartialSignature is a scalar, so it's 32 bytes.
pub type MuSigPartialSignature = [u8; 32];

pub fn create_key_agg_ctx(
    pks: Vec<PublicKey>,
    tweak: Option<[u8; 32]>,
) -> Result<KeyAggContext, BridgeError> {
    let musig_pks: Vec<musig2::secp256k1::PublicKey> = pks
        .iter()
        .map(|pk| musig2::secp256k1::PublicKey::from_slice(&pk.serialize()).unwrap())
        .collect::<Vec<musig2::secp256k1::PublicKey>>();
    let key_agg_ctx = KeyAggContext::new(musig_pks)?;
    if let Some(tweak) = tweak {
        Ok(key_agg_ctx.with_taproot_tweak(&tweak)?)
    } else {
        Ok(key_agg_ctx)
    }
}

pub fn get_agg_pubkey(key_agg_ctx: &KeyAggContext) -> PublicKey {
    PublicKey::from_slice(
        &key_agg_ctx
            .aggregated_pubkey::<musig2::secp256k1::PublicKey>()
            .serialize(),
    )
    .unwrap()
}

// Giving Vec<PublicKey> as an argument since we need to find the index of the keypair in the list of public keys;
// otherwise, we can simply pass it as an argument. Also we need more entropy for the nonce.
pub fn nonce_pair(
    keypair: &secp256k1::Keypair,
    rng: &mut impl Rng,
    pks: Vec<PublicKey>,
    tweak: Option<[u8; 32]>,
) -> (MuSigSecNonce, MuSigPubNonce) {
    let key_agg_ctx = create_key_agg_ctx(pks, tweak).unwrap();
    let musig_pubkey =
        musig2::secp256k1::PublicKey::from_slice(&keypair.public_key().serialize()).unwrap();
    let idx = key_agg_ctx.pubkey_index(musig_pubkey).unwrap();
    let agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let rnd = rng.gen::<[u8; 32]>();
    let spices = SecNonceSpices::new().with_seckey(
        musig2::secp256k1::SecretKey::from_slice(&keypair.secret_key().secret_bytes()).unwrap(),
    );
    let sec_nonce = SecNonce::build(rnd)
        .with_pubkey(musig_pubkey)
        .with_aggregated_pubkey(agg_pubkey)
        .with_extra_input(&(idx as u32).to_be_bytes())
        .with_spices(spices)
        .build();
    let pub_nonce = ByteArray66(sec_nonce.public_nonce().try_into().unwrap());
    (sec_nonce.into(), pub_nonce)
}

pub fn partial_sign(
    pks: Vec<PublicKey>,
    tweak: Option<[u8; 32]>,
    sec_nonce: MuSigSecNonce,
    agg_nonce: MuSigAggNonce,
    keypair: &secp256k1::Keypair,
    sighash: [u8; 32],
    // tweak: Option<[u8; 32]>,
) -> MuSigPartialSignature {
    let key_agg_ctx = create_key_agg_ctx(pks, tweak).unwrap();
    let musig_sec_nonce = SecNonce::from_bytes(&sec_nonce).unwrap();
    let musig_agg_nonce = AggNonce::from_bytes(&agg_nonce).unwrap();
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
