use bitcoin::Network;
use crypto_bigint::rand_core::OsRng;
use musig2::{
    secp::Point, secp256k1::Scalar, sign_partial, AggNonce, FirstRound, KeyAggContext,
    PartialSignature, SecNonce, SecNonceSpices,
};
use secp256k1::{rand::Rng, schnorr, Keypair, PublicKey};

use crate::{actor::Actor, errors::BridgeError};

// We can directly use the musig2 crate for this
// No need for extra types etc.
pub type MusigPubNonce = [u8; 66];
pub type MusigSecNonce = [u8; 64];
// pub type MusigAggNonce = [u8; 66];
pub type MusigPartialSignature = [u8; 32];

pub fn create_key_agg_ctx(pks: Vec<PublicKey>) -> Result<KeyAggContext, BridgeError> {
    let musig_pks: Vec<musig2::secp256k1::PublicKey> = pks
        .iter()
        .map(|pk| musig2::secp256k1::PublicKey::from_slice(&pk.serialize()).unwrap())
        .collect::<Vec<musig2::secp256k1::PublicKey>>();
    Ok(KeyAggContext::new(musig_pks)?)
}

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
    pks: Vec<PublicKey>,
) -> (MusigSecNonce, MusigPubNonce) {
    let key_agg_ctx = create_key_agg_ctx(pks).unwrap();
    let musig_pubkey =
        musig2::secp256k1::PublicKey::from_slice(&keypair.public_key().serialize()).unwrap();
    let idx = key_agg_ctx.pubkey_index(musig_pubkey).unwrap();
    let agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let rnd = rng.gen::<[u8; 32]>();
    let spices = SecNonceSpices::new().with_seckey(
        musig2::secp256k1::SecretKey::from_slice(&keypair.secret_key().secret_bytes()).unwrap(),
    );
    let first_round = FirstRound::new(key_agg_ctx, rnd, idx, spices.clone()).unwrap();
    // This part is also done when generating the first round, so I guess we can make it more
    // efficient if we only store the nonce_seed since we can recreate everything using it.
    let sec_nonce = SecNonce::build(rnd)
        .with_pubkey(musig_pubkey)
        .with_aggregated_pubkey(agg_pubkey)
        .with_extra_input(&(idx as u32).to_be_bytes())
        .with_spices(spices)
        .build();
    (sec_nonce.into(), first_round.our_public_nonce().into())
}

pub fn partial_sign(
    pks: Vec<PublicKey>,
    sec_nonce: MusigSecNonce,
    agg_nonce: AggNonce,
    keypair: &secp256k1::Keypair,
    sighash: [u8; 32],
    // tweak: Option<[u8; 32]>,
    // other_sigs: Option<&[MusigPartialSignature]>,
) -> MusigPartialSignature {
    let key_agg_ctx = create_key_agg_ctx(pks).unwrap();
    let musig_sec_nonce = SecNonce::from_bytes(&sec_nonce).unwrap();
    let partial_signature: [u8; 32] = sign_partial(
        &key_agg_ctx,
        musig2::secp256k1::SecretKey::from_slice(&keypair.secret_key().secret_bytes()).unwrap(),
        musig_sec_nonce,
        &agg_nonce,
        &sighash,
    )
    .unwrap();
    partial_signature
}
