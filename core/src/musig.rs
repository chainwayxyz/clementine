pub type MusigPubNonce = [u8; 32];
pub type MusigSecNonce = [u8; 32];
pub type MusigAggNonce = [u8; 32];
pub type MusigPartialSignature = [u8; 32];

pub fn nonce_pair(_key: &secp256k1::Keypair) -> (MusigSecNonce, MusigPubNonce) {
    // let kp = keypair_to(key);
    // zkp::new_musig_nonce_pair(
    // 	&SECP,
    // 	MusigSessionId::assume_unique_per_nonce_gen(rand::random()),
    // 	None,
    // 	Some(kp.secret_key()),
    // 	kp.public_key(),
    // 	None,
    // 	Some(rand::random()),
    // ).expect("non-zero session id")
    ([0u8; 32] as MusigSecNonce, [0u8; 32] as MusigPubNonce)
}
