use secp256k1::{schnorr, Keypair};

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

pub fn partial_sign(
	pubkeys: impl IntoIterator<Item = secp256k1::PublicKey>,
	agg_nonce: MusigAggNonce,
	key: &secp256k1::Keypair,
	sec_nonce: MusigSecNonce,
	sighash: [u8; 32],
	tweak: Option<[u8; 32]>,
	other_sigs: Option<&[MusigPartialSignature]>,
) -> (MusigPartialSignature, Option<schnorr::Signature>) {
	// let agg = if let Some(tweak) = tweak {
	// 	tweaked_key_agg(pubkeys, tweak).0
	// } else {
	// 	key_agg(pubkeys)
	// };

	// let msg = zkp::Message::from_digest(sighash);
	// let session = MusigSession::new(&SECP, &agg, agg_nonce, msg);
	// let my_sig = session.partial_sign(&SECP, sec_nonce, &keypair_to(&key), &agg)
	// 	.expect("nonce not reused");
	// let final_sig = if let Some(others) = other_sigs {
	// 	let mut sigs = Vec::with_capacity(others.len() + 1);
	// 	sigs.extend_from_slice(others);
	// 	sigs.push(my_sig);
	// 	Some(session.partial_sig_agg(&sigs))
	// } else {
	// 	None
	// };
	([0u8;32] as MusigPartialSignature, None)
}