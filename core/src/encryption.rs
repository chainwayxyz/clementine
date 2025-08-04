use bitcoin::secp256k1::rand::{self, RngCore};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use x25519_dalek::{
    EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret,
};

/// Encrypts a message for a recipient using X25519 key agreement and XChaCha20Poly1305 authenticated encryption.
///
/// # Parameters
/// - `recipient_pubkey`: The recipient's X25519 public key as a 32-byte array.
/// - `message`: The plaintext message to encrypt.
///
/// # Returns
/// Returns a `Result` containing the encrypted message as a `Vec<u8>`, or an error.
/// The output format is: `[ephemeral_public_key (32 bytes)] || [nonce (24 bytes)] || [ciphertext (variable length)]`.
///
/// # Encryption Scheme
/// - Uses X25519 to perform an ECDH key agreement between a randomly generated ephemeral key and the recipient's public key.
/// - The shared secret is used as the key for XChaCha20Poly1305 authenticated encryption.
/// - The output includes the ephemeral public key and nonce required for decryption.
pub fn encrypt_bytes(recipient_pubkey: [u8; 32], message: &[u8]) -> Result<Vec<u8>, eyre::Report> {
    let recipient_pubkey = X25519PublicKey::from(recipient_pubkey);

    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);
    let cipher = XChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
        .map_err(|e| eyre::eyre!("Failed to create cipher: {e}"))?;

    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, message)
        .map_err(|e| eyre::eyre!("Failed to encrypt message: {e}"))?;

    let mut output = vec![];
    output.extend_from_slice(ephemeral_public.as_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts a message encrypted with `encrypt_bytes` using the recipient's X25519 private key.
///
/// # Parameters
/// - `recipient_privkey`: A 32-byte slice representing the recipient's X25519 private key.
/// - `encrypted`: A byte slice containing the encrypted data. The expected format is:
///     - 32 bytes: ephemeral public key
///     - 24 bytes: XChaCha20-Poly1305 nonce
///     - remaining bytes: ciphertext (including authentication tag)
///
/// # Returns
/// - `Ok(Vec<u8>)`: The decrypted message bytes.
/// - `Err(eyre::Report)`: If decryption fails or the input is invalid.
pub fn decrypt_bytes(recipient_privkey: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, eyre::Report> {
    if encrypted.len() < MIN_ENCRYPTED_LEN {
        return Err(eyre::eyre!("Invalid encrypted length"));
    }

    let ephemeral_pubkey_bytes: [u8; EPHEMERAL_PUBKEY_LEN] = encrypted[0..EPHEMERAL_PUBKEY_LEN]
        .try_into()
        .map_err(|_| eyre::eyre!("Invalid ephemeral public key length"))?;
    let ephemeral_pubkey = X25519PublicKey::from(ephemeral_pubkey_bytes);
    let nonce = XNonce::from_slice(&encrypted[EPHEMERAL_PUBKEY_LEN..MIN_ENCRYPTED_LEN]);
    let ciphertext = &encrypted[MIN_ENCRYPTED_LEN..];

    let recipient_priv_bytes: [u8; 32] = recipient_privkey
        .try_into()
        .map_err(|_| eyre::eyre!("Invalid recipient private key length"))?;
    let recipient_secret = X25519StaticSecret::from(recipient_priv_bytes);

    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_pubkey);
    let cipher = XChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
        .map_err(|_| eyre::eyre!("Failed to create cipher"))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| eyre::eyre!("Failed to decrypt message"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn test_encrypt_decrypt() {
        // Original keys in hex format
        let privkey = <[u8; 32]>::from_hex(
            "a80bc8cf095c2b37d4c6233114e0dd91f43d75de5602466232dbfcc1fc66c542",
        )
        .unwrap();
        let pubkey = <[u8; 32]>::from_hex(
            "025d32d10ec7b899df4eeb4d80918b7f0a1f2a28f6af24f71aa2a59c69c0d531",
        )
        .unwrap();

        // Test message
        let message = b"Hello, Clementine!";

        // Encrypt
        let encrypted = encrypt_bytes(pubkey, message).unwrap();

        // Decrypt
        let decrypted = decrypt_bytes(&privkey, &encrypted).unwrap();

        // Verify
        assert_eq!(message, decrypted.as_slice());
    }
}
