use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1, SecretKey};
use bitcoin::taproot::{TapNodeHash, TapTweakHash};
use bitcoin::{Address, Network, TapSighash, XOnlyPublicKey};
use clementine_errors::BridgeError;
use clementine_utils::sign::TapTweakData;
use eyre::Context;
use std::sync::LazyLock;

pub(crate) static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

#[cfg(feature = "citrea")]
use sha2::{Digest, Sha256};

fn calc_tweaked_keypair(
    keypair: &Keypair,
    merkle_root: Option<TapNodeHash>,
) -> Result<Keypair, BridgeError> {
    Ok(keypair
        .add_xonly_tweak(
            &SECP,
            &TapTweakHash::from_key_and_tweak(keypair.x_only_public_key().0, merkle_root)
                .to_scalar(),
        )
        .wrap_err("Failed to add tweak to keypair")?)
}

#[derive(Clone, Debug)]
pub(crate) struct TxSenderSigningKey {
    keypair: Keypair,
    xonly_public_key: XOnlyPublicKey,
    address: Address,
}

impl TxSenderSigningKey {
    pub(crate) fn new(secret_key: SecretKey, network: Network) -> Self {
        let keypair = Keypair::from_secret_key(&SECP, &secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, network);

        Self {
            keypair,
            xonly_public_key: xonly,
            address,
        }
    }

    pub(crate) fn address(&self) -> &Address {
        &self.address
    }

    pub(crate) fn xonly_public_key(&self) -> XOnlyPublicKey {
        self.xonly_public_key
    }

    pub(crate) fn sign_with_tweak_data(
        &self,
        sighash: TapSighash,
        tweak_data: TapTweakData,
    ) -> Result<schnorr::Signature, BridgeError> {
        let keypair;
        let keypair_ref = match tweak_data {
            TapTweakData::KeyPath(merkle_root) => {
                keypair = calc_tweaked_keypair(&self.keypair, merkle_root)?;
                &keypair
            }
            TapTweakData::ScriptPath => &self.keypair,
            TapTweakData::Unknown => return Err(eyre::eyre!("Spend Data Unknown").into()),
        };

        Ok(SECP
            .sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), keypair_ref))
    }

    /// Signs a blob using ECDSA and returns (signature, public_key).
    /// This is used for Citrea DA payload authentication.
    /// Returns (signature, public_key) as serialized bytes.
    #[cfg(feature = "citrea")]
    pub(crate) fn sign_blob(&self, blob: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let secret_key = self.keypair.secret_key();
        let message = {
            let mut hasher = Sha256::default();
            hasher.update(blob);
            hasher.finalize().into()
        };
        let public_key = self.keypair.public_key();
        let msg = Message::from_digest(message);
        let sig = SECP.sign_ecdsa(&msg, &secret_key);
        (
            sig.serialize_compact().to_vec(),
            public_key.serialize().to_vec(),
        )
    }
}
