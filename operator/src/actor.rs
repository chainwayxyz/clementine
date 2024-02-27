use crate::constant::EVMAddress;
use crate::errors::BridgeError;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::{
    hashes::Hash,
    secp256k1::{
        ecdsa, schnorr, All, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
    },
    Address, TapSighash, TapTweakHash,
};

use bitcoin::{TapLeafHash, TapNodeHash, TxOut};
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug)]
pub struct Actor {
    pub secp: Secp256k1<All>,
    keypair: Keypair,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub xonly_public_key: XOnlyPublicKey,
    pub address: Address,
    pub evm_address: EVMAddress,
}

impl Default for Actor {
    fn default() -> Self {
        Self::new(&mut OsRng)
    }
}

impl Actor {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        let secp: Secp256k1<All> = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(rng);
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&secp, xonly, None, bitcoin::Network::Regtest);

        let pk_serialized = pk.serialize_uncompressed();
        let pk_serialized: [u8; 64] = pk_serialized[1..].try_into().unwrap();
        let mut evm_address = [0u8; 32];
        let mut keccak_hasher = Keccak::v256();
        keccak_hasher.update(&pk_serialized);
        keccak_hasher.finalize(&mut evm_address);
        let evm_address: EVMAddress = evm_address[12..].try_into().unwrap();

        Actor {
            secp,
            keypair,
            secret_key: keypair.secret_key(),
            public_key: pk,
            xonly_public_key: xonly,
            address,
            evm_address,
        }
    }

    pub fn sign_with_tweak(
        &self,
        sighash: TapSighash,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<schnorr::Signature, BridgeError> {
        Ok(self.secp.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self.keypair.add_xonly_tweak(
                &self.secp,
                &TapTweakHash::from_key_and_tweak(self.xonly_public_key, merkle_root).to_scalar(),
            )?,
        ))
    }

    pub fn sign(&self, sighash: TapSighash) -> schnorr::Signature {
        self.secp.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self.keypair,
        )
    }

    pub fn sign_ecdsa(&self, data: [u8; 32]) -> ecdsa::Signature {
        self.secp.sign_ecdsa(
            &Message::from_digest_slice(&data).expect("should be hash"),
            &self.secret_key,
        )
    }

    pub fn sign_taproot_script_spend_tx(
        &self,
        tx: &mut bitcoin::Transaction,
        prevouts: &Vec<TxOut>,
        spend_script: &bitcoin::Script,
        input_index: usize,
    ) -> schnorr::Signature {
        let mut sighash_cache = SighashCache::new(tx);
        let sig_hash = sighash_cache
            .taproot_script_spend_signature_hash(
                input_index,
                &bitcoin::sighash::Prevouts::All(prevouts),
                TapLeafHash::from_script(&spend_script, LeafVersion::TapScript),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap();
        self.sign(sig_hash)
    }

    pub fn sign_taproot_pubkey_spend_tx(
        &self,
        tx: &mut bitcoin::Transaction,
        prevouts: &Vec<TxOut>,
        input_index: usize,
    ) -> Result<schnorr::Signature, BridgeError> {
        let mut sighash_cache = SighashCache::new(tx);
        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )?;
        self.sign_with_tweak(sig_hash, None)
    }

    // pub fn verify_script_spend_signature(
    //     _tx: &bitcoin::Transaction,
    //     _presign: &schnorr::Signature,
    //     _xonly_public_key: &XOnlyPublicKey,
    //     spend_script: &bitcoin::Script,
    //     input_index: usize,
    //     prevouts: &Vec<TxOut>,
    // ) -> Option<bool> {
    //     let sighash_cache = SighashCache::new(_tx);
    //     let sig_hash = sighash_cache
    //         .taproot_script_spend_signature_hash(
    //             input_index,
    //             &bitcoin::sighash::Prevouts::All(&prevouts),
    //             TapLeafHash::from_script(&spend_script, LeafVersion::TapScript),
    //             bitcoin::sighash::TapSighashType::Default,
    //         )
    //         .unwrap();

    //     Some(true)
    // }
}
