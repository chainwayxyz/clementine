use crate::errors::BridgeError;
use crate::transaction_builder::CreateTxOutputs;
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

#[derive(Debug, Clone)]
pub struct Actor {
    pub secp: Secp256k1<All>,
    keypair: Keypair,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub xonly_public_key: XOnlyPublicKey,
    pub address: Address,
}

impl Default for Actor {
    fn default() -> Self {
        unimplemented!("Actor::default is not implemented");
    }
}

impl Actor {
    pub fn new(sk: SecretKey, network: bitcoin::Network) -> Self {
        let secp: Secp256k1<All> = Secp256k1::new();
        let pk = sk.public_key(&secp);
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&secp, xonly, None, network);

        Actor {
            secp,
            keypair,
            secret_key: keypair.secret_key(),
            public_key: pk,
            xonly_public_key: xonly,
            address,
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
    ) -> Result<schnorr::Signature, BridgeError> {
        let mut sighash_cache = SighashCache::new(tx);
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(prevouts),
            TapLeafHash::from_script(spend_script, LeafVersion::TapScript),
            bitcoin::sighash::TapSighashType::Default,
        )?;
        Ok(self.sign(sig_hash))
    }

    pub fn sighash_taproot_script_spend(
        &self,
        tx: &mut CreateTxOutputs,
        input_index: usize,
    ) -> Result<TapSighash, BridgeError> {
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx.tx);
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(&tx.prevouts),
            TapLeafHash::from_script(&tx.scripts[input_index], LeafVersion::TapScript),
            bitcoin::sighash::TapSighashType::Default,
        )?;
        Ok(sig_hash)
    }

    pub fn sign_taproot_script_spend_tx_new(
        &self,
        tx: &mut CreateTxOutputs,
        input_index: usize,
    ) -> Result<schnorr::Signature, BridgeError> {
        // TODO: if sighash_cache exists in the CreateTxOutputs, use it
        // else create a new one and save it to the CreateTxOutputs

        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx.tx);
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(&tx.prevouts),
            TapLeafHash::from_script(&tx.scripts[input_index], LeafVersion::TapScript),
            bitcoin::sighash::TapSighashType::Default,
        )?;
        Ok(self.sign(sig_hash))
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
