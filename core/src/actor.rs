use crate::errors::BridgeError;
use crate::transaction_builder::CreateTxOutputs;
use crate::utils;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::{
    hashes::Hash,
    secp256k1::{ecdsa, schnorr, Keypair, Message, SecretKey, XOnlyPublicKey},
    Address, TapSighash, TapTweakHash,
};
use bitcoin::{TapLeafHash, TapNodeHash, TapSighashType, TxOut};

#[derive(Debug, Clone)]
pub struct Actor {
    keypair: Keypair,
    secret_key: SecretKey,
    pub xonly_public_key: XOnlyPublicKey,
    pub address: Address,
}

impl Actor {
    pub fn new(sk: SecretKey, network: bitcoin::Network) -> Self {
        let keypair = Keypair::from_secret_key(&utils::SECP, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&utils::SECP, xonly, None, network);

        Actor {
            keypair,
            secret_key: keypair.secret_key(),
            xonly_public_key: xonly,
            address,
        }
    }

    pub fn sign_with_tweak(
        &self,
        sighash: TapSighash,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<schnorr::Signature, BridgeError> {
        Ok(utils::SECP.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self.keypair.add_xonly_tweak(
                &utils::SECP,
                &TapTweakHash::from_key_and_tweak(self.xonly_public_key, merkle_root).to_scalar(),
            )?,
        ))
    }

    pub fn sign(&self, sighash: TapSighash) -> schnorr::Signature {
        utils::SECP.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self.keypair,
        )
    }

    pub fn sign_ecdsa(&self, data: [u8; 32]) -> ecdsa::Signature {
        utils::SECP.sign_ecdsa(
            &Message::from_digest_slice(&data).expect("should be hash"),
            &self.secret_key,
        )
    }

    pub fn sign_taproot_script_spend_tx(
        &self,
        tx: &mut bitcoin::Transaction,
        prevouts: &[TxOut],
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
        txin_index: usize,
        script_index: usize,
    ) -> Result<TapSighash, BridgeError> {
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx.tx);
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            &bitcoin::sighash::Prevouts::All(&tx.prevouts),
            TapLeafHash::from_script(
                &tx.scripts[txin_index][script_index],
                LeafVersion::TapScript,
            ),
            bitcoin::sighash::TapSighashType::Default,
        )?;
        Ok(sig_hash)
    }

    pub fn sign_taproot_script_spend_tx_new(
        &self,
        tx: &mut CreateTxOutputs,
        txin_index: usize,
        script_index: usize,
    ) -> Result<schnorr::Signature, BridgeError> {
        // TODO: if sighash_cache exists in the CreateTxOutputs, use it
        // else create a new one and save it to the CreateTxOutputs

        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx.tx);
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            &bitcoin::sighash::Prevouts::All(&tx.prevouts),
            TapLeafHash::from_script(
                &tx.scripts[txin_index][script_index],
                LeafVersion::TapScript,
            ),
            bitcoin::sighash::TapSighashType::Default,
        )?;
        Ok(self.sign(sig_hash))
    }

    pub fn sign_taproot_pubkey_spend_tx(
        &self,
        tx: &mut bitcoin::Transaction,
        prevouts: &[TxOut],
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

    pub fn sign_taproot_pubkey_spend_tx_with_sighash(
        &self,
        tx: &mut bitcoin::Transaction,
        prevouts: &[TxOut],
        input_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let mut sighash_cache = SighashCache::new(tx);
        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(prevouts),
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;
        self.sign_with_tweak(sig_hash, None)
    }

    pub fn sign_taproot_script_spend_tx_new_tweaked(
        &self,
        tx: &mut CreateTxOutputs,
        txin_index: usize,
        script_index: usize,
    ) -> Result<schnorr::Signature, BridgeError> {
        // TODO: if sighash_cache exists in the CreateTxOutputs, use it
        // else create a new one and save it to the CreateTxOutputs

        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut tx.tx);
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            &bitcoin::sighash::Prevouts::All(&tx.prevouts),
            TapLeafHash::from_script(
                &tx.scripts[txin_index][script_index],
                LeafVersion::TapScript,
            ),
            bitcoin::sighash::TapSighashType::Default,
        )?;
        Ok(self.sign_with_tweak(sig_hash, None).unwrap())
    }
}
