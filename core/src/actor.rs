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

#[derive(Debug)]
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
    pub fn new(sk: SecretKey) -> Self {
        let secp: Secp256k1<All> = Secp256k1::new();
        let pk = sk.public_key(&secp);
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&secp, xonly, None, bitcoin::Network::Regtest);

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

    pub fn convert_tx_to_sighash(
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
        let sig_hash = Self::convert_tx_to_sighash(tx, input_index)?;
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

#[cfg(test)]
mod tests {
    use crypto_bigint::rand_core::OsRng;
    use musig2::{AggNonce, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices};
    use secp256k1::PublicKey;

    use super::Actor;

    #[test]
    fn test_musig2() {
        let mut actors = Vec::new();
        let mut pks = Vec::new();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let rng = &mut OsRng;
        tracing::debug!("Generated setup...");

        for _ in 0..3 {
            let (sk, pk) = secp.generate_keypair(rng);
            pks.push(pk);
            actors.push(Actor::new(sk));
        }
        tracing::debug!("Generated actors...");

        let message = "Hello, World!";
        let nonce_seed = [0u8; 32];
        tracing::debug!("Generated nonce_seed...");

        let key_agg_ctx = KeyAggContext::new(pks).unwrap();
        tracing::debug!("Generated key_agg_ctx...");

        let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
        tracing::debug!("Aggregated pubkey is {:?}", aggregated_pubkey);

        let mut pub_nonces_first_round = Vec::new();

        let first_round_0 = FirstRound::new(
            key_agg_ctx.clone(),
            nonce_seed,
            0,
            SecNonceSpices::new()
                .with_seckey(actors[0].secret_key)
                .with_message(&message),
        )
        .unwrap();
        pub_nonces_first_round.push(first_round_0.our_public_nonce());
        tracing::debug!(
            "Public nonce for actor 0: {:?}",
            first_round_0.our_public_nonce()
        );

        let first_round_1 = FirstRound::new(
            key_agg_ctx.clone(),
            nonce_seed,
            1,
            SecNonceSpices::new()
                .with_seckey(actors[1].secret_key)
                .with_message(&message),
        )
        .unwrap();
        pub_nonces_first_round.push(first_round_1.our_public_nonce());
        tracing::debug!(
            "Public nonce for actor 1: {:?}",
            first_round_1.our_public_nonce()
        );

        let first_round_2 = FirstRound::new(
            key_agg_ctx.clone(),
            nonce_seed,
            2,
            SecNonceSpices::new()
                .with_seckey(actors[2].secret_key)
                .with_message(&message),
        )
        .unwrap();
        pub_nonces_first_round.push(first_round_2.our_public_nonce());
        tracing::debug!(
            "Public nonce for actor 2: {:?}",
            first_round_2.our_public_nonce()
        );

        tracing::debug!("Generated first_rounds...");

        let aggregated_nonce = AggNonce::sum(&pub_nonces_first_round);
        tracing::debug!("Aggregated nonce is {:?}", aggregated_nonce);

        let mut partial_signatures = Vec::new();

        let partial_signature_0: PartialSignature = first_round_0
            .sign_for_aggregator(actors[0].secret_key, message, &aggregated_nonce)
            .unwrap();
        tracing::debug!("Partial signature for actor 0: {:?}", partial_signature_0);
        partial_signatures.push(partial_signature_0);

        let partial_signature_1: PartialSignature = first_round_1
            .sign_for_aggregator(actors[1].secret_key, message, &aggregated_nonce)
            .unwrap();
        tracing::debug!("Partial signature for actor 1: {:?}", partial_signature_1);
        partial_signatures.push(partial_signature_1);

        let partial_signature_2: PartialSignature = first_round_2
            .sign_for_aggregator(actors[2].secret_key, message, &aggregated_nonce)
            .unwrap();
        tracing::debug!("Partial signature for actor 2: {:?}", partial_signature_2);
        partial_signatures.push(partial_signature_2);

        tracing::debug!("Generated partial_signatures...");

        let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
            &key_agg_ctx,
            &aggregated_nonce,
            partial_signatures,
            message,
        )
        .unwrap();
        tracing::debug!("Final signature is {:?}", final_signature);

        musig2::verify_single(aggregated_pubkey, &final_signature, message)
            .expect("Verification failed!");
        tracing::debug!("Verification passed!");
    }
}
