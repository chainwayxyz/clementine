use bitcoin::hashes::sha256;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::{TapNodeHash, Txid};
use bitcoin::{
    hashes::Hash,
    secp256k1::{
        ecdsa, schnorr, All, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
    },
    Address, TapSighash, TapTweakHash,
};
use tiny_keccak::{Hasher, Keccak};
use circuit_helpers::config::REGTEST;

#[derive(Clone, Debug)]
pub struct Actor {
    secp: Secp256k1<All>,
    keypair: Keypair,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub xonly_public_key: XOnlyPublicKey,
    pub address: Address,
    pub evm_address: [u8; 20],
}

impl Default for Actor {
    fn default() -> Self {
        Self::new(&mut OsRng)
    }
}

#[derive(Clone, Debug)]
pub struct EVMSignature {
    v: u8,
    r: [u8; 32],
    s: [u8; 32],
}

impl Actor {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        let secp: Secp256k1<All> = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(rng);
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&secp, xonly, None, REGTEST);

        let pk_serialized = pk.serialize_uncompressed();
        let pk_serialized: [u8; 64] = pk_serialized[1..].try_into().unwrap();
        let mut evm_address = [0u8; 32];
        let mut keccak_hasher = Keccak::v256();
        keccak_hasher.update(&pk_serialized);
        keccak_hasher.finalize(&mut evm_address);
        let evm_address: [u8; 20] = evm_address[12..].try_into().unwrap();

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
    ) -> schnorr::Signature {
        self.secp.sign_schnorr(
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &self
                .keypair
                .add_xonly_tweak(
                    &self.secp,
                    &TapTweakHash::from_key_and_tweak(self.xonly_public_key, merkle_root)
                        .to_scalar(),
                )
                .unwrap(),
        )
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

    pub fn sign_deposit(
        &self,
        txid: Txid,
        deposit_address: [u8; 4],
        hash: [u8; 32],
    ) -> EVMSignature {
        let mut message = [0; 68];
        message[..32].copy_from_slice(&txid.to_byte_array());
        message[32..36].copy_from_slice(&deposit_address);
        message[36..].copy_from_slice(&hash);

        let message = sha256::Hash::hash(&message);
        let signature = self.secp.sign_ecdsa_recoverable(
            &Message::from_digest_slice(&message.to_byte_array()).expect("should be hash"),
            &self.secret_key,
        );
        let (rec_id, signature): (ecdsa::RecoveryId, [u8; 64]) = signature.serialize_compact();
        let v = rec_id.to_i32() as u8 + 27;
        let r: [u8; 32] = signature[..32].try_into().unwrap();
        let s: [u8; 32] = signature[32..].try_into().unwrap();

        EVMSignature {
            v,
            r,
            s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa() {
        let prover = Actor::new(&mut OsRng);
        let txid = Txid::all_zeros();
        let deposit_address = [2; 4];
        let hash = [3; 32];

        let sig = prover.sign_deposit(txid, deposit_address, hash);
        let v = sig.v;
        let r = sig.r;
        let s = sig.s;

        println!("bytes32 txid = bytes32(0x{});", hex::encode(txid));
        println!(
            "address deposit_address = address(bytes20(hex\"{}\"));",
            hex::encode(deposit_address)
        );
        println!("bytes32 _hash = bytes32(0x{});", hex::encode(hash));
        println!("bytes32 r = bytes32(0x{});", hex::encode(r));
        println!("bytes32 s = bytes32(0x{});", hex::encode(s));
        println!("uint8 v = {};", v);
        println!(
            "address expected = address(bytes20(hex\"{}\"));",
            hex::encode(prover.evm_address)
        );
    }
}
