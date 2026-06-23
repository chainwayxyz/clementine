use crate::{
    actor::Actor, bitvm_client::SECP, deposit::DepositData, errors::BridgeError,
    operator::PublicHash, rpc::clementine::DepositParams,
};
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{schnorr::Signature, Message},
    Address, OutPoint, XOnlyPublicKey,
};
use bitvm::signatures::winternitz;
use prost::Message as _;

const SETUP_DOMAIN: &[u8] = b"clementine/operator_setup/v1";
const DEPOSIT_KEYS_DOMAIN: &[u8] = b"clementine/operator_deposit_keys/v1";

struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn new(domain: &[u8]) -> Self {
        let mut transcript = Self { bytes: Vec::new() };
        transcript.push_bytes(domain);
        transcript
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.bytes
            .extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(bytes);
    }

    fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_xonly_pk(&mut self, pk: XOnlyPublicKey) {
        self.push_bytes(&pk.serialize());
    }

    fn push_outpoint(&mut self, outpoint: OutPoint) {
        self.push_bytes(&outpoint.txid.to_byte_array());
        self.push_u32(outpoint.vout);
    }

    fn push_address(&mut self, address: &Address) {
        self.push_bytes(address.to_string().as_bytes());
    }

    fn push_winternitz_public_keys(&mut self, keys: &[winternitz::PublicKey]) {
        self.bytes
            .extend_from_slice(&(keys.len() as u64).to_le_bytes());
        for key in keys {
            self.bytes
                .extend_from_slice(&(key.len() as u64).to_le_bytes());
            for digit in key {
                self.push_bytes(digit);
            }
        }
    }

    fn push_schnorr_sigs(&mut self, sigs: &[Signature]) {
        self.bytes
            .extend_from_slice(&(sigs.len() as u64).to_le_bytes());
        for sig in sigs {
            self.push_bytes(&sig.serialize());
        }
    }

    fn push_hashes(&mut self, hashes: &[PublicHash]) {
        self.bytes
            .extend_from_slice(&(hashes.len() as u64).to_le_bytes());
        for hash in hashes {
            self.push_bytes(hash);
        }
    }

    fn push_deposit_data(&mut self, deposit_data: &DepositData) -> Result<(), BridgeError> {
        let mut deposit_data = deposit_data.clone();
        // sort here so that the array ordering doesn't cause mismatches
        deposit_data.actors.verifiers.sort();
        deposit_data.actors.watchtowers.sort();
        deposit_data.actors.operators.sort();
        let deposit_params: DepositParams = deposit_data.into();
        self.push_bytes(&deposit_params.encode_to_vec());
        Ok(())
    }

    fn digest(self) -> [u8; 32] {
        sha256::Hash::hash(&self.bytes).to_byte_array()
    }
}

fn sign_digest(actor: &Actor, digest: [u8; 32]) -> Signature {
    SECP.sign_schnorr(&Message::from_digest(digest), &actor.keypair)
}

fn verify_digest(
    operator_xonly_pk: XOnlyPublicKey,
    digest: [u8; 32],
    signature: &Signature,
) -> Result<(), BridgeError> {
    SECP.verify_schnorr(signature, &Message::from_digest(digest), &operator_xonly_pk)
        .map_err(|_| eyre::eyre!("Operator auth signature verification failed").into())
}

fn setup_digest(
    operator_xonly_pk: XOnlyPublicKey,
    collateral_funding_outpoint: OutPoint,
    wallet_reimburse_address: &Address,
    kickoff_winternitz_public_keys: &[winternitz::PublicKey],
    unspent_kickoff_sigs: &[Signature],
) -> [u8; 32] {
    let mut transcript = Transcript::new(SETUP_DOMAIN);
    transcript.push_xonly_pk(operator_xonly_pk);
    transcript.push_outpoint(collateral_funding_outpoint);
    transcript.push_address(wallet_reimburse_address);
    transcript.push_winternitz_public_keys(kickoff_winternitz_public_keys);
    transcript.push_schnorr_sigs(unspent_kickoff_sigs);
    transcript.digest()
}

fn deposit_keys_digest(
    operator_xonly_pk: XOnlyPublicKey,
    deposit_data: &DepositData,
    winternitz_public_keys: &[winternitz::PublicKey],
    challenge_ack_hashes: &[PublicHash],
) -> Result<[u8; 32], BridgeError> {
    let mut transcript = Transcript::new(DEPOSIT_KEYS_DOMAIN);
    transcript.push_xonly_pk(operator_xonly_pk);
    transcript.push_deposit_data(deposit_data)?;
    transcript.push_winternitz_public_keys(winternitz_public_keys);
    transcript.push_hashes(challenge_ack_hashes);
    Ok(transcript.digest())
}

/// Signs the operator setup data that the aggregator forwards during setup.
pub fn sign_operator_setup(
    actor: &Actor,
    collateral_funding_outpoint: OutPoint,
    wallet_reimburse_address: &Address,
    kickoff_winternitz_public_keys: &[winternitz::PublicKey],
    unspent_kickoff_sigs: &[Signature],
) -> Signature {
    sign_digest(
        actor,
        setup_digest(
            actor.xonly_public_key,
            collateral_funding_outpoint,
            wallet_reimburse_address,
            kickoff_winternitz_public_keys,
            unspent_kickoff_sigs,
        ),
    )
}

/// Verifies the operator setup data before it is persisted by a verifier.
pub fn verify_operator_setup(
    operator_xonly_pk: XOnlyPublicKey,
    collateral_funding_outpoint: OutPoint,
    wallet_reimburse_address: &Address,
    kickoff_winternitz_public_keys: &[winternitz::PublicKey],
    unspent_kickoff_sigs: &[Signature],
    signature: &Signature,
) -> Result<(), BridgeError> {
    verify_digest(
        operator_xonly_pk,
        setup_digest(
            operator_xonly_pk,
            collateral_funding_outpoint,
            wallet_reimburse_address,
            kickoff_winternitz_public_keys,
            unspent_kickoff_sigs,
        ),
        signature,
    )
}

/// Signs per-deposit operator keys that the aggregator forwards to verifiers.
pub fn sign_operator_deposit_keys(
    actor: &Actor,
    deposit_data: &DepositData,
    winternitz_public_keys: &[winternitz::PublicKey],
    challenge_ack_hashes: &[PublicHash],
) -> Result<Signature, BridgeError> {
    Ok(sign_digest(
        actor,
        deposit_keys_digest(
            actor.xonly_public_key,
            deposit_data,
            winternitz_public_keys,
            challenge_ack_hashes,
        )?,
    ))
}

/// Verifies per-deposit operator keys before they are persisted by a verifier.
pub fn verify_operator_deposit_keys(
    operator_xonly_pk: XOnlyPublicKey,
    deposit_data: &DepositData,
    winternitz_public_keys: &[winternitz::PublicKey],
    challenge_ack_hashes: &[PublicHash],
    signature: &Signature,
) -> Result<(), BridgeError> {
    verify_digest(
        operator_xonly_pk,
        deposit_keys_digest(
            operator_xonly_pk,
            deposit_data,
            winternitz_public_keys,
            challenge_ack_hashes,
        )?,
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deposit::{Actors, BaseDepositData, DepositInfo, DepositType, SecurityCouncil},
        EVMAddress,
    };
    use bitcoin::{address::NetworkUnchecked, hashes::Hash, secp256k1::SecretKey, Network, Txid};
    use std::str::FromStr;

    fn actor(byte: u8) -> Actor {
        Actor::new(
            SecretKey::from_slice(&[byte; 32]).expect("test secret key is valid"),
            Network::Regtest,
        )
    }

    fn test_wpk(byte: u8) -> winternitz::PublicKey {
        vec![[byte; 20], [byte.wrapping_add(1); 20]]
    }

    fn unchecked_address(address: &Address) -> bitcoin::Address<NetworkUnchecked> {
        bitcoin::Address::from_str(&address.to_string()).expect("test address parses")
    }

    fn deposit_data(operator_xonly_pk: XOnlyPublicKey) -> DepositData {
        let verifier = actor(4);
        let recovery = actor(5);
        let security_council = actor(6);

        DepositData {
            nofn_xonly_pk: None,
            deposit: DepositInfo {
                deposit_outpoint: OutPoint {
                    txid: Txid::from_slice(&[7; 32]).expect("test txid is valid"),
                    vout: 0,
                },
                deposit_type: DepositType::BaseDeposit(BaseDepositData {
                    evm_address: EVMAddress([8; 20]),
                    recovery_taproot_address: unchecked_address(&recovery.address),
                }),
            },
            actors: Actors {
                verifiers: vec![verifier.public_key],
                watchtowers: vec![],
                operators: vec![operator_xonly_pk],
            },
            security_council: SecurityCouncil {
                pks: vec![security_council.xonly_public_key],
                threshold: 1,
            },
        }
    }

    #[test]
    fn setup_auth_signature_binds_reimburse_address() {
        let operator = actor(1);
        let other = actor(2);
        let outpoint = OutPoint {
            txid: Txid::from_slice(&[3; 32]).expect("test txid is valid"),
            vout: 0,
        };
        let wpks = vec![test_wpk(10), test_wpk(20)];
        let sigs = vec![
            SECP.sign_schnorr(&Message::from_digest([11; 32]), &operator.keypair),
            SECP.sign_schnorr(&Message::from_digest([12; 32]), &operator.keypair),
        ];

        let sig = sign_operator_setup(&operator, outpoint, &operator.address, &wpks, &sigs);
        verify_operator_setup(
            operator.xonly_public_key,
            outpoint,
            &operator.address,
            &wpks,
            &sigs,
            &sig,
        )
        .expect("valid setup auth signature verifies");

        assert!(verify_operator_setup(
            operator.xonly_public_key,
            outpoint,
            &other.address,
            &wpks,
            &sigs,
            &sig,
        )
        .is_err());
    }

    #[test]
    fn deposit_key_auth_signature_binds_winternitz_keys() {
        let operator = actor(1);
        let deposit_data = deposit_data(operator.xonly_public_key);
        let wpks = vec![test_wpk(30), test_wpk(40)];
        let hashes = vec![[41; 20], [42; 20]];

        let sig = sign_operator_deposit_keys(&operator, &deposit_data, &wpks, &hashes)
            .expect("deposit key auth signs");
        verify_operator_deposit_keys(
            operator.xonly_public_key,
            &deposit_data,
            &wpks,
            &hashes,
            &sig,
        )
        .expect("valid deposit key auth signature verifies");

        let mut cached_deposit_data = deposit_data.clone();
        cached_deposit_data.nofn_xonly_pk = Some(actor(9).xonly_public_key);
        verify_operator_deposit_keys(
            operator.xonly_public_key,
            &cached_deposit_data,
            &wpks,
            &hashes,
            &sig,
        )
        .expect("nofn cache state is not part of deposit key auth signature");

        let mut tampered_wpks = wpks.clone();
        tampered_wpks[0][0][0] ^= 1;
        assert!(verify_operator_deposit_keys(
            operator.xonly_public_key,
            &deposit_data,
            &tampered_wpks,
            &hashes,
            &sig,
        )
        .is_err());
    }

    #[test]
    fn deposit_key_auth_signature_canonicalizes_actor_order() {
        let operator = actor(1);
        let verifier_a = actor(10);
        let verifier_b = actor(11);
        let watchtower_a = actor(12);
        let watchtower_b = actor(13);
        let other_operator = actor(14);
        let wpks = vec![test_wpk(30), test_wpk(40)];
        let hashes = vec![[41; 20], [42; 20]];

        let mut signed_deposit_data = deposit_data(operator.xonly_public_key);
        signed_deposit_data.actors.verifiers = vec![verifier_b.public_key, verifier_a.public_key];
        signed_deposit_data.actors.watchtowers =
            vec![watchtower_b.xonly_public_key, watchtower_a.xonly_public_key];
        signed_deposit_data.actors.operators =
            vec![other_operator.xonly_public_key, operator.xonly_public_key];

        let mut reordered_deposit_data = signed_deposit_data.clone();
        reordered_deposit_data.actors.verifiers.reverse();
        reordered_deposit_data.actors.watchtowers.reverse();
        reordered_deposit_data.actors.operators.reverse();

        let sig = sign_operator_deposit_keys(&operator, &signed_deposit_data, &wpks, &hashes)
            .expect("deposit key auth signs");

        verify_operator_deposit_keys(
            operator.xonly_public_key,
            &reordered_deposit_data,
            &wpks,
            &hashes,
            &sig,
        )
        .expect("actor order is not part of deposit key auth signature");
    }
}
