//! Provides functions to build Bitcoin transactions
//! related to commit-reveal pattern for Citrea rollup.

pub mod data_serialization;
mod reveal_scripts;
pub mod sync;

#[cfg(all(test, feature = "standalone"))]
mod tests;

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script;
use bitcoin::secp256k1::{Message, PublicKey, SecretKey};
use bitcoin::{Address, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use clementine_primitives::MIN_TAPROOT_AMOUNT;
use sha2::{Digest, Sha256};

use crate::signer::SECP;
pub use tx_sender_types::CitreaTxRequest;

/// Type represents a typed enum for transaction kind
/// Conversion to u16 (to_bytes) should be same as used in citrea repo.
/// citrea/crates/bitcoin-da/src/helpers/mod.rs
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum TransactionKind {
    /// This type of transaction includes full body (< 400kb)
    Complete = 0,
    /// This type of transaction includes txids of chunks (>= 400kb)
    Aggregate = 1,
    /// This type of transaction includes chunk parts of body (>= 400kb)
    Chunks = 2,
    /// This type of transaction includes a new batch proof method_id
    BatchProofMethodId = 3,
    /// SequencerCommitment
    SequencerCommitment = 4,
    // /// ForcedTransaction
    // ForcedTransaction, // = ?,
    /// An unknown type of transaction
    Unknown(u16),
}

impl TransactionKind {
    /// Serialize itself into bytes.
    fn to_bytes(self) -> [u8; 2] {
        match self {
            TransactionKind::Complete => 0u16.to_le_bytes(),
            TransactionKind::Aggregate => 1u16.to_le_bytes(),
            TransactionKind::Chunks => 2u16.to_le_bytes(),
            TransactionKind::BatchProofMethodId => 3u16.to_le_bytes(),
            TransactionKind::SequencerCommitment => 4u16.to_le_bytes(),
            TransactionKind::Unknown(n) => n.to_le_bytes(),
        }
    }

    /// Construct a `TransactionKind` from its numeric representation.
    pub(crate) fn from_u16(value: u16) -> TransactionKind {
        match value {
            0 => TransactionKind::Complete,
            1 => TransactionKind::Aggregate,
            2 => TransactionKind::Chunks,
            3 => TransactionKind::BatchProofMethodId,
            4 => TransactionKind::SequencerCommitment,
            n => TransactionKind::Unknown(n),
        }
    }

    /// Returns the numeric transaction kind as an `i16` for storage.
    pub(crate) fn as_i16(&self) -> i16 {
        match self {
            TransactionKind::Complete => 0,
            TransactionKind::Aggregate => 1,
            TransactionKind::Chunks => 2,
            TransactionKind::BatchProofMethodId => 3,
            TransactionKind::SequencerCommitment => 4,
            TransactionKind::Unknown(n) => *n as i16,
        }
    }
}

/// Build the commit part of commit-reveal pair
/// Multiple commits can be in the same tx (if chunks are used, each commit needs a different nonce so that the addresses are different)
pub(crate) fn build_commit_transaction(recipients: &[Address]) -> Transaction {
    let outputs = recipients
        .iter()
        .map(|recipient| TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: recipient.script_pubkey(),
        })
        .collect();

    Transaction {
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
        input: vec![],
        output: outputs,
    }
}

/// Build the reveal part of commit-reveal pair
pub(crate) fn build_reveal_transaction(input_txid: Txid, input_vout: u32) -> Transaction {
    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: input_txid,
            vout: input_vout,
        },
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    }];

    Transaction {
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
        input: inputs,
        output: vec![],
    }
}

/// Signs a message with a private key
/// Returns (signature, public_key)
pub fn sign_blob_with_private_key(blob: &[u8], private_key: &SecretKey) -> (Vec<u8>, Vec<u8>) {
    let message = calculate_sha256(blob);
    let public_key = PublicKey::from_secret_key(&SECP, private_key);
    let msg = Message::from_digest(message);
    let sig = SECP.sign_ecdsa(&msg, private_key);
    (
        sig.serialize_compact().to_vec(),
        public_key.serialize().to_vec(),
    )
}

pub(crate) fn calculate_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    hasher.finalize().into()
}
