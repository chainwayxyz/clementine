//! Provides functions to build Bitcoin transactions
//! related to commit-reveal pattern for Citrea rollup.

pub mod reveal_scripts;
pub mod sync;
#[cfg(feature = "testing")]
pub mod test_utils;

#[cfg(test)]
mod tests;

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script;
use bitcoin::secp256k1::{Message, PublicKey, SecretKey};
use bitcoin::{Address, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use clementine_primitives::MIN_TAPROOT_AMOUNT;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::signer::SECP;

/// These are real blobs we put on DA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawTxData {
    /// borsh(DataOnDa::Complete(compress(Proof)))
    BatchProof(Vec<u8>),
    /// let compressed = compress(borsh(Proof))
    /// let chunks = compressed.chunks(MAX_TX_BODY_SIZE)
    /// [borsh(DataOnDa::Chunk(chunk)) for chunk in chunks]
    Chunks(Vec<Vec<u8>>),
    /// borsh(DataOnDa::BatchProofMethodId(MethodId))
    BatchProofMethodId(Vec<u8>),
    /// borsh(DataOnDa::SequencerCommitment(SequencerCommitment))
    SequencerCommitment(Vec<u8>),
}

/// Type represents a typed enum for transaction kind
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

// The minimal dust value output in reveal txs.
pub const REVEAL_OUTPUT_AMOUNT: Amount = Amount::from_sat(546);

// /// Both transaction and its hash
// #[derive(Clone, Serialize)]
// pub struct TxWithId {
//     /// ID (hash)
//     pub id: Txid,
//     /// Transaction
//     pub tx: Transaction,
// }

// impl fmt::Debug for TxWithId {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         f.debug_struct("TxWithId")
//             .field("id", &self.id)
//             .field("tx", &"...")
//             .finish()
//     }
// }

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

// /// Build control block for the reveal script with taproot spend info.
// /// This is a heavy operation because we need to hash the reveal script.
// fn build_control_block(
//     reveal_script: &ScriptBuf,
//     public_key: XOnlyPublicKey,
// ) -> (ControlBlock, Option<TapNodeHash>, TapLeafHash) {
//     // create spend info for tapscript
//     let taproot_spend_info = TaprootBuilder::new()
//         .add_leaf(0, reveal_script.clone())
//         .expect("Cannot add reveal script to taptree")
//         .finalize(&SECP, public_key)
//         .expect("Cannot finalize taptree");

//     // create tapleaf hash
//     let tapleaf_hash = TapLeafHash::from_script(reveal_script, LeafVersion::TapScript);

//     // create control block for tapscript
//     let control_block = taproot_spend_info
//         .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
//         .expect("Cannot create control block");

//     (
//         control_block,
//         taproot_spend_info.merkle_root(),
//         tapleaf_hash,
//     )
// }

// /// Build witness in the form of [signature, reveal_script, control_block]
// fn build_witness(
//     commit_tx: &Transaction,
//     reveal_tx: &mut Transaction,
//     tapscript_hash: TapLeafHash,
//     reveal_script: ScriptBuf,
//     control_block: ControlBlock,
//     key_pair: &Keypair,
// ) {
//     // start signing reveal tx
//     let mut sighash_cache = SighashCache::new(reveal_tx);

//     // create data to sign
//     let signature_hash = sighash_cache
//         .taproot_script_spend_signature_hash(
//             0,
//             &Prevouts::All(&[&commit_tx.output[0]]),
//             tapscript_hash,
//             bitcoin::sighash::TapSighashType::Default,
//         )
//         .expect("Cannot create hash for signature");

//     // sign reveal tx data
//     let signature = SECP.sign_schnorr(
//         &Message::from_digest(signature_hash.to_byte_array()),
//         key_pair,
//     );

//     // add signature to witness and finalize reveal tx
//     let witness = sighash_cache.witness_mut(0).unwrap();
//     witness.clear();
//     witness.push(signature.as_ref());
//     witness.push(reveal_script);
//     witness.push(control_block.serialize());
// }

// /// Update witness' signature only from the form of [signature, reveal_script, control_block]
// ///  without touching reveal_script, control_block.
// /// This is an optimization of mining to get the necessary wtxid prefix.
// /// The optimization is that we don't have to hash the reveal script again and again
// ///  which can be costly when the reveal script is huge.
// /// It's possible only when reveal script is the same (hence nonce is the same)
// ///  but only the outputs are changed.
// fn update_witness(
//     commit_tx: &Transaction,
//     reveal_tx: &mut Transaction,
//     tapscript_hash: TapLeafHash,
//     key_pair: &Keypair,
// ) {
//     // start signing reveal tx
//     let mut sighash_cache = SighashCache::new(reveal_tx);

//     // create data to sign
//     let signature_hash = sighash_cache
//         .taproot_script_spend_signature_hash(
//             0,
//             &Prevouts::All(&[&commit_tx.output[0]]),
//             tapscript_hash,
//             bitcoin::sighash::TapSighashType::Default,
//         )
//         .expect("Cannot create hash for signature");

//     // sign reveal tx data
//     let signature = SECP.sign_schnorr(
//         &Message::from_digest(signature_hash.to_byte_array()),
//         key_pair,
//     );

//     // add signature to witness and finalize reveal tx
//     let witness = sighash_cache.witness_mut(0).unwrap();

//     let reveal_script = witness.nth(1).unwrap();
//     let control_block = witness.nth(2).unwrap();

//     let mut new_witness = Witness::new();
//     new_witness.push(signature.as_ref());
//     new_witness.push(reveal_script);
//     new_witness.push(control_block);

//     *witness = new_witness;
// }

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
