//! This module contains functions to create transactions for the DA layer.

use bitcoin::blockdata::opcodes::all::{OP_CHECKSIGVERIFY, OP_ENDIF, OP_IF, OP_NIP};
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::{Address, Network, ScriptBuf, XOnlyPublicKey};

use crate::citrea::TransactionKind;
use crate::signer::TxSenderSigningKey;
use crate::TxSender;

/// Bundle of data required for committing and later revealing a Citrea payload.
#[derive(Debug, Clone)]
pub struct CitreaSigningData {
    pub reveal_script: ScriptBuf,
    pub control_block: ControlBlock,
    pub commit_address: Address,
}

impl TxSender {
    /// Creates a reveal script for a Citrea transaction based on transaction kind and body.
    ///
    /// The script structure follows the commit-reveal pattern:
    /// - public_key OP_CHECKSIGVERIFY (verifies the reveal key)
    /// - transaction_kind (2 bytes)
    /// - OP_FALSE OP_IF (start data push)
    /// - [signature and signer_public_key for Complete, SequencerCommitment, Aggregate]
    /// - body (pushed in 520-byte chunks)
    /// - OP_ENDIF
    /// - nonce (fixed to 16) OP_NIP
    ///
    /// # Arguments
    /// * `transaction_kind` - The type of Citrea transaction
    /// * `body` - The transaction body bytes
    ///
    /// # Returns
    /// A tuple containing:
    /// - The constructed reveal script
    /// - The control block for spending the taproot output
    /// - The commit transaction address (P2TR)
    pub fn create_reveal_script(
        &self,
        transaction_kind: TransactionKind,
        body: &[u8],
    ) -> CitreaSigningData {
        create_reveal_script(
            self.xonly_public_key(),
            &self.da_signer,
            self.network,
            transaction_kind,
            body,
        )
    }
}

fn create_reveal_script(
    public_key: XOnlyPublicKey,
    da_signer: &TxSenderSigningKey,
    network: Network,
    transaction_kind: TransactionKind,
    body: &[u8],
) -> CitreaSigningData {
    let kind_bytes = transaction_kind.to_bytes();

    // Nonce is fixed to 16
    let nonce: i64 = 16;

    // Determine if this transaction kind requires signature and signer_public_key
    let needs_signature = matches!(
        transaction_kind,
        TransactionKind::Complete
            | TransactionKind::SequencerCommitment
            | TransactionKind::Aggregate
    );

    let mut reveal_script_builder = script::Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::from(kind_bytes))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF);

    // Add signature and signer_public_key for transaction kinds that require authentication
    if needs_signature {
        let (signature, signer_public_key) = da_signer.sign_blob(body);
        reveal_script_builder = reveal_script_builder
            .push_slice(PushBytesBuf::try_from(signature).expect("Cannot push signature"))
            .push_slice(
                PushBytesBuf::try_from(signer_public_key).expect("Cannot push signer public key"),
            );
    }

    // Push body in chunks of 520 bytes
    for chunk in body.chunks(520) {
        reveal_script_builder = reveal_script_builder
            .push_slice(PushBytesBuf::try_from(chunk.to_vec()).expect("Cannot push body chunk"));
    }

    // Push end if, nonce, and NIP
    reveal_script_builder = reveal_script_builder
        .push_opcode(OP_ENDIF)
        .push_slice(nonce.to_le_bytes())
        .push_opcode(OP_NIP);

    let reveal_script = reveal_script_builder.into_script();

    // Build control block and address
    let secp = Secp256k1::<All>::new();
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .expect("Cannot add reveal script to taptree")
        .finalize(&secp, public_key)
        .expect("Cannot finalize taptree");

    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .expect("Cannot create control block");

    let merkle_root = taproot_spend_info.merkle_root();
    let commit_address = Address::p2tr(&secp, public_key, merkle_root, network);

    CitreaSigningData {
        reveal_script,
        control_block,
        commit_address,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use clementine_primitives::MIN_TAPROOT_AMOUNT;

    use crate::citrea::data_serialization::DataOnDa;
    use crate::citrea::{TransactionKind, MAX_CHUNK_SIZE};
    use crate::signer::TxSenderSigningKey;

    use super::create_reveal_script;

    const TAPROOT_INPUT_COUNT: usize = 10;
    const TAPROOT_OUTPUT_COUNT: usize = 2;
    const STANDARD_TX_MAX_VBYTES: u64 = 100_000;

    #[test]
    fn max_chunk_reveal_transaction_stays_under_standard_weight() {
        let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid test secret key");
        let signer = TxSenderSigningKey::new(secret_key, Network::Regtest);

        let raw_chunk = vec![0u8; MAX_CHUNK_SIZE as usize];
        let reveal_body =
            borsh::to_vec(&DataOnDa::Chunk(raw_chunk)).expect("max chunk DA body must serialize");
        assert!(
            reveal_body.len() > MAX_CHUNK_SIZE as usize,
            "test must cover the final Borsh-wrapped reveal body"
        );

        let signing_data = create_reveal_script(
            signer.xonly_public_key(),
            &signer,
            Network::Regtest,
            TransactionKind::Chunks,
            &reveal_body,
        );

        let mut inputs: Vec<TxIn> = (0..TAPROOT_INPUT_COUNT)
            .map(|vout| TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: vout as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();

        let mut reveal_witness = Witness::new();
        reveal_witness.push([0u8; 65]);
        reveal_witness.push(signing_data.reveal_script);
        reveal_witness.push(signing_data.control_block.serialize());
        inputs[0].witness = reveal_witness;

        for input in inputs.iter_mut().skip(1) {
            input.witness.push([0u8; 65]);
        }

        let script_pubkey = signer.address().script_pubkey();
        let outputs = (0..TAPROOT_OUTPUT_COUNT)
            .map(|_| TxOut {
                value: MIN_TAPROOT_AMOUNT,
                script_pubkey: script_pubkey.clone(),
            })
            .collect();

        let reveal_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        let weight = reveal_tx.weight().to_wu();
        let vbytes = reveal_tx.weight().to_vbytes_ceil();
        println!("weight: {weight}, vbytes: {vbytes}");
        assert!(
            vbytes < STANDARD_TX_MAX_VBYTES,
            "max chunk reveal transaction is {weight} WU / {vbytes} vB"
        );
    }
}
