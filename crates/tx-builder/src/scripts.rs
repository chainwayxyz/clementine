//! Concrete script implementations for common Bitcoin script patterns.

use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::*;
use bitcoin::opcodes::OP_FALSE;
use bitcoin::script::Builder;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::taproot;
use bitcoin::{ScriptBuf, Txid, Witness};
use bitvm::signatures::winternitz::{Parameters, PublicKey};

use crate::script::{ScriptLeaf, ScriptNode, SpendableScript};
use crate::witness::WinternitzCommitInput;
use crate::witness::{
    BaseDepositInput, CheckSigInput, MultisigInput, PreimageRevealInput, ReplacementDepositInput,
    TimelockInput, WitnessCodec,
};
use clementine_errors::WitnessError;

fn parse_taproot_signature(item: &[u8], index: usize) -> Result<taproot::Signature, WitnessError> {
    taproot::Signature::from_slice(item).map_err(|err| WitnessError::InvalidTaprootSignature {
        index,
        message: err.to_string(),
    })
}

/// `<pk> OP_CHECKSIG` — single-key signature check.
#[derive(Debug, Clone)]
pub struct CheckSig {
    pub pk: XOnlyPublicKey,
}

impl CheckSig {
    pub fn new(pk: XOnlyPublicKey) -> Self {
        Self { pk }
    }
}

impl SpendableScript for CheckSig {
    fn to_script_buf(&self) -> ScriptBuf {
        Builder::new()
            .push_x_only_key(&self.pk)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}

impl WitnessCodec for CheckSig {
    type EncodeInput = CheckSigInput;
    type Decoded = CheckSigInput;

    fn encode_witness(&self, input: &Self::EncodeInput) -> Result<Witness, WitnessError> {
        Ok(Witness::from_slice(&[input.serialize()]))
    }

    fn decode_witness(&self, witness: &Witness) -> Result<Self::Decoded, WitnessError> {
        match witness.len() {
            1 => parse_taproot_signature(
                witness.iter().next().expect("witness length was checked"),
                0,
            ),
            actual => Err(WitnessError::WrongItemCount {
                expected: "1",
                actual,
            }),
        }
    }
}

/// `<locktime> OP_CSV OP_DROP [<pk> OP_CHECKSIG | OP_TRUE]`
#[derive(Debug, Clone)]
pub struct TimelockScript {
    pub pk: Option<XOnlyPublicKey>,
    pub locktime: u16,
}

impl TimelockScript {
    pub fn new(pk: Option<XOnlyPublicKey>, locktime: u16) -> Self {
        Self { pk, locktime }
    }
}

impl SpendableScript for TimelockScript {
    fn to_script_buf(&self) -> ScriptBuf {
        let builder = Builder::new()
            .push_int(self.locktime as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP);

        match self.pk {
            Some(pk) => builder.push_x_only_key(&pk).push_opcode(OP_CHECKSIG),
            None => builder.push_opcode(bitcoin::opcodes::OP_TRUE),
        }
        .into_script()
    }
}

impl WitnessCodec for TimelockScript {
    type EncodeInput = TimelockInput;
    type Decoded = TimelockInput;

    fn encode_witness(&self, input: &Self::EncodeInput) -> Result<Witness, WitnessError> {
        match input {
            Some(signature) => {
                if self.pk.is_none() {
                    return Err(WitnessError::Message(
                        "timelock script without key cannot encode a signature".to_string(),
                    ));
                }
                Ok(Witness::from_slice(&[signature.serialize()]))
            }
            None => Ok(Witness::new()),
        }
    }

    fn decode_witness(&self, witness: &Witness) -> Result<Self::Decoded, WitnessError> {
        match witness.len() {
            0 => Ok(None),
            1 => {
                if self.pk.is_none() {
                    return Err(WitnessError::Message(
                        "timelock script without key cannot decode a signature witness".to_string(),
                    ));
                }
                Ok(Some(parse_taproot_signature(
                    witness.iter().next().expect("witness length was checked"),
                    0,
                )?))
            }
            actual => Err(WitnessError::WrongItemCount {
                expected: "0 or 1",
                actual,
            }),
        }
    }
}

/// k-of-n threshold multisig using `OP_CHECKSIGADD`.
#[derive(Debug, Clone)]
pub struct Multisig {
    pub pubkeys: Vec<XOnlyPublicKey>,
    pub threshold: u32,
}

impl Multisig {
    pub fn new(pubkeys: Vec<XOnlyPublicKey>, threshold: u32) -> Self {
        Self { pubkeys, threshold }
    }

    /// Creates a multisig with pubkeys sorted in ascending lexicographic order.
    pub fn new_sorted(mut pubkeys: Vec<XOnlyPublicKey>, threshold: u32) -> Self {
        pubkeys.sort();
        Self { pubkeys, threshold }
    }
}

impl SpendableScript for Multisig {
    fn to_script_buf(&self) -> ScriptBuf {
        let mut builder = Builder::new()
            .push_x_only_key(&self.pubkeys[0])
            .push_opcode(OP_CHECKSIG);
        for pk in self.pubkeys.iter().skip(1) {
            builder = builder.push_x_only_key(pk).push_opcode(OP_CHECKSIGADD);
        }
        builder
            .push_int(self.threshold as i64)
            .push_opcode(OP_NUMEQUAL)
            .into_script()
    }
}

impl WitnessCodec for Multisig {
    type EncodeInput = MultisigInput;
    type Decoded = MultisigInput;

    fn encode_witness(&self, input: &Self::EncodeInput) -> Result<Witness, WitnessError> {
        if input.len() != self.pubkeys.len() {
            return Err(WitnessError::Message(format!(
                "multisig signature slot count ({}) does not match script pubkey count ({})",
                input.len(),
                self.pubkeys.len()
            )));
        }

        let mut witness = Witness::new();
        for signature in input.iter().rev() {
            match signature {
                Some(sig) => witness.push(sig.serialize()),
                None => witness.push([]),
            }
        }
        Ok(witness)
    }

    fn decode_witness(&self, witness: &Witness) -> Result<Self::Decoded, WitnessError> {
        if witness.len() != self.pubkeys.len() {
            return Err(WitnessError::WrongItemCount {
                expected: "exactly the multisig pubkey count",
                actual: witness.len(),
            });
        }

        let mut signatures = vec![None; self.pubkeys.len()];
        for (offset, item) in witness.iter().enumerate() {
            let target_index = self.pubkeys.len() - 1 - offset;
            if item.is_empty() {
                continue;
            }
            signatures[target_index] = Some(parse_taproot_signature(item, offset)?);
        }

        Ok(signatures)
    }
}

/// Winternitz one-time-signature commitment followed by a terminal `OP_CHECKSIG`.

#[derive(Debug, Clone)]
pub struct WinternitzCommit {
    pub commitments: Vec<(PublicKey, u32)>,
    pub checksig_pubkey: XOnlyPublicKey,
    pub log_d: u32,
}

impl WinternitzCommit {
    pub fn new(
        commitments: Vec<(PublicKey, u32)>,
        checksig_pubkey: XOnlyPublicKey,
        log_d: u32,
    ) -> Self {
        Self {
            commitments,
            checksig_pubkey,
            log_d,
        }
    }

    pub fn get_params(&self, index: usize) -> Parameters {
        Parameters::new(self.commitments[index].1, self.log_d)
    }
}

impl SpendableScript for WinternitzCommit {
    fn to_script_buf(&self) -> ScriptBuf {
        let mut total_script = ScriptBuf::new();
        for (index, (pubkey, _size)) in self.commitments.iter().enumerate() {
            let params = self.get_params(index);
            let verifier_script =
                bitvm::signatures::signing_winternitz::WINTERNITZ_MESSAGE_VERIFIER
                    .checksig_verify_and_clear_stack(&params, pubkey);
            total_script.extend(
                verifier_script.compile().instructions().map(|instruction| {
                    instruction.expect("BitVM verifier script was just compiled")
                }),
            );
        }

        total_script.push_slice(self.checksig_pubkey.serialize());
        total_script.push_opcode(OP_CHECKSIG);
        total_script
    }
}

impl WitnessCodec for WinternitzCommit {
    type EncodeInput = WinternitzCommitInput;
    type Decoded = WinternitzCommitInput;

    fn encode_witness(&self, input: &Self::EncodeInput) -> Result<Witness, WitnessError> {
        let mut witness = Witness::new();
        witness.push(input.signature.serialize());
        for stack_item in &input.stack_items {
            witness.push(stack_item);
        }
        Ok(witness)
    }

    fn decode_witness(&self, witness: &Witness) -> Result<Self::Decoded, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::WrongItemCount {
                expected: "at least 1",
                actual: 0,
            });
        }

        let mut iter = witness.iter();
        let signature =
            parse_taproot_signature(iter.next().expect("witness emptiness was checked"), 0)?;
        let stack_items = iter.map(|item| item.to_vec()).collect();

        Ok(WinternitzCommitInput {
            signature,
            stack_items,
        })
    }
}

/// `OP_SIZE 20 OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUALVERIFY <pk> OP_CHECKSIG`
#[derive(Debug, Clone)]
pub struct PreimageRevealScript {
    pub pk: XOnlyPublicKey,
    pub hash: [u8; 20],
}

impl PreimageRevealScript {
    pub fn new(pk: XOnlyPublicKey, hash: [u8; 20]) -> Self {
        Self { pk, hash }
    }
}

impl SpendableScript for PreimageRevealScript {
    fn to_script_buf(&self) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_SIZE)
            .push_int(20)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_HASH160)
            .push_slice(self.hash)
            .push_opcode(OP_EQUALVERIFY)
            .push_x_only_key(&self.pk)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}

impl WitnessCodec for PreimageRevealScript {
    type EncodeInput = PreimageRevealInput;
    type Decoded = PreimageRevealInput;

    fn encode_witness(&self, input: &Self::EncodeInput) -> Result<Witness, WitnessError> {
        if input.preimage.len() != 20 {
            return Err(WitnessError::InvalidPreimageLength {
                expected: 20,
                actual: input.preimage.len(),
            });
        }

        let actual_hash = bitcoin::hashes::hash160::Hash::hash(&input.preimage);
        if actual_hash != bitcoin::hashes::hash160::Hash::from_byte_array(self.hash) {
            return Err(WitnessError::InvalidPreimageHash);
        }

        let mut witness = Witness::new();
        witness.push(input.signature.serialize());
        witness.push(&input.preimage);
        Ok(witness)
    }

    fn decode_witness(&self, witness: &Witness) -> Result<Self::Decoded, WitnessError> {
        if witness.len() != 2 {
            return Err(WitnessError::WrongItemCount {
                expected: "2",
                actual: witness.len(),
            });
        }

        let mut iter = witness.iter();
        let signature =
            parse_taproot_signature(iter.next().expect("witness length was checked"), 0)?;
        let preimage = iter.next().expect("witness length was checked").to_vec();
        if preimage.len() != 20 {
            return Err(WitnessError::InvalidPreimageLength {
                expected: 20,
                actual: preimage.len(),
            });
        }
        let actual_hash = bitcoin::hashes::hash160::Hash::hash(&preimage);
        if actual_hash != bitcoin::hashes::hash160::Hash::from_byte_array(self.hash) {
            return Err(WitnessError::InvalidPreimageHash);
        }

        Ok(PreimageRevealInput {
            signature,
            preimage,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BaseDepositScript {
    pub nofn_xonly_pk: XOnlyPublicKey,
    pub evm_address: [u8; 20],
}

impl BaseDepositScript {
    pub fn new(nofn_xonly_pk: XOnlyPublicKey, evm_address: [u8; 20]) -> Self {
        Self {
            nofn_xonly_pk,
            evm_address,
        }
    }
}

impl SpendableScript for BaseDepositScript {
    fn to_script_buf(&self) -> ScriptBuf {
        let citrea: [u8; 6] = *b"citrea";

        Builder::new()
            .push_x_only_key(&self.nofn_xonly_pk)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(citrea)
            .push_slice(self.evm_address)
            .push_opcode(OP_ENDIF)
            .into_script()
    }
}

impl WitnessCodec for BaseDepositScript {
    type EncodeInput = BaseDepositInput;
    type Decoded = BaseDepositInput;

    fn encode_witness(&self, input: &Self::EncodeInput) -> Result<Witness, WitnessError> {
        Ok(Witness::from_slice(&[input.serialize()]))
    }

    fn decode_witness(&self, witness: &Witness) -> Result<Self::Decoded, WitnessError> {
        match witness.len() {
            1 => parse_taproot_signature(
                witness.iter().next().expect("witness length was checked"),
                0,
            ),
            actual => Err(WitnessError::WrongItemCount {
                expected: "1",
                actual,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplacementDepositScript {
    pub nofn_xonly_pk: XOnlyPublicKey,
    pub old_move_txid: Txid,
}

impl ReplacementDepositScript {
    pub fn new(nofn_xonly_pk: XOnlyPublicKey, old_move_txid: Txid) -> Self {
        Self {
            nofn_xonly_pk,
            old_move_txid,
        }
    }
}

impl SpendableScript for ReplacementDepositScript {
    fn to_script_buf(&self) -> ScriptBuf {
        let citrea_replace: [u8; 13] = *b"citreaReplace";

        Builder::new()
            .push_x_only_key(&self.nofn_xonly_pk)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(citrea_replace)
            .push_slice(self.old_move_txid.as_byte_array())
            .push_opcode(OP_ENDIF)
            .into_script()
    }
}

impl WitnessCodec for ReplacementDepositScript {
    type EncodeInput = ReplacementDepositInput;
    type Decoded = ReplacementDepositInput;

    fn encode_witness(&self, input: &Self::EncodeInput) -> Result<Witness, WitnessError> {
        Ok(Witness::from_slice(&[input.serialize()]))
    }

    fn decode_witness(&self, witness: &Witness) -> Result<Self::Decoded, WitnessError> {
        match witness.len() {
            1 => parse_taproot_signature(
                witness.iter().next().expect("witness length was checked"),
                0,
            ),
            actual => Err(WitnessError::WrongItemCount {
                expected: "1",
                actual,
            }),
        }
    }
}

/// Wraps an arbitrary pre-built `ScriptBuf`.
#[derive(Debug, Clone)]
pub struct OtherSpendable(pub ScriptBuf);

impl OtherSpendable {
    pub fn new(script: ScriptBuf) -> Self {
        Self(script)
    }
}

impl SpendableScript for OtherSpendable {
    fn to_script_buf(&self) -> ScriptBuf {
        self.0.clone()
    }
}

macro_rules! impl_leaf_conversions {
    ($variant:ident, $ty:ty) => {
        impl From<$ty> for ScriptLeaf {
            fn from(value: $ty) -> Self {
                ScriptLeaf::$variant(value)
            }
        }

        impl From<$ty> for ScriptNode {
            fn from(value: $ty) -> Self {
                ScriptNode::Leaf(ScriptLeaf::$variant(value))
            }
        }
    };
}

impl_leaf_conversions!(CheckSig, CheckSig);
impl_leaf_conversions!(Timelock, TimelockScript);
impl_leaf_conversions!(Multisig, Multisig);

impl_leaf_conversions!(WinternitzCommit, WinternitzCommit);
impl_leaf_conversions!(PreimageReveal, PreimageRevealScript);
impl_leaf_conversions!(BaseDeposit, BaseDepositScript);
impl_leaf_conversions!(ReplacementDeposit, ReplacementDepositScript);
impl_leaf_conversions!(Other, OtherSpendable);

#[cfg(test)]
mod tests {
    use super::Multisig;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    fn xonly_from_seed(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
        let kp = Keypair::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from_keypair(&kp).0
    }

    #[test]
    fn multisig_new_preserves_input_order() {
        let pk3 = xonly_from_seed(3);
        let pk1 = xonly_from_seed(1);
        let pk2 = xonly_from_seed(2);
        let multisig = Multisig::new(vec![pk3, pk1, pk2], 2);
        assert_eq!(multisig.pubkeys, vec![pk3, pk1, pk2]);
    }

    #[test]
    fn multisig_new_sorted_orders_pubkeys() {
        let pk3 = xonly_from_seed(3);
        let pk1 = xonly_from_seed(1);
        let pk2 = xonly_from_seed(2);
        let multisig = Multisig::new_sorted(vec![pk3, pk1, pk2], 2);
        assert_eq!(multisig.pubkeys, vec![pk1, pk2, pk3]);
    }
}
