use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::secp256k1::schnorr;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::XOnlyPublicKey;
use bitcoin::{ScriptBuf, Witness};
use std::fmt::Debug;
use std::hash::Hash;

use crate::witness::WitnessInput;
use clementine_errors::WitnessError;

pub type WitnessInputMap<I> = HashMap<I, WitnessInput>;
pub type WitnessMaterialMap<I> = HashMap<I, WitnessMaterial>;
pub type WitnessMaterialEntry<I> = (I, WitnessMaterial);

pub trait WitnessMaterialExt: Sized {
    fn signature(self, signature: schnorr::Signature) -> WitnessMaterialEntry<Self> {
        (self, WitnessMaterial::Signature(signature))
    }

    fn witness_input(self, witness_input: WitnessInput) -> WitnessMaterialEntry<Self> {
        (self, WitnessMaterial::WitnessInput(witness_input))
    }

    fn prebuilt_witness(self, witness_input: WitnessInput) -> WitnessMaterialEntry<Self> {
        self.witness_input(witness_input)
    }

    fn revealed_script(
        self,
        script: ScriptBuf,
        witness_input: WitnessInput,
        spend_info: Arc<TaprootSpendInfo>,
    ) -> WitnessMaterialEntry<Self> {
        (
            self,
            WitnessMaterial::RevealedScript {
                script,
                witness_input,
                spend_info,
            },
        )
    }

    fn raw_witness(self, stack_items: Vec<Vec<u8>>) -> WitnessMaterialEntry<Self> {
        self.witness_input(WitnessInput::RawWitness(stack_items))
    }

    fn full_witness(self, witness: Witness) -> WitnessMaterialEntry<Self> {
        (self, WitnessMaterial::FullWitness(witness))
    }

    fn preimage_reveal(
        self,
        signature: schnorr::Signature,
        preimage: Vec<u8>,
    ) -> WitnessMaterialEntry<Self> {
        (
            self,
            WitnessMaterial::PreimageReveal {
                signature,
                preimage,
            },
        )
    }

    fn multisig_signatures(
        self,
        signatures: Vec<(XOnlyPublicKey, schnorr::Signature)>,
    ) -> WitnessMaterialEntry<Self> {
        (self, WitnessMaterial::MultisigSignatures(signatures))
    }

    fn winternitz_witness(
        self,
        signature: schnorr::Signature,
        stack_items: Vec<Vec<u8>>,
    ) -> WitnessMaterialEntry<Self> {
        (
            self,
            WitnessMaterial::WinternitzWitness {
                signature,
                stack_items,
            },
        )
    }
}

impl<I> WitnessMaterialExt for I {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessMaterial {
    Signature(schnorr::Signature),
    WitnessInput(WitnessInput),
    RevealedScript {
        script: ScriptBuf,
        witness_input: WitnessInput,
        spend_info: Arc<TaprootSpendInfo>,
    },
    FullWitness(Witness),
    MultisigSignatures(Vec<(XOnlyPublicKey, schnorr::Signature)>),
    PreimageReveal {
        signature: schnorr::Signature,
        preimage: Vec<u8>,
    },
    WinternitzWitness {
        signature: schnorr::Signature,
        stack_items: Vec<Vec<u8>>,
    },
}

fn witness_material_kind_name(material: &WitnessMaterial) -> &'static str {
    match material {
        WitnessMaterial::Signature(_) => "Signature",
        WitnessMaterial::WitnessInput(_) => "WitnessInput",
        WitnessMaterial::RevealedScript { .. } => "RevealedScript",
        WitnessMaterial::FullWitness(_) => "FullWitness",
        WitnessMaterial::MultisigSignatures(_) => "MultisigSignatures",
        WitnessMaterial::PreimageReveal { .. } => "PreimageReveal",
        WitnessMaterial::WinternitzWitness { .. } => "WinternitzWitness",
    }
}

pub fn insert_witness_material<I: Eq + Hash + Debug>(
    materials: &mut WitnessMaterialMap<I>,
    entry: WitnessMaterialEntry<I>,
) -> Result<(), WitnessError> {
    let (key, material) = entry;
    match materials.get(&key) {
        Some(existing) if existing == &material => Ok(()),
        Some(existing) => Err(WitnessError::Message(format!(
            "duplicate witness material provided for `{:?}`: existing {} conflicts with new {}",
            key,
            witness_material_kind_name(existing),
            witness_material_kind_name(&material),
        ))),
        None => {
            materials.insert(key, material);
            Ok(())
        }
    }
}

pub fn extend_witness_materials<I, It>(
    materials: &mut WitnessMaterialMap<I>,
    entries: It,
) -> Result<(), WitnessError>
where
    I: Eq + Hash + Debug,
    It: IntoIterator<Item = WitnessMaterialEntry<I>>,
{
    for entry in entries {
        insert_witness_material(materials, entry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        extend_witness_materials, insert_witness_material, WitnessMaterial, WitnessMaterialExt,
        WitnessMaterialMap,
    };
    use crate::witness::WitnessInput;
    use bitcoin::secp256k1::schnorr::Signature;
    use bitcoin::Witness;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum TestInput {
        Sig0,
    }

    fn signature(fill: u8) -> Signature {
        Signature::from_slice(&[fill; 64]).expect("fixed-size schnorr signature")
    }

    #[test]
    fn duplicate_identical_signature_is_idempotent() {
        let mut materials: WitnessMaterialMap<TestInput> = WitnessMaterialMap::new();
        let signature = signature(1);

        insert_witness_material(&mut materials, TestInput::Sig0.signature(signature))
            .expect("first insert");

        insert_witness_material(&mut materials, TestInput::Sig0.signature(signature))
            .expect("duplicate identical insert");

        match materials.get(&TestInput::Sig0) {
            Some(WitnessMaterial::Signature(actual)) => assert_eq!(*actual, signature),
            other => panic!("unexpected witness material: {other:?}"),
        }
    }

    #[test]
    fn conflicting_material_kinds_are_rejected() {
        let mut materials: WitnessMaterialMap<TestInput> = WitnessMaterialMap::new();

        insert_witness_material(
            &mut materials,
            TestInput::Sig0.prebuilt_witness(WitnessInput::Multisig(vec![None])),
        )
        .expect("first insert");

        let error =
            insert_witness_material(&mut materials, TestInput::Sig0.signature(signature(9)))
                .expect_err("conflicting witness material kinds should fail");

        assert!(error
            .to_string()
            .contains("duplicate witness material provided"));
    }

    #[test]
    fn extend_preserves_duplicate_signature_idempotently() {
        let mut materials: WitnessMaterialMap<TestInput> = WitnessMaterialMap::new();
        let signature = signature(7);

        extend_witness_materials(
            &mut materials,
            [
                TestInput::Sig0.signature(signature),
                TestInput::Sig0.signature(signature),
            ],
        )
        .expect("idempotent signature insert");

        match materials.get(&TestInput::Sig0) {
            Some(WitnessMaterial::Signature(actual)) => assert_eq!(*actual, signature),
            other => panic!("unexpected witness material: {other:?}"),
        }
    }

    #[test]
    fn final_preimage_reveal_material_is_stored_directly() {
        let mut materials: WitnessMaterialMap<TestInput> = WitnessMaterialMap::new();

        extend_witness_materials(
            &mut materials,
            [TestInput::Sig0.preimage_reveal(signature(5), vec![7; 20])],
        )
        .expect("store preimage reveal material");

        match materials.get(&TestInput::Sig0) {
            Some(WitnessMaterial::PreimageReveal {
                signature: actual_signature,
                preimage,
            }) => {
                assert_eq!(*actual_signature, signature(5));
                assert_eq!(preimage, &vec![7; 20]);
            }
            other => panic!("unexpected witness material: {other:?}"),
        }
    }

    #[test]
    fn final_winternitz_witness_material_is_stored_directly() {
        let mut materials: WitnessMaterialMap<TestInput> = WitnessMaterialMap::new();

        extend_witness_materials(
            &mut materials,
            [TestInput::Sig0.winternitz_witness(signature(8), vec![vec![1, 2], vec![3, 4]])],
        )
        .expect("store Winternitz witness material");

        match materials.get(&TestInput::Sig0) {
            Some(WitnessMaterial::WinternitzWitness {
                signature: actual_signature,
                stack_items,
            }) => {
                assert_eq!(*actual_signature, signature(8));
                assert_eq!(stack_items, &vec![vec![1, 2], vec![3, 4]]);
            }
            other => panic!("unexpected witness material: {other:?}"),
        }
    }

    #[test]
    fn raw_witness_helper_stores_witness_input() {
        let mut materials: WitnessMaterialMap<TestInput> = WitnessMaterialMap::new();

        extend_witness_materials(
            &mut materials,
            [TestInput::Sig0.raw_witness(vec![vec![1, 2]])],
        )
        .expect("store raw witness");

        match materials.get(&TestInput::Sig0) {
            Some(WitnessMaterial::WitnessInput(WitnessInput::RawWitness(items))) => {
                assert_eq!(items, &vec![vec![1, 2]]);
            }
            other => panic!("unexpected witness material: {other:?}"),
        }
    }

    #[test]
    fn full_witness_helper_stores_complete_witness() {
        let mut materials: WitnessMaterialMap<TestInput> = WitnessMaterialMap::new();
        let mut witness = Witness::new();
        witness.push([1u8, 2u8]);
        witness.push([3u8, 4u8]);

        extend_witness_materials(
            &mut materials,
            [TestInput::Sig0.full_witness(witness.clone())],
        )
        .expect("store full witness");

        match materials.get(&TestInput::Sig0) {
            Some(WitnessMaterial::FullWitness(witness)) => {
                let actual: Vec<Vec<u8>> = witness.iter().map(|item| item.to_vec()).collect();
                assert_eq!(actual, vec![vec![1, 2], vec![3, 4]]);
            }
            other => panic!("unexpected witness material: {other:?}"),
        }
    }
}
