use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

use bitcoin::secp256k1::Message;
use bitcoin::transaction::Version;
use bitcoin::{
    OutPoint, Script, ScriptBuf, Sequence, TapSighash, TapSighashType, Transaction, TxOut, Txid,
    Witness, XOnlyPublicKey,
};

use crate::input::{debug_validate_spend_for_spendable, ResolvedInput, SpendableTxIn};
use crate::output::{ResolvedOutput, UnspentTxOut};
use crate::script::ScriptLeaf;
use crate::spec::SpendSpec;
use crate::witness::{PreimageRevealInput, WinternitzCommitInput, WitnessInput};
use crate::witness_material::{WitnessMaterial, WitnessMaterialEntry, WitnessMaterialMap};
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::LeafVersion;
use clementine_errors::{BridgeError, TxError};
use eyre::eyre;

/// An unsigned transaction with metadata for witness construction.
///
/// Created by [`TxHandlerBuilder::finalize`].
pub type InputSighash<I> = (I, [u8; 32]);

#[derive(Debug, Clone)]
pub struct TxHandler<Tx, Input, Output, Leaf, Actor> {
    tx_type: Tx,
    /// Map of input references to their indices in the transaction.
    input_indices: HashMap<Input, usize>,
    /// Map of output references to their indices in the transaction.
    output_indices: HashMap<Output, usize>,
    /// Resolved inputs used for sighash and witness construction.
    inputs: Vec<ResolvedInput<Input, Leaf, Actor>>,
    /// Resolved outputs used for chaining child transactions.
    outputs: Vec<ResolvedOutput<Output, Leaf>>,
    /// Cached Bitcoin transaction used for serialization and sighash calculation.
    cached_tx: Transaction,
    /// Cached txid of the witness-stripped transaction.
    cached_txid: Txid,
}

#[derive(Debug)]
enum PreparedWitness {
    KeySpend(bitcoin::taproot::Signature),
    Script(WitnessInput),
    RevealedScript {
        script: ScriptBuf,
        witness_input: WitnessInput,
        spend_info: Arc<bitcoin::taproot::TaprootSpendInfo>,
    },
    FullWitness(Witness),
}

impl<Tx, Input, Output, Leaf, Actor> TxHandler<Tx, Input, Output, Leaf, Actor>
where
    Tx: Clone,
    Input: Clone + Eq + Hash + Debug,
    Output: Clone + Eq + Hash + Debug,
    Leaf: Clone + Debug + PartialEq,
    Actor: Clone + Debug,
{
    fn bridge_error(message: impl Into<String>) -> BridgeError {
        TxError::Other(eyre!(message.into())).into()
    }

    /// Returns the transaction type.
    pub fn tx_type(&self) -> Tx {
        self.tx_type.clone()
    }

    /// Returns the ordered typed input identifiers for this transaction.
    pub fn inputs(&self) -> impl Iterator<Item = &Input> {
        self.inputs.iter().map(ResolvedInput::id)
    }

    /// Returns the ordered typed output identifiers for this transaction.
    pub fn outputs(&self) -> impl Iterator<Item = &Output> {
        self.outputs.iter().map(ResolvedOutput::id)
    }

    /// Returns a [`SpendableTxIn`] referencing the named output.
    pub fn get_spendable_output(
        &self,
        output: impl Into<Output>,
    ) -> Result<SpendableTxIn<Leaf>, BridgeError> {
        let output = output.into();
        let idx = self.resolve_output_index(&output)?;
        let txout = self.resolved_output_at(idx)?;

        Ok(SpendableTxIn::from_output(
            OutPoint {
                txid: self.cached_txid,
                vout: idx as u32,
            },
            txout.unspent(),
        ))
    }

    /// Returns the underlying Bitcoin transaction.
    pub fn transaction(&self) -> &Transaction {
        &self.cached_tx
    }

    /// Consumes the handler and returns the underlying Bitcoin transaction.
    pub fn into_transaction(self) -> Transaction {
        self.cached_tx
    }

    /// Returns the txid of the underlying transaction.
    pub fn txid(&self) -> Txid {
        self.cached_txid
    }

    /// Returns a reference to the txid of the underlying transaction.
    pub fn txid_ref(&self) -> &Txid {
        &self.cached_txid
    }

    /// Returns true when every input already has witness data.
    pub fn is_fully_signed(&self) -> bool {
        self.cached_tx
            .input
            .iter()
            .all(|input| !input.witness.is_empty())
    }

    /// Returns `self` when every input already has witness data.
    pub fn ensure_fully_signed(self) -> Result<Self, BridgeError> {
        if self.is_fully_signed() {
            Ok(self)
        } else {
            Err(Self::bridge_error("missing witness data"))
        }
    }

    /// Returns the number of transaction inputs.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Returns the typed input identifier at the given vin.
    pub fn input_for_index(&self, index: usize) -> Result<Input, BridgeError> {
        Ok(self.resolved_input_at(index)?.id().clone())
    }

    /// Returns the typed output identifier at the given vout.
    pub fn output_for_index(&self, index: usize) -> Result<Output, BridgeError> {
        Ok(self.resolved_output_at(index)?.id().clone())
    }

    /// Returns the vout of the named output.
    pub fn output_index(&self, output: impl Into<Output>) -> Result<u32, BridgeError> {
        let output = output.into();
        Ok(self.resolve_output_index(&output)? as u32)
    }

    /// Returns true if the input already has witness data set.
    pub fn input_has_witness(&self, input: impl Into<Input>) -> Result<bool, BridgeError> {
        let input = input.into();
        let input_index = self.resolve_input_index(&input)?;
        Ok(self.witness_at(input_index)?.is_some())
    }

    /// Returns the witness data for the given input, if set.
    pub fn witness_for_input(
        &self,
        input: impl Into<Input>,
    ) -> Result<Option<&Witness>, BridgeError> {
        let input = input.into();
        let input_index = self.resolve_input_index(&input)?;
        self.witness_at(input_index)
    }

    /// Returns the witness data for the input at the given vin, if set.
    pub fn witness_for_index(&self, index: usize) -> Result<Option<&Witness>, BridgeError> {
        self.witness_at(index)
    }

    pub fn merkle_root_for_input(
        &self,
        input: impl Into<Input>,
    ) -> Result<Option<bitcoin::TapNodeHash>, BridgeError> {
        let input = input.into();
        let input_index = self.resolve_input_index(&input)?;
        Ok(self
            .resolved_input_at(input_index)?
            .spendable()
            .get_spend_info()
            .as_ref()
            .and_then(|spend_info| spend_info.merkle_root()))
    }

    /// Returns the input owner for the given input.
    pub fn input_owner(&self, input: impl Into<Input>) -> Result<Option<Actor>, BridgeError> {
        let input = input.into();
        Ok(self.resolved_input(&input)?.owner())
    }

    /// Returns the ordered typed input identifiers owned by the given actor.
    pub fn inputs_for_owner(&self, owner: Actor) -> Vec<Input>
    where
        Actor: PartialEq,
    {
        self.inputs
            .iter()
            .filter(|input| input.owner() == Some(owner.clone()))
            .map(|input| input.id().clone())
            .collect()
    }

    /// Returns the spend spec for the given input.
    pub fn spend(&self, input: impl Into<Input>) -> Result<SpendSpec<Leaf, Actor>, BridgeError> {
        let input = input.into();
        Ok(self.resolved_input(&input)?.spend().clone())
    }

    /// Returns the resolved leaf for the given input, if any.
    pub fn leaf_for_input(&self, input: impl Into<Input>) -> Result<Option<Leaf>, BridgeError> {
        let input = input.into();
        Ok(self.resolved_input(&input)?.leaf())
    }

    /// Returns the configured sighash type for the input at the given vin.
    pub fn sighash_type_for_input_index(
        &self,
        index: usize,
    ) -> Result<TapSighashType, BridgeError> {
        Ok(self
            .resolved_input_at(index)?
            .sighash_type()
            .unwrap_or(TapSighashType::Default))
    }

    /// Computes a BIP341 sighash for the named input.
    ///
    /// Uses the sighash type stored when the input was added.
    pub fn sighash_for_input(&self, input: impl Into<Input>) -> Result<[u8; 32], BridgeError> {
        let input = input.into();
        let idx = self.resolve_input_index(&input)?;
        let sighash_type = self.inputs[idx]
            .sighash_type()
            .unwrap_or(TapSighashType::Default);
        self.sighash_for_input_index(idx, sighash_type)
    }

    /// Returns the configured sighash type for an input (defaults to `Default`).
    pub fn sighash_type_for_input(
        &self,
        input: impl Into<Input>,
    ) -> Result<TapSighashType, BridgeError> {
        let input = input.into();
        let idx = self.resolve_input_index(&input)?;
        Ok(self.inputs[idx]
            .sighash_type()
            .unwrap_or(TapSighashType::Default))
    }

    /// Computes BIP341 sighashes for every input owned by the given actor.
    pub fn sighashes_for_owner(&self, owner: Actor) -> Result<Vec<InputSighash<Input>>, BridgeError>
    where
        Actor: PartialEq,
    {
        self.inputs_for_owner(owner)
            .into_iter()
            .map(|input| {
                if matches!(self.spend(input.clone())?, SpendSpec::RevealRequired { .. }) {
                    return Ok(None);
                }
                let sighash = self.sighash_for_input(input.clone())?;
                Ok(Some((input, sighash)))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|entries| entries.into_iter().flatten().collect())
    }

    /// Applies a key-spend witness to the named input after validating its spend path.
    pub fn apply_keyspend_signature_for_input(
        &mut self,
        input: impl Into<Input>,
        signature: bitcoin::taproot::Signature,
    ) -> Result<(), BridgeError> {
        let input = input.into();
        match self.spend(input.clone())? {
            SpendSpec::KeySpend { .. } => {
                self.set_witness_at_input(input, Witness::p2tr_key_spend(&signature))
            }
            other => Err(Self::bridge_error(format!(
                "cannot apply key-spend signature to input {input:?} with spend spec {other:?}"
            ))),
        }
    }

    fn set_witness_at_input(
        &mut self,
        input: impl Into<Input>,
        witness: Witness,
    ) -> Result<(), BridgeError> {
        let input = input.into();
        let input_index = self.resolve_input_index(&input)?;
        if self.witness_at(input_index)?.is_some() {
            return Err(TxError::WitnessAlreadySet.into());
        }
        self.cached_tx.input[input_index].witness = witness;
        Ok(())
    }

    /// Applies a typed witness-material payload to the named input.
    pub fn apply_witness_for_input(
        &mut self,
        input: impl Into<Input>,
        material: WitnessMaterial,
    ) -> Result<(), BridgeError> {
        let input = input.into();
        match self.prepare_witness_for_input(input.clone(), material)? {
            PreparedWitness::KeySpend(signature) => {
                self.apply_keyspend_signature_for_input(input, signature)
            }
            PreparedWitness::Script(witness_input) => {
                self.apply_witness_input_for_input(input, witness_input)
            }
            PreparedWitness::RevealedScript {
                script,
                witness_input,
                spend_info,
            } => self.apply_revealed_script_witness_for_input(
                input,
                script,
                witness_input,
                spend_info.as_ref(),
            ),
            PreparedWitness::FullWitness(witness) => self.set_witness_at_input(input, witness),
        }
    }

    /// Fills the witness for a single named input from typed witness material.
    pub fn fill_witness(
        &mut self,
        input: impl Into<Input>,
        material: WitnessMaterial,
    ) -> Result<(), BridgeError> {
        let input = input.into();
        self.apply_witness_for_input(input, material)
    }

    /// Applies a `(input, material)` pair produced by typed input helpers like
    /// `Input::signature(...)`.
    pub fn apply_witness_material_entry<I>(
        &mut self,
        entry: WitnessMaterialEntry<I>,
    ) -> Result<(), BridgeError>
    where
        I: Into<Input>,
    {
        let (input, material) = entry;
        self.apply_witness_for_input(input, material)
    }

    /// Fills the witness for a single typed `(input, material)` entry.
    pub fn fill_witness_entry<I>(
        &mut self,
        entry: WitnessMaterialEntry<I>,
    ) -> Result<(), BridgeError>
    where
        I: Into<Input>,
    {
        self.apply_witness_material_entry(entry)
    }

    /// Fills witnesses for every `(input, material)` entry in the provided map.
    ///
    /// This helper only applies the material you provide; it does not sign inputs
    /// or verify that every input in the transaction has been satisfied.
    pub fn fill_witnesses(
        &mut self,
        materials: &WitnessMaterialMap<Input>,
    ) -> Result<(), BridgeError> {
        for (input, material) in materials {
            self.fill_witness(input.clone(), material.clone())?;
        }
        Ok(())
    }

    /// Returns the resolved input stored at the given vin.
    fn resolved_input_at(
        &self,
        index: usize,
    ) -> Result<&ResolvedInput<Input, Leaf, Actor>, BridgeError> {
        self.inputs
            .get(index)
            .ok_or_else(|| Self::bridge_error(format!("input index {index} out of range")))
    }

    /// Returns the resolved output stored at the given vout.
    fn resolved_output_at(
        &self,
        index: usize,
    ) -> Result<&ResolvedOutput<Output, Leaf>, BridgeError> {
        self.outputs
            .get(index)
            .ok_or_else(|| Self::bridge_error(format!("output index {index} out of range")))
    }

    /// Returns the spendable input metadata for the given typed input.
    pub fn spendable_for_input(
        &self,
        input: impl Into<Input>,
    ) -> Result<&SpendableTxIn<Leaf>, BridgeError> {
        let input = input.into();
        Ok(self.resolved_input(&input)?.spendable())
    }

    /// Returns the selected named leaf script for the given typed input, if any.
    pub fn named_leaf_script_for_input(
        &self,
        input: impl Into<Input>,
    ) -> Result<Option<&ScriptLeaf>, BridgeError> {
        let input = input.into();
        let resolved_input = self.resolved_input(&input)?;
        Ok(match resolved_input.spend() {
            SpendSpec::NamedLeaf { leaf, .. } => resolved_input
                .spendable()
                .get_named_leaf_script(leaf.clone()),
            _ => None,
        })
    }

    /// Computes a BIP341 sighash for the named input and returns the typed value.
    pub fn tap_sighash_for_input(
        &self,
        input: impl Into<Input>,
    ) -> Result<TapSighash, BridgeError> {
        let input = input.into();
        TapSighash::from_slice(&self.sighash_for_input(input)?)
            .map_err(|err| Self::bridge_error(format!("taproot sighash decode error: {err}")))
    }

    /// Computes a BIP341 script-path sighash for the named input and explicit script.
    pub fn tap_script_sighash_for_input_script(
        &self,
        input: impl Into<Input>,
        spend_script: &Script,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, BridgeError> {
        let input = input.into();
        let input_index = self.resolve_input_index(&input)?;
        TapSighash::from_slice(&self.script_sighash_for_input_script_index(
            input_index,
            spend_script,
            sighash_type,
        )?)
        .map_err(|err| Self::bridge_error(format!("taproot sighash decode error: {err}")))
    }

    fn script_sighash_for_input_script_index(
        &self,
        input_index: usize,
        spend_script: &Script,
        sighash_type: TapSighashType,
    ) -> Result<[u8; 32], BridgeError> {
        let prevouts_vec: Vec<&TxOut> = self
            .inputs
            .iter()
            .map(|input| input.spendable().get_prevout())
            .collect();
        let prevouts = match sighash_type {
            TapSighashType::SinglePlusAnyoneCanPay
            | TapSighashType::AllPlusAnyoneCanPay
            | TapSighashType::NonePlusAnyoneCanPay => {
                Prevouts::One(input_index, prevouts_vec[input_index])
            }
            _ => Prevouts::All(&prevouts_vec),
        };
        let leaf_hash = bitcoin::TapLeafHash::from_script(spend_script, LeafVersion::TapScript);
        let mut cache = SighashCache::new(&self.cached_tx);
        let sighash = cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .map_err(|e| Self::bridge_error(format!("taproot script spend sighash error: {e}")))?;
        Ok(sighash.to_byte_array())
    }

    // -- internal helpers ------------------------------------------------

    fn resolve_output_index(&self, output: &Output) -> Result<usize, BridgeError> {
        self.output_indices
            .get(output)
            .copied()
            .ok_or_else(|| Self::bridge_error(format!("output {output:?} not found")))
    }

    fn resolve_input_index(&self, input: &Input) -> Result<usize, BridgeError> {
        self.input_indices
            .get(input)
            .copied()
            .ok_or_else(|| Self::bridge_error(format!("input {input:?} not found")))
    }

    fn resolved_input(
        &self,
        input: &Input,
    ) -> Result<&ResolvedInput<Input, Leaf, Actor>, BridgeError> {
        self.resolve_input_index(input)
            .and_then(|idx| self.resolved_input_at(idx))
    }

    fn witness_at(&self, index: usize) -> Result<Option<&Witness>, BridgeError> {
        let witness = &self
            .cached_tx
            .input
            .get(index)
            .ok_or_else(|| Self::bridge_error(format!("input index {index} out of range")))?
            .witness;
        Ok((!witness.is_empty()).then_some(witness))
    }

    fn taproot_signature_for_input(
        &self,
        input: impl Into<Input>,
        signature: bitcoin::secp256k1::schnorr::Signature,
    ) -> Result<bitcoin::taproot::Signature, BridgeError> {
        let input = input.into();
        Ok(bitcoin::taproot::Signature {
            signature,
            sighash_type: self.sighash_type_for_input(input)?,
        })
    }

    fn taproot_multisig_signatures_for_input(
        &self,
        input: impl Into<Input>,
        signatures: Vec<(
            bitcoin::XOnlyPublicKey,
            bitcoin::secp256k1::schnorr::Signature,
        )>,
    ) -> Result<Vec<Option<bitcoin::taproot::Signature>>, BridgeError> {
        let input = input.into();
        let input_index = self.resolve_input_index(&input)?;
        let resolved_input = self.resolved_input_at(input_index)?;
        let script_leaf = match resolved_input.spend() {
            SpendSpec::NamedLeaf { leaf, .. } => resolved_input
                .spendable()
                .get_named_leaf_script(leaf.clone())
                .ok_or_else(|| {
                    Self::bridge_error(format!("named leaf {leaf:?} not found on input {input:?}"))
                })?,
            other => {
                return Err(Self::bridge_error(format!(
                    "cannot apply multisig signatures to non-script input {input:?} with spend spec {other:?}"
                )));
            }
        };

        let multisig = match script_leaf {
            crate::script::ScriptLeaf::Multisig(script) => script,
            _ => {
                return Err(Self::bridge_error(format!(
                    "multisig signatures can only be applied to Multisig script inputs; got {} for input {:?}",
                    script_leaf.kind_name(),
                    input,
                )));
            }
        };

        let sighash_type = self.sighash_type_for_input(input.clone())?;
        let mut slots = vec![None; multisig.pubkeys.len()];

        for (pubkey, signature) in signatures {
            let slot_index = multisig
                .pubkeys
                .iter()
                .position(|pk| *pk == pubkey)
                .ok_or_else(|| {
                    Self::bridge_error(format!(
                        "unknown multisig pubkey {pubkey} for input {input:?}"
                    ))
                })?;

            if slots[slot_index].is_some() {
                return Err(Self::bridge_error(format!(
                    "duplicate multisig signature provided for pubkey {pubkey} on input {input:?}"
                )));
            }

            slots[slot_index] = Some(bitcoin::taproot::Signature {
                signature,
                sighash_type,
            });
        }

        Ok(slots)
    }

    fn prepare_witness_for_input(
        &self,
        input: impl Into<Input>,
        material: WitnessMaterial,
    ) -> Result<PreparedWitness, BridgeError> {
        let input = input.into();
        match material {
            WitnessMaterial::Signature(signature) => {
                self.verify_signature_material_for_input(input.clone(), signature)?;
                match self.spend(input.clone())? {
                    SpendSpec::KeySpend { .. } => Ok(PreparedWitness::KeySpend(
                        self.taproot_signature_for_input(input, signature)?,
                    )),
                    SpendSpec::NamedLeaf { .. } => Ok(PreparedWitness::Script(
                        self.witness_input_for_script_signature(input, signature)?,
                    )),
                    other => Err(Self::bridge_error(format!(
                        "cannot apply signature witness to input {input:?} with spend spec {other:?}"
                    ))),
                }
            }
            WitnessMaterial::WitnessInput(witness_input) => match witness_input {
                WitnessInput::KeySpend(signature) => Ok(PreparedWitness::KeySpend(signature)),
                witness_input => match self.spend(input.clone())? {
                    SpendSpec::RevealRequired { .. } => Err(Self::bridge_error(format!(
                        "RevealRequired input {input:?} needs explicit revealed script material"
                    ))),
                    _ => Ok(PreparedWitness::Script(witness_input)),
                },
            },
            WitnessMaterial::RevealedScript {
                script,
                witness_input,
                spend_info,
            } => Ok(PreparedWitness::RevealedScript {
                script,
                witness_input,
                spend_info,
            }),
            WitnessMaterial::FullWitness(witness) => Ok(PreparedWitness::FullWitness(witness)),
            WitnessMaterial::MultisigSignatures(signatures) => {
                Ok(PreparedWitness::Script(WitnessInput::Multisig(
                    self.taproot_multisig_signatures_for_input(input, signatures)?,
                )))
            }
            WitnessMaterial::PreimageReveal {
                signature,
                preimage,
            } => Ok(PreparedWitness::Script(WitnessInput::PreimageReveal(
                PreimageRevealInput {
                    signature: self.taproot_signature_for_input(input, signature)?,
                    preimage,
                },
            ))),
            WitnessMaterial::WinternitzWitness {
                signature,
                stack_items,
            } => Ok(PreparedWitness::Script(WitnessInput::WinternitzCommit(
                WinternitzCommitInput {
                    signature: self.taproot_signature_for_input(input, signature)?,
                    stack_items,
                },
            ))),
        }
    }

    fn verify_signature_material_for_input(
        &self,
        input: impl Into<Input>,
        signature: bitcoin::secp256k1::schnorr::Signature,
    ) -> Result<(), BridgeError> {
        let input = input.into();
        let pubkey = match self.spend(input.clone())? {
            SpendSpec::KeySpend { .. } => self
                .spendable_for_input(input.clone())?
                .get_spend_info()
                .as_ref()
                .ok_or(TxError::MissingSpendInfo)?
                .output_key()
                .to_x_only_public_key(),
            SpendSpec::NamedLeaf { .. } => self
                .named_leaf_script_for_input(input.clone())?
                .and_then(|script| script.sig_owner_key())
                .ok_or_else(|| {
                    Self::bridge_error(format!(
                        "cannot verify bare signature material for input {input:?}"
                    ))
                })?,
            SpendSpec::RevealRequired { .. } => {
                return Err(Self::bridge_error(format!(
                    "cannot verify bare signature material for RevealRequired input {input:?}"
                )))
            }
        };
        let sighash = self.tap_sighash_for_input(input.clone())?;
        bitcoin::secp256k1::Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(*sighash.as_byte_array()),
                &pubkey,
            )
            .map_err(|_| {
                Self::bridge_error(format!("invalid schnorr signature for input {input:?}"))
            })
    }

    fn witness_input_for_script_signature(
        &self,
        input: impl Into<Input>,
        signature: bitcoin::secp256k1::schnorr::Signature,
    ) -> Result<WitnessInput, BridgeError> {
        let input = input.into();
        let input_index = self.resolve_input_index(&input)?;
        let resolved_input = self.resolved_input_at(input_index)?;
        let script_leaf = match resolved_input.spend() {
            SpendSpec::NamedLeaf { leaf, .. } => resolved_input
                .spendable()
                .get_named_leaf_script(leaf.clone())
                .ok_or_else(|| {
                    Self::bridge_error(format!("named leaf {leaf:?} not found on input {input:?}"))
                })?,
            other => {
                return Err(Self::bridge_error(format!(
                    "cannot derive script witness input for input {input:?} with spend spec {other:?}"
                )));
            }
        };

        let taproot_signature = self.taproot_signature_for_input(input.clone(), signature)?;

        match script_leaf {
            crate::script::ScriptLeaf::CheckSig(_) => Ok(WitnessInput::CheckSig(taproot_signature)),
            crate::script::ScriptLeaf::Timelock(_) => Ok(WitnessInput::Timelock(Some(
                taproot_signature,
            ))),
            crate::script::ScriptLeaf::Multisig(_) => Err(Self::bridge_error(format!(
                "bare signature witness material is not valid for multisig input {input:?}; use multisig_signatures(...)"
            ))),
            crate::script::ScriptLeaf::WinternitzCommit(_) => Err(Self::bridge_error(format!(
                "bare signature witness material is not valid for Winternitz input {input:?}; use winternitz_witness(...)"
            ))),
            crate::script::ScriptLeaf::PreimageReveal(_) => Err(Self::bridge_error(format!(
                "bare signature witness material is not valid for preimage-reveal input {input:?}; use preimage_reveal(...)"
            ))),
            crate::script::ScriptLeaf::BaseDeposit(_) => {
                Ok(WitnessInput::BaseDeposit(taproot_signature))
            }
            crate::script::ScriptLeaf::ReplacementDeposit(_) => {
                Ok(WitnessInput::ReplacementDeposit(taproot_signature))
            }
            crate::script::ScriptLeaf::Other(_) => Err(Self::bridge_error(format!(
                "witness encode unsupported for Other script leaf on input {input:?}"
            ))),
        }
    }

    fn sighash_for_input_index(
        &self,
        input_index: usize,
        sighash_type: bitcoin::TapSighashType,
    ) -> Result<[u8; 32], BridgeError> {
        let prevouts_vec: Vec<&TxOut> = self
            .inputs
            .iter()
            .map(|input| input.spendable().get_prevout())
            .collect();
        let prevouts = match sighash_type {
            bitcoin::TapSighashType::SinglePlusAnyoneCanPay
            | bitcoin::TapSighashType::AllPlusAnyoneCanPay
            | bitcoin::TapSighashType::NonePlusAnyoneCanPay => {
                Prevouts::One(input_index, prevouts_vec[input_index])
            }
            _ => Prevouts::All(&prevouts_vec),
        };

        let mut cache = SighashCache::new(&self.cached_tx);

        let sighash = match self.inputs[input_index].spend() {
            SpendSpec::KeySpend { .. } => cache
                .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
                .map_err(|e| Self::bridge_error(format!("taproot key spend sighash error: {e}")))?,
            SpendSpec::NamedLeaf { leaf, .. } => {
                let script_buf = self.inputs[input_index]
                    .spendable()
                    .get_named_leaf_script(leaf.clone())
                    .ok_or_else(|| {
                        Self::bridge_error(format!(
                            "named leaf {leaf:?} not found on input index {input_index}"
                        ))
                    })?
                    .to_script_buf();

                let leaf_hash =
                    bitcoin::TapLeafHash::from_script(&script_buf, LeafVersion::TapScript);
                cache
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &prevouts,
                        leaf_hash,
                        sighash_type,
                    )
                    .map_err(|e| {
                        Self::bridge_error(format!("taproot script spend sighash error: {e}"))
                    })?
            }
            SpendSpec::RevealRequired { .. } => {
                return Err(Self::bridge_error(format!(
                    "RevealRequired input {input_index} needs an explicitly revealed script to compute its sighash"
                )));
            }
        };

        Ok(sighash.to_byte_array())
    }

    fn apply_witness_input_for_input(
        &mut self,
        input: impl Into<Input>,
        witness_input: WitnessInput,
    ) -> Result<(), BridgeError> {
        let input = input.into();
        match witness_input {
            WitnessInput::KeySpend(sig) => self.apply_keyspend_signature_for_input(input, sig),
            witness_input => {
                let input_index = self.resolve_input_index(&input)?;
                let resolved_input = self.resolved_input_at(input_index)?;
                let leaf = match resolved_input.spend() {
                    SpendSpec::NamedLeaf { leaf, .. } => leaf.clone(),
                    other => {
                        return Err(Self::bridge_error(format!(
                            "cannot apply script witness input {:?} to input {:?} with spend spec {:?}",
                            witness_input.kind_name(),
                            input,
                            other,
                        )));
                    }
                };

                let script_leaf = resolved_input
                    .spendable()
                    .get_named_leaf_script(leaf.clone())
                    .ok_or_else(|| {
                        Self::bridge_error(format!(
                            "named leaf {leaf:?} not found on input {input:?}"
                        ))
                    })?;

                let stack_witness = match witness_input {
                    WitnessInput::RawWitness(items) => Self::witness_from_raw_items(&items),
                    witness_input => script_leaf.encode_witness(&witness_input)?,
                };
                let spend_script = script_leaf.to_script_buf();
                let spend_info = resolved_input
                    .spendable()
                    .get_spend_info()
                    .as_ref()
                    .ok_or(TxError::MissingSpendInfo)?;
                let control_block = spend_info
                    .control_block(&(spend_script.clone(), LeafVersion::TapScript))
                    .ok_or_else(|| {
                        Self::bridge_error(format!(
                            "control block not found for leaf {leaf:?} on input {input:?}"
                        ))
                    })?;
                let mut witness = stack_witness;
                witness.push(spend_script.as_bytes());
                witness.push(control_block.serialize());
                self.set_witness_at_input(input, witness)
            }
        }
    }

    fn apply_revealed_script_witness_for_input(
        &mut self,
        input: impl Into<Input>,
        script: bitcoin::ScriptBuf,
        witness_input: WitnessInput,
        spend_info: &bitcoin::taproot::TaprootSpendInfo,
    ) -> Result<(), BridgeError> {
        let input = input.into();
        let input_index = self.resolve_input_index(&input)?;
        if self.witness_at(input_index)?.is_some() {
            return Err(TxError::WitnessAlreadySet.into());
        }

        match self.spend(input.clone())? {
            SpendSpec::RevealRequired { .. } => {}
            other => {
                return Err(Self::bridge_error(format!(
                    "explicit revealed script witness can only be applied to RevealRequired inputs; input {input:?} has spend spec {other:?}"
                )))
            }
        }

        self.validate_revealed_tap_script_commitment_for_input(
            input.clone(),
            script.as_script(),
            spend_info,
        )?;

        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| {
                Self::bridge_error(format!(
                    "control block not found for revealed script on input {input:?}"
                ))
            })?;

        let stack_witness = match witness_input {
            WitnessInput::KeySpend(_) => {
                return Err(Self::bridge_error(format!(
                    "revealed script witness for input {input:?} cannot use KeySpend input"
                )))
            }
            witness_input => Self::witness_from_revealed_input(&witness_input)?,
        };

        let mut witness = stack_witness;
        witness.push(script.as_bytes());
        witness.push(control_block.serialize());
        self.cached_tx.input[input_index].witness = witness;
        Ok(())
    }

    fn validate_revealed_tap_script_commitment_for_input(
        &self,
        input: impl Into<Input>,
        script: &Script,
        spend_info: &bitcoin::taproot::TaprootSpendInfo,
    ) -> Result<(), BridgeError> {
        let input = input.into();
        let spendable = self.spendable_for_input(input.clone())?;
        let control_block = spend_info
            .control_block(&(script.to_owned(), LeafVersion::TapScript))
            .ok_or_else(|| {
                Self::bridge_error(format!(
                    "control block not found for revealed script on input {input:?}"
                ))
            })?;

        if control_block.leaf_version != LeafVersion::TapScript {
            return Err(Self::bridge_error(format!(
                "revealed script for input {:?} must use tapscript leaf version, got {:?}",
                input, control_block.leaf_version
            )));
        }

        let expected_output_key = spend_info.output_key().to_x_only_public_key();
        let prevout_output_key =
            Self::taproot_output_key_from_script_pubkey(&spendable.get_prevout().script_pubkey)?;
        if prevout_output_key != expected_output_key {
            return Err(Self::bridge_error(format!(
                "stored taproot spend info does not match prevout script_pubkey for input {input:?}"
            )));
        }

        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        if !control_block.verify_taproot_commitment(&secp, expected_output_key, script) {
            return Err(Self::bridge_error(format!(
                "revealed script/control block do not match taproot commitment for input {input:?}"
            )));
        }

        Ok(())
    }

    fn taproot_output_key_from_script_pubkey(
        script_pubkey: &Script,
    ) -> Result<XOnlyPublicKey, BridgeError> {
        if !script_pubkey.is_p2tr() {
            return Err(Self::bridge_error("prevout script_pubkey is not taproot"));
        }
        XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34]).map_err(|err| {
            Self::bridge_error(format!(
                "invalid taproot output key in script_pubkey: {err}"
            ))
        })
    }

    fn witness_from_raw_items(items: &[Vec<u8>]) -> Witness {
        let mut witness = Witness::new();
        for item in items {
            witness.push(item);
        }
        witness
    }

    fn witness_from_revealed_input(witness_input: &WitnessInput) -> Result<Witness, BridgeError> {
        match witness_input {
            WitnessInput::KeySpend(_) => Err(Self::bridge_error(
                "revealed script witness cannot encode a KeySpend input",
            )),
            WitnessInput::RawWitness(items) => Ok(Self::witness_from_raw_items(items)),
            WitnessInput::CheckSig(signature)
            | WitnessInput::BaseDeposit(signature)
            | WitnessInput::ReplacementDeposit(signature) => {
                Ok(Witness::from_slice(&[signature.serialize()]))
            }
            WitnessInput::Timelock(signature) => match signature {
                Some(signature) => Ok(Witness::from_slice(&[signature.serialize()])),
                None => Ok(Witness::new()),
            },
            WitnessInput::Multisig(signatures) => {
                let mut witness = Witness::new();
                for signature in signatures.iter().rev() {
                    match signature {
                        Some(signature) => witness.push(signature.serialize()),
                        None => witness.push([]),
                    }
                }
                Ok(witness)
            }
            WitnessInput::WinternitzCommit(input) => {
                let mut witness = Witness::new();
                witness.push(input.signature.serialize());
                for stack_item in &input.stack_items {
                    witness.push(stack_item);
                }
                Ok(witness)
            }
            WitnessInput::PreimageReveal(input) => {
                let mut witness = Witness::new();
                witness.push(input.signature.serialize());
                witness.push(&input.preimage);
                Ok(witness)
            }
        }
    }
}

/// Fluent builder for constructing a [`TxHandler`].
///
/// Generated code uses the pattern:
/// ```ignore
/// TxHandlerBuilder::<MySpec>::new(MyTx::Escrow)
///     .with_version(Version(3))
///     .add_input(MyInput::Sig, spendable, sequence, spend)
///     .add_output(MyOutput::Main, output)
///     .finalize()
/// ```
pub struct TxHandlerBuilder<Tx, Input, Output, Leaf, Actor> {
    tx_type: Tx,
    version: Version,
    lock_time: bitcoin::absolute::LockTime,
    input_indices: HashMap<Input, usize>,
    inputs: Vec<ResolvedInput<Input, Leaf, Actor>>,
    output_indices: HashMap<Output, usize>,
    outputs: Vec<ResolvedOutput<Output, Leaf>>,
}

impl<Tx, Input, Output, Leaf, Actor> TxHandlerBuilder<Tx, Input, Output, Leaf, Actor>
where
    Input: Clone + Eq + Hash + Debug,
    Output: Clone + Eq + Hash + Debug,
    Leaf: Clone + Debug + PartialEq,
    Actor: Clone + Debug,
{
    /// Start building a new transaction of the given type.
    pub fn new(tx_type: Tx) -> Self {
        TxHandlerBuilder {
            tx_type,
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input_indices: HashMap::new(),
            inputs: Vec::new(),
            output_indices: HashMap::new(),
            outputs: Vec::new(),
        }
    }

    /// Set the transaction version (V2 or V3).
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Set the transaction lock time.
    pub fn with_lock_time(mut self, lock_time: bitcoin::absolute::LockTime) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Add a transaction input.
    pub fn add_input(
        mut self,
        input: impl Into<Input>,
        spendable: SpendableTxIn<Leaf>,
        sequence: Sequence,
        spend: SpendSpec<Leaf, Actor>,
    ) -> Self {
        let input = input.into();
        if cfg!(debug_assertions) {
            debug_validate_spend_for_spendable(&spend, &spendable).unwrap_or_else(|msg| {
                panic!("invalid spend spec for input {input:?} (spend: {spend:?}): {msg}")
            });
        }
        let idx = self.inputs.len();
        self.input_indices.insert(input.clone(), idx);
        self.inputs
            .push(ResolvedInput::new(input, spendable, sequence, spend));
        self
    }

    /// Add a transaction output.
    pub fn add_output(mut self, output: impl Into<Output>, unspent: UnspentTxOut<Leaf>) -> Self {
        let output = output.into();
        let idx = self.outputs.len();
        self.output_indices.insert(output.clone(), idx);
        self.outputs.push(ResolvedOutput::new(output, unspent));
        self
    }

    /// Finalize and return the [`TxHandler`] containing the unsigned transaction.
    pub fn finalize(self) -> TxHandler<Tx, Input, Output, Leaf, Actor> {
        let tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self.inputs.iter().map(ResolvedInput::to_txin).collect(),
            output: self
                .outputs
                .iter()
                .map(|output| output.unspent().txout().clone())
                .collect(),
        };
        let txid = tx.compute_txid();

        TxHandler {
            tx_type: self.tx_type,
            input_indices: self.input_indices,
            output_indices: self.output_indices,
            inputs: self.inputs,
            outputs: self.outputs,
            cached_tx: tx,
            cached_txid: txid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::UnspentTxOut;
    use crate::script::{BatchScripts, ScriptLeaf, ScriptNode, SpendableScript};
    use crate::scripts::{CheckSig, Multisig, TimelockScript};
    use crate::witness::WitnessInput;
    use crate::witness_material::{WitnessMaterial, WitnessMaterialExt};
    use bitcoin::amount::Amount;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::taproot::LeafVersion;
    use bitcoin::{Network, OutPoint};

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    #[allow(dead_code)]
    enum TestActor {
        Nobody,
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    enum TestTx {
        Tx1,
        Tx2,
        Tx3,
        Tx4,
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    enum TestInput {
        Sig0,
        Sig1,
        ScriptSig,
        KeySig,
        NestedBatchSpend,
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    #[allow(dead_code)]
    enum TestLeaf {
        Leaf0,
        Leaf1,
        Leaf2,
        Leaf3,
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    enum TestOutput {
        Out0,
    }

    type TestTxHandler = TxHandler<TestTx, TestInput, TestOutput, TestLeaf, TestActor>;
    type TestTxHandlerBuilder =
        TxHandlerBuilder<TestTx, TestInput, TestOutput, TestLeaf, TestActor>;
    // -- helpers --

    fn xonly(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key bytes");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from_keypair(&keypair).0
    }

    fn spendable_from_output(
        output: &UnspentTxOut<TestLeaf>,
        txid_seed: u8,
        vout: u32,
    ) -> SpendableTxIn<TestLeaf> {
        let named_leaves = if output.named_leaves().is_empty() {
            default_named_leaves(output.scripts())
        } else {
            output.named_leaves().clone()
        };
        SpendableTxIn::new(
            OutPoint::new(
                bitcoin::Txid::from_slice(&[txid_seed; 32]).expect("valid txid bytes"),
                vout,
            ),
            output.txout().clone(),
            output.scripts().clone(),
            named_leaves,
            output.spendinfo().clone(),
        )
    }

    fn default_named_leaves(scripts: &[ScriptNode]) -> Vec<(TestLeaf, ScriptLeaf)> {
        fn flatten(nodes: &[ScriptNode], out: &mut Vec<ScriptLeaf>) {
            for node in nodes {
                match node {
                    ScriptNode::Leaf(leaf) => out.push(leaf.clone()),
                    ScriptNode::Scripts(inner) => flatten(inner, out),
                    ScriptNode::TapNodeHash(_) => {}
                }
            }
        }

        fn leaf_name(index: usize) -> Option<TestLeaf> {
            match index {
                0 => Some(TestLeaf::Leaf0),
                1 => Some(TestLeaf::Leaf1),
                2 => Some(TestLeaf::Leaf2),
                3 => Some(TestLeaf::Leaf3),
                _ => None,
            }
        }

        let mut flattened = Vec::new();
        flatten(scripts, &mut flattened);

        flattened
            .into_iter()
            .enumerate()
            .filter_map(|(index, leaf)| leaf_name(index).map(|name| (name, leaf)))
            .collect()
    }

    fn schnorr_from_seed(seed: u8) -> bitcoin::secp256k1::schnorr::Signature {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key bytes");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let msg = Message::from_digest([seed; 32]);
        secp.sign_schnorr_no_aux_rand(&msg, &keypair)
    }

    fn sign_input_sighash(
        handler: &TestTxHandler,
        input: TestInput,
        seed: u8,
    ) -> bitcoin::secp256k1::schnorr::Signature {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key bytes");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let msg = Message::from_digest(
            handler
                .sighash_for_input(input)
                .expect("sighash should exist"),
        );
        secp.sign_schnorr_no_aux_rand(&msg, &keypair)
    }

    fn input_descriptor(input: TestInput) -> SpendSpec<TestLeaf, TestActor> {
        match input {
            TestInput::Sig0 | TestInput::Sig1 | TestInput::KeySig => {
                SpendSpec::key(TestActor::Nobody, bitcoin::TapSighashType::Default)
            }
            TestInput::ScriptSig => SpendSpec::named_leaf_with(
                TestLeaf::Leaf1,
                TestActor::Nobody,
                bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
            ),
            TestInput::NestedBatchSpend => SpendSpec::named_leaf_with(
                TestLeaf::Leaf3,
                TestActor::Nobody,
                bitcoin::TapSighashType::Default,
            ),
        }
    }

    #[test]
    fn sighash_keyspend_default_matches_direct_cache() {
        let parent0 = UnspentTxOut::from_scripts(
            Amount::from_sat(50_000),
            vec![],
            Some(xonly(2)),
            Network::Regtest,
        );
        let parent1 = UnspentTxOut::from_scripts(
            Amount::from_sat(25_000),
            vec![],
            Some(xonly(3)),
            Network::Regtest,
        );

        let spendable0 = spendable_from_output(&parent0, 10, 0);
        let spendable1 = spendable_from_output(&parent1, 11, 1);

        let handler = TestTxHandlerBuilder::new(TestTx::Tx1)
            .add_input(
                TestInput::Sig0,
                spendable0.clone(),
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                input_descriptor(TestInput::Sig0),
            )
            .add_input(
                TestInput::Sig1,
                spendable1.clone(),
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                input_descriptor(TestInput::Sig1),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let prevouts_vec: Vec<&TxOut> = vec![spendable0.get_prevout(), spendable1.get_prevout()];
        let prevouts = Prevouts::All(&prevouts_vec);
        let mut cache = SighashCache::new(handler.transaction());
        let expected = cache
            .taproot_key_spend_signature_hash(0, &prevouts, bitcoin::TapSighashType::Default)
            .expect("direct key-spend sighash")
            .to_byte_array();

        assert_eq!(
            handler
                .sighash_for_input(TestInput::Sig0)
                .expect("runtime sighash"),
            expected
        );
    }

    #[test]
    fn sighash_scriptspend_single_acp_matches_direct_cache() {
        let script0 = CheckSig::new(xonly(4));
        let script1 = CheckSig::new(xonly(5));
        let parent = UnspentTxOut::from_scripts(
            Amount::from_sat(100_000),
            vec![script0.clone().into(), script1.clone().into()],
            None,
            Network::Regtest,
        );

        let spendable = spendable_from_output(&parent, 12, 0);

        let handler = TestTxHandlerBuilder::new(TestTx::Tx2)
            .add_input(
                TestInput::ScriptSig,
                spendable.clone(),
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                input_descriptor(TestInput::ScriptSig),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let prevouts = Prevouts::One(0, spendable.get_prevout());
        let leaf_hash =
            bitcoin::TapLeafHash::from_script(&script1.to_script_buf(), LeafVersion::TapScript);
        let mut cache = SighashCache::new(handler.transaction());
        let expected = cache
            .taproot_script_spend_signature_hash(
                0,
                &prevouts,
                leaf_hash,
                bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
            )
            .expect("direct script-spend sighash")
            .to_byte_array();

        assert_eq!(
            handler
                .sighash_for_input(TestInput::ScriptSig)
                .expect("runtime sighash"),
            expected
        );
    }

    #[test]
    fn witness_construction_matches_expected_shapes() {
        let secp = Secp256k1::new();
        let signer_sk = SecretKey::from_slice(&[42; 32]).expect("valid secret key bytes");
        let signer_keypair = Keypair::from_secret_key(&secp, &signer_sk);
        let msg = Message::from_digest([9u8; 32]);
        let schnorr_sig = secp.sign_schnorr_no_aux_rand(&msg, &signer_keypair);
        let tr_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: bitcoin::TapSighashType::Default,
        };

        let key_parent = UnspentTxOut::from_scripts(
            Amount::from_sat(30_000),
            vec![],
            Some(xonly(6)),
            Network::Regtest,
        );
        let ignored_leaf = CheckSig::new(xonly(12));
        let script_leaf = CheckSig::new(xonly(7));
        let script_parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![ignored_leaf.into(), script_leaf.clone().into()],
            None,
            Network::Regtest,
        );

        let key_spendable = spendable_from_output(&key_parent, 13, 0);
        let script_spendable = spendable_from_output(&script_parent, 14, 1);

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx3)
            .add_input(
                TestInput::KeySig,
                key_spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                input_descriptor(TestInput::KeySig),
            )
            .add_input(
                TestInput::ScriptSig,
                script_spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                input_descriptor(TestInput::ScriptSig),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(60_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        handler
            .apply_witness_material_entry((
                TestInput::KeySig,
                WitnessMaterial::WitnessInput(WitnessInput::KeySpend(tr_sig)),
            ))
            .expect("set key witness");

        let key_wit: Vec<Vec<u8>> = handler.transaction().input[0]
            .witness
            .iter()
            .map(|e| e.to_vec())
            .collect();
        assert_eq!(key_wit.len(), 1);
        assert_eq!(key_wit[0], tr_sig.to_vec());

        let stack_item = b"stack-item".to_vec();
        handler
            .apply_witness_material_entry((
                TestInput::ScriptSig,
                WitnessMaterial::WitnessInput(WitnessInput::RawWitness(vec![stack_item.clone()])),
            ))
            .expect("set script witness");

        let script = script_leaf.to_script_buf();
        let control_block = script_parent
            .spendinfo()
            .as_ref()
            .expect("spend info")
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("control block for script")
            .serialize();

        let script_wit: Vec<Vec<u8>> = handler.transaction().input[1]
            .witness
            .iter()
            .map(|e| e.to_vec())
            .collect();
        assert_eq!(script_wit.len(), 3);
        assert_eq!(script_wit[0], stack_item);
        assert_eq!(script_wit[1], script.as_bytes());
        assert_eq!(script_wit[2], control_block);
    }

    #[test]
    fn script_signature_material_preserves_non_default_sighash_byte() {
        let ignored_leaf = CheckSig::new(xonly(22));
        let script_leaf = CheckSig::new(xonly(23));
        let script_parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![ignored_leaf.into(), script_leaf.clone().into()],
            None,
            Network::Regtest,
        );
        let script_spendable = spendable_from_output(&script_parent, 24, 0);

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx3)
            .add_input(
                TestInput::ScriptSig,
                script_spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                input_descriptor(TestInput::ScriptSig),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();
        let schnorr_sig = sign_input_sighash(&handler, TestInput::ScriptSig, 23);
        let expected = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
        };

        handler
            .apply_witness_material_entry((
                TestInput::ScriptSig,
                WitnessMaterial::Signature(schnorr_sig),
            ))
            .expect("apply script witness material");

        let witness_items: Vec<Vec<u8>> = handler.transaction().input[0]
            .witness
            .iter()
            .map(|item| item.to_vec())
            .collect();
        assert_eq!(witness_items[0], expected.serialize().to_vec());
    }

    #[test]
    fn raw_witness_input_supports_flattened_nested_batch_index() {
        let outer0 = CheckSig::new(xonly(8));
        let outer1 = CheckSig::new(xonly(9));
        let nested0 = CheckSig::new(xonly(10));
        let nested1 = CheckSig::new(xonly(11));
        let nested_batch = BatchScripts::Scripts(vec![nested0.into(), nested1.clone().into()]);

        let parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![outer0.into(), outer1.into(), nested_batch],
            None,
            Network::Regtest,
        );
        let spendable = spendable_from_output(&parent, 15, 0);

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx4)
            .add_input(
                TestInput::NestedBatchSpend,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                input_descriptor(TestInput::NestedBatchSpend),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let stack_item = b"nested-stack-item".to_vec();
        handler
            .apply_witness_material_entry((
                TestInput::NestedBatchSpend,
                WitnessMaterial::WitnessInput(WitnessInput::RawWitness(vec![stack_item.clone()])),
            ))
            .expect("set nested batch witness by leaf enum");

        let nested_script = nested1.to_script_buf();
        let control_block = parent
            .spendinfo()
            .as_ref()
            .expect("spend info")
            .control_block(&(nested_script.clone(), LeafVersion::TapScript))
            .expect("control block for nested script")
            .serialize();

        let witness: Vec<Vec<u8>> = handler.transaction().input[0]
            .witness
            .iter()
            .map(|item| item.to_vec())
            .collect();
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0], stack_item);
        assert_eq!(witness[1], nested_script.as_bytes());
        assert_eq!(witness[2], control_block);
    }

    #[test]
    fn raw_witness_input_is_appended_to_named_leaf_proof() {
        let script_leaf = CheckSig::new(xonly(44));
        let parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![script_leaf.clone().into()],
            None,
            Network::Regtest,
        );
        let spendable = spendable_from_output(&parent, 45, 0);

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx3)
            .add_input(
                TestInput::ScriptSig,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::named_leaf_with(
                    TestLeaf::Leaf0,
                    TestActor::Nobody,
                    bitcoin::TapSighashType::Default,
                ),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        handler
            .apply_witness_for_input(
                TestInput::ScriptSig,
                WitnessMaterial::WitnessInput(WitnessInput::RawWitness(vec![vec![1], vec![2, 3]])),
            )
            .expect("apply raw witness input");

        let control_block = parent
            .spendinfo()
            .as_ref()
            .expect("spend info")
            .control_block(&(script_leaf.to_script_buf(), LeafVersion::TapScript))
            .expect("control block")
            .serialize();
        let witness: Vec<Vec<u8>> = handler.transaction().input[0]
            .witness
            .iter()
            .map(|item| item.to_vec())
            .collect();

        assert_eq!(witness.len(), 4);
        assert_eq!(witness[0], vec![1]);
        assert_eq!(witness[1], vec![2, 3]);
        assert_eq!(witness[2], script_leaf.to_script_buf().as_bytes());
        assert_eq!(witness[3], control_block);
    }

    #[test]
    fn revealed_script_material_applies_to_reveal_required_input() {
        let script_leaf = CheckSig::new(xonly(46));
        let parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![script_leaf.clone().into()],
            None,
            Network::Regtest,
        );
        let spendable = spendable_from_output(&parent, 47, 0);
        let script = script_leaf.to_script_buf();
        let spend_info = parent.spendinfo().as_ref().expect("spend info").clone();
        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("control block")
            .serialize();

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx3)
            .add_input(
                TestInput::ScriptSig,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::reveal_required().with_metadata(
                    Some(TestActor::Nobody),
                    Some(bitcoin::TapSighashType::Default),
                ),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        handler
            .fill_witness_entry(TestInput::ScriptSig.revealed_script(
                script.clone(),
                WitnessInput::RawWitness(vec![vec![9, 9]]),
                spend_info,
            ))
            .expect("apply explicit revealed script witness");

        let witness: Vec<Vec<u8>> = handler.transaction().input[0]
            .witness
            .iter()
            .map(|item| item.to_vec())
            .collect();

        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0], vec![9, 9]);
        assert_eq!(witness[1], script.as_bytes());
        assert_eq!(witness[2], control_block);
    }

    #[test]
    fn revealed_script_material_rejects_mismatched_commitment() {
        let script_leaf = CheckSig::new(xonly(50));
        let other_leaf = CheckSig::new(xonly(51));
        let sibling_leaf = CheckSig::new(xonly(52));
        let parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![script_leaf.clone().into()],
            None,
            Network::Regtest,
        );
        let other_parent = UnspentTxOut::<TestLeaf>::from_scripts(
            Amount::from_sat(40_000),
            vec![other_leaf.clone().into(), sibling_leaf.into()],
            None,
            Network::Regtest,
        );
        let spendable = spendable_from_output(&parent, 52, 0);
        let mismatched_spend_info = other_parent
            .spendinfo()
            .as_ref()
            .expect("spend info")
            .clone();

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx3)
            .add_input(
                TestInput::ScriptSig,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::reveal_required().with_metadata(
                    Some(TestActor::Nobody),
                    Some(bitcoin::TapSighashType::Default),
                ),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let err = handler
            .fill_witness_entry(TestInput::ScriptSig.revealed_script(
                script_leaf.to_script_buf(),
                WitnessInput::RawWitness(vec![vec![1, 2, 3]]),
                mismatched_spend_info,
            ))
            .expect_err("mismatched control block should fail");

        let message = err.to_string();
        assert!(!message.is_empty());
    }

    #[test]
    fn full_witness_material_sets_input_witness_verbatim() {
        let spendable = spendable_from_output(
            &UnspentTxOut::from_partial(bitcoin::TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }),
            48,
            0,
        );

        let mut witness = Witness::new();
        witness.push([1u8, 2u8]);
        witness.push([3u8, 4u8, 5u8]);

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx1)
            .add_input(
                TestInput::KeySig,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::key_spend(),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        handler
            .apply_witness_for_input(
                TestInput::KeySig,
                WitnessMaterial::FullWitness(witness.clone()),
            )
            .expect("apply full witness material");

        assert_eq!(handler.transaction().input[0].witness, witness);
    }

    #[test]
    fn second_witness_write_is_rejected() {
        let spendable = spendable_from_output(
            &UnspentTxOut::from_partial(bitcoin::TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }),
            49,
            0,
        );

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx1)
            .add_input(
                TestInput::KeySig,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::key_spend(),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let first = bitcoin::taproot::Signature {
            signature: schnorr_from_seed(91),
            sighash_type: bitcoin::TapSighashType::Default,
        };
        let second = bitcoin::taproot::Signature {
            signature: schnorr_from_seed(92),
            sighash_type: bitcoin::TapSighashType::Default,
        };

        handler
            .apply_witness_for_input(
                TestInput::KeySig,
                WitnessMaterial::WitnessInput(WitnessInput::KeySpend(first)),
            )
            .expect("apply first witness");

        let err = handler
            .apply_witness_for_input(
                TestInput::KeySig,
                WitnessMaterial::WitnessInput(WitnessInput::KeySpend(second)),
            )
            .expect_err("second witness write should be rejected");

        assert!(err.to_string().to_ascii_lowercase().contains("witness"));
        assert!(err.to_string().to_ascii_lowercase().contains("already"));
    }

    #[test]
    fn script_spend_descriptor_for_key_only_spendable_is_rejected_during_validation() {
        let key_only_parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![],
            Some(xonly(27)),
            Network::Regtest,
        );
        let spendable = spendable_from_output(&key_only_parent, 28, 0);
        let spend = SpendSpec::named_leaf_with(
            TestLeaf::Leaf0,
            TestActor::Nobody,
            bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
        );

        let err = debug_validate_spend_for_spendable(&spend, &spendable)
            .expect_err("script spend on key-only output should fail during validation");
        assert!(err.contains("named leaf Leaf0 is not available on spendable input"));
    }

    #[test]
    fn reveal_required_descriptor_without_taproot_metadata_is_rejected_during_validation() {
        let spendable: SpendableTxIn<TestLeaf> = SpendableTxIn::new_partial(
            OutPoint::new(
                bitcoin::Txid::from_slice(&[29; 32]).expect("valid txid bytes"),
                0,
            ),
            bitcoin::TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
        );
        let spend = SpendSpec::reveal_required().with_metadata(
            Some(TestActor::Nobody),
            Some(bitcoin::TapSighashType::Default),
        );

        let err = debug_validate_spend_for_spendable(&spend, &spendable)
            .expect_err("RevealRequired without spend info should fail during validation");
        assert!(err.contains("RevealRequired inputs require taproot spend info"));
    }

    #[test]
    fn sighashes_for_owner_skips_reveal_required_inputs() {
        let reveal_parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![CheckSig::new(xonly(61)).into()],
            None,
            Network::Regtest,
        );
        let key_parent = UnspentTxOut::from_scripts(
            Amount::from_sat(30_000),
            vec![],
            Some(xonly(62)),
            Network::Regtest,
        );
        let reveal_spendable = spendable_from_output(&reveal_parent, 63, 0);
        let key_spendable = spendable_from_output(&key_parent, 64, 1);

        let handler = TestTxHandlerBuilder::new(TestTx::Tx3)
            .add_input(
                TestInput::ScriptSig,
                reveal_spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::reveal_required().with_metadata(
                    Some(TestActor::Nobody),
                    Some(bitcoin::TapSighashType::Default),
                ),
            )
            .add_input(
                TestInput::KeySig,
                key_spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::key(TestActor::Nobody, bitcoin::TapSighashType::Default),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(60_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let sighashes = handler
            .sighashes_for_owner(TestActor::Nobody)
            .expect("generic owner sighash collection should succeed");

        assert_eq!(sighashes.len(), 1);
        assert_eq!(sighashes[0].0, TestInput::KeySig);
    }

    #[test]
    fn script_signature_material_uses_leaf_codec_for_keyless_timelock() {
        let schnorr_sig = schnorr_from_seed(31);

        let ignored_leaf = CheckSig::new(xonly(24));
        let script_parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![ignored_leaf.into(), TimelockScript::new(None, 7).into()],
            None,
            Network::Regtest,
        );
        let script_spendable = spendable_from_output(&script_parent, 25, 0);

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx3)
            .add_input(
                TestInput::ScriptSig,
                script_spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                input_descriptor(TestInput::ScriptSig),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let error = handler
            .apply_witness_material_entry((
                TestInput::ScriptSig,
                WitnessMaterial::Signature(schnorr_sig),
            ))
            .expect_err("keyless timelock should reject a bare signature witness");

        assert!(error
            .to_string()
            .contains("cannot verify bare signature material"));
    }

    #[test]
    fn multisig_signature_material_uses_leaf_codec_validation() {
        let secp = Secp256k1::new();
        let signer_sk = SecretKey::from_slice(&[32; 32]).expect("valid secret key bytes");
        let signer_keypair = Keypair::from_secret_key(&secp, &signer_sk);
        let msg = Message::from_digest([13u8; 32]);
        let schnorr_sig = secp.sign_schnorr_no_aux_rand(&msg, &signer_keypair);
        let script_parent = UnspentTxOut::from_scripts(
            Amount::from_sat(40_000),
            vec![CheckSig::new(xonly(25)).into()],
            None,
            Network::Regtest,
        );
        let script_spendable = spendable_from_output(&script_parent, 26, 0);

        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx3)
            .add_input(
                TestInput::ScriptSig,
                script_spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::named_leaf_with(
                    TestLeaf::Leaf0,
                    TestActor::Nobody,
                    bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
                ),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let error = handler
            .apply_witness_material_entry((
                TestInput::ScriptSig,
                WitnessMaterial::MultisigSignatures(vec![(xonly(26), schnorr_sig)]),
            ))
            .expect_err("non-multisig script leaves should reject multisig material");

        assert!(error
            .to_string()
            .contains("can only be applied to Multisig script inputs"));
    }

    #[test]
    fn multisig_signature_material_is_ordered_by_script_pubkeys() {
        let pk0 = xonly(31);
        let pk1 = xonly(32);
        let pk2 = xonly(33);
        let multisig = Multisig::new(vec![pk0, pk1, pk2], 2);
        let parent = UnspentTxOut::from_scripts(
            Amount::from_sat(100_000),
            vec![multisig.into()],
            None,
            Network::Regtest,
        );
        let spendable = spendable_from_output(&parent, 16, 0);
        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx2)
            .add_input(
                TestInput::ScriptSig,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::named_leaf_with(
                    TestLeaf::Leaf0,
                    TestActor::Nobody,
                    bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
                ),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let sig0 = schnorr_from_seed(71);
        let sig2 = schnorr_from_seed(72);
        handler
            .apply_witness_for_input(
                TestInput::ScriptSig,
                WitnessMaterial::MultisigSignatures(vec![(pk2, sig2), (pk0, sig0)]),
            )
            .expect("pubkey-based signatures should map to multisig slots");

        let witness: Vec<Vec<u8>> = handler.transaction().input[0]
            .witness
            .iter()
            .map(|e| e.to_vec())
            .collect();
        let tr_sig0 = bitcoin::taproot::Signature {
            signature: sig0,
            sighash_type: bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
        };
        let tr_sig2 = bitcoin::taproot::Signature {
            signature: sig2,
            sighash_type: bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
        };

        assert_eq!(witness.len(), 5);
        assert_eq!(witness[0], tr_sig2.serialize().to_vec());
        assert_eq!(witness[1], Vec::<u8>::new());
        assert_eq!(witness[2], tr_sig0.serialize().to_vec());
    }

    #[test]
    fn multisig_signature_material_rejects_unknown_pubkey() {
        let multisig = Multisig::new(vec![xonly(41), xonly(42)], 2);
        let parent = UnspentTxOut::from_scripts(
            Amount::from_sat(100_000),
            vec![multisig.into()],
            None,
            Network::Regtest,
        );
        let spendable = spendable_from_output(&parent, 17, 0);
        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx2)
            .add_input(
                TestInput::ScriptSig,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::named_leaf_with(
                    TestLeaf::Leaf0,
                    TestActor::Nobody,
                    bitcoin::TapSighashType::Default,
                ),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let err = handler
            .apply_witness_for_input(
                TestInput::ScriptSig,
                WitnessMaterial::MultisigSignatures(vec![(xonly(99), schnorr_from_seed(73))]),
            )
            .expect_err("unknown pubkey should fail");
        assert!(err.to_string().contains("unknown multisig pubkey"));
    }

    #[test]
    fn multisig_signature_material_rejects_duplicate_pubkey() {
        let pk = xonly(51);
        let multisig = Multisig::new(vec![pk, xonly(52)], 2);
        let parent = UnspentTxOut::from_scripts(
            Amount::from_sat(100_000),
            vec![multisig.into()],
            None,
            Network::Regtest,
        );
        let spendable = spendable_from_output(&parent, 18, 0);
        let mut handler = TestTxHandlerBuilder::new(TestTx::Tx2)
            .add_input(
                TestInput::ScriptSig,
                spendable,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                SpendSpec::named_leaf_with(
                    TestLeaf::Leaf0,
                    TestActor::Nobody,
                    bitcoin::TapSighashType::Default,
                ),
            )
            .add_output(
                TestOutput::Out0,
                UnspentTxOut::from_partial(bitcoin::TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            )
            .finalize();

        let err = handler
            .apply_witness_for_input(
                TestInput::ScriptSig,
                WitnessMaterial::MultisigSignatures(vec![
                    (pk, schnorr_from_seed(74)),
                    (pk, schnorr_from_seed(75)),
                ]),
            )
            .expect_err("duplicate pubkey should fail");
        assert!(err.to_string().contains("duplicate multisig signature"));
    }
}
