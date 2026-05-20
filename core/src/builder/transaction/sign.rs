//! # Transaction Signing Utilities
//!
//! This module provides logic signing the transactions used in the Clementine bridge.

use super::{BuildContextView, TxContextLoader, TxHandler};
use crate::actor::{Actor, TweakCache, WinternitzDerivationPath};
use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder;
use crate::builder::transaction::TxCacheExt;
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::database::DatabaseTransaction;
use crate::deposit::KickoffData;
use crate::operator::Operator;
use crate::protocol::create::BatchName;
use crate::protocol::ids::{Input, KickoffIdx, TransactionType};
use crate::protocol::tx::mini_assert::MiniAssertInput;
use crate::rpc::clementine::TaggedSignature;
use crate::utils::Last20Bytes;
use crate::verifier::Verifier;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Transaction, XOnlyPublicKey};
use clementine_errors::{BridgeError, TxError};
use clementine_primitives::BridgeRound;
use eyre::Context;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha12Rng;
use secp256k1::rand::seq::SliceRandom;
use std::sync::Arc;
use tx_builder::script::{ScriptLeaf, SpendableScript};
use tx_builder::scripts::TimelockScript;
use tx_builder::witness::WitnessInput;
use tx_builder::witness_material::{
    insert_witness_material, WitnessMaterialExt, WitnessMaterialMap,
};

fn collect_saved_signature_witness_materials(
    txhandler: &TxHandler,
    signatures: &[TaggedSignature],
) -> Result<WitnessMaterialMap<Input>, BridgeError> {
    let mut materials = WitnessMaterialMap::new();
    let tx_type = txhandler.tx_type();

    for tagged_signature in signatures {
        let Some(saved_tx_type) = tagged_signature
            .tx_id
            .clone()
            .and_then(|id| TransactionType::try_from(id).ok())
        else {
            continue;
        };
        if saved_tx_type != tx_type {
            continue;
        }

        let input_id: Input = tagged_signature
            .input_id
            .clone()
            .ok_or_else(|| eyre::eyre!("Missing input_id on saved signature for {tx_type:?}"))?
            .try_into()
            .wrap_err_with(|| format!("Invalid input_id on saved signature for {tx_type:?}"))?;
        if txhandler.input_has_witness(input_id)? {
            continue;
        }

        let signature =
            bitcoin::secp256k1::schnorr::Signature::from_slice(tagged_signature.signature.as_ref())
                .wrap_err_with(|| {
                    format!(
                        "Failed to parse saved signature bytes for {tx_type:?} input {input_id:?}"
                    )
                })?;

        insert_witness_material(&mut materials, input_id.signature(signature))?;
    }

    Ok(materials)
}

pub(crate) fn apply_schnorr_signatures(
    signer: &Actor,
    txhandler: &mut TxHandler,
    signatures: &[TaggedSignature],
    tweak_cache: Option<&mut TweakCache>,
) -> Result<(), BridgeError> {
    let materials = collect_saved_signature_witness_materials(txhandler, signatures)?;
    txhandler.fill_witnesses(&materials)?;
    signer.sign_schnorr(txhandler, tweak_cache)
}

/// Data to identify the deposit and kickoff.
#[derive(Debug, Clone)]
pub struct TransactionRequestData {
    pub deposit_outpoint: OutPoint,
    pub kickoff_data: KickoffData,
}

/// Deterministically (given same seed) generates a set of kickoff indices for an operator to sign, using the operator's public key, deposit block hash, and deposit outpoint as the seed.
/// To make the output consistent across versions, a fixed rng algorithm (ChaCha12Rng) is used.
///
/// This function creates a deterministic seed from the operator's public key, deposit block hash,
/// and deposit outpoint, then uses it to select a subset of kickoff indices.
/// deposit_blockhash is also included in the seed to ensure the randomness of the selected kickoff indices, otherwise deposit_outpoint
/// can be selected in a way to create hash collisions by the user depositing.
///
/// # Arguments
/// * `paramset` - Protocol parameter set.
/// * `op_xonly_pk` - Operator's x-only public key.
/// * `deposit_blockhash` - Block hash of the block containing the deposit.
/// * `deposit_outpoint` - Outpoint of the deposit.
///
/// # Returns
/// A vector of indices that the operator should sign, with the count determined by the protocol parameter `num_signed_kickoffs`.
pub fn get_kickoff_utxos_to_sign(
    paramset: &'static ProtocolParamset,
    op_xonly_pk: XOnlyPublicKey,
    deposit_blockhash: BlockHash,
    deposit_outpoint: bitcoin::OutPoint,
) -> Vec<usize> {
    let deposit_data = [
        op_xonly_pk.serialize().to_vec(),
        deposit_blockhash.to_byte_array().to_vec(),
        deposit_outpoint.txid.to_byte_array().to_vec(),
        deposit_outpoint.vout.to_le_bytes().to_vec(),
    ]
    .concat();

    let seed = bitcoin::hashes::sha256d::Hash::hash(&deposit_data).to_byte_array();
    let mut rng = ChaCha12Rng::from_seed(seed);

    let mut numbers: Vec<usize> = (0..paramset.num_kickoffs_per_round).collect();
    numbers.shuffle(&mut rng);

    numbers
        .into_iter()
        .take(paramset.num_signed_kickoffs)
        .collect()
}

/// Creates and signs all transaction types that can be signed by the entity.
///
/// This function handles the creation and signing of transactions based on the provided
/// transaction data. It returns a vector of signed transactions with their corresponding types.
///
/// # Note
/// This function should not be used for transaction types that require special handling:
/// - MiniAsserts
/// - WatchtowerChallenge
/// - LatestBlockhash
/// - Disprove
///
/// These transaction types have their own specialized signing flows.
pub(crate) async fn create_and_sign_txs(
    signer: &Actor,
    batch: BatchName,
    config: BridgeConfig,
    db: crate::database::Database,
    ctx: &mut impl BuildContextView,
    block_hash: Option<[u8; 20]>, //to sign kickoff
) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
    let round = ctx.round_idx()?;
    let operator_xonly_pk = ctx.operator_xonly_pk()?;
    let txhandlers = crate::builder::transaction::build_batch(ctx, &batch)?;

    let mut signatures = Vec::new();

    if let Ok(kickoff_data) = ctx.kickoff_data() {
        // signatures saved during deposit
        let deposit_sigs_query = db
            .get_deposit_signatures(
                None,
                ctx.deposit()?.get_deposit_outpoint(),
                operator_xonly_pk,
                round,
                kickoff_data.kickoff_idx as usize,
            )
            .await?;
        signatures.extend(deposit_sigs_query.unwrap_or_default());
    }

    // signatures saved during setup
    let setup_sigs_query = db
        .get_unspent_kickoff_sigs(None, operator_xonly_pk, round)
        .await?;

    signatures.extend(setup_sigs_query.unwrap_or_default());

    let mut signed_txs = Vec::with_capacity(txhandlers.len());
    let mut tweak_cache = TweakCache::default();

    for (tx_type, mut txhandler) in txhandlers.into_iter() {
        apply_schnorr_signatures(signer, &mut txhandler, &signatures, Some(&mut tweak_cache))?;

        if let TransactionType::OperatorChallengeAck(_, _, watchtower_idx) = tx_type {
            let path = WinternitzDerivationPath::ChallengeAckHash(
                watchtower_idx as u32,
                ctx.deposit()?.get_deposit_outpoint(),
                config.protocol_paramset(),
            );
            match signer
                .generate_preimage_from_path(path)
                .and_then(|preimage| signer.sign_preimage(&mut txhandler, preimage))
            {
                Ok(()) => {}
                Err(error) => {
                    tracing::debug!(
                        "Couldn't collect preimage witness materials for transaction {:?} in create_and_sign_txs for round {:?}: {:?}",
                        tx_type,
                        round,
                        error
                    );
                }
            }
        }

        if let TransactionType::Kickoff(_, _) = tx_type {
            if let Some(block_hash) = block_hash {
                let kickoff_data = ctx.kickoff_data()?;
                // need to commit blockhash to start kickoff
                let path = WinternitzDerivationPath::Kickoff(
                    kickoff_data.bridge_round,
                    kickoff_data.kickoff_idx,
                    config.protocol_paramset(),
                );
                signer.sign_winternitz(&mut txhandler, &[(block_hash.to_vec(), path)])?;
            }
            // do not give err if blockhash was not given
        }

        let checked_txhandler = txhandler.ensure_fully_signed();

        match checked_txhandler {
            Ok(checked_txhandler) => {
                signed_txs.push((tx_type, checked_txhandler.transaction().clone()));
            }
            Err(e) => {
                tracing::debug!(
                    "Couldn't sign transaction {:?} in create_and_sign_all_txs: {:?}.
                    This might be normal if the transaction is not needed to be/cannot be signed.",
                    tx_type,
                    e
                );
            }
        }
    }

    Ok(signed_txs)
}

impl<C> Verifier<C>
where
    C: CitreaClientT,
{
    /// Creates and signs the watchtower challenge with the given commit data.
    ///
    /// # Arguments
    /// * `transaction_data` - Data to identify the deposit and kickoff.
    /// * `commit_data` - Commit data for the watchtower challenge.
    ///
    /// # Returns
    /// A tuple of:
    ///     1. TransactionType: WatchtowerChallenge
    ///     2. Transaction: Signed watchtower challenge transaction
    pub async fn create_watchtower_challenge(
        &self,
        transaction_data: TransactionRequestData,
        commit_data: &[u8],
        dbtx: Option<DatabaseTransaction<'_>>,
    ) -> Result<(TransactionType, Transaction), BridgeError> {
        if commit_data.len() != self.config.protocol_paramset().watchtower_challenge_bytes {
            return Err(TxError::IncorrectWatchtowerChallengeDataLength.into());
        }

        let deposit_data = self
            .db
            .get_deposit_data(None, transaction_data.deposit_outpoint)
            .await?
            .ok_or(BridgeError::DepositNotFound(
                transaction_data.deposit_outpoint,
            ))?
            .1;

        let mut loader = TxContextLoader::new(self.db.clone(), dbtx);
        let mut ctx = loader
            .load_kickoff(
                transaction_data.kickoff_data,
                deposit_data.clone(),
                Some(&self.signer),
                self.config.protocol_paramset(),
            )
            .await?;
        let round = transaction_data.kickoff_data.bridge_round.to_round_idx()?;
        let kickoff = KickoffIdx::new(transaction_data.kickoff_data.kickoff_idx as usize);
        let watchtower_index = deposit_data.get_watchtower_index(&self.signer.xonly_public_key)?;
        let mut watchtower_challenge_txhandler =
            crate::builder::transaction::build_watchtower_challenge(
                &mut ctx,
                TransactionType::WatchtowerChallenge(round, kickoff, watchtower_index),
                commit_data.to_vec(),
            )?;

        apply_schnorr_signatures(&self.signer, &mut watchtower_challenge_txhandler, &[], None)?;

        Ok((
            TransactionType::WatchtowerChallenge(round, kickoff, watchtower_index),
            watchtower_challenge_txhandler.transaction().clone(),
        ))
    }

    /// Creates and signs all the unspent kickoff connector (using the previously saved signatures from operator during setup)
    ///  transactions for a single round of an operator.
    ///
    /// # Arguments
    /// * `round_idx` - Index of the round.
    /// * `operator_xonly_pk` - Operator's x-only public key.
    ///
    /// # Returns
    /// A vector of tuples:
    ///     1. TransactionType::UnspentKickoff(round, kickoff)
    ///     2. Transaction: Signed unspent kickoff connector transaction
    pub async fn create_and_sign_unspent_kickoff_connector_txs(
        &self,
        round_idx: BridgeRound,
        operator_xonly_pk: XOnlyPublicKey,
        mut dbtx: Option<DatabaseTransaction<'_>>,
    ) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
        let mut loader = TxContextLoader::new(self.db.clone(), dbtx.as_deref_mut());
        let mut ctx = loader
            .load_round(
                operator_xonly_pk,
                round_idx,
                self.config.protocol_paramset(),
            )
            .await?;
        let typed_round = round_idx.to_round_idx()?;
        let txhandlers = crate::builder::transaction::build_batch(
            &mut ctx,
            &BatchName::UnspentKickoffs { round: typed_round },
        )?;

        // signatures saved during setup
        let unspent_kickoff_sigs = self
            .db
            .get_unspent_kickoff_sigs(dbtx, operator_xonly_pk, round_idx)
            .await?
            .ok_or(eyre::eyre!(
                "No unspent kickoff signatures found for operator {:?} and round {:?}",
                operator_xonly_pk,
                round_idx
            ))?;

        let mut signed_txs = Vec::with_capacity(txhandlers.len());
        let mut tweak_cache = TweakCache::default();

        for (tx_type, mut txhandler) in txhandlers.into_iter() {
            if !matches!(tx_type, TransactionType::UnspentKickoff(_, _)) {
                // do not try to sign unrelated txs
                continue;
            }
            let res = apply_schnorr_signatures(
                &self.signer,
                &mut txhandler,
                &unspent_kickoff_sigs,
                Some(&mut tweak_cache),
            )
                .wrap_err(format!(
                    "Couldn't sign transaction {tx_type:?} in create_and_sign_unspent_kickoff_connector_txs for round {round_idx:?} and operator {operator_xonly_pk:?}",
                ));

            let checked_txhandler = txhandler.ensure_fully_signed();

            match checked_txhandler {
                Ok(checked_txhandler) => {
                    signed_txs.push((tx_type, checked_txhandler.transaction().clone()));
                }
                Err(e) => {
                    tracing::trace!(
                        "Couldn't sign transaction {:?} in create_and_sign_unspent_kickoff_connector_txs: {:?}: {:?}",
                        tx_type,
                        e,
                        res.err()
                    );
                }
            }
        }

        Ok(signed_txs)
    }
}

impl<C> Operator<C>
where
    C: CitreaClientT,
{
    /// Creates and signs all the assert commitment transactions for a single kickoff of an operator.
    ///
    /// # Arguments
    /// * `assert_data` - Data to identify the deposit and kickoff.
    /// * `commit_data` - BitVM assertions for the kickoff, for each assert tx.
    ///
    /// # Returns
    /// A vector of tuples:
    ///     1. TransactionType::MiniAssert(round, kickoff, idx)
    ///     2. Transaction: Signed assert commitment transaction
    pub async fn create_assert_commitment_txs(
        &self,
        assert_data: TransactionRequestData,
        commit_data: Vec<Vec<Vec<u8>>>,
        dbtx: Option<DatabaseTransaction<'_>>,
    ) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
        let deposit_data = self
            .db
            .get_deposit_data(None, assert_data.deposit_outpoint)
            .await?
            .ok_or(BridgeError::DepositNotFound(assert_data.deposit_outpoint))?
            .1;

        let round = assert_data.kickoff_data.bridge_round.to_round_idx()?;
        let kickoff = KickoffIdx::new(assert_data.kickoff_data.kickoff_idx as usize);
        let mut loader = TxContextLoader::new(self.db.clone(), dbtx);
        let mut ctx = loader
            .load_kickoff(
                assert_data.kickoff_data,
                deposit_data.clone(),
                Some(&self.signer),
                self.config.protocol_paramset(),
            )
            .await?;
        let operator_xonly_pk = ctx.operator()?.xonly_pk;
        let mut txhandlers = crate::builder::transaction::build_batch(
            &mut ctx,
            &BatchName::MiniAsserts { round, kickoff },
        )?;
        let assert_scripts = ctx
            .kickoff()?
            .operator_bitvm_keys
            .get_assert_scripts(operator_xonly_pk);

        let mut signed_txhandlers = Vec::new();
        for idx in 0..ClementineBitVMPublicKeys::number_of_assert_txs() {
            let mini_assert_key = TransactionType::MiniAssert(round, kickoff, idx);
            let mut mini_assert_txhandler = txhandlers.take_required(mini_assert_key)?;
            let assert_script = assert_scripts
                .get(idx)
                .ok_or(TxError::IndexOverflow)?
                .clone();
            let derivations = ClementineBitVMPublicKeys::get_assert_derivations(
                idx,
                assert_data.deposit_outpoint,
                self.config.protocol_paramset(),
            );
            // Combine data to be committed with the corresponding bitvm derivation path (needed to regenerate the winternitz secret keys
            // to sign the transaction)
            let winternitz_data: Vec<(Vec<u8>, WinternitzDerivationPath)> = derivations
                .iter()
                .zip(commit_data[idx].iter())
                .map(|(derivation, commit_data)| match derivation {
                    WinternitzDerivationPath::BitvmAssert(_len, _, _, _, _) => {
                        (commit_data.clone(), derivation.clone())
                    }
                    _ => unreachable!(),
                })
                .collect();
            let script = match &assert_script {
                ScriptLeaf::WinternitzCommit(script) => script,
                _other => {
                    return Err(eyre::eyre!(
                        "expected Winternitz assert script for mini assert {idx}, got different script kind"
                    )
                    .into())
                }
            };
            let input_id = MiniAssertInput::Assert;
            let nofn_xonly_pk = ctx.deposit()?.clone().get_nofn_xonly_pk()?;
            let timeout_script = TimelockScript::new(
                Some(nofn_xonly_pk),
                self.config.protocol_paramset().assert_timeout_timelock,
            );
            let (_, spend_info) = builder::address::create_taproot_address(
                &[timeout_script.to_script_buf(), script.to_script_buf()],
                None,
                self.config.protocol_paramset().network,
            );
            let sighash_type = mini_assert_txhandler.sighash_type_for_input(input_id)?;
            let sighash = mini_assert_txhandler.tap_script_sighash_for_input_script(
                input_id,
                script.to_script_buf().as_script(),
                sighash_type,
            )?;
            let winternitz_input = self.signer.build_winternitz_commit_input(
                script,
                sighash,
                sighash_type,
                &winternitz_data,
            )?;
            mini_assert_txhandler.fill_witness_entry(input_id.revealed_script(
                script.to_script_buf(),
                WitnessInput::WinternitzCommit(winternitz_input),
                Arc::new(spend_info),
            ))?;
            signed_txhandlers.push(mini_assert_txhandler.ensure_fully_signed()?);
        }

        Ok(signed_txhandlers
            .into_iter()
            .enumerate()
            .map(|(idx, txhandler)| {
                (
                    TransactionType::MiniAssert(round, kickoff, idx),
                    txhandler.transaction().clone(),
                )
            })
            .collect())
    }

    /// Creates and signs the latest blockhash transaction for a single kickoff of an operator.
    ///
    /// # Arguments
    /// * `assert_data` - Data to identify the deposit and kickoff.
    /// * `block_hash` - Block hash to commit using winternitz signatures.
    ///
    /// # Returns
    /// A tuple of:
    ///     1. TransactionType::LatestBlockhash(round, kickoff)
    ///     2. Transaction: Signed latest blockhash transaction
    pub async fn create_latest_blockhash_tx(
        &self,
        assert_data: TransactionRequestData,
        block_hash: BlockHash,
        dbtx: Option<DatabaseTransaction<'_>>,
    ) -> Result<(TransactionType, Transaction), BridgeError> {
        let deposit_data = self
            .db
            .get_deposit_data(None, assert_data.deposit_outpoint)
            .await?
            .ok_or(BridgeError::DepositNotFound(assert_data.deposit_outpoint))?
            .1;

        let mut loader = TxContextLoader::new(self.db.clone(), dbtx);
        let mut ctx = loader
            .load_kickoff(
                assert_data.kickoff_data,
                deposit_data,
                Some(&self.signer),
                self.config.protocol_paramset(),
            )
            .await?;
        let round = assert_data.kickoff_data.bridge_round.to_round_idx()?;
        let kickoff = KickoffIdx::new(assert_data.kickoff_data.kickoff_idx as usize);
        let mut latest_blockhash_txhandler = crate::builder::transaction::build_tx(
            &mut ctx,
            TransactionType::LatestBlockhash(round, kickoff),
        )?;

        let block_hash: [u8; 32] = {
            let raw = block_hash.to_byte_array();

            #[cfg(test)]
            {
                self.config.test_params.maybe_disrupt_block_hash(raw)
            }

            #[cfg(not(test))]
            {
                raw
            }
        };

        // get last 20 bytes of block_hash
        let block_hash_last_20 = block_hash.last_20_bytes().to_vec();

        tracing::info!(
            "Creating latest blockhash tx with block hash's last 20 bytes: {:?}",
            block_hash_last_20
        );
        self.signer.sign_winternitz(
            &mut latest_blockhash_txhandler,
            &[(
                block_hash_last_20,
                ClementineBitVMPublicKeys::get_latest_blockhash_derivation(
                    assert_data.deposit_outpoint,
                    self.config.protocol_paramset(),
                ),
            )],
        )?;

        let latest_blockhash_txhandler = latest_blockhash_txhandler.ensure_fully_signed()?;

        // log the block hash witness
        tracing::info!(
            "Latest blockhash tx created with block hash witness: {:?}",
            latest_blockhash_txhandler.transaction().input
        );

        Ok((
            TransactionType::LatestBlockhash(round, kickoff),
            latest_blockhash_txhandler.transaction().to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::actor::Actor;
    use crate::builder::address::create_taproot_address;
    use crate::builder::transaction::{self, TxHandlerBuilder};
    use crate::protocol::ids::{Input, Leaf};
    use crate::protocol::spec::SpendSpec;
    use crate::protocol::tx::{
        challenge::ChallengeInput, kickoff::KickoffLeaf, move_to_vault::MoveToVaultOutput,
        reimburse::ReimburseInput,
    };
    use crate::rpc::clementine::{GrpcInputId, TaggedSignature};
    use crate::test::common::create_test_config_with_thread_name;
    use bitcoin::secp256k1::{rand::thread_rng, schnorr, SecretKey};
    use bitcoin::sighash::TapSighashType;
    use bitcoin::{Amount, Network, OutPoint};
    use clementine_utils::sign::TapTweakData;
    use tx_builder::script::ScriptLeaf as RuntimeScriptLeaf;
    use tx_builder::scripts::CheckSig as RuntimeCheckSig;
    use tx_builder::witness_material::WitnessMaterial;

    use super::*;

    fn create_key_spend_tx_handler(actor: &Actor) -> TxHandler {
        let (tap_addr, spend_info) =
            create_taproot_address(&[], Some(actor.xonly_public_key), Network::Regtest);
        let prevtxo = bitcoin::TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: tap_addr.script_pubkey(),
        };

        TxHandlerBuilder::new(TransactionType::MoveToVault)
            .add_input(
                ReimburseInput::ReimburseInKickoff,
                transaction::spendable_txin(
                    OutPoint::default(),
                    prevtxo,
                    vec![],
                    vec![],
                    Some(spend_info),
                ),
                bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                transaction::input_descriptor(SpendSpec::key_spend()),
            )
            .add_output(
                MoveToVaultOutput::DepositInMove,
                transaction::unspent_txout(
                    bitcoin::TxOut {
                        value: Amount::from_sat(999),
                        script_pubkey: actor.address.script_pubkey(),
                    },
                    vec![],
                    vec![],
                    None,
                ),
            )
            .finalize()
    }

    fn create_script_spend_tx_handler(actor: &Actor) -> TxHandler {
        let script = RuntimeScriptLeaf::CheckSig(RuntimeCheckSig::new(actor.xonly_public_key));
        let leaf = Leaf::Kickoff(KickoffLeaf::OperatorImmediate);
        let script_buf = script.to_script_buf();
        let (tap_addr, spend_info) = create_taproot_address(
            &[script_buf],
            Some(actor.xonly_public_key),
            Network::Regtest,
        );

        TxHandlerBuilder::new(TransactionType::MoveToVault)
            .add_input(
                ReimburseInput::ReimburseInKickoff,
                transaction::spendable_txin(
                    OutPoint::default(),
                    bitcoin::TxOut {
                        value: Amount::from_sat(1000),
                        script_pubkey: tap_addr.script_pubkey(),
                    },
                    vec![script.clone().into()],
                    vec![(leaf, script)],
                    Some(spend_info),
                ),
                bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                transaction::input_descriptor(
                    SpendSpec::named_leaf(leaf).with_metadata(None, Some(TapSighashType::Default)),
                ),
            )
            .add_output(
                MoveToVaultOutput::DepositInMove,
                transaction::unspent_txout(
                    bitcoin::TxOut {
                        value: Amount::from_sat(999),
                        script_pubkey: actor.address.script_pubkey(),
                    },
                    vec![],
                    vec![],
                    None,
                ),
            )
            .finalize()
    }

    fn tagged_signature(
        tx_type: &TransactionType,
        input_id: Input,
        signature: schnorr::Signature,
    ) -> TaggedSignature {
        TaggedSignature {
            signature: signature.serialize().to_vec(),
            tx_id: Some(tx_type.clone().into()),
            input_id: Some(GrpcInputId::from(input_id)),
        }
    }

    #[tokio::test]
    /// Checks if get_kickoff_utxos_to_sign returns the same values as before.
    /// This test should never fail, do not make changes to code that changes the result of
    /// get_kickoff_utxos_to_sign, as doing so will invalidate all past deposits.
    async fn test_get_kickoff_utxos_to_sign_consistency() {
        let config = create_test_config_with_thread_name().await;
        let mut paramset = config.protocol_paramset().clone();
        paramset.num_kickoffs_per_round = 2000;
        paramset.num_signed_kickoffs = 20;
        let paramset_ref: &'static ProtocolParamset = Box::leak(Box::new(paramset));
        let op_xonly_pk = XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap();
        let deposit_blockhash =
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let deposit_outpoint = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000:0",
        )
        .unwrap();
        let utxos_to_sign = get_kickoff_utxos_to_sign(
            paramset_ref,
            op_xonly_pk,
            deposit_blockhash,
            deposit_outpoint,
        );
        assert_eq!(utxos_to_sign.len(), 20);
        assert_eq!(
            utxos_to_sign,
            vec![
                1124, 447, 224, 1664, 1673, 1920, 713, 125, 1936, 1150, 1079, 1922, 596, 984, 567,
                1134, 530, 539, 700, 1864
            ]
        );

        // one more test
        let deposit_blockhash =
            BlockHash::from_str("1100000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let utxos_to_sign = get_kickoff_utxos_to_sign(
            paramset_ref,
            op_xonly_pk,
            deposit_blockhash,
            deposit_outpoint,
        );

        assert_eq!(utxos_to_sign.len(), 20);
        assert_eq!(
            utxos_to_sign,
            vec![
                1454, 26, 157, 1900, 451, 1796, 881, 544, 23, 1080, 1112, 1503, 1233, 1583, 1054,
                603, 329, 1635, 213, 1331
            ]
        );
    }

    #[test]
    fn saved_key_spend_signature_is_loaded_for_matching_tx_and_input() {
        let actor = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let mut txhandler = create_key_spend_tx_handler(&actor);
        let input_id = Input::Reimburse(ReimburseInput::ReimburseInKickoff);
        let signature = actor
            .sign_with_tweak_data(
                txhandler
                    .tap_sighash_for_input(input_id)
                    .expect("sighash should exist"),
                TapTweakData::KeyPath(
                    txhandler
                        .merkle_root_for_input(input_id)
                        .expect("key spend merkle root"),
                ),
                None,
            )
            .expect("key spend signature");

        let materials = collect_saved_signature_witness_materials(
            &txhandler,
            &[tagged_signature(&txhandler.tx_type(), input_id, signature)],
        )
        .expect("saved signature should be accepted");

        assert_eq!(
            materials.get(&input_id),
            Some(&WitnessMaterial::Signature(signature))
        );
        txhandler
            .fill_witnesses(&materials)
            .expect("txhandler should verify and apply valid key-spend signature");
    }

    #[test]
    fn saved_script_signature_is_loaded_for_matching_tx_and_input() {
        let actor = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let mut txhandler = create_script_spend_tx_handler(&actor);
        let input_id = Input::Reimburse(ReimburseInput::ReimburseInKickoff);
        let signature = actor
            .sign_with_tweak_data(
                txhandler
                    .tap_sighash_for_input(input_id)
                    .expect("sighash should exist"),
                TapTweakData::ScriptPath,
                None,
            )
            .expect("script signature");

        let materials = collect_saved_signature_witness_materials(
            &txhandler,
            &[tagged_signature(&txhandler.tx_type(), input_id, signature)],
        )
        .expect("saved signature should be accepted");

        assert_eq!(
            materials.get(&input_id),
            Some(&WitnessMaterial::Signature(signature))
        );
        txhandler
            .fill_witnesses(&materials)
            .expect("txhandler should verify and apply valid script signature");
    }

    #[test]
    fn saved_signature_ignores_other_transaction_types() {
        let actor = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let txhandler = create_key_spend_tx_handler(&actor);
        let input_id = Input::Reimburse(ReimburseInput::ReimburseInKickoff);
        let signature = actor
            .sign_with_tweak_data(
                txhandler.tap_sighash_for_input(input_id).expect("sighash"),
                TapTweakData::KeyPath(txhandler.merkle_root_for_input(input_id).expect("merkle")),
                None,
            )
            .expect("signature");

        let materials = collect_saved_signature_witness_materials(
            &txhandler,
            &[tagged_signature(
                &TransactionType::EmergencyStop,
                input_id,
                signature,
            )],
        )
        .expect("other tx ids should be ignored");

        assert!(
            materials.is_empty(),
            "non-matching tx ids should be ignored"
        );
    }

    #[test]
    fn saved_signature_rejects_invalid_signer() {
        let actor = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let foreign = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let mut txhandler = create_key_spend_tx_handler(&actor);
        let input_id = Input::Reimburse(ReimburseInput::ReimburseInKickoff);
        let invalid_signature = foreign
            .sign_with_tweak_data(
                txhandler.tap_sighash_for_input(input_id).expect("sighash"),
                TapTweakData::KeyPath(txhandler.merkle_root_for_input(input_id).expect("merkle")),
                None,
            )
            .expect("signature");

        let error = collect_saved_signature_witness_materials(
            &txhandler,
            &[tagged_signature(
                &txhandler.tx_type(),
                input_id,
                invalid_signature,
            )],
        )
        .and_then(|materials| txhandler.fill_witnesses(&materials))
        .expect_err("invalid signer should be rejected");

        assert!(error.to_string().contains("invalid schnorr signature"));
    }

    #[test]
    fn saved_signature_rejects_wrong_input_for_transaction() {
        let actor = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let txhandler = create_key_spend_tx_handler(&actor);
        let input_id = Input::Reimburse(ReimburseInput::ReimburseInKickoff);
        let signature = actor
            .sign_with_tweak_data(
                txhandler.tap_sighash_for_input(input_id).expect("sighash"),
                TapTweakData::KeyPath(txhandler.merkle_root_for_input(input_id).expect("merkle")),
                None,
            )
            .expect("signature");

        let error = collect_saved_signature_witness_materials(
            &txhandler,
            &[tagged_signature(
                &txhandler.tx_type(),
                Input::Challenge(ChallengeInput::Challenge),
                signature,
            )],
        )
        .expect_err("wrong input id should be rejected");

        assert!(error.to_string().contains("input"));
    }
}
