//! # Transaction Signing Utilities
//!
//! This module provides logic signing the transactions used in the Clementine bridge.

use super::challenge::create_watchtower_challenge_txhandler;
use super::{ContractContext, TxHandlerCache};
use crate::actor::{Actor, TweakCache, WinternitzDerivationPath};
use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder;
use crate::builder::transaction::creator::ReimburseDbCache;
use crate::builder::transaction::TransactionType;
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::KickoffData;
use crate::errors::{BridgeError, TxError};
use crate::operator::{Operator, RoundIndex};
use crate::utils::RbfSigningInfo;
use crate::verifier::Verifier;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Transaction, XOnlyPublicKey};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha12Rng;
use secp256k1::rand::seq::SliceRandom;

/// Data to identify the deposit and kickoff.
#[derive(Debug, Clone)]
pub struct TransactionRequestData {
    pub deposit_outpoint: OutPoint,
    pub kickoff_data: KickoffData,
}

/// Deterministically (given same seed) generates a set of kickoff indices for an operator to sign, using the operator's public key, deposit block hash, and deposit outpoint as the seed.
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
pub async fn create_and_sign_txs(
    db: Database,
    signer: &Actor,
    config: BridgeConfig,
    transaction_data: TransactionRequestData,
    block_hash: Option<[u8; 20]>, //to sign kickoff
) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
    let deposit_data = db
        .get_deposit_data(None, transaction_data.deposit_outpoint)
        .await?
        .ok_or(BridgeError::DepositNotFound(
            transaction_data.deposit_outpoint,
        ))?
        .1;

    let context = ContractContext::new_context_for_kickoff(
        transaction_data.kickoff_data,
        deposit_data.clone(),
        config.protocol_paramset(),
    );

    let txhandlers = builder::transaction::create_txhandlers(
        TransactionType::AllNeededForDeposit,
        context,
        &mut TxHandlerCache::new(),
        &mut ReimburseDbCache::new_for_deposit(
            db.clone(),
            transaction_data.kickoff_data.operator_xonly_pk,
            deposit_data.get_deposit_outpoint(),
            config.protocol_paramset(),
        ),
    )
    .await?;

    // signatures saved during deposit
    let deposit_sigs_query = db
        .get_deposit_signatures(
            None,
            transaction_data.deposit_outpoint,
            transaction_data.kickoff_data.operator_xonly_pk,
            transaction_data.kickoff_data.round_idx,
            transaction_data.kickoff_data.kickoff_idx as usize,
        )
        .await?;
    let mut signatures = deposit_sigs_query.unwrap_or_default();

    // signatures saved during setup
    let setup_sigs_query = db
        .get_unspent_kickoff_sigs(
            None,
            transaction_data.kickoff_data.operator_xonly_pk,
            transaction_data.kickoff_data.round_idx,
        )
        .await?;

    signatures.extend(setup_sigs_query.unwrap_or_default());

    let mut signed_txs = Vec::with_capacity(txhandlers.len());
    let mut tweak_cache = TweakCache::default();

    for (tx_type, mut txhandler) in txhandlers.into_iter() {
        let result =
            signer.tx_sign_and_fill_sigs(&mut txhandler, &signatures, Some(&mut tweak_cache));

        if let TransactionType::OperatorChallengeAck(watchtower_idx) = tx_type {
            let path = WinternitzDerivationPath::ChallengeAckHash(
                watchtower_idx as u32,
                transaction_data.deposit_outpoint,
                config.protocol_paramset(),
            );
            let preimage = signer.generate_preimage_from_path(path)?;
            let _ = signer.tx_sign_preimage(&mut txhandler, preimage);
        }

        if let TransactionType::Kickoff = tx_type {
            if let Some(block_hash) = block_hash {
                // need to commit blockhash to start kickoff
                let path = WinternitzDerivationPath::Kickoff(
                    transaction_data.kickoff_data.round_idx,
                    transaction_data.kickoff_data.kickoff_idx,
                    config.protocol_paramset(),
                );
                signer.tx_sign_winternitz(&mut txhandler, &[(block_hash.to_vec(), path)])?;
            }
            // do not give err if blockhash was not given
        }

        let checked_txhandler = txhandler.promote();

        match checked_txhandler {
            Ok(checked_txhandler) => {
                signed_txs.push((tx_type, checked_txhandler.get_cached_tx().clone()));
            }
            Err(e) => {
                tracing::trace!(
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
    ///     3. RbfSigningInfo: Rbf signing info for the watchtower challenge (for re-signing the transaction after a rbf input is added to the tx)
    pub async fn create_watchtower_challenge(
        &self,
        transaction_data: TransactionRequestData,
        commit_data: &[u8],
    ) -> Result<(TransactionType, Transaction, RbfSigningInfo), BridgeError> {
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

        let context = ContractContext::new_context_with_signer(
            transaction_data.kickoff_data,
            deposit_data.clone(),
            self.config.protocol_paramset(),
            self.signer.clone(),
        );

        let mut txhandlers = builder::transaction::create_txhandlers(
            TransactionType::AllNeededForDeposit,
            context,
            &mut TxHandlerCache::new(),
            &mut ReimburseDbCache::new_for_deposit(
                self.db.clone(),
                transaction_data.kickoff_data.operator_xonly_pk,
                transaction_data.deposit_outpoint,
                self.config.protocol_paramset(),
            ),
        )
        .await?;

        let kickoff_txhandler = txhandlers
            .remove(&TransactionType::Kickoff)
            .ok_or(TxError::TxHandlerNotFound(TransactionType::Kickoff))?;

        let watchtower_index = deposit_data.get_watchtower_index(&self.signer.xonly_public_key)?;

        let watchtower_challenge_txhandler = create_watchtower_challenge_txhandler(
            &kickoff_txhandler,
            watchtower_index,
            commit_data,
            self.config.protocol_paramset(),
        )?;

        let merkle_root = watchtower_challenge_txhandler.get_merkle_root_of_txin(0)?;

        Ok((
            TransactionType::WatchtowerChallenge(watchtower_index),
            watchtower_challenge_txhandler.get_cached_tx().clone(),
            RbfSigningInfo {
                vout: 0,
                tweak_merkle_root: merkle_root,
            },
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
    ///     1. TransactionType: UnspentKickoff(idx) for idx'th kickoff in the round
    ///     2. Transaction: Signed unspent kickoff connector transaction
    pub async fn create_and_sign_unspent_kickoff_connector_txs(
        &self,
        round_idx: RoundIndex,
        operator_xonly_pk: XOnlyPublicKey,
    ) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
        let context = ContractContext::new_context_for_round(
            operator_xonly_pk,
            round_idx,
            self.config.protocol_paramset(),
        );

        let txhandlers = builder::transaction::create_txhandlers(
            TransactionType::UnspentKickoff(0),
            context,
            &mut TxHandlerCache::new(),
            &mut ReimburseDbCache::new_for_rounds(
                self.db.clone(),
                operator_xonly_pk,
                self.config.protocol_paramset(),
            ),
        )
        .await?;

        // signatures saved during setup
        let unspent_kickoff_sigs = self
            .db
            .get_unspent_kickoff_sigs(None, operator_xonly_pk, round_idx)
            .await?
            .ok_or(eyre::eyre!(
                "No unspent kickoff signatures found for operator {:?} and round {:?}",
                operator_xonly_pk,
                round_idx
            ))?;

        let mut signed_txs = Vec::with_capacity(txhandlers.len());
        let mut tweak_cache = TweakCache::default();

        for (tx_type, mut txhandler) in txhandlers.into_iter() {
            if !matches!(tx_type, TransactionType::UnspentKickoff(_)) {
                // do not try to sign unrelated txs
                continue;
            }
            self.signer.tx_sign_and_fill_sigs(
                &mut txhandler,
                &unspent_kickoff_sigs,
                Some(&mut tweak_cache),
            )?;

            let checked_txhandler = txhandler.promote();

            match checked_txhandler {
                Ok(checked_txhandler) => {
                    signed_txs.push((tx_type, checked_txhandler.get_cached_tx().clone()));
                }
                Err(e) => {
                    tracing::trace!(
                        "Couldn't sign transaction {:?} in create_and_sign_unspent_kickoff_connector_txs: {:?}",
                        tx_type,
                        e
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
    ///     1. TransactionType: MiniAssert(idx) for idx'th assert commitment
    ///     2. Transaction: Signed assert commitment transaction
    pub async fn create_assert_commitment_txs(
        &self,
        assert_data: TransactionRequestData,
        commit_data: Vec<Vec<Vec<u8>>>,
    ) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
        let deposit_data = self
            .db
            .get_deposit_data(None, assert_data.deposit_outpoint)
            .await?
            .ok_or(BridgeError::DepositNotFound(assert_data.deposit_outpoint))?
            .1;

        let context = ContractContext::new_context_with_signer(
            assert_data.kickoff_data,
            deposit_data.clone(),
            self.config.protocol_paramset(),
            self.signer.clone(),
        );

        let mut txhandlers = builder::transaction::create_txhandlers(
            TransactionType::MiniAssert(0),
            context,
            &mut TxHandlerCache::new(),
            &mut ReimburseDbCache::new_for_deposit(
                self.db.clone(),
                self.signer.xonly_public_key,
                assert_data.deposit_outpoint,
                self.config.protocol_paramset(),
            ),
        )
        .await?;

        let mut signed_txhandlers = Vec::new();

        for idx in 0..ClementineBitVMPublicKeys::number_of_assert_txs() {
            let mut mini_assert_txhandler = txhandlers
                .remove(&TransactionType::MiniAssert(idx))
                .ok_or(TxError::TxHandlerNotFound(TransactionType::MiniAssert(idx)))?;
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
            self.signer
                .tx_sign_winternitz(&mut mini_assert_txhandler, &winternitz_data)?;
            signed_txhandlers.push(mini_assert_txhandler.promote()?);
        }

        Ok(signed_txhandlers
            .into_iter()
            .map(|txhandler| {
                (
                    txhandler.get_transaction_type(),
                    txhandler.get_cached_tx().clone(),
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
    ///     1. TransactionType: LatestBlockhash
    ///     2. Transaction: Signed latest blockhash transaction
    pub async fn create_latest_blockhash_tx(
        &self,
        assert_data: TransactionRequestData,
        block_hash: BlockHash,
    ) -> Result<(TransactionType, Transaction), BridgeError> {
        let deposit_data = self
            .db
            .get_deposit_data(None, assert_data.deposit_outpoint)
            .await?
            .ok_or(BridgeError::DepositNotFound(assert_data.deposit_outpoint))?
            .1;

        let context = ContractContext::new_context_with_signer(
            assert_data.kickoff_data,
            deposit_data,
            self.config.protocol_paramset(),
            self.signer.clone(),
        );

        let mut txhandlers = builder::transaction::create_txhandlers(
            TransactionType::LatestBlockhash,
            context,
            &mut TxHandlerCache::new(),
            &mut ReimburseDbCache::new_for_deposit(
                self.db.clone(),
                assert_data.kickoff_data.operator_xonly_pk,
                assert_data.deposit_outpoint,
                self.config.protocol_paramset(),
            ),
        )
        .await?;

        let mut latest_blockhash_txhandler =
            txhandlers
                .remove(&TransactionType::LatestBlockhash)
                .ok_or(TxError::TxHandlerNotFound(TransactionType::LatestBlockhash))?;

        // get last 20 bytes of block_hash
        let block_hash = block_hash.to_byte_array();

        #[cfg(test)]
        let mut block_hash = block_hash;

        #[cfg(test)]
        {
            if self.config.test_params.disrupt_latest_block_hash_commit {
                tracing::info!("Disrupting block hash commitment for testing purposes");
                tracing::info!("Original block hash: {:?}", block_hash);
                block_hash[31] ^= 0x01;
            }
        }

        let block_hash_last_20 = block_hash[block_hash.len() - 20..].to_vec();

        tracing::info!(
            "Creating latest blockhash tx with block hash's last 20 bytes: {:?}",
            block_hash_last_20
        );
        self.signer.tx_sign_winternitz(
            &mut latest_blockhash_txhandler,
            &[(
                block_hash_last_20,
                ClementineBitVMPublicKeys::get_latest_blockhash_derivation(
                    assert_data.deposit_outpoint,
                    self.config.protocol_paramset(),
                ),
            )],
        )?;

        let latest_blockhash_txhandler = latest_blockhash_txhandler.promote()?;

        // log the block hash witness
        tracing::info!(
            "Latest blockhash tx created with block hash witness: {:?}",
            latest_blockhash_txhandler.get_cached_tx().input
        );

        Ok((
            latest_blockhash_txhandler.get_transaction_type(),
            latest_blockhash_txhandler.get_cached_tx().to_owned(),
        ))
    }
}
