use super::challenge::create_watchtower_challenge_txhandler;
use super::{ContractContext, TxHandlerCache};
use crate::actor::{Actor, TweakCache, WinternitzDerivationPath};
use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder;
use crate::builder::transaction::creator::ReimburseDbCache;
use crate::builder::transaction::{DepositData, TransactionType};
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::{BridgeError, TxError};
use crate::operator::Operator;
use crate::rpc::clementine::KickoffId;
use crate::verifier::Verifier;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Transaction, XOnlyPublicKey};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha12Rng;
use secp256k1::rand::seq::SliceRandom;

#[derive(Debug, Clone)]
pub struct TransactionRequestData {
    pub deposit_data: DepositData,
    pub kickoff_id: KickoffId,
}

/// Deterministically generates a set of kickoff indices for an operator to sign.
///
/// This function creates a deterministic seed from the operator's public key, deposit block hash,
/// and deposit outpoint, then uses it to select a subset of kickoff indices.
///
/// Returns a vector of indices that the operator should sign, with the count determined
/// by the protocol parameter `num_signed_kickoffs`.
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
    let context = ContractContext::new_context_for_kickoffs(
        transaction_data.kickoff_id,
        transaction_data.deposit_data.clone(),
        config.protocol_paramset(),
    );

    let txhandlers = builder::transaction::create_txhandlers(
        TransactionType::AllNeededForDeposit,
        context,
        &mut TxHandlerCache::new(),
        &mut ReimburseDbCache::new_for_deposit(
            db.clone(),
            transaction_data.kickoff_id.operator_idx,
            transaction_data.deposit_data.get_deposit_outpoint(),
            config.protocol_paramset(),
        ),
    )
    .await?;

    // signatures saved during deposit
    let deposit_sigs_query = db
        .get_deposit_signatures(
            None,
            transaction_data.deposit_data.get_deposit_outpoint(),
            transaction_data.kickoff_id.operator_idx as usize,
            transaction_data.kickoff_id.round_idx as usize,
            transaction_data.kickoff_id.kickoff_idx as usize,
        )
        .await?;
    let mut signatures = deposit_sigs_query.unwrap_or_default();

    // signatures saved during setup
    let setup_sigs_query = db
        .get_unspent_kickoff_sigs(
            None,
            transaction_data.kickoff_id.operator_idx as usize,
            transaction_data.kickoff_id.round_idx as usize,
        )
        .await?;

    signatures.extend(setup_sigs_query.unwrap_or_default());

    let mut signed_txs = Vec::with_capacity(txhandlers.len());
    let mut tweak_cache = TweakCache::default();

    for (tx_type, mut txhandler) in txhandlers.into_iter() {
        let _ = signer.tx_sign_and_fill_sigs(&mut txhandler, &signatures, Some(&mut tweak_cache));

        if let TransactionType::OperatorChallengeAck(watchtower_idx) = tx_type {
            let path = WinternitzDerivationPath::ChallengeAckHash(
                watchtower_idx as u32,
                transaction_data.deposit_data.get_deposit_outpoint(),
                config.protocol_paramset(),
            );
            let preimage = signer.generate_preimage_from_path(path)?;
            let _ = signer.tx_sign_preimage(&mut txhandler, preimage);
        }

        if let TransactionType::Kickoff = tx_type {
            if let Some(block_hash) = block_hash {
                // need to commit blockhash to start kickoff
                let path = WinternitzDerivationPath::Kickoff(
                    transaction_data.kickoff_id.round_idx,
                    transaction_data.kickoff_id.kickoff_idx,
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
                    "Couldn't sign transaction {:?} in create_and_sign_all_txs: {:?}",
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
    /// Creates and signs the watchtower challenge
    pub async fn create_and_sign_watchtower_challenge(
        &self,
        transaction_data: TransactionRequestData,
        commit_data: &[u8],
    ) -> Result<(TransactionType, Transaction), BridgeError> {
        if commit_data.len() != self.config.protocol_paramset().watchtower_challenge_bytes {
            return Err(TxError::IncorrectWatchtowerChallengeDataLength.into());
        }

        let context = ContractContext::new_context_for_asserts(
            transaction_data.kickoff_id,
            transaction_data.deposit_data.clone(),
            self.config.protocol_paramset(),
            self.signer.clone(),
        );

        let mut txhandlers = builder::transaction::create_txhandlers(
            TransactionType::AllNeededForDeposit,
            context,
            &mut TxHandlerCache::new(),
            &mut ReimburseDbCache::new_for_deposit(
                self.db.clone(),
                transaction_data.kickoff_id.operator_idx,
                transaction_data.deposit_data.get_deposit_outpoint(),
                self.config.protocol_paramset(),
            ),
        )
        .await?;

        let kickoff_txhandler = txhandlers
            .remove(&TransactionType::Kickoff)
            .ok_or(TxError::TxHandlerNotFound(TransactionType::Kickoff))?;

        let watchtower_index = transaction_data
            .deposit_data
            .get_watchtower_index(&self.signer.xonly_public_key)?;

        let mut watchtower_challenge_txhandler = create_watchtower_challenge_txhandler(
            &kickoff_txhandler,
            watchtower_index,
            commit_data,
            self.config.protocol_paramset(),
        )?;

        self.signer
            .tx_sign_and_fill_sigs(&mut watchtower_challenge_txhandler, &[], None)?;

        let checked_txhandler = watchtower_challenge_txhandler.promote()?;

        Ok((
            TransactionType::WatchtowerChallenge(watchtower_index),
            checked_txhandler.get_cached_tx().clone(),
        ))
    }

    /// Creates and signs all the unspent kickoff connector (using the previously saved signatures from operator)
    /// transactions for a single round of an operator
    pub async fn create_and_sign_unspent_kickoff_connector_txs(
        &self,
        round_idx: u32,
        operator_idx: u32,
    ) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
        let context = ContractContext::new_context_for_rounds(
            operator_idx,
            round_idx,
            self.config.protocol_paramset(),
        );

        let txhandlers = builder::transaction::create_txhandlers(
            TransactionType::UnspentKickoff(0),
            context,
            &mut TxHandlerCache::new(),
            &mut ReimburseDbCache::new_for_rounds(
                self.db.clone(),
                operator_idx,
                self.config.protocol_paramset(),
            ),
        )
        .await?;

        // signatures saved during setup
        let unspent_kickoff_sigs = self
            .db
            .get_unspent_kickoff_sigs(None, operator_idx as usize, round_idx as usize)
            .await?
            .ok_or(BridgeError::Error(format!(
                "No unspent kickoff signatures found for operator {} and round {}",
                operator_idx, round_idx
            )))?;

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
    pub async fn create_assert_commitment_txs(
        &self,
        assert_data: TransactionRequestData,
    ) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
        let context = ContractContext::new_context_for_asserts(
            assert_data.kickoff_id,
            assert_data.deposit_data.clone(),
            self.config.protocol_paramset(),
            self.signer.clone(),
        );

        let mut txhandlers = builder::transaction::create_txhandlers(
            TransactionType::MiniAssert(0),
            context,
            &mut TxHandlerCache::new(),
            &mut ReimburseDbCache::new_for_deposit(
                self.db.clone(),
                assert_data.kickoff_id.operator_idx,
                assert_data.deposit_data.get_deposit_outpoint(),
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
                assert_data.deposit_data.get_deposit_outpoint(),
                self.config.protocol_paramset(),
            );
            let dummy_data: Vec<(Vec<u8>, WinternitzDerivationPath)> = derivations
                .iter()
                .map(|derivation| match derivation {
                    WinternitzDerivationPath::BitvmAssert(len, _, _, _, _) => {
                        (vec![0u8; *len as usize / 2], derivation.clone())
                    }
                    _ => unreachable!(),
                })
                .collect();
            self.signer
                .tx_sign_winternitz(&mut mini_assert_txhandler, &dummy_data)?;
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
}
