//! # Transaction Handler Creation Logic
//!
//! This module provides the logic for constructing, caching, and managing transaction handlers (`TxHandler`) for all transaction types in the Clementine bridge.
//!
//! It is responsible for orchestrating the creation of all transaction flows for a given operator, round, and deposit, including collateral, kickoff, challenge, reimbursement, and assertion transactions. It also manages context and database-backed caching to support efficient and correct transaction construction.
//!
//! ## Key Types
//!
//! - [`KickoffWinternitzKeys`] - Helper for managing Winternitz keys for kickoff transactions, to retrieve the correct keys for a given round.
//! - [`ReimburseDbCache`] - Retrieves and caches relevant data from the database for transaction handler creation.
//! - [`ContractContext`] - Holds context for a specific operator, round, and optionally deposit, in short all the information needed to create the relevant transactions.
//! - [`TxHandlerCache`] - Stores and manages cached transaction handlers for efficient flow construction. This is important during the deposit, as the functions create all transactions for a single operator, kickoff utxo, and deposit tuple, which has common transactions between them. (Mainly round tx and move to vault tx)
//!
//! ## Main Functions
//!
//! - [`create_txhandlers`] - Orchestrates the creation of all required transaction handlers for a given context and transaction type.
//! - [`create_round_txhandlers`] - Creates round and ready-to-reimburse transaction handlers for a specific operator and round.
//!

use super::input::UtxoVout;
use super::operator_assert::{
    create_latest_blockhash_timeout_txhandler, create_latest_blockhash_txhandler,
};
use super::{remove_txhandler_from_map, RoundTxInput};
use crate::actor::Actor;
use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder;
use crate::builder::script::{SpendableScript, TimelockScript, WinternitzCommit};
use crate::builder::transaction::operator_reimburse::DisprovePath;
use crate::builder::transaction::{
    create_assert_timeout_txhandlers, create_challenge_timeout_txhandler, create_kickoff_txhandler,
    create_mini_asserts, create_round_txhandler, create_unspent_kickoff_txhandlers, AssertScripts,
    TransactionType, TxHandler,
};
use crate::config::protocol::ProtocolParamset;
use crate::database::{Database, DatabaseTransaction};
use crate::deposit::{DepositData, KickoffData, OperatorData};
use crate::errors::{BridgeError, TxError};
use crate::operator::{PublicHash, RoundIndex};
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{OutPoint, XOnlyPublicKey};
use bitvm::clementine::additional_disprove::{
    create_additional_replacable_disprove_script_with_dummy, replace_placeholders_in_script,
};
use circuits_lib::bridge_circuit::deposit_constant;
use circuits_lib::common::constants::{FIRST_FIVE_OUTPUTS, NUMBER_OF_ASSERT_TXS};
use eyre::Context;
use eyre::OptionExt;
use std::collections::BTreeMap;
use std::sync::Arc;

// helper function to get a txhandler from a hashmap
fn get_txhandler(
    txhandlers: &BTreeMap<TransactionType, TxHandler>,
    tx_type: TransactionType,
) -> Result<&TxHandler, TxError> {
    txhandlers
        .get(&tx_type)
        .ok_or(TxError::TxHandlerNotFound(tx_type))
}

/// Helper struct to get specific kickoff winternitz keys for a sequential collateral tx
#[derive(Debug, Clone)]
pub struct KickoffWinternitzKeys {
    pub keys: Vec<bitvm::signatures::winternitz::PublicKey>,
    num_kickoffs_per_round: usize,
    num_rounds: usize,
}

impl KickoffWinternitzKeys {
    /// Creates a new [`KickoffWinternitzKeys`] with the given keys and number per round.
    pub fn new(
        keys: Vec<bitvm::signatures::winternitz::PublicKey>,
        num_kickoffs_per_round: usize,
        num_rounds: usize,
    ) -> Self {
        Self {
            keys,
            num_kickoffs_per_round,
            num_rounds,
        }
    }

    /// Get the winternitz keys for a specific round tx.
    ///
    /// # Arguments
    /// * `round_idx` - The index of the round.
    ///
    /// # Returns
    /// A slice of Winternitz public keys for the given round.
    pub fn get_keys_for_round(
        &self,
        round_idx: RoundIndex,
    ) -> Result<&[bitvm::signatures::winternitz::PublicKey], TxError> {
        // 0th round is the collateral, there are no keys for the 0th round
        // Additionally there are no keys after num_rounds + 1, +1 is because we need additional round to generate
        // reimbursement connectors of previous round
        if round_idx == RoundIndex::Collateral || round_idx.to_index() > self.num_rounds + 1 {
            return Err(TxError::InvalidRoundIndex(round_idx));
        }
        let start_idx = (round_idx.to_index())
            .checked_sub(1) // 0th round is the collateral, there are no keys for the 0th round
            .ok_or(TxError::IndexOverflow)?
            .checked_mul(self.num_kickoffs_per_round)
            .ok_or(TxError::IndexOverflow)?;
        let end_idx = start_idx
            .checked_add(self.num_kickoffs_per_round)
            .ok_or(TxError::IndexOverflow)?;
        Ok(&self.keys[start_idx..end_idx])
    }
}

/// Struct to retrieve and cache data from DB for creating TxHandlers on demand
/// It can only store information for one deposit and operator pair.
/// It has two context modes, for rounds or for deposits. Deposit context needs additional information, like the deposit outpoint, which is not needed for rounds.
/// Round context can only create transactions that do not depend on the deposit, like the round tx and ready to reimburse tx.
/// Deposit context can create all transactions.
/// Note: This cache is specific to a single operator, for each operator a new cache is needed.
#[derive(Debug)]
pub struct ReimburseDbCache<'a, 'b> {
    pub db: Database,
    pub operator_xonly_pk: XOnlyPublicKey,
    pub deposit_outpoint: Option<bitcoin::OutPoint>,
    pub paramset: &'static ProtocolParamset,
    /// Optional database transaction to use for the cache.
    dbtx: Option<DatabaseTransaction<'a, 'b>>,
    /// winternitz keys to sign the kickoff tx with the blockhash
    kickoff_winternitz_keys: Option<KickoffWinternitzKeys>,
    /// bitvm assert scripts for each assert utxo
    bitvm_assert_addr: Option<Vec<[u8; 32]>>,
    /// bitvm disprove scripts taproot merkle tree root hash
    bitvm_disprove_root_hash: Option<[u8; 32]>,
    /// Public hashes to acknowledge watchtower challenges
    challenge_ack_hashes: Option<Vec<PublicHash>>,
    /// operator data
    operator_data: Option<OperatorData>,
    /// latest blockhash root hash
    latest_blockhash_root_hash: Option<[u8; 32]>,
    /// replaceable additional disprove script
    replaceable_additional_disprove_script: Option<Vec<u8>>,
}

impl<'a, 'b> ReimburseDbCache<'a, 'b> {
    /// Creates a db cache that can be used to create txhandlers for a specific operator and deposit/kickoff
    pub fn new_for_deposit(
        db: Database,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: bitcoin::OutPoint,
        paramset: &'static ProtocolParamset,
        dbtx: Option<DatabaseTransaction<'a, 'b>>,
    ) -> Self {
        Self {
            db,
            operator_xonly_pk,
            deposit_outpoint: Some(deposit_outpoint),
            paramset,
            dbtx,
            kickoff_winternitz_keys: None,
            bitvm_assert_addr: None,
            bitvm_disprove_root_hash: None,
            challenge_ack_hashes: None,
            operator_data: None,
            latest_blockhash_root_hash: None,
            replaceable_additional_disprove_script: None,
        }
    }

    /// Creates a db cache that can be used to create txhandlers for a specific operator and collateral chain
    pub fn new_for_rounds(
        db: Database,
        operator_xonly_pk: XOnlyPublicKey,
        paramset: &'static ProtocolParamset,
        dbtx: Option<DatabaseTransaction<'a, 'b>>,
    ) -> Self {
        Self {
            db,
            operator_xonly_pk,
            deposit_outpoint: None,
            paramset,
            dbtx,
            kickoff_winternitz_keys: None,
            bitvm_assert_addr: None,
            bitvm_disprove_root_hash: None,
            challenge_ack_hashes: None,
            operator_data: None,
            latest_blockhash_root_hash: None,
            replaceable_additional_disprove_script: None,
        }
    }

    /// Creates a db cache from a contract context. This context can possible include a deposit data, for which it will be equivalent to new_for_deposit, otherwise it will be equivalent to new_for_rounds.
    pub fn from_context(
        db: Database,
        context: &ContractContext,
        dbtx: Option<DatabaseTransaction<'a, 'b>>,
    ) -> Self {
        if context.deposit_data.is_some() {
            let deposit_data = context
                .deposit_data
                .as_ref()
                .expect("checked in if statement");
            Self::new_for_deposit(
                db,
                context.operator_xonly_pk,
                deposit_data.get_deposit_outpoint(),
                context.paramset,
                dbtx,
            )
        } else {
            Self::new_for_rounds(db, context.operator_xonly_pk, context.paramset, dbtx)
        }
    }

    pub async fn get_operator_data(&mut self) -> Result<&OperatorData, BridgeError> {
        match self.operator_data {
            Some(ref data) => Ok(data),
            None => {
                self.operator_data = Some(
                    self.db
                        .get_operator(self.dbtx.as_deref_mut(), self.operator_xonly_pk)
                        .await
                        .wrap_err("Failed to get operator data from database")?
                        .ok_or_eyre(format!(
                            "Operator not found for xonly_pk {}",
                            self.operator_xonly_pk
                        ))?,
                );
                Ok(self.operator_data.as_ref().expect("Inserted before"))
            }
        }
    }

    async fn get_bitvm_setup(&mut self, deposit_outpoint: OutPoint) -> Result<(), BridgeError> {
        let (assert_addr, bitvm_hash, latest_blockhash_root_hash) = self
            .db
            .get_bitvm_setup(
                self.dbtx.as_deref_mut(),
                self.operator_xonly_pk,
                deposit_outpoint,
            )
            .await
            .wrap_err("Failed to get bitvm setup in ReimburseDbCache::get_bitvm_setup")?
            .ok_or(TxError::BitvmSetupNotFound(
                self.operator_xonly_pk,
                deposit_outpoint.txid,
            ))?;
        self.bitvm_assert_addr = Some(assert_addr);
        self.bitvm_disprove_root_hash = Some(bitvm_hash);
        self.latest_blockhash_root_hash = Some(latest_blockhash_root_hash);
        Ok(())
    }

    pub async fn get_kickoff_winternitz_keys(
        &mut self,
    ) -> Result<&KickoffWinternitzKeys, BridgeError> {
        match self.kickoff_winternitz_keys {
            Some(ref keys) => Ok(keys),
            None => {
                self.kickoff_winternitz_keys = Some(KickoffWinternitzKeys::new(
                    self.db
                        .get_operator_kickoff_winternitz_public_keys(
                            self.dbtx.as_deref_mut(),
                            self.operator_xonly_pk,
                        )
                        .await
                        .wrap_err("Failed to get kickoff winternitz keys from database")?,
                    self.paramset.num_kickoffs_per_round,
                    self.paramset.num_round_txs,
                ));
                Ok(self
                    .kickoff_winternitz_keys
                    .as_ref()
                    .expect("Inserted before"))
            }
        }
    }

    pub async fn get_bitvm_assert_hash(&mut self) -> Result<&[[u8; 32]], BridgeError> {
        if let Some(deposit_outpoint) = &self.deposit_outpoint {
            match self.bitvm_assert_addr {
                Some(ref addr) => Ok(addr),
                None => {
                    self.get_bitvm_setup(*deposit_outpoint).await?;
                    Ok(self.bitvm_assert_addr.as_ref().expect("Inserted before"))
                }
            }
        } else {
            Err(TxError::InsufficientContext.into())
        }
    }

    pub async fn get_replaceable_additional_disprove_script(
        &mut self,
    ) -> Result<&Vec<u8>, BridgeError> {
        if let Some(ref script) = self.replaceable_additional_disprove_script {
            return Ok(script);
        }

        let deposit_outpoint = self.deposit_outpoint.ok_or(TxError::InsufficientContext)?;

        let bitvm_wpks = self
            .db
            .get_operator_bitvm_keys(
                self.dbtx.as_deref_mut(),
                self.operator_xonly_pk,
                deposit_outpoint,
            )
            .await?;

        let challenge_ack_hashes = self
            .db
            .get_operators_challenge_ack_hashes(
                self.dbtx.as_deref_mut(),
                self.operator_xonly_pk,
                deposit_outpoint,
            )
            .await?
            .ok_or(BridgeError::InvalidChallengeAckHashes)?;

        let bitvm_keys = ClementineBitVMPublicKeys::from_flattened_vec(&bitvm_wpks);

        let script = create_additional_replacable_disprove_script_with_dummy(
            *self.paramset.bridge_circuit_constant()?,
            bitvm_keys.bitvm_pks.0[0].to_vec(),
            bitvm_keys.latest_blockhash_pk.to_vec(),
            bitvm_keys.challenge_sending_watchtowers_pk.to_vec(),
            challenge_ack_hashes,
        );

        self.replaceable_additional_disprove_script = Some(script);
        Ok(self
            .replaceable_additional_disprove_script
            .as_ref()
            .expect("Cached above"))
    }

    pub async fn get_challenge_ack_hashes(&mut self) -> Result<&[PublicHash], BridgeError> {
        if let Some(deposit_outpoint) = &self.deposit_outpoint {
            match self.challenge_ack_hashes {
                Some(ref hashes) => Ok(hashes),
                None => {
                    self.challenge_ack_hashes = Some(
                        self.db
                            .get_operators_challenge_ack_hashes(
                                self.dbtx.as_deref_mut(),
                                self.operator_xonly_pk,
                                *deposit_outpoint,
                            )
                            .await
                            .wrap_err("Failed to get challenge ack hashes from database in ReimburseDbCache")?
                            .ok_or(eyre::eyre!(
                                "Watchtower public hashes not found for operator {0:?} and deposit {1}",
                                self.operator_xonly_pk,
                                deposit_outpoint.txid,
                            ))?,
                    );
                    Ok(self.challenge_ack_hashes.as_ref().expect("Inserted before"))
                }
            }
        } else {
            Err(TxError::InsufficientContext.into())
        }
    }

    pub async fn get_bitvm_disprove_root_hash(&mut self) -> Result<&[u8; 32], BridgeError> {
        if let Some(deposit_outpoint) = &self.deposit_outpoint {
            match self.bitvm_disprove_root_hash {
                Some(ref hash) => Ok(hash),
                None => {
                    self.get_bitvm_setup(*deposit_outpoint).await?;
                    Ok(self
                        .bitvm_disprove_root_hash
                        .as_ref()
                        .expect("Inserted before"))
                }
            }
        } else {
            Err(TxError::InsufficientContext.into())
        }
    }

    pub async fn get_latest_blockhash_root_hash(&mut self) -> Result<&[u8; 32], BridgeError> {
        if let Some(deposit_outpoint) = &self.deposit_outpoint {
            match self.latest_blockhash_root_hash {
                Some(ref hash) => Ok(hash),
                None => {
                    self.get_bitvm_setup(*deposit_outpoint).await?;
                    Ok(self
                        .latest_blockhash_root_hash
                        .as_ref()
                        .expect("Inserted before"))
                }
            }
        } else {
            Err(TxError::InsufficientContext.into())
        }
    }
}

/// Context for a single operator and round, and optionally a single deposit.
/// Data about deposit and kickoff idx is needed to create the deposit-related transactions.
/// For non deposit related transactions, like the round tx and ready to reimburse tx, the round idx is enough.
#[derive(Debug, Clone)]
pub struct ContractContext {
    /// required
    operator_xonly_pk: XOnlyPublicKey,
    round_idx: RoundIndex,
    paramset: &'static ProtocolParamset,
    /// optional (only used for after kickoff)
    kickoff_idx: Option<u32>,
    deposit_data: Option<DepositData>,
    signer: Option<Actor>,
}

impl ContractContext {
    /// Contains all necessary context for creating txhandlers for a specific operator and collateral chain
    pub fn new_context_for_round(
        operator_xonly_pk: XOnlyPublicKey,
        round_idx: RoundIndex,
        paramset: &'static ProtocolParamset,
    ) -> Self {
        Self {
            operator_xonly_pk,
            round_idx,
            paramset,
            kickoff_idx: None,
            deposit_data: None,
            signer: None,
        }
    }

    /// Contains all necessary context for creating txhandlers for a specific operator, kickoff utxo, and a deposit
    pub fn new_context_for_kickoff(
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        paramset: &'static ProtocolParamset,
    ) -> Self {
        Self {
            operator_xonly_pk: kickoff_data.operator_xonly_pk,
            round_idx: kickoff_data.round_idx,
            paramset,
            kickoff_idx: Some(kickoff_data.kickoff_idx),
            deposit_data: Some(deposit_data),
            signer: None,
        }
    }

    /// Contains all necessary context for creating txhandlers for a specific operator, kickoff utxo, and a deposit
    /// Additionally holds signer of an actor that can generate the actual winternitz public keys.
    pub fn new_context_with_signer(
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        paramset: &'static ProtocolParamset,
        signer: Actor,
    ) -> Self {
        Self {
            operator_xonly_pk: kickoff_data.operator_xonly_pk,
            round_idx: kickoff_data.round_idx,
            paramset,
            kickoff_idx: Some(kickoff_data.kickoff_idx),
            deposit_data: Some(deposit_data),
            signer: Some(signer),
        }
    }
}

/// Stores and manages cached transaction handlers for efficient flow construction.
///
/// This cache is used to avoid redundant construction of common transactions (such as round and move-to-vault transactions)
/// when creating all transactions for a single operator, kickoff utxo, and deposit tuple. It is especially important during deposit flows,
/// where many transactions share common intermediates. The cache tracks the previous ready-to-reimburse transaction and a map of saved
/// transaction handlers by type.
/// Note: Why is prev_ready_to_reimburse needed and not just stored in saved_txs? Because saved_txs can include the ReadyToReimburse txhandler for the current round, prev_ready_to_reimburse is specifically from the previous round.
///
/// # Fields
///
/// - `prev_ready_to_reimburse`: Optionally stores the previous round's ready-to-reimburse transaction handler.
/// - `saved_txs`: A map from [`TransactionType`] to [`TxHandler`], storing cached transaction handlers for the current context.
///
/// # Usage
///
/// - Use `store_for_next_kickoff` to cache the current round's main transactions before moving to the next kickoff within the same round.
/// - Use `store_for_next_round` to update the cache when moving to the next round, preserving the necessary state.
/// - Use `get_cached_txs` to retrieve and clear the current cache when constructing new transactions.
/// - Use `get_prev_ready_to_reimburse` to access the previous round's ready-to-reimburse transaction to create the next round's round tx.
pub struct TxHandlerCache {
    pub prev_ready_to_reimburse: Option<TxHandler>,
    pub saved_txs: BTreeMap<TransactionType, TxHandler>,
}

impl Default for TxHandlerCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TxHandlerCache {
    /// Creates a new, empty cache.
    pub fn new() -> Self {
        Self {
            saved_txs: BTreeMap::new(),
            prev_ready_to_reimburse: None,
        }
    }
    /// Stores txhandlers for the next kickoff, caching MoveToVault, Round, and ReadyToReimburse.
    ///
    /// Removes these transaction types from the provided map and stores them in the cache.
    /// This is used to preserve the state between kickoffs within the same round.
    pub fn store_for_next_kickoff(
        &mut self,
        txhandlers: &mut BTreeMap<TransactionType, TxHandler>,
    ) -> Result<(), BridgeError> {
        // can possibly cache next round tx too, as next round has the needed reimburse utxos
        // but need to implement a new TransactionType for that
        for tx_type in [
            TransactionType::MoveToVault,
            TransactionType::Round,
            TransactionType::ReadyToReimburse,
        ]
        .iter()
        {
            let txhandler = txhandlers
                .remove(tx_type)
                .ok_or(TxError::TxHandlerNotFound(*tx_type))?;
            self.saved_txs.insert(*tx_type, txhandler);
        }
        Ok(())
    }
    /// Stores MoveToVault and previous ReadyToReimburse for the next round.
    ///
    /// Moves the MoveToVault and ReadyToReimburse txhandlers from the cache to their respective fields,
    /// clearing the rest of the cache. This is used to preserve the state between rounds.
    pub fn store_for_next_round(&mut self) -> Result<(), BridgeError> {
        let move_to_vault =
            remove_txhandler_from_map(&mut self.saved_txs, TransactionType::MoveToVault)?;
        self.prev_ready_to_reimburse = Some(remove_txhandler_from_map(
            &mut self.saved_txs,
            TransactionType::ReadyToReimburse,
        )?);
        self.saved_txs = BTreeMap::new();
        self.saved_txs
            .insert(move_to_vault.get_transaction_type(), move_to_vault);
        Ok(())
    }
    /// Gets the previous ReadyToReimburse txhandler, if any.
    ///
    /// This is used to chain rounds together, as the output of the previous ready-to-reimburse transaction
    /// is needed as input for the next round's round transaction. Without caching, we would have to create the full collateral chain again.
    pub fn get_prev_ready_to_reimburse(&self) -> Option<&TxHandler> {
        self.prev_ready_to_reimburse.as_ref()
    }
    /// Takes and returns all cached txhandlers, clearing the cache.
    pub fn get_cached_txs(&mut self) -> BTreeMap<TransactionType, TxHandler> {
        std::mem::take(&mut self.saved_txs)
    }
}

/// Creates all required transaction handlers for a given context and transaction type.
///
/// This function builds and caches all necessary transaction handlers for the specified transaction type, operator, round, and deposit context.
/// It handles the full flow of collateral, kickoff, challenge, reimbursement, and assertion transactions, including round management and challenge handling.
/// Function returns early if the needed txhandler is already created.
/// Currently there are 3 kinds of specific transaction types that can be given as parameter that change the logic flow
/// - AllNeededForDeposit: Creates all transactions, including the round tx's and deposit related tx's.
/// - Round related tx's (Round, ReadyToReimburse, UnspentKickoff): Creates only round related tx's and returns early.
/// - MiniAssert and LatestBlockhash: These tx's are created to commit data in their witness using winternitz signatures. To enable signing these transactions, the kickoff transaction (where the input of MiniAssert and LatestBlockhash resides) needs to be created with the full list of scripts in its TxHandler data. This may take some time especially for a deposit where thousands of kickoff tx's are created. That's why if MiniAssert or LatestBlockhash is not requested, these scripts are not created and just the merkle root hash of these scripts is used to create the kickoff tx. But if these tx's are requested, the full list of scripts is needed to create the kickoff tx, to enable signing these transactions with winternitz signatures.
///
/// # Arguments
///
/// * `transaction_type` - The type of transaction(s) to create.
/// * `context` - The contract context (operator, round, deposit, etc).
/// * `txhandler_cache` - Cache for storing/retrieving intermediate txhandlers.
/// * `db_cache` - Database-backed cache for retrieving protocol data.
///
/// # Returns
///
/// A map of [`TransactionType`] to [`TxHandler`] for all constructed transactions, or a [`BridgeError`] if construction fails.
pub async fn create_txhandlers(
    transaction_type: TransactionType,
    context: ContractContext,
    txhandler_cache: &mut TxHandlerCache,
    db_cache: &mut ReimburseDbCache<'_, '_>,
) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
    let paramset = db_cache.paramset;

    let operator_data = db_cache.get_operator_data().await?.clone();
    let kickoff_winternitz_keys = db_cache.get_kickoff_winternitz_keys().await?.clone();

    let ContractContext {
        operator_xonly_pk,
        round_idx,
        ..
    } = context;

    let mut txhandlers = txhandler_cache.get_cached_txs();
    if !txhandlers.contains_key(&TransactionType::Round) {
        // create round tx, ready to reimburse tx, and unspent kickoff txs if not in cache
        let round_txhandlers = create_round_txhandlers(
            paramset,
            round_idx,
            &operator_data,
            &kickoff_winternitz_keys,
            txhandler_cache.get_prev_ready_to_reimburse(),
        )?;
        for round_txhandler in round_txhandlers.into_iter() {
            txhandlers.insert(round_txhandler.get_transaction_type(), round_txhandler);
        }
    }

    if matches!(
        transaction_type,
        TransactionType::Round
            | TransactionType::ReadyToReimburse
            | TransactionType::UnspentKickoff(_)
    ) {
        // return if only one of the collateral tx's were requested
        // do not continue as we might not have the necessary context for the remaining tx's
        return Ok(txhandlers);
    }

    // get the next round txhandler (because reimburse connectors will be in it)
    let next_round_txhandler = create_round_txhandler(
        operator_data.xonly_pk,
        RoundTxInput::Prevout(Box::new(
            get_txhandler(&txhandlers, TransactionType::ReadyToReimburse)?
                .get_spendable_output(UtxoVout::CollateralInReadyToReimburse)?,
        )),
        kickoff_winternitz_keys.get_keys_for_round(round_idx.next_round())?,
        paramset,
    )?;

    let mut deposit_data = context.deposit_data.ok_or(TxError::InsufficientContext)?;
    let kickoff_data = KickoffData {
        operator_xonly_pk,
        round_idx,
        kickoff_idx: context.kickoff_idx.ok_or(TxError::InsufficientContext)?,
    };

    if !txhandlers.contains_key(&TransactionType::MoveToVault) {
        // if not cached create move_txhandler
        let move_txhandler =
            builder::transaction::create_move_to_vault_txhandler(&mut deposit_data, paramset)?;
        txhandlers.insert(move_txhandler.get_transaction_type(), move_txhandler);
    }

    let challenge_ack_hashes = db_cache.get_challenge_ack_hashes().await?.to_vec();

    let num_asserts = ClementineBitVMPublicKeys::number_of_assert_txs();
    let public_hashes = challenge_ack_hashes;

    let move_txid = txhandlers
        .get(&TransactionType::MoveToVault)
        .ok_or(TxError::TxHandlerNotFound(TransactionType::MoveToVault))?
        .get_txid()
        .to_byte_array();

    let round_txid = txhandlers
        .get(&TransactionType::Round)
        .ok_or(TxError::TxHandlerNotFound(TransactionType::Round))?
        .get_txid()
        .to_byte_array();

    let vout = kickoff_data.kickoff_idx + 1; // TODO: Extract directly from round tx - not safe
    let watchtower_challenge_start_idx = (FIRST_FIVE_OUTPUTS + NUMBER_OF_ASSERT_TXS) as u16;
    let secp = Secp256k1::verification_only();

    let nofn_key: XOnlyPublicKey = deposit_data.get_nofn_xonly_pk()?;

    let watchtower_xonly_pk = deposit_data.get_watchtowers();
    let watchtower_pubkeys = watchtower_xonly_pk
        .iter()
        .map(|xonly_pk| {
            let nofn_2week = Arc::new(TimelockScript::new(
                Some(nofn_key),
                paramset.watchtower_challenge_timeout_timelock,
            ));

            let builder = TaprootBuilder::new();
            let tweaked = builder
                .add_leaf(0, nofn_2week.to_script_buf())
                .expect("Valid script leaf")
                .finalize(&secp, *xonly_pk)
                .expect("taproot finalize must succeed");

            tweaked.output_key().serialize()
        })
        .collect::<Vec<_>>();

    let deposit_constant = deposit_constant(
        operator_xonly_pk.serialize(),
        watchtower_challenge_start_idx,
        &watchtower_pubkeys,
        move_txid,
        round_txid,
        vout,
        context.paramset.genesis_chain_state_hash,
    );

    tracing::debug!(
        target: "ci",
        "Create txhandlers - Genesis height: {:?}, operator_xonly_pk: {:?}, move_txid: {:?}, round_txid: {:?}, vout: {:?}, watchtower_challenge_start_idx: {:?}, genesis_chain_state_hash: {:?}, deposit_constant: {:?}",
        context.paramset.genesis_height,
        operator_xonly_pk,
        move_txid,
        round_txid,
        vout,
        watchtower_challenge_start_idx,
        context.paramset.genesis_chain_state_hash,
        deposit_constant.0,
    );

    tracing::debug!(
        "Deposit constant for {:?}: {:?} - deposit outpoint: {:?}",
        operator_xonly_pk,
        deposit_constant.0,
        deposit_data.get_deposit_outpoint(),
    );

    let payout_tx_blockhash_pk = kickoff_winternitz_keys
        .get_keys_for_round(round_idx)?
        .get(kickoff_data.kickoff_idx as usize)
        .ok_or(TxError::IndexOverflow)?
        .clone();

    tracing::debug!(
        target: "ci",
        "Payout tx blockhash pk: {:?}",
        payout_tx_blockhash_pk
    );

    let additional_disprove_script = db_cache
        .get_replaceable_additional_disprove_script()
        .await?
        .clone();

    let additional_disprove_script = replace_placeholders_in_script(
        additional_disprove_script,
        payout_tx_blockhash_pk,
        deposit_constant.0,
    );
    let disprove_root_hash = *db_cache.get_bitvm_disprove_root_hash().await?;
    let latest_blockhash_root_hash = *db_cache.get_latest_blockhash_root_hash().await?;

    let disprove_path = if transaction_type == TransactionType::Disprove {
        let actor = context.signer.clone().ok_or(TxError::InsufficientContext)?;
        let bitvm_pks =
            actor.generate_bitvm_pks_for_deposit(deposit_data.get_deposit_outpoint(), paramset)?;
        let disprove_scripts = bitvm_pks.get_g16_verifier_disprove_scripts()?;
        DisprovePath::Scripts(disprove_scripts)
    } else {
        DisprovePath::HiddenNode(&disprove_root_hash)
    };

    let kickoff_txhandler = if matches!(
        transaction_type,
        TransactionType::LatestBlockhash | TransactionType::MiniAssert(_)
    ) {
        // create scripts if any mini assert tx or latest blockhash tx is specifically requested as it needs
        // the actual scripts to be able to spend
        let actor = context.signer.clone().ok_or(TxError::InsufficientContext)?;

        // deposit_data.deposit_outpoint.txid

        let bitvm_pks =
            actor.generate_bitvm_pks_for_deposit(deposit_data.get_deposit_outpoint(), paramset)?;

        let assert_scripts = bitvm_pks.get_assert_scripts(operator_data.xonly_pk);

        let latest_blockhash_script = Arc::new(WinternitzCommit::new(
            vec![(bitvm_pks.latest_blockhash_pk.to_vec(), 40)],
            operator_data.xonly_pk,
            context.paramset.winternitz_log_d,
        ));

        let kickoff_txhandler = create_kickoff_txhandler(
            kickoff_data,
            get_txhandler(&txhandlers, TransactionType::Round)?,
            get_txhandler(&txhandlers, TransactionType::MoveToVault)?,
            &mut deposit_data,
            operator_data.xonly_pk,
            AssertScripts::AssertSpendableScript(assert_scripts),
            disprove_path,
            additional_disprove_script.clone(),
            AssertScripts::AssertSpendableScript(vec![latest_blockhash_script]),
            &public_hashes,
            paramset,
        )?;

        // Create and insert mini_asserts into return Vec
        let mini_asserts = create_mini_asserts(&kickoff_txhandler, num_asserts, paramset)?;

        for mini_assert in mini_asserts.into_iter() {
            txhandlers.insert(mini_assert.get_transaction_type(), mini_assert);
        }

        let latest_blockhash_txhandler =
            create_latest_blockhash_txhandler(&kickoff_txhandler, paramset)?;
        txhandlers.insert(
            latest_blockhash_txhandler.get_transaction_type(),
            latest_blockhash_txhandler,
        );

        kickoff_txhandler
    } else {
        // use db data for scripts
        create_kickoff_txhandler(
            kickoff_data,
            get_txhandler(&txhandlers, TransactionType::Round)?,
            get_txhandler(&txhandlers, TransactionType::MoveToVault)?,
            &mut deposit_data,
            operator_data.xonly_pk,
            AssertScripts::AssertScriptTapNodeHash(db_cache.get_bitvm_assert_hash().await?),
            disprove_path,
            additional_disprove_script.clone(),
            AssertScripts::AssertScriptTapNodeHash(&[latest_blockhash_root_hash]),
            &public_hashes,
            paramset,
        )?
    };

    txhandlers.insert(kickoff_txhandler.get_transaction_type(), kickoff_txhandler);

    // Creates the challenge_tx handler.
    let challenge_txhandler = builder::transaction::create_challenge_txhandler(
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        &operator_data.reimburse_addr,
        context.signer.map(|s| s.get_evm_address()).transpose()?,
        paramset,
    )?;
    txhandlers.insert(
        challenge_txhandler.get_transaction_type(),
        challenge_txhandler,
    );

    // Creates the challenge timeout txhandler
    let challenge_timeout_txhandler = create_challenge_timeout_txhandler(
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        paramset,
    )?;

    txhandlers.insert(
        challenge_timeout_txhandler.get_transaction_type(),
        challenge_timeout_txhandler,
    );

    let kickoff_not_finalized_txhandler =
        builder::transaction::create_kickoff_not_finalized_txhandler(
            get_txhandler(&txhandlers, TransactionType::Kickoff)?,
            get_txhandler(&txhandlers, TransactionType::ReadyToReimburse)?,
            paramset,
        )?;
    txhandlers.insert(
        kickoff_not_finalized_txhandler.get_transaction_type(),
        kickoff_not_finalized_txhandler,
    );

    let latest_blockhash_timeout_txhandler = create_latest_blockhash_timeout_txhandler(
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        get_txhandler(&txhandlers, TransactionType::Round)?,
        paramset,
    )?;
    txhandlers.insert(
        latest_blockhash_timeout_txhandler.get_transaction_type(),
        latest_blockhash_timeout_txhandler,
    );

    // create watchtower tx's except WatchtowerChallenges
    for watchtower_idx in 0..deposit_data.get_num_watchtowers() {
        // Each watchtower will sign their Groth16 proof of the header chain circuit. Then, the operator will either
        // - acknowledge the challenge by sending the operator_challenge_ACK_tx, otherwise their burn connector
        // will get burned by operator_challenge_nack
        let watchtower_challenge_timeout_txhandler =
            builder::transaction::create_watchtower_challenge_timeout_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                watchtower_idx,
                paramset,
            )?;
        txhandlers.insert(
            watchtower_challenge_timeout_txhandler.get_transaction_type(),
            watchtower_challenge_timeout_txhandler,
        );

        let operator_challenge_nack_txhandler =
            builder::transaction::create_operator_challenge_nack_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                watchtower_idx,
                get_txhandler(&txhandlers, TransactionType::Round)?,
                paramset,
            )?;
        txhandlers.insert(
            operator_challenge_nack_txhandler.get_transaction_type(),
            operator_challenge_nack_txhandler,
        );

        let operator_challenge_ack_txhandler =
            builder::transaction::create_operator_challenge_ack_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                watchtower_idx,
                paramset,
            )?;
        txhandlers.insert(
            operator_challenge_ack_txhandler.get_transaction_type(),
            operator_challenge_ack_txhandler,
        );
    }

    if let TransactionType::WatchtowerChallenge(_) = transaction_type {
        return Err(eyre::eyre!(
            "Can't directly create a watchtower challenge in create_txhandlers as it needs commit data".to_string(),
        ).into());
    }

    let assert_timeouts = create_assert_timeout_txhandlers(
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        get_txhandler(&txhandlers, TransactionType::Round)?,
        num_asserts,
        paramset,
    )?;

    for assert_timeout in assert_timeouts.into_iter() {
        txhandlers.insert(assert_timeout.get_transaction_type(), assert_timeout);
    }

    // Creates the disprove_timeout_tx handler.
    let disprove_timeout_txhandler = builder::transaction::create_disprove_timeout_txhandler(
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        paramset,
    )?;

    txhandlers.insert(
        disprove_timeout_txhandler.get_transaction_type(),
        disprove_timeout_txhandler,
    );

    // Creates the reimburse_tx handler.
    let reimburse_txhandler = builder::transaction::create_reimburse_txhandler(
        get_txhandler(&txhandlers, TransactionType::MoveToVault)?,
        &next_round_txhandler,
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        kickoff_data.kickoff_idx as usize,
        paramset,
        &operator_data.reimburse_addr,
    )?;

    txhandlers.insert(
        reimburse_txhandler.get_transaction_type(),
        reimburse_txhandler,
    );

    match transaction_type {
        TransactionType::AllNeededForDeposit | TransactionType::Disprove => {
            let disprove_txhandler = builder::transaction::create_disprove_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                get_txhandler(&txhandlers, TransactionType::Round)?,
            )?;

            txhandlers.insert(
                disprove_txhandler.get_transaction_type(),
                disprove_txhandler,
            );
        }
        _ => {}
    }

    Ok(txhandlers)
}

/// Creates the round and ready-to-reimburse txhandlers for a specific operator and round index.
/// These transactions currently include round tx, ready to reimburse tx, and unspent kickoff txs.
///
/// # Arguments
///
/// * `paramset` - Protocol parameter set.
/// * `round_idx` - The index of the round.
/// * `operator_data` - Data for the operator.
/// * `kickoff_winternitz_keys` - All winternitz keys of the operator.
/// * `prev_ready_to_reimburse` - Previous ready-to-reimburse txhandler, if any, to not create the full collateral chain if we already have the previous round's ready to reimburse txhandler.
///
/// # Returns
///
/// A vector of [`TxHandler`] for the round, ready-to-reimburse, and unspent kickoff transactions, or a [`BridgeError`] if construction fails.
pub fn create_round_txhandlers(
    paramset: &'static ProtocolParamset,
    round_idx: RoundIndex,
    operator_data: &OperatorData,
    kickoff_winternitz_keys: &KickoffWinternitzKeys,
    prev_ready_to_reimburse: Option<&TxHandler>,
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::with_capacity(2 + paramset.num_kickoffs_per_round);

    let (round_txhandler, ready_to_reimburse_txhandler) = match prev_ready_to_reimburse {
        Some(prev_ready_to_reimburse_txhandler) => {
            if round_idx == RoundIndex::Collateral || round_idx == RoundIndex::Round(0) {
                return Err(
                    eyre::eyre!("Round 0 cannot be created from prev_ready_to_reimburse").into(),
                );
            }
            let round_txhandler = builder::transaction::create_round_txhandler(
                operator_data.xonly_pk,
                RoundTxInput::Prevout(Box::new(
                    prev_ready_to_reimburse_txhandler
                        .get_spendable_output(UtxoVout::CollateralInReadyToReimburse)?,
                )),
                kickoff_winternitz_keys.get_keys_for_round(round_idx)?,
                paramset,
            )?;

            let ready_to_reimburse_txhandler =
                builder::transaction::create_ready_to_reimburse_txhandler(
                    &round_txhandler,
                    operator_data.xonly_pk,
                    paramset,
                )?;
            (round_txhandler, ready_to_reimburse_txhandler)
        }
        None => {
            // create nth sequential collateral tx and reimburse generator tx for the operator
            builder::transaction::create_round_nth_txhandler(
                operator_data.xonly_pk,
                operator_data.collateral_funding_outpoint,
                paramset.collateral_funding_amount,
                round_idx,
                kickoff_winternitz_keys,
                paramset,
            )?
        }
    };

    let unspent_kickoffs = create_unspent_kickoff_txhandlers(
        &round_txhandler,
        &ready_to_reimburse_txhandler,
        paramset,
    )?;

    txhandlers.push(round_txhandler);
    txhandlers.push(ready_to_reimburse_txhandler);

    for unspent_kickoff in unspent_kickoffs.into_iter() {
        txhandlers.push(unspent_kickoff);
    }

    Ok(txhandlers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitvm_client::ClementineBitVMPublicKeys;
    use crate::builder::transaction::sign::get_kickoff_utxos_to_sign;
    use crate::builder::transaction::{TransactionType, TxHandlerBuilder};
    use crate::config::BridgeConfig;
    use crate::deposit::{DepositInfo, KickoffData};
    use crate::rpc::clementine::{SignedTxsWithType, TransactionRequest};
    use crate::test::common::citrea::MockCitreaClient;
    use crate::test::common::test_actors::TestActors;
    use crate::test::common::*;
    use bitcoin::{BlockHash, Transaction, XOnlyPublicKey};
    use futures::future::try_join_all;
    use std::collections::HashMap;
    use tokio::sync::mpsc;

    fn signed_txs_to_txid(signed_txs: SignedTxsWithType) -> Vec<(TransactionType, bitcoin::Txid)> {
        signed_txs
            .signed_txs
            .into_iter()
            .map(|signed_tx| {
                (
                    signed_tx.transaction_type.unwrap().try_into().unwrap(),
                    bitcoin::consensus::deserialize::<Transaction>(&signed_tx.raw_tx)
                        .unwrap()
                        .compute_txid(),
                )
            })
            .collect()
    }

    /// This test first creates a vec of transaction types the entity should be able to sign.
    /// Afterwards it calls internal_create_signed_txs for verifiers and operators,
    /// internal_create_assert_commitment_txs for operators, and internal_create_watchtower_challenge for verifiers
    /// and checks if all transaction types that should be signed are returned from these functions.
    /// If a transaction type is not found, it means the entity is not able to sign it.
    async fn check_if_signable(
        actors: TestActors<MockCitreaClient>,
        deposit_info: DepositInfo,
        deposit_blockhash: BlockHash,
        config: BridgeConfig,
    ) {
        let paramset = config.protocol_paramset();
        let deposit_outpoint = deposit_info.deposit_outpoint;

        let mut txs_operator_can_sign = vec![
            TransactionType::Round,
            TransactionType::ReadyToReimburse,
            TransactionType::Kickoff,
            TransactionType::KickoffNotFinalized,
            TransactionType::Challenge,
            //TransactionType::Disprove, TODO: add when we add actual disprove scripts
            TransactionType::DisproveTimeout,
            TransactionType::Reimburse,
            TransactionType::ChallengeTimeout,
            TransactionType::LatestBlockhashTimeout,
        ];
        txs_operator_can_sign
            .extend((0..actors.get_num_verifiers()).map(TransactionType::OperatorChallengeNack));
        txs_operator_can_sign
            .extend((0..actors.get_num_verifiers()).map(TransactionType::OperatorChallengeAck));
        txs_operator_can_sign.extend(
            (0..ClementineBitVMPublicKeys::number_of_assert_txs())
                .map(TransactionType::AssertTimeout),
        );
        txs_operator_can_sign
            .extend((0..paramset.num_kickoffs_per_round).map(TransactionType::UnspentKickoff));
        txs_operator_can_sign.extend(
            (0..actors.get_num_verifiers()).map(TransactionType::WatchtowerChallengeTimeout),
        );

        let operator_xonly_pks: Vec<XOnlyPublicKey> = actors.get_operators_xonly_pks();
        let mut utxo_idxs: Vec<Vec<usize>> = Vec::with_capacity(operator_xonly_pks.len());

        for op_xonly_pk in &operator_xonly_pks {
            utxo_idxs.push(get_kickoff_utxos_to_sign(
                config.protocol_paramset(),
                *op_xonly_pk,
                deposit_blockhash,
                deposit_outpoint,
            ));
        }

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut created_txs: HashMap<(KickoffData, TransactionType), Vec<bitcoin::Txid>> =
            HashMap::new();

        // try to sign everything for all operators
        let operator_task_handles: Vec<_> = actors
            .get_operators()
            .iter_mut()
            .enumerate()
            .map(|(operator_idx, operator_rpc)| {
                let txs_operator_can_sign = txs_operator_can_sign.clone();
                let mut operator_rpc = operator_rpc.clone();
                let utxo_idxs = utxo_idxs.clone();
                let tx = tx.clone();
                let operator_xonly_pk = operator_xonly_pks[operator_idx];
                async move {
                    for round_idx in RoundIndex::iter_rounds(paramset.num_round_txs) {
                        for &kickoff_idx in &utxo_idxs[operator_idx] {
                            let kickoff_data = KickoffData {
                                operator_xonly_pk,
                                round_idx,
                                kickoff_idx: kickoff_idx as u32,
                            };
                            let start_time = std::time::Instant::now();
                            let raw_txs = operator_rpc
                                .internal_create_signed_txs(TransactionRequest {
                                    deposit_outpoint: Some(deposit_outpoint.into()),
                                    kickoff_id: Some(kickoff_data.into()),
                                })
                                .await
                                .unwrap()
                                .into_inner();
                            // test if all needed tx's are signed
                            for tx_type in &txs_operator_can_sign {
                                assert!(
                                    raw_txs
                                        .signed_txs
                                        .iter()
                                        .any(|signed_tx| signed_tx.transaction_type
                                            == Some((*tx_type).into())),
                                    "Tx type: {:?} not found in signed txs for operator",
                                    tx_type
                                );
                            }
                            tracing::info!(
                                "Operator signed txs {:?} from rpc call in time {:?}",
                                TransactionType::AllNeededForDeposit,
                                start_time.elapsed()
                            );
                            tx.send((kickoff_data, signed_txs_to_txid(raw_txs)))
                                .unwrap();
                            let raw_assert_txs = operator_rpc
                                .internal_create_assert_commitment_txs(TransactionRequest {
                                    deposit_outpoint: Some(deposit_outpoint.into()),
                                    kickoff_id: Some(kickoff_data.into()),
                                })
                                .await
                                .unwrap()
                                .into_inner();
                            tracing::info!(
                                "Operator Signed Assert txs of size: {}",
                                raw_assert_txs.signed_txs.len()
                            );
                            tx.send((kickoff_data, signed_txs_to_txid(raw_assert_txs)))
                                .unwrap();
                        }
                    }
                }
            })
            .map(tokio::task::spawn)
            .collect();

        let mut txs_verifier_can_sign = vec![
            TransactionType::Challenge,
            TransactionType::KickoffNotFinalized,
            TransactionType::LatestBlockhashTimeout,
            //TransactionType::Disprove,
        ];
        txs_verifier_can_sign
            .extend((0..actors.get_num_verifiers()).map(TransactionType::OperatorChallengeNack));
        txs_verifier_can_sign.extend(
            (0..ClementineBitVMPublicKeys::number_of_assert_txs())
                .map(TransactionType::AssertTimeout),
        );
        txs_verifier_can_sign
            .extend((0..paramset.num_kickoffs_per_round).map(TransactionType::UnspentKickoff));
        txs_verifier_can_sign.extend(
            (0..actors.get_num_verifiers()).map(TransactionType::WatchtowerChallengeTimeout),
        );

        // try to sign everything for all verifiers
        // try signing verifier transactions
        let verifier_task_handles: Vec<_> = actors
            .get_verifiers()
            .iter_mut()
            .map(|verifier_rpc| {
                let txs_verifier_can_sign = txs_verifier_can_sign.clone();
                let mut verifier_rpc = verifier_rpc.clone();
                let utxo_idxs = utxo_idxs.clone();
                let tx = tx.clone();
                let operator_xonly_pks = operator_xonly_pks.clone();
                async move {
                    for (operator_idx, utxo_idx) in utxo_idxs.iter().enumerate() {
                        for round_idx in RoundIndex::iter_rounds(paramset.num_round_txs) {
                            for &kickoff_idx in utxo_idx {
                                let kickoff_data = KickoffData {
                                    operator_xonly_pk: operator_xonly_pks[operator_idx],
                                    round_idx,
                                    kickoff_idx: kickoff_idx as u32,
                                };
                                let start_time = std::time::Instant::now();
                                let raw_txs = verifier_rpc
                                    .internal_create_signed_txs(TransactionRequest {
                                        deposit_outpoint: Some(deposit_outpoint.into()),
                                        kickoff_id: Some(kickoff_data.into()),
                                    })
                                    .await
                                    .unwrap()
                                    .into_inner();
                                // test if all needed tx's are signed
                                for tx_type in &txs_verifier_can_sign {
                                    assert!(
                                        raw_txs
                                            .signed_txs
                                            .iter()
                                            .any(|signed_tx| signed_tx.transaction_type
                                                == Some((*tx_type).into())),
                                        "Tx type: {:?} not found in signed txs for verifier",
                                        tx_type
                                    );
                                }
                                tracing::info!(
                                    "Verifier signed txs {:?} from rpc call in time {:?}",
                                    TransactionType::AllNeededForDeposit,
                                    start_time.elapsed()
                                );
                                tx.send((kickoff_data, signed_txs_to_txid(raw_txs)))
                                    .unwrap();
                                let _watchtower_challenge_tx = verifier_rpc
                                    .internal_create_watchtower_challenge(TransactionRequest {
                                        deposit_outpoint: Some(deposit_outpoint.into()),
                                        kickoff_id: Some(kickoff_data.into()),
                                    })
                                    .await
                                    .unwrap()
                                    .into_inner();
                            }
                        }
                    }
                }
            })
            .map(tokio::task::spawn)
            .collect();

        drop(tx);
        while let Some((kickoff_id, txids)) = rx.recv().await {
            for (tx_type, txid) in txids {
                created_txs
                    .entry((kickoff_id, tx_type))
                    .or_default()
                    .push(txid);
            }
        }

        let mut incorrect = false;

        for ((kickoff_id, tx_type), txids) in &created_txs {
            // check if all txids are equal
            if !txids.iter().all(|txid| txid == &txids[0]) {
                tracing::error!(
                    "Mismatch in Txids for kickoff_id: {:?}, tx_type: {:?}, Txids: {:?}",
                    kickoff_id,
                    tx_type,
                    txids
                );
                incorrect = true;
            }
        }
        assert!(!incorrect);

        try_join_all(operator_task_handles).await.unwrap();
        try_join_all(verifier_task_handles).await.unwrap();
    }

    #[cfg(feature = "automation")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn test_deposit_and_sign_txs() {
        let mut config = create_test_config_with_thread_name().await;
        let WithProcessCleanup(_, ref rpc, _, _) = create_regtest_rpc(&mut config).await;

        let (actors, deposit_params, _, deposit_blockhash, _) =
            run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
                .await
                .unwrap();

        check_if_signable(actors, deposit_params, deposit_blockhash, config.clone()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg(feature = "automation")]
    #[serial_test::serial]
    async fn test_replacement_deposit_and_sign_txs() {
        let mut config = create_test_config_with_thread_name().await;
        let WithProcessCleanup(_, ref rpc, _, _) = create_regtest_rpc(&mut config).await;

        let (mut actors, _deposit_info, old_move_txid, _deposit_blockhash, _verifiers_public_keys) =
            run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
                .await
                .unwrap();

        let old_nofn_xonly_pk = actors.get_nofn_aggregated_xonly_pk().unwrap();
        // remove 1 verifier then run a replacement deposit
        actors.remove_verifier(2).await.unwrap();

        let (
            actors,
            replacement_deposit_info,
            _replacement_move_txid,
            replacement_deposit_blockhash,
        ) = run_single_replacement_deposit(
            &mut config,
            rpc,
            old_move_txid,
            actors,
            old_nofn_xonly_pk,
        )
        .await
        .unwrap();

        check_if_signable(
            actors,
            replacement_deposit_info,
            replacement_deposit_blockhash,
            config.clone(),
        )
        .await;
    }

    #[test]
    fn test_txhandler_cache_store_for_next_kickoff() {
        let mut cache = TxHandlerCache::new();
        let mut txhandlers = BTreeMap::new();
        txhandlers.insert(
            TransactionType::MoveToVault,
            TxHandlerBuilder::new(TransactionType::MoveToVault).finalize(),
        );
        txhandlers.insert(
            TransactionType::Round,
            TxHandlerBuilder::new(TransactionType::Round).finalize(),
        );
        txhandlers.insert(
            TransactionType::ReadyToReimburse,
            TxHandlerBuilder::new(TransactionType::ReadyToReimburse).finalize(),
        );
        txhandlers.insert(
            TransactionType::Kickoff,
            TxHandlerBuilder::new(TransactionType::Kickoff).finalize(),
        );

        // should store the first 3 txhandlers, and not insert kickoff
        assert!(cache.store_for_next_kickoff(&mut txhandlers).is_ok());
        assert!(txhandlers.len() == 1);
        assert!(cache.saved_txs.len() == 3);
        assert!(cache.saved_txs.contains_key(&TransactionType::MoveToVault));
        assert!(cache.saved_txs.contains_key(&TransactionType::Round));
        assert!(cache
            .saved_txs
            .contains_key(&TransactionType::ReadyToReimburse));
        // prev_ready_to_reimburse should be None as it is the first iteration
        assert!(cache.prev_ready_to_reimburse.is_none());

        // txhandlers should contain all cached tx's
        txhandlers = cache.get_cached_txs();
        assert!(txhandlers.len() == 3);
        assert!(txhandlers.contains_key(&TransactionType::MoveToVault));
        assert!(txhandlers.contains_key(&TransactionType::Round));
        assert!(txhandlers.contains_key(&TransactionType::ReadyToReimburse));
        assert!(cache.store_for_next_kickoff(&mut txhandlers).is_ok());
        // prev ready to reimburse still none as we didn't go to next round
        assert!(cache.prev_ready_to_reimburse.is_none());

        // should delete saved txs and store prev ready to reimburse, but it should keep movetovault
        assert!(cache.store_for_next_round().is_ok());
        assert!(cache.saved_txs.len() == 1);
        assert!(cache.prev_ready_to_reimburse.is_some());
        assert!(cache.saved_txs.contains_key(&TransactionType::MoveToVault));

        // retrieve cached movetovault
        txhandlers = cache.get_cached_txs();

        // create new round txs
        txhandlers.insert(
            TransactionType::ReadyToReimburse,
            TxHandlerBuilder::new(TransactionType::ReadyToReimburse).finalize(),
        );
        txhandlers.insert(
            TransactionType::Round,
            TxHandlerBuilder::new(TransactionType::Round).finalize(),
        );
        // add not relevant tx
        txhandlers.insert(
            TransactionType::WatchtowerChallenge(0),
            TxHandlerBuilder::new(TransactionType::WatchtowerChallenge(0)).finalize(),
        );

        // should add all 3 tx's to cache again
        assert!(cache.store_for_next_kickoff(&mut txhandlers).is_ok());
        assert!(cache.saved_txs.len() == 3);
        assert!(cache.saved_txs.contains_key(&TransactionType::MoveToVault));
        assert!(cache.saved_txs.contains_key(&TransactionType::Round));
        assert!(cache
            .saved_txs
            .contains_key(&TransactionType::ReadyToReimburse));
        // prev ready to reimburse is still stored
        assert!(cache.prev_ready_to_reimburse.is_some());
    }
}
