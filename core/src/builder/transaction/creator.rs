use crate::actor::Actor;
use crate::actor::WinternitzDerivationPath::WatchtowerChallenge;
use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder;
use crate::builder::script::WinternitzCommit;
use crate::builder::transaction::{
    create_assert_timeout_txhandlers, create_challenge_timeout_txhandler, create_kickoff_txhandler,
    create_mini_asserts, create_round_txhandler, create_unspent_kickoff_txhandlers, AssertScripts,
    DepositData, OperatorData, TransactionType, TxHandler,
};
use crate::config::protocol::ProtocolParamset;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::operator::PublicHash;
use crate::rpc::clementine::KickoffId;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::{remove_txhandler_from_map, RoundTxInput};

// helper function to get a txhandler from a hashmap
fn get_txhandler(
    txhandlers: &BTreeMap<TransactionType, TxHandler>,
    tx_type: TransactionType,
) -> Result<&TxHandler, BridgeError> {
    txhandlers
        .get(&tx_type)
        .ok_or(BridgeError::TxHandlerNotFound(tx_type))
}

#[derive(Debug, Clone)]
/// Helper struct to get specific kickoff winternitz keys for a sequential collateral tx
pub struct KickoffWinternitzKeys {
    pub keys: Vec<bitvm::signatures::winternitz::PublicKey>,
    num_kickoffs_per_round: usize,
}

impl KickoffWinternitzKeys {
    pub fn new(
        keys: Vec<bitvm::signatures::winternitz::PublicKey>,
        num_kickoffs_per_round: usize,
    ) -> Self {
        Self {
            keys,
            num_kickoffs_per_round,
        }
    }

    /// Get the winternitz keys for a specific sequential collateral tx
    pub fn get_keys_for_round(
        &self,
        round_idx: usize,
    ) -> &[bitvm::signatures::winternitz::PublicKey] {
        &self.keys
            [round_idx * self.num_kickoffs_per_round..(round_idx + 1) * self.num_kickoffs_per_round]
    }
}

/// Struct to retrieve and cache data from DB for creating TxHandlers on demand
/// It can only store information for one reimbursement (i.e. one kickoff)
#[derive(Debug, Clone)]
pub struct ReimburseDbCache {
    pub db: Database,
    pub operator_idx: u32,
    pub deposit_data: Option<DepositData>,
    pub paramset: &'static ProtocolParamset,
    /// watchtower challenge addresses
    watchtower_challenge_hashes: Option<Vec<[u8; 32]>>,
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
}

impl ReimburseDbCache {
    /// Creates a db cache that can be used to create txhandlers for a specific operator and deposit/kickoff
    pub fn new_for_deposit(
        db: Database,
        operator_idx: u32,
        deposit_data: DepositData,
        paramset: &'static ProtocolParamset,
    ) -> Self {
        Self {
            db,
            operator_idx,
            deposit_data: Some(deposit_data),
            paramset,
            watchtower_challenge_hashes: None,
            kickoff_winternitz_keys: None,
            bitvm_assert_addr: None,
            bitvm_disprove_root_hash: None,
            challenge_ack_hashes: None,
            operator_data: None,
        }
    }

    /// Creates a db cache that can be used to create txhandlers for a specific operator and collateral chain
    pub fn new_for_rounds(
        db: Database,
        operator_idx: u32,
        paramset: &'static ProtocolParamset,
    ) -> Self {
        Self {
            db,
            operator_idx,
            deposit_data: None,
            paramset,
            watchtower_challenge_hashes: None,
            kickoff_winternitz_keys: None,
            bitvm_assert_addr: None,
            bitvm_disprove_root_hash: None,
            challenge_ack_hashes: None,
            operator_data: None,
        }
    }

    pub fn from_context(db: Database, context: ContractContext) -> Self {
        if context.deposit_data.is_some() {
            Self::new_for_deposit(
                db,
                context.operator_idx,
                context.deposit_data.expect("checked in if statement"),
                context.paramset,
            )
        } else {
            Self::new_for_rounds(db, context.operator_idx, context.paramset)
        }
    }

    pub async fn get_operator_data(&mut self) -> Result<&OperatorData, BridgeError> {
        match self.operator_data {
            Some(ref data) => Ok(data),
            None => {
                self.operator_data = Some(
                    self.db
                        .get_operator(None, self.operator_idx as i32)
                        .await?
                        .ok_or(BridgeError::OperatorNotFound(self.operator_idx))?,
                );
                Ok(self.operator_data.as_ref().expect("Inserted before"))
            }
        }
    }

    pub async fn watchtower_challenge_root_hash(&mut self) -> Result<&[[u8; 32]], BridgeError> {
        if let Some(deposit_data) = &self.deposit_data {
            match self.watchtower_challenge_hashes {
                Some(ref addr) => Ok(addr),
                None => {
                    // Get all watchtower challenge addresses for the operator.
                    let watchtower_challenge_addr = (0..self.paramset.num_watchtowers)
                        .map(|i| {
                            self.db.get_watchtower_challenge_hash(
                                None,
                                i as u32,
                                self.operator_idx,
                                deposit_data.deposit_outpoint,
                            )
                        })
                        .collect::<Vec<_>>();
                    self.watchtower_challenge_hashes =
                        Some(futures::future::try_join_all(watchtower_challenge_addr).await?);
                    Ok(self
                        .watchtower_challenge_hashes
                        .as_ref()
                        .expect("Inserted before"))
                }
            }
        } else {
            Err(BridgeError::InsufficientContext)
        }
    }

    pub async fn get_kickoff_winternitz_keys(
        &mut self,
    ) -> Result<&KickoffWinternitzKeys, BridgeError> {
        match self.kickoff_winternitz_keys {
            Some(ref keys) => Ok(keys),
            None => {
                self.kickoff_winternitz_keys = Some(KickoffWinternitzKeys::new(
                    self.db
                        .get_operator_kickoff_winternitz_public_keys(None, self.operator_idx)
                        .await?,
                    self.paramset.num_kickoffs_per_round,
                ));
                Ok(self
                    .kickoff_winternitz_keys
                    .as_ref()
                    .expect("Inserted before"))
            }
        }
    }

    pub async fn get_bitvm_assert_hash(&mut self) -> Result<&[[u8; 32]], BridgeError> {
        if let Some(deposit_data) = &self.deposit_data {
            match self.bitvm_assert_addr {
                Some(ref addr) => Ok(addr),
                None => {
                    let (assert_addr, bitvm_hash) = self
                        .db
                        .get_bitvm_setup(
                            None,
                            self.operator_idx as i32,
                            deposit_data.deposit_outpoint,
                        )
                        .await?
                        .ok_or(BridgeError::BitvmSetupNotFound(
                            self.operator_idx as i32,
                            deposit_data.deposit_outpoint.txid,
                        ))?;
                    self.bitvm_assert_addr = Some(assert_addr);
                    self.bitvm_disprove_root_hash = Some(bitvm_hash);
                    Ok(self.bitvm_assert_addr.as_ref().expect("Inserted before"))
                }
            }
        } else {
            Err(BridgeError::InsufficientContext)
        }
    }

    pub async fn get_challenge_ack_hashes(&mut self) -> Result<&[PublicHash], BridgeError> {
        if let Some(deposit_data) = &self.deposit_data {
            match self.challenge_ack_hashes {
                Some(ref hashes) => Ok(hashes),
                None => {
                    self.challenge_ack_hashes = Some(
                        self.db
                            .get_operators_challenge_ack_hashes(
                                None,
                                self.operator_idx as i32,
                                deposit_data.deposit_outpoint,
                            )
                            .await?
                            .ok_or(BridgeError::WatchtowerPublicHashesNotFound(
                                self.operator_idx as i32,
                                deposit_data.deposit_outpoint.txid,
                            ))?,
                    );
                    Ok(self.challenge_ack_hashes.as_ref().expect("Inserted before"))
                }
            }
        } else {
            Err(BridgeError::InsufficientContext)
        }
    }

    pub async fn get_bitvm_disprove_root_hash(&mut self) -> Result<&[u8; 32], BridgeError> {
        if let Some(deposit_data) = &self.deposit_data {
            match self.bitvm_disprove_root_hash {
                Some(ref hash) => Ok(hash),
                None => {
                    let bitvm_hash = self
                        .db
                        .get_bitvm_root_hash(
                            None,
                            self.operator_idx as i32,
                            deposit_data.deposit_outpoint,
                        )
                        .await?
                        .ok_or(BridgeError::BitvmSetupNotFound(
                            self.operator_idx as i32,
                            deposit_data.deposit_outpoint.txid,
                        ))?;
                    self.bitvm_disprove_root_hash = Some(bitvm_hash);
                    Ok(self
                        .bitvm_disprove_root_hash
                        .as_ref()
                        .expect("Inserted before"))
                }
            }
        } else {
            Err(BridgeError::InsufficientContext)
        }
    }
}

#[derive(Debug, Clone)]
/// Context for a single operator and round, and optionally a single deposit
pub struct ContractContext {
    /// required
    operator_idx: u32,
    round_idx: u32,
    paramset: &'static ProtocolParamset,
    /// optional (only used for after kickoff)
    kickoff_idx: Option<u32>,
    deposit_data: Option<DepositData>,
    signer: Option<Actor>,
    // TODO: why different winternitz_secret_key???
}

impl ContractContext {
    /// Contains all necessary context for creating txhandlers for a specific operator and collateral chain
    pub fn new_context_for_rounds(
        operator_idx: u32,
        round_idx: u32,
        paramset: &'static ProtocolParamset,
    ) -> Self {
        Self {
            operator_idx,
            round_idx,
            paramset,
            kickoff_idx: None,
            deposit_data: None,
            signer: None,
        }
    }

    /// Contains all necessary context for creating txhandlers for a specific operator, kickoff utxo, and a deposit
    pub fn new_context_for_kickoffs(
        kickoff_id: KickoffId,
        deposit_data: DepositData,
        paramset: &'static ProtocolParamset,
    ) -> Self {
        Self {
            operator_idx: kickoff_id.operator_idx,
            round_idx: kickoff_id.round_idx,
            paramset,
            kickoff_idx: Some(kickoff_id.kickoff_idx),
            deposit_data: Some(deposit_data),
            signer: None,
        }
    }

    /// Contains all necessary context for creating txhandlers for a specific operator, kickoff utxo, and a deposit
    /// Additionally holds signer of an actor that can generate the actual winternitz public keys.
    pub fn new_context_for_asserts(
        kickoff_id: KickoffId,
        deposit_data: DepositData,
        paramset: &'static ProtocolParamset,
        signer: Actor,
    ) -> Self {
        Self {
            operator_idx: kickoff_id.operator_idx,
            round_idx: kickoff_id.round_idx,
            paramset,
            kickoff_idx: Some(kickoff_id.kickoff_idx),
            deposit_data: Some(deposit_data),
            signer: Some(signer),
        }
    }
}

/// Struct to store common txhandlers for kickoffs
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
    pub fn new() -> Self {
        Self {
            saved_txs: BTreeMap::new(),
            prev_ready_to_reimburse: None,
        }
    }
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
                .ok_or(BridgeError::TxHandlerNotFound(*tx_type))?;
            self.saved_txs.insert(*tx_type, txhandler);
        }
        Ok(())
    }
    /// store move_to_vault and previous ready to reimburse
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
    pub fn get_prev_ready_to_reimburse(&self) -> Option<&TxHandler> {
        self.prev_ready_to_reimburse.as_ref()
    }
    pub fn get_cached_txs(&mut self) -> BTreeMap<TransactionType, TxHandler> {
        std::mem::take(&mut self.saved_txs)
    }
}

#[tracing::instrument(skip_all, err, fields(deposit_data = ?db_cache.deposit_data, txtype = ?transaction_type, ?context))]
pub async fn create_txhandlers(
    transaction_type: TransactionType,
    context: ContractContext,
    txhandler_cache: &mut TxHandlerCache,
    db_cache: &mut ReimburseDbCache,
) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
    let ReimburseDbCache { paramset, .. } = db_cache.clone();

    let operator_data = db_cache.get_operator_data().await?.clone();
    let kickoff_winternitz_keys = db_cache.get_kickoff_winternitz_keys().await?;

    let ContractContext {
        operator_idx,
        round_idx,
        ..
    } = context;

    let mut txhandlers = txhandler_cache.get_cached_txs();

    if !txhandlers.contains_key(&TransactionType::Round) {
        // create round tx, ready to reimburse tx, and unspent kickoff txs if not in cache
        let round_txhandlers = create_round_txhandlers(
            paramset,
            round_idx as usize,
            &operator_data,
            kickoff_winternitz_keys,
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
        RoundTxInput::Prevout(
            get_txhandler(&txhandlers, TransactionType::ReadyToReimburse)?
                .get_spendable_output(0)?,
        ),
        kickoff_winternitz_keys.get_keys_for_round(round_idx as usize + 1),
        paramset,
    )?;

    let kickoff_id = KickoffId {
        operator_idx,
        round_idx,
        kickoff_idx: context
            .kickoff_idx
            .ok_or(BridgeError::InsufficientContext)?,
    };
    let deposit_data = context
        .deposit_data
        .ok_or(BridgeError::InsufficientContext)?;

    if !txhandlers.contains_key(&TransactionType::MoveToVault) {
        // if not cached create move_txhandler
        let move_txhandler = builder::transaction::create_move_to_vault_txhandler(
            deposit_data.deposit_outpoint,
            deposit_data.evm_address,
            &deposit_data.recovery_taproot_address,
            deposit_data.nofn_xonly_pk,
            paramset.user_takes_after,
            paramset.bridge_amount,
            paramset.network,
        )?;
        txhandlers.insert(move_txhandler.get_transaction_type(), move_txhandler);
    }

    let num_asserts = ClementineBitVMPublicKeys::number_of_assert_txs();
    let public_hashes = db_cache.get_challenge_ack_hashes().await?.to_vec();
    let watchtower_challenge_root_hashes =
        db_cache.watchtower_challenge_root_hash().await?.to_vec();

    let kickoff_txhandler = if let TransactionType::MiniAssert(_) = transaction_type {
        // create scripts if any mini assert tx is specifically requested as it needs
        // the actual scripts to be able to spend
        let actor = context
            .signer
            .clone()
            .ok_or(BridgeError::InsufficientContext)?;

        // deposit_data.deposit_outpoint.txid

        let bitvm_pks =
            actor.generate_bitvm_pks_for_deposit(deposit_data.deposit_outpoint.txid, paramset)?;

        let assert_scripts = bitvm_pks.get_assert_scripts(operator_data.xonly_pk);

        let kickoff_txhandler = create_kickoff_txhandler(
            kickoff_id,
            get_txhandler(&txhandlers, TransactionType::Round)?,
            get_txhandler(&txhandlers, TransactionType::MoveToVault)?,
            deposit_data.nofn_xonly_pk,
            operator_data.xonly_pk,
            AssertScripts::AssertSpendableScript(assert_scripts),
            db_cache.get_bitvm_disprove_root_hash().await?,
            &watchtower_challenge_root_hashes,
            &public_hashes,
            paramset,
        )?;

        // Create and insert mini_asserts into return Vec
        let mini_asserts = create_mini_asserts(&kickoff_txhandler, num_asserts)?;

        for mini_assert in mini_asserts.into_iter() {
            txhandlers.insert(mini_assert.get_transaction_type(), mini_assert);
        }

        kickoff_txhandler
    } else {
        let disprove_root_hash = *db_cache.get_bitvm_disprove_root_hash().await?;
        // use db data for scripts
        create_kickoff_txhandler(
            kickoff_id,
            get_txhandler(&txhandlers, TransactionType::Round)?,
            get_txhandler(&txhandlers, TransactionType::MoveToVault)?,
            deposit_data.nofn_xonly_pk,
            operator_data.xonly_pk,
            AssertScripts::AssertScriptTapNodeHash(db_cache.get_bitvm_assert_hash().await?),
            &disprove_root_hash,
            &watchtower_challenge_root_hashes,
            &public_hashes,
            paramset,
        )?
    };
    txhandlers.insert(kickoff_txhandler.get_transaction_type(), kickoff_txhandler);

    // Creates the challenge_tx handler.
    let challenge_txhandler = builder::transaction::create_challenge_txhandler(
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        &operator_data.reimburse_addr,
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
        )?;
    txhandlers.insert(
        kickoff_not_finalized_txhandler.get_transaction_type(),
        kickoff_not_finalized_txhandler,
    );

    // create watchtower tx's except WatchtowerChallenges
    for watchtower_idx in 0..paramset.num_watchtowers {
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

    // Generate watchtower challenge with correct script if specifically requested
    if let TransactionType::WatchtowerChallenge(watchtower_idx) = transaction_type {
        // generate with actual scripts if we want to specifically create a watchtower challenge tx
        let path = WatchtowerChallenge(
            kickoff_id.operator_idx,
            deposit_data.deposit_outpoint.txid,
            paramset,
        );

        let actor = context.signer.ok_or(BridgeError::InsufficientContext)?;
        let public_key = actor.derive_winternitz_pk(path)?;

        let watchtower_challenge_txhandler =
            builder::transaction::create_watchtower_challenge_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                watchtower_idx,
                deposit_data.nofn_xonly_pk,
                Arc::new(WinternitzCommit::new(
                    vec![(
                        public_key,
                        paramset.watchtower_challenge_message_length as u32,
                    )],
                    actor.xonly_public_key,
                    paramset.winternitz_log_d,
                )),
                paramset,
            )?;
        txhandlers.insert(
            watchtower_challenge_txhandler.get_transaction_type(),
            watchtower_challenge_txhandler,
        );
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
        kickoff_id.kickoff_idx as usize,
        paramset.num_kickoffs_per_round,
        &operator_data.reimburse_addr,
    )?;

    txhandlers.insert(
        reimburse_txhandler.get_transaction_type(),
        reimburse_txhandler,
    );

    match transaction_type {
        TransactionType::AllNeededForDeposit => {
            let disprove_txhandler = builder::transaction::create_disprove_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                get_txhandler(&txhandlers, TransactionType::Round)?,
            )?;
            txhandlers.insert(
                disprove_txhandler.get_transaction_type(),
                disprove_txhandler,
            );
        }
        TransactionType::Disprove => {
            // TODO: if TransactionType::Disprove, we need to add the actual disprove script here because requester wants to disprove the withdrawal
        }
        _ => {}
    }

    Ok(txhandlers)
}

/// Function to create the round txhandler and ready to reimburse txhandler for a specific operator and round index
pub fn create_round_txhandlers(
    paramset: &'static ProtocolParamset,
    round_idx: usize,
    operator_data: &OperatorData,
    kickoff_winternitz_keys: &KickoffWinternitzKeys,
    prev_ready_to_reimburse: Option<&TxHandler>,
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::with_capacity(2 + paramset.num_kickoffs_per_round);

    let (round_txhandler, ready_to_reimburse_txhandler) = match prev_ready_to_reimburse {
        Some(prev_ready_to_reimburse_txhandler) => {
            let round_txhandler = builder::transaction::create_round_txhandler(
                operator_data.xonly_pk,
                RoundTxInput::Prevout(prev_ready_to_reimburse_txhandler.get_spendable_output(0)?),
                kickoff_winternitz_keys.get_keys_for_round(round_idx),
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
    use crate::actor::Actor;
    use crate::bitvm_client::ClementineBitVMPublicKeys;
    use crate::builder::transaction::sign::get_kickoff_utxos_to_sign;
    use crate::builder::transaction::TransactionType;
    use crate::builder::transaction::TxHandlerBuilder;
    use crate::citrea::mock::MockCitreaClient;
    use crate::rpc::clementine::{AssertRequest, KickoffId, TransactionRequest};
    use crate::test::common::*;
    use bitcoin::XOnlyPublicKey;
    use futures::future::try_join_all;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_deposit_and_sign_txs() {
        let mut config = create_test_config_with_thread_name().await;
        let WithProcessCleanup(_, ref rpc, _, _) = create_regtest_rpc(&mut config).await;

        let (
            mut verifiers,
            mut operators,
            _,
            mut watchtowers,
            _cleanup,
            deposit_params,
            _,
            deposit_blockhash,
        ) = run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None)
            .await
            .unwrap();

        let paramset = config.protocol_paramset();

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
        ];
        txs_operator_can_sign
            .extend((0..paramset.num_watchtowers).map(TransactionType::OperatorChallengeNack));
        txs_operator_can_sign
            .extend((0..paramset.num_watchtowers).map(TransactionType::OperatorChallengeAck));
        txs_operator_can_sign.extend(
            (0..ClementineBitVMPublicKeys::number_of_assert_txs())
                .map(TransactionType::AssertTimeout),
        );
        txs_operator_can_sign
            .extend((0..paramset.num_kickoffs_per_round).map(TransactionType::UnspentKickoff));
        txs_operator_can_sign
            .extend((0..paramset.num_watchtowers).map(TransactionType::WatchtowerChallengeTimeout));

        let all_operators_secret_keys = config.all_operators_secret_keys.clone().unwrap();
        let operator_xonly_pks: Vec<XOnlyPublicKey> = all_operators_secret_keys
            .iter()
            .map(|&sk| {
                Actor::new(
                    sk,
                    config.winternitz_secret_key,
                    config.protocol_paramset().network,
                )
                .xonly_public_key
            })
            .collect();
        let mut utxo_idxs: Vec<Vec<usize>> = Vec::with_capacity(operator_xonly_pks.len());
        let deposit_outpoint: bitcoin::OutPoint = deposit_params
            .clone()
            .deposit_outpoint
            .unwrap()
            .try_into()
            .unwrap();

        for op_xonly_pk in operator_xonly_pks {
            utxo_idxs.push(get_kickoff_utxos_to_sign(
                config.protocol_paramset(),
                op_xonly_pk,
                deposit_blockhash,
                deposit_outpoint,
            ));
        }

        // try to sign everything for all operators
        let operator_task_handles: Vec<_> = operators
            .iter_mut()
            .enumerate()
            .map(|(operator_idx, operator_rpc)| {
                let txs_operator_can_sign = txs_operator_can_sign.clone();
                let deposit_params = deposit_params.clone();
                let mut operator_rpc = operator_rpc.clone();
                let utxo_idxs = utxo_idxs.clone();
                async move {
                    for round_idx in 0..paramset.num_round_txs {
                        for &kickoff_idx in &utxo_idxs[operator_idx] {
                            let kickoff_id = KickoffId {
                                operator_idx: operator_idx as u32,
                                round_idx: round_idx as u32,
                                kickoff_idx: kickoff_idx as u32,
                            };
                            let start_time = std::time::Instant::now();
                            let raw_tx = operator_rpc
                                .internal_create_signed_txs(TransactionRequest {
                                    deposit_params: deposit_params.clone().into(),
                                    transaction_type: Some(
                                        TransactionType::AllNeededForDeposit.into(),
                                    ),
                                    kickoff_id: Some(kickoff_id),
                                })
                                .await
                                .unwrap()
                                .into_inner();
                            // test if all needed tx's are signed
                            for tx_type in &txs_operator_can_sign {
                                assert!(
                                    raw_tx
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
                            let _raw_assert_txs = operator_rpc
                                .internal_create_assert_commitment_txs(AssertRequest {
                                    deposit_params: deposit_params.clone().into(),
                                    kickoff_id: Some(kickoff_id),
                                })
                                .await
                                .unwrap()
                                .into_inner()
                                .signed_txs;
                            tracing::info!(
                                "Operator Signed Assert txs of size: {}",
                                _raw_assert_txs.len()
                            );
                        }
                    }
                }
            })
            .map(tokio::task::spawn)
            .collect();

        // try signing watchtower challenges for all watchtowers
        let watchtower_task_handles: Vec<_> = watchtowers
            .iter_mut()
            .enumerate()
            .map(|(watchtower_idx, watchtower_rpc)| {
                let deposit_params = deposit_params.clone();
                let mut watchtower_rpc = watchtower_rpc.clone();
                let utxo_idxs = utxo_idxs.clone();
                async move {
                    for (operator_idx, utxo_idx) in utxo_idxs.iter().enumerate() {
                        for round_idx in 0..paramset.num_round_txs {
                            for &kickoff_idx in utxo_idx {
                                let kickoff_id = KickoffId {
                                    operator_idx: operator_idx as u32,
                                    round_idx: round_idx as u32,
                                    kickoff_idx: kickoff_idx as u32,
                                };
                                let _raw_tx = watchtower_rpc
                                    .internal_create_watchtower_challenge(TransactionRequest {
                                        deposit_params: deposit_params.clone().into(),
                                        transaction_type: Some(
                                            TransactionType::WatchtowerChallenge(watchtower_idx)
                                                .into(),
                                        ),
                                        kickoff_id: Some(kickoff_id),
                                    })
                                    .await
                                    .unwrap();
                                tracing::info!(
                                    "Watchtower Signed tx: {:?}",
                                    TransactionType::WatchtowerChallenge(watchtower_idx)
                                );
                            }
                        }
                    }
                }
            })
            .map(tokio::task::spawn)
            .collect();

        let mut txs_verifier_can_sign = vec![
            TransactionType::Challenge,
            TransactionType::KickoffNotFinalized,
            //TransactionType::Disprove,
        ];
        txs_verifier_can_sign
            .extend((0..paramset.num_watchtowers).map(TransactionType::OperatorChallengeNack));
        txs_verifier_can_sign.extend(
            (0..ClementineBitVMPublicKeys::number_of_assert_txs())
                .map(TransactionType::AssertTimeout),
        );
        txs_verifier_can_sign
            .extend((0..paramset.num_kickoffs_per_round).map(TransactionType::UnspentKickoff));
        txs_verifier_can_sign
            .extend((0..paramset.num_watchtowers).map(TransactionType::WatchtowerChallengeTimeout));

        // try to sign everything for all verifiers
        // try signing verifier transactions
        let verifier_task_handles: Vec<_> = verifiers
            .iter_mut()
            .map(|verifier_rpc| {
                let txs_verifier_can_sign = txs_verifier_can_sign.clone();
                let deposit_params = deposit_params.clone();
                let mut verifier_rpc = verifier_rpc.clone();
                let utxo_idxs = utxo_idxs.clone();
                async move {
                    for (operator_idx, utxo_idx) in utxo_idxs.iter().enumerate() {
                        for round_idx in 0..paramset.num_round_txs {
                            for &kickoff_idx in utxo_idx {
                                let kickoff_id = KickoffId {
                                    operator_idx: operator_idx as u32,
                                    round_idx: round_idx as u32,
                                    kickoff_idx: kickoff_idx as u32,
                                };
                                let start_time = std::time::Instant::now();
                                let raw_tx = verifier_rpc
                                    .internal_create_signed_txs(TransactionRequest {
                                        deposit_params: deposit_params.clone().into(),
                                        transaction_type: Some(
                                            TransactionType::AllNeededForDeposit.into(),
                                        ),
                                        kickoff_id: Some(kickoff_id),
                                    })
                                    .await
                                    .unwrap()
                                    .into_inner();
                                // test if all needed tx's are signed
                                for tx_type in &txs_verifier_can_sign {
                                    assert!(
                                        raw_tx
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
                            }
                        }
                    }
                }
            })
            .map(tokio::task::spawn)
            .collect();

        try_join_all(operator_task_handles).await.unwrap();
        try_join_all(watchtower_task_handles).await.unwrap();
        try_join_all(verifier_task_handles).await.unwrap();
    }

    use super::*;

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
        // prev ready to reimburse still none as we didnt go to next round
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
