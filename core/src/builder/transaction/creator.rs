use crate::actor::WinternitzDerivationPath::WatchtowerChallenge;
use crate::actor::{Actor, WinternitzDerivationPath};
use crate::builder::script::{SpendableScript, WinternitzCommit};
use crate::builder::transaction::{DepositData, OperatorData, TransactionType, TxHandler};
use crate::config::BridgeConfig;
use crate::constants::WATCHTOWER_CHALLENGE_MESSAGE_LENGTH;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::operator::PublicHash;
use crate::rpc::clementine::KickoffId;
use crate::{builder, utils};
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use std::collections::BTreeMap;
use std::sync::Arc;

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
    keys: Vec<bitvm::signatures::winternitz::PublicKey>,
    num_kickoffs_per_seq: usize,
}

impl KickoffWinternitzKeys {
    pub fn new(
        keys: Vec<bitvm::signatures::winternitz::PublicKey>,
        num_kickoffs_per_seq: usize,
    ) -> Self {
        Self {
            keys,
            num_kickoffs_per_seq,
        }
    }

    /// Get the winternitz keys for a specific sequential collateral tx
    pub fn get_keys_for_seq_col(
        &self,
        seq_col_idx: usize,
    ) -> &[bitvm::signatures::winternitz::PublicKey] {
        &self.keys
            [seq_col_idx * self.num_kickoffs_per_seq..(seq_col_idx + 1) * self.num_kickoffs_per_seq]
    }
}

/// Struct to retrieve and store DB data for creating TxHandlers on demand
#[derive(Debug, Clone)]
pub struct TxHandlerDbData {
    db: Database,
    operator_idx: u32,
    deposit_data: DepositData,
    config: BridgeConfig,
    /// watchtower challenge addresses
    watchtower_challenge_addr: Option<Vec<ScriptBuf>>,
    /// winternitz keys to sign the kickoff tx with the blockhash
    kickoff_winternitz_keys: Option<KickoffWinternitzKeys>,
    /// bitvm assert scripts for each assert utxo
    bitvm_assert_addr: Option<Vec<ScriptBuf>>,
    /// bitvm disprove scripts taproot merkle tree root hash
    bitvm_disprove_root_hash: Option<[u8; 32]>,
    /// Public hashes to acknowledge watchtower challenges
    challenge_ack_hashes: Option<Vec<PublicHash>>,
}

impl TxHandlerDbData {
    pub fn new(
        db: Database,
        operator_idx: u32,
        deposit_data: DepositData,
        config: BridgeConfig,
    ) -> Self {
        Self {
            db,
            operator_idx,
            deposit_data,
            config,
            watchtower_challenge_addr: None,
            kickoff_winternitz_keys: None,
            bitvm_assert_addr: None,
            bitvm_disprove_root_hash: None,
            challenge_ack_hashes: None,
        }
    }
    pub async fn get_watchtower_challenge_addr(&mut self) -> Result<&[ScriptBuf], BridgeError> {
        match self.watchtower_challenge_addr {
            Some(ref addr) => Ok(addr),
            None => {
                // Get all watchtower challenge addresses for the operator.
                let watchtower_challenge_addr = (0..self.config.num_watchtowers)
                    .map(|i| {
                        self.db.get_watchtower_challenge_address(
                            None,
                            i as u32,
                            self.operator_idx,
                            self.deposit_data.deposit_outpoint,
                        )
                    })
                    .collect::<Vec<_>>();
                self.watchtower_challenge_addr =
                    Some(futures::future::try_join_all(watchtower_challenge_addr).await?);
                Ok(self
                    .watchtower_challenge_addr
                    .as_ref()
                    .expect("Inserted before"))
            }
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
                    self.config.num_kickoffs_per_sequential_collateral_tx,
                ));
                Ok(self
                    .kickoff_winternitz_keys
                    .as_ref()
                    .expect("Inserted before"))
            }
        }
    }

    pub async fn get_bitvm_assert_addr(&mut self) -> Result<&[ScriptBuf], BridgeError> {
        match self.bitvm_assert_addr {
            Some(ref addr) => Ok(addr),
            None => {
                let (assert_addr, bitvm_hash) = self
                    .db
                    .get_bitvm_setup(
                        None,
                        self.operator_idx as i32,
                        self.deposit_data.deposit_outpoint,
                    )
                    .await?
                    .ok_or(BridgeError::BitvmSetupNotFound(
                        self.operator_idx as i32,
                        self.deposit_data.deposit_outpoint.txid,
                    ))?;
                self.bitvm_assert_addr = Some(assert_addr);
                self.bitvm_disprove_root_hash = Some(bitvm_hash);
                Ok(self.bitvm_assert_addr.as_ref().expect("Inserted before"))
            }
        }
    }

    pub async fn get_challenge_ack_hashes(&mut self) -> Result<&[PublicHash], BridgeError> {
        match self.challenge_ack_hashes {
            Some(ref hashes) => Ok(hashes),
            None => {
                self.challenge_ack_hashes = Some(
                    self.db
                        .get_operators_challenge_ack_hashes(
                            None,
                            self.operator_idx as i32,
                            self.deposit_data.deposit_outpoint,
                        )
                        .await?
                        .ok_or(BridgeError::WatchtowerPublicHashesNotFound(
                            self.operator_idx as i32,
                            self.deposit_data.deposit_outpoint.txid,
                        ))?,
                );
                Ok(self.challenge_ack_hashes.as_ref().expect("Inserted before"))
            }
        }
    }

    pub async fn get_bitvm_disprove_root_hash(&mut self) -> Result<&[u8; 32], BridgeError> {
        match self.bitvm_disprove_root_hash {
            Some(ref hash) => Ok(hash),
            None => {
                let bitvm_hash = self
                    .db
                    .get_bitvm_root_hash(
                        None,
                        self.operator_idx as i32,
                        self.deposit_data.deposit_outpoint,
                    )
                    .await?
                    .ok_or(BridgeError::BitvmSetupNotFound(
                        self.operator_idx as i32,
                        self.deposit_data.deposit_outpoint.txid,
                    ))?;
                self.bitvm_disprove_root_hash = Some(bitvm_hash);
                Ok(self
                    .bitvm_disprove_root_hash
                    .as_ref()
                    .expect("Inserted before"))
            }
        }
    }
}

pub async fn create_txhandlers(
    config: BridgeConfig,
    deposit: DepositData,
    nofn_xonly_pk: XOnlyPublicKey,
    transaction_type: TransactionType,
    kickoff_id: KickoffId,
    operator_data: OperatorData,
    prev_reimburse_generator: Option<TxHandler>,
    db_data: &mut TxHandlerDbData,
) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
    let mut txhandlers = BTreeMap::new();

    // Create move_tx handler. This is unique for each deposit tx.
    // Technically this can be also given as a parameter because it is calculated repeatedly in streams
    let move_txhandler = builder::transaction::create_move_to_vault_txhandler(
        deposit.deposit_outpoint,
        deposit.evm_address,
        &deposit.recovery_taproot_address,
        nofn_xonly_pk,
        config.user_takes_after,
        config.bridge_amount_sats,
        config.network,
    )?;
    txhandlers.insert(move_txhandler.get_transaction_type(), move_txhandler);

    let kickoff_winternitz_keys = db_data.get_kickoff_winternitz_keys().await?;

    let (
        sequential_collateral_txhandler,
        ready_to_reimburse_txhandler,
        reimburse_generator_txhandler,
    ) = match prev_reimburse_generator {
        Some(prev_reimburse_generator) => {
            let sequential_collateral_txhandler =
                builder::transaction::create_sequential_collateral_txhandler(
                    operator_data.xonly_pk,
                    *prev_reimburse_generator
                        .get_spendable_output(0)?
                        .get_prev_outpoint(),
                    prev_reimburse_generator
                        .get_spendable_output(0)?
                        .get_prevout()
                        .value,
                    config.timeout_block_count,
                    config.num_kickoffs_per_sequential_collateral_tx,
                    config.network,
                    kickoff_winternitz_keys
                        .get_keys_for_seq_col(kickoff_id.sequential_collateral_idx as usize),
                )?;

            let ready_to_reimburse_txhandler =
                builder::transaction::create_ready_to_reimburse_txhandler(
                    &sequential_collateral_txhandler,
                    operator_data.xonly_pk,
                    config.network,
                )?;

            // Create the reimburse_generator_tx handler.
            let reimburse_generator_txhandler =
                builder::transaction::create_reimburse_generator_txhandler(
                    &ready_to_reimburse_txhandler,
                    operator_data.xonly_pk,
                    config.num_kickoffs_per_sequential_collateral_tx,
                    config.network,
                )?;
            (
                sequential_collateral_txhandler,
                ready_to_reimburse_txhandler,
                reimburse_generator_txhandler,
            )
        }
        None => {
            // create nth sequential collateral tx and reimburse generator tx for the operator
            let (
                sequential_collateral_txhandler,
                ready_to_reimburse_txhandler,
                reimburse_generator_txhandler,
            ) = builder::transaction::create_seq_collat_reimburse_gen_nth_txhandler(
                operator_data.xonly_pk,
                operator_data.collateral_funding_outpoint,
                config.collateral_funding_amount,
                config.timeout_block_count,
                config.num_kickoffs_per_sequential_collateral_tx,
                config.network,
                kickoff_id.sequential_collateral_idx as usize,
                kickoff_winternitz_keys,
            )?;
            (
                sequential_collateral_txhandler,
                ready_to_reimburse_txhandler,
                reimburse_generator_txhandler,
            )
        }
    };

    txhandlers.insert(
        sequential_collateral_txhandler.get_transaction_type(),
        sequential_collateral_txhandler,
    );
    txhandlers.insert(
        ready_to_reimburse_txhandler.get_transaction_type(),
        ready_to_reimburse_txhandler,
    );
    txhandlers.insert(
        reimburse_generator_txhandler.get_transaction_type(),
        reimburse_generator_txhandler,
    );

    let kickoff_txhandler = builder::transaction::create_kickoff_txhandler(
        get_txhandler(&txhandlers, TransactionType::SequentialCollateral)?,
        kickoff_id.kickoff_idx as usize,
        nofn_xonly_pk,
        operator_data.xonly_pk,
        *get_txhandler(&txhandlers, TransactionType::MoveToVault)?.get_txid(),
        kickoff_id.operator_idx as usize,
        config.network,
    )?;
    txhandlers.insert(kickoff_txhandler.get_transaction_type(), kickoff_txhandler);

    let kickoff_utxo_timeout_txhandler =
        builder::transaction::create_kickoff_utxo_timeout_txhandler(
            get_txhandler(&txhandlers, TransactionType::SequentialCollateral)?,
            kickoff_id.kickoff_idx as usize,
        )?;
    txhandlers.insert(
        kickoff_utxo_timeout_txhandler.get_transaction_type(),
        kickoff_utxo_timeout_txhandler,
    );

    // Creates the kickoff_timeout_tx handler.
    let kickoff_timeout_txhandler = builder::transaction::create_assert_timeout_txhandler(
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        get_txhandler(&txhandlers, TransactionType::SequentialCollateral)?,
    )?;
    txhandlers.insert(
        kickoff_timeout_txhandler.get_transaction_type(),
        kickoff_timeout_txhandler,
    );

    // Creates the challenge_tx handler.
    let challenge_txhandler = builder::transaction::create_challenge_txhandler(
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        &operator_data.reimburse_addr,
    )?;
    txhandlers.insert(
        challenge_txhandler.get_transaction_type(),
        challenge_txhandler,
    );

    let kickoff_not_finalized_txhandler =
        builder::transaction::create_kickoff_not_finalized_txhandler(
            get_txhandler(&txhandlers, TransactionType::Kickoff)?,
            get_txhandler(&txhandlers, TransactionType::SequentialCollateral)?,
        )?;
    txhandlers.insert(
        kickoff_not_finalized_txhandler.get_transaction_type(),
        kickoff_not_finalized_txhandler,
    );

    // Generate Happy reimburse txs conditionally
    if matches!(
        transaction_type,
        TransactionType::StartHappyReimburse
            | TransactionType::HappyReimburse
            | TransactionType::AllNeededForVerifierDeposit
    ) {
        // Creates the start_happy_reimburse_tx handler.
        let start_happy_reimburse_txhandler =
            builder::transaction::create_start_happy_reimburse_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                operator_data.xonly_pk,
                config.network,
            )?;
        txhandlers.insert(
            start_happy_reimburse_txhandler.get_transaction_type(),
            start_happy_reimburse_txhandler,
        );

        // Creates the happy_reimburse_tx handler.
        let happy_reimburse_txhandler = builder::transaction::create_happy_reimburse_txhandler(
            get_txhandler(&txhandlers, TransactionType::MoveToVault)?,
            get_txhandler(&txhandlers, TransactionType::StartHappyReimburse)?,
            get_txhandler(&txhandlers, TransactionType::ReimburseGenerator)?,
            kickoff_id.kickoff_idx as usize,
            &operator_data.reimburse_addr,
        )?;
        txhandlers.insert(
            happy_reimburse_txhandler.get_transaction_type(),
            happy_reimburse_txhandler,
        );

        if !matches!(
            transaction_type,
            TransactionType::AllNeededForOperatorDeposit
                | TransactionType::AllNeededForVerifierDeposit
        ) {
            // We do not need other txhandlers, exit early
            return Ok(txhandlers);
        }
    }

    // Generate watchtower challenges (addresses from db) if all txs are needed
    if matches!(
        transaction_type,
        TransactionType::AllNeededForVerifierDeposit
            | TransactionType::WatchtowerChallengeKickoff
            | TransactionType::WatchtowerChallenge(_)
            | TransactionType::OperatorChallengeNack(_)
            | TransactionType::OperatorChallengeAck(_)
    ) {
        let needed_watchtower_idx: i32 =
            if let TransactionType::WatchtowerChallenge(idx) = transaction_type {
                idx as i32
            } else {
                -1
            };

        let watchtower_challenge_addr = db_data.get_watchtower_challenge_addr().await?;

        // Each watchtower will sign their Groth16 proof of the header chain circuit. Then, the operator will either
        // - acknowledge the challenge by sending the operator_challenge_ACK_tx, which will prevent the burning of the kickoff_tx.output[2],
        // - or do nothing, which will cause one to send the operator_challenge_NACK_tx, which will burn the kickoff_tx.output[2]
        // using watchtower_challenge_tx.output[0].

        let watchtower_challenge_kickoff_txhandler =
            builder::transaction::create_watchtower_challenge_kickoff_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                config.num_watchtowers as u32,
                watchtower_challenge_addr,
            )?;
        txhandlers.insert(
            watchtower_challenge_kickoff_txhandler.get_transaction_type(),
            watchtower_challenge_kickoff_txhandler,
        );

        let public_hashes = db_data.get_challenge_ack_hashes().await?;

        // Each watchtower will sign their Groth16 proof of the header chain circuit. Then, the operator will either
        // - acknowledge the challenge by sending the operator_challenge_ACK_tx, which will prevent the burning of the kickoff_tx.output[2],
        // - or do nothing, which will cause one to send the operator_challenge_NACK_tx, which will burn the kickoff_tx.output[2]
        // using watchtower_challenge_tx.output[0].
        for (watchtower_idx, public_hash) in public_hashes.iter().enumerate() {
            let watchtower_challenge_txhandler = if watchtower_idx as i32 != needed_watchtower_idx {
                // create it with db if we don't need actual winternitz script
                builder::transaction::create_watchtower_challenge_txhandler(
                    get_txhandler(&txhandlers, TransactionType::WatchtowerChallengeKickoff)?,
                    watchtower_idx,
                    public_hash,
                    nofn_xonly_pk,
                    operator_data.xonly_pk,
                    config.network,
                    None,
                )?
            } else {
                // generate with actual scripts if we want to specifically create a watchtower challenge tx
                let path =
                    WatchtowerChallenge(kickoff_id.operator_idx, deposit.deposit_outpoint.txid);

                let actor = Actor::new(
                    config.secret_key,
                    config.winternitz_secret_key,
                    config.network,
                );
                let public_key = actor.derive_winternitz_pk(path)?;

                builder::transaction::create_watchtower_challenge_txhandler(
                    get_txhandler(&txhandlers, TransactionType::WatchtowerChallengeKickoff)?,
                    watchtower_idx,
                    public_hash,
                    nofn_xonly_pk,
                    operator_data.xonly_pk,
                    config.network,
                    Some(Arc::new(WinternitzCommit::new(
                        public_key,
                        actor.xonly_public_key,
                        WATCHTOWER_CHALLENGE_MESSAGE_LENGTH,
                    ))),
                )?
            };
            txhandlers.insert(
                watchtower_challenge_txhandler.get_transaction_type(),
                watchtower_challenge_txhandler,
            );
            // Creates the operator_challenge_NACK_tx handler.
            let operator_challenge_nack_txhandler =
                builder::transaction::create_operator_challenge_nack_txhandler(
                    get_txhandler(
                        &txhandlers,
                        TransactionType::WatchtowerChallenge(watchtower_idx),
                    )?,
                    watchtower_idx,
                    get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                )?;
            txhandlers.insert(
                operator_challenge_nack_txhandler.get_transaction_type(),
                operator_challenge_nack_txhandler,
            );

            if let TransactionType::OperatorChallengeAck(index) = transaction_type {
                // only create this if we specifically want to generate the Operator Challenge ACK tx
                if index == watchtower_idx {
                    let operator_challenge_ack_txhandler =
                        builder::transaction::create_operator_challenge_ack_txhandler(
                            get_txhandler(
                                &txhandlers,
                                TransactionType::WatchtowerChallenge(watchtower_idx),
                            )?,
                            watchtower_idx,
                        )?;

                    txhandlers.insert(
                        operator_challenge_ack_txhandler.get_transaction_type(),
                        operator_challenge_ack_txhandler,
                    );
                }
            }
        }
        if transaction_type != TransactionType::AllNeededForVerifierDeposit {
            // We do not need other txhandlers, exit early
            return Ok(txhandlers);
        }
    }

    // If we didn't return until this part, generate remaining assert/disprove tx's

    if matches!(
        transaction_type,
        TransactionType::AssertBegin | TransactionType::AssertEnd | TransactionType::MiniAssert(_)
    ) {
        // if we specifically want to generate assert txs, we need to generate correct Winternitz scripts
        let actor = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.network,
        );
        let mut assert_scripts: Vec<Arc<dyn SpendableScript>> =
            Vec::with_capacity(utils::BITVM_CACHE.intermediate_variables.len());
        for (intermediate_step, intermediate_step_size) in
            utils::BITVM_CACHE.intermediate_variables.iter()
        {
            let path = WinternitzDerivationPath::BitvmAssert(
                *intermediate_step_size as u32 * 2,
                intermediate_step.to_string(),
                deposit.deposit_outpoint.txid,
            );
            let pk = actor.derive_winternitz_pk(path)?;
            assert_scripts.push(Arc::new(WinternitzCommit::new(
                pk,
                operator_data.xonly_pk,
                *intermediate_step_size as u32 * 2,
            )));
        }
        // Creates the assert_begin_tx handler.
        let assert_begin_txhandler =
            builder::transaction::create_assert_begin_txhandler_from_scripts(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                &assert_scripts,
                config.network,
            )?;

        txhandlers.insert(
            assert_begin_txhandler.get_transaction_type(),
            assert_begin_txhandler,
        );

        let root_hash = db_data.get_bitvm_disprove_root_hash().await?;

        // Creates the assert_end_tx handler.
        let mini_asserts_and_assert_end_txhandlers =
            builder::transaction::create_mini_asserts_and_assert_end_from_scripts(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                get_txhandler(&txhandlers, TransactionType::AssertBegin)?,
                &assert_scripts,
                root_hash,
                nofn_xonly_pk,
                operator_data.xonly_pk,
                config.network,
            )?;
        for txhandler in mini_asserts_and_assert_end_txhandlers {
            txhandlers.insert(txhandler.get_transaction_type(), txhandler);
        }
    } else {
        let root_hash = *db_data.get_bitvm_disprove_root_hash().await?;
        let assert_tx_addrs = db_data.get_bitvm_assert_addr().await?;

        // Creates the assert_begin_tx handler.
        let assert_begin_txhandler = builder::transaction::create_assert_begin_txhandler(
            get_txhandler(&txhandlers, TransactionType::Kickoff)?,
            assert_tx_addrs,
            config.network,
        )?;

        txhandlers.insert(
            assert_begin_txhandler.get_transaction_type(),
            assert_begin_txhandler,
        );

        // Creates the assert_end_tx handler.
        let assert_end_txhandler = builder::transaction::create_assert_end_txhandler(
            get_txhandler(&txhandlers, TransactionType::Kickoff)?,
            get_txhandler(&txhandlers, TransactionType::AssertBegin)?,
            assert_tx_addrs,
            &root_hash,
            nofn_xonly_pk,
            operator_data.xonly_pk,
            config.network,
        )?;

        txhandlers.insert(
            assert_end_txhandler.get_transaction_type(),
            assert_end_txhandler,
        );
    }

    // Creates the disprove_timeout_tx handler.
    let disprove_timeout_txhandler = builder::transaction::create_disprove_timeout_txhandler(
        get_txhandler(&txhandlers, TransactionType::AssertEnd)?,
        get_txhandler(&txhandlers, TransactionType::Kickoff)?,
        operator_data.xonly_pk,
        config.network,
    )?;

    txhandlers.insert(
        disprove_timeout_txhandler.get_transaction_type(),
        disprove_timeout_txhandler,
    );

    // Creates the already_disproved_tx handler.
    let already_disproved_txhandler = builder::transaction::create_already_disproved_txhandler(
        get_txhandler(&txhandlers, TransactionType::AssertEnd)?,
        get_txhandler(&txhandlers, TransactionType::SequentialCollateral)?,
    )?;

    txhandlers.insert(
        already_disproved_txhandler.get_transaction_type(),
        already_disproved_txhandler,
    );

    // Creates the reimburse_tx handler.
    let reimburse_txhandler = builder::transaction::create_reimburse_txhandler(
        get_txhandler(&txhandlers, TransactionType::MoveToVault)?,
        get_txhandler(&txhandlers, TransactionType::DisproveTimeout)?,
        get_txhandler(&txhandlers, TransactionType::ReimburseGenerator)?,
        kickoff_id.kickoff_idx as usize,
        &operator_data.reimburse_addr,
    )?;

    txhandlers.insert(
        reimburse_txhandler.get_transaction_type(),
        reimburse_txhandler,
    );

    match transaction_type {
        TransactionType::AllNeededForOperatorDeposit => {
            let disprove_txhandler = builder::transaction::create_disprove_txhandler(
                get_txhandler(&txhandlers, TransactionType::AssertEnd)?,
                get_txhandler(&txhandlers, TransactionType::SequentialCollateral)?,
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

#[cfg(test)]
mod tests {
    use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
    use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
    use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
    use crate::test_utils::BITCOIN_STARTUP_MUTEX;
    use crate::{
        config::BridgeConfig,
        create_test_config_with_thread_name,
        database::Database,
        errors::BridgeError,
        initialize_database,
        rpc::clementine::DepositParams,
        servers::{
            create_aggregator_grpc_server, create_operator_grpc_server,
            create_verifier_grpc_server, create_watchtower_grpc_server,
        },
        utils,
        utils::initialize_logger,
        EVMAddress,
    };
    use crate::{
        create_actors, create_regtest_rpc,
        extended_rpc::ExtendedRpc,
        get_available_port,
        rpc::clementine::{self, clementine_aggregator_client::ClementineAggregatorClient},
    };
    use bitcoin::Txid;
    use futures::future::try_join_all;
    use std::panic;

    use crate::builder::transaction::TransactionType;
    use crate::constants::{
        KICKOFF_BLOCKHASH_COMMIT_LENGTH, WATCHTOWER_CHALLENGE_MESSAGE_LENGTH, WINTERNITZ_LOG_D,
    };
    use crate::rpc::clementine::{AssertRequest, KickoffId, TransactionRequest};
    use std::str::FromStr;

    #[tokio::test(flavor = "multi_thread")]

    async fn test_deposit_and_sign_txs() {
        let config = create_test_config_with_thread_name!(None);

        let (mut verifiers, mut operators, mut aggregator, mut watchtowers, _regtest) =
            create_actors!(config);

        tracing::info!("Setting up aggregator");
        let start = std::time::Instant::now();

        aggregator
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap();

        tracing::info!("Setup completed in {:?}", start.elapsed());
        tracing::info!("Depositing");
        let deposit_start = std::time::Instant::now();
        let deposit_outpoint = bitcoin::OutPoint {
            txid: Txid::from_str(
                "17e3fc7aae1035e77a91e96d1ba27f91a40a912cf669b367eb32c13a8f82bb02",
            )
            .unwrap(),
            vout: 0,
        };
        let recovery_taproot_address = bitcoin::Address::from_str(
            "tb1pk8vus63mx5zwlmmmglq554kwu0zm9uhswqskxg99k66h8m3arguqfrvywa",
        )
        .unwrap();
        let recovery_addr_checked = recovery_taproot_address.assume_checked();
        let evm_address = EVMAddress([1u8; 20]);

        let deposit_params = DepositParams {
            deposit_outpoint: Some(deposit_outpoint.into()),
            evm_address: evm_address.0.to_vec(),
            recovery_taproot_address: recovery_addr_checked.to_string(),
        };

        aggregator
            .new_deposit(deposit_params.clone())
            .await
            .unwrap();
        tracing::info!("Deposit completed in {:?}", deposit_start.elapsed());

        let mut txs_operator_can_sign = vec![
            TransactionType::SequentialCollateral,
            TransactionType::ReadyToReimburse,
            TransactionType::ReimburseGenerator,
            TransactionType::Kickoff,
            TransactionType::KickoffNotFinalized,
            TransactionType::Challenge,
            TransactionType::AssertTimeout,
            TransactionType::KickoffUtxoTimeout,
            TransactionType::WatchtowerChallengeKickoff,
            TransactionType::StartHappyReimburse,
            TransactionType::HappyReimburse,
            TransactionType::AssertBegin,
            TransactionType::AssertEnd,
            //TransactionType::Disprove, TODO: add when we add actual disprove scripts
            TransactionType::DisproveTimeout,
            TransactionType::AlreadyDisproved,
            TransactionType::Reimburse,
            TransactionType::MiniAssert(0),
        ];
        txs_operator_can_sign
            .extend((0..config.num_watchtowers).map(TransactionType::OperatorChallengeNack));
        txs_operator_can_sign
            .extend((0..config.num_watchtowers).map(TransactionType::OperatorChallengeAck));

        let full_commit_data = utils::BITVM_CACHE
            .intermediate_variables
            .values()
            .map(|len| vec![1u8; *len])
            .collect::<Vec<_>>();

        // try to sign everything for all operators
        let thread_handles: Vec<_> = operators
            .iter_mut()
            .enumerate()
            .map(|(operator_idx, operator_rpc)| {
                let txs_operator_can_sign = txs_operator_can_sign.clone();
                let deposit_params = deposit_params.clone();
                let full_commit_data = full_commit_data.clone();
                let mut operator_rpc = operator_rpc.clone();
                async move {
                    for sequential_collateral_idx in 0..config.num_sequential_collateral_txs {
                        for kickoff_idx in 0..config.num_kickoffs_per_sequential_collateral_tx {
                            let kickoff_id = KickoffId {
                                operator_idx: operator_idx as u32,
                                sequential_collateral_idx: sequential_collateral_idx as u32,
                                kickoff_idx: kickoff_idx as u32,
                            };
                            for tx_type in &txs_operator_can_sign {
                                let _raw_tx = operator_rpc
                                    .internal_create_signed_tx(TransactionRequest {
                                        deposit_params: deposit_params.clone().into(),
                                        transaction_type: Some((*tx_type).into()),
                                        kickoff_id: Some(kickoff_id),
                                        commit_data: if let TransactionType::MiniAssert(
                                            assert_idx,
                                        ) = tx_type
                                        {
                                            full_commit_data[*assert_idx].clone()
                                        } else if *tx_type == TransactionType::Kickoff {
                                            vec![
                                                1u8;
                                                KICKOFF_BLOCKHASH_COMMIT_LENGTH as usize
                                                    * WINTERNITZ_LOG_D as usize
                                                    / 8
                                            ]
                                        } else {
                                            vec![]
                                        },
                                    })
                                    .await
                                    .unwrap();
                                tracing::info!("Operator Signed tx: {:?}", tx_type);
                            }
                            // TODO: run with release after bitvm optimization? all raw tx's don't fit 4mb (grpc limit) for now
                            #[cfg(debug_assertions)]
                            {
                                let _raw_assert_txs = operator_rpc
                                    .internal_create_assert_commitment_txs(AssertRequest {
                                        deposit_params: deposit_params.clone().into(),
                                        kickoff_id: Some(kickoff_id),
                                        commit_data: full_commit_data.clone(),
                                    })
                                    .await
                                    .unwrap()
                                    .into_inner()
                                    .raw_txs;
                                tracing::info!(
                                    "Operator Signed Assert txs of size: {}",
                                    _raw_assert_txs.len()
                                );
                            }
                        }
                    }
                }
            })
            .map(tokio::task::spawn)
            .collect();

        // try signing watchtower challenges for all watchtowers
        let watchtower_thread_handles: Vec<_> = watchtowers
            .iter_mut()
            .enumerate()
            .map(|(watchtower_idx, watchtower_rpc)| {
                let deposit_params = deposit_params.clone();
                let mut watchtower_rpc = watchtower_rpc.clone();
                async move {
                    for operator_idx in 0..config.num_operators {
                        for sequential_collateral_idx in 0..config.num_sequential_collateral_txs {
                            for kickoff_idx in 0..config.num_kickoffs_per_sequential_collateral_tx {
                                let kickoff_id = KickoffId {
                                    operator_idx: operator_idx as u32,
                                    sequential_collateral_idx: sequential_collateral_idx as u32,
                                    kickoff_idx: kickoff_idx as u32,
                                };
                                let _raw_tx = watchtower_rpc
                                    .internal_create_signed_tx(TransactionRequest {
                                        deposit_params: deposit_params.clone().into(),
                                        transaction_type: Some(
                                            TransactionType::WatchtowerChallenge(watchtower_idx)
                                                .into(),
                                        ),
                                        kickoff_id: Some(kickoff_id),
                                        commit_data: vec![
                                            1u8;
                                            WATCHTOWER_CHALLENGE_MESSAGE_LENGTH
                                                as usize
                                                * WINTERNITZ_LOG_D as usize
                                                / 8
                                        ],
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
            TransactionType::AssertTimeout,
            TransactionType::KickoffUtxoTimeout,
            TransactionType::KickoffNotFinalized,
            TransactionType::WatchtowerChallengeKickoff,
            //TransactionType::Disprove,
            TransactionType::DisproveTimeout,
            TransactionType::AlreadyDisproved,
        ];
        txs_verifier_can_sign
            .extend((0..config.num_watchtowers).map(TransactionType::OperatorChallengeNack));

        // try to sign everything for all verifiers
        // try signing verifier transactions
        let verifier_thread_handles: Vec<_> = verifiers
            .iter_mut()
            .map(|verifier_rpc| {
                let txs_verifier_can_sign = txs_verifier_can_sign.clone();
                let deposit_params = deposit_params.clone();
                let mut verifier_rpc = verifier_rpc.clone();
                async move {
                    for operator_idx in 0..config.num_operators {
                        for sequential_collateral_idx in 0..config.num_sequential_collateral_txs {
                            for kickoff_idx in 0..config.num_kickoffs_per_sequential_collateral_tx {
                                let kickoff_id = KickoffId {
                                    operator_idx: operator_idx as u32,
                                    sequential_collateral_idx: sequential_collateral_idx as u32,
                                    kickoff_idx: kickoff_idx as u32,
                                };
                                for tx_type in &txs_verifier_can_sign {
                                    let _raw_tx = verifier_rpc
                                        .internal_create_signed_tx(TransactionRequest {
                                            deposit_params: deposit_params.clone().into(),
                                            transaction_type: Some((*tx_type).into()),
                                            kickoff_id: Some(kickoff_id),
                                            commit_data: vec![],
                                        })
                                        .await
                                        .unwrap();
                                    tracing::info!("Verifier Signed tx: {:?}", tx_type);
                                }
                            }
                        }
                    }
                }
            })
            .map(tokio::task::spawn)
            .collect();

        try_join_all(thread_handles).await.unwrap();
        try_join_all(watchtower_thread_handles).await.unwrap();
        try_join_all(verifier_thread_handles).await.unwrap();
    }
}
