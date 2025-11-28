use crate::config::BridgeConfig;
use crate::database::DatabaseTransaction;
use crate::deposit::{DepositData, KickoffData};
use crate::operator::RoundIndex;
use crate::utils::NamedEntity;

use bitcoin::BlockHash;
use bitcoin::Transaction;
use bitcoin::Txid;
use bitcoin::Witness;
use bitcoin::XOnlyPublicKey;
use statig::awaitable::InitializedStateMachine;
use tokio::sync::Mutex;
use tonic::async_trait;

use std::collections::HashMap;
use std::sync::Arc;

use crate::builder::transaction::TxHandler;

use std::collections::BTreeMap;

use crate::builder::transaction::ContractContext;

use crate::builder::transaction::TransactionType;

use crate::errors::BridgeError;

use std::collections::HashSet;

use super::block_cache;
use super::kickoff;
use super::round;

#[derive(Debug, Clone)]
/// Duties are notifications that are sent to the owner (verifier or operator) of the state machine to notify them on changes to the current
/// contract state that require action.
/// Note that for all kickoff state duties, they are only sent if withdrawal process is still going on, meaning the burn connector and
/// kickoff finalizer is still on-chain/unspent.
pub enum Duty {
    /// -- Round state duties --
    /// This duty is sent after a new ready to reimburse tx is sent by the corresponding operator.
    /// used_kickoffs is a set of kickoff indexes that have been used in the previous round.
    /// If there are unspent kickoffs, the owner can send a unspent kickoff connector tx.
    NewReadyToReimburse {
        round_idx: RoundIndex,
        operator_xonly_pk: XOnlyPublicKey,
        used_kickoffs: HashSet<usize>,
    },
    /// This duty is sent after a kickoff utxo is spent by the operator.
    /// It includes the txid in which the utxo was spent, so that the owner can verify if this is an actual kickoff sent by operator.
    /// Witness is also sent as if tx is an actual kickoff, the witness includes payout blockhash.
    CheckIfKickoff {
        txid: Txid,
        block_height: u32,
        witness: Witness,
        challenged_before: bool,
    },
    /// -- Kickoff state duties --
    /// This duty is only sent if a kickoff was challenged.
    /// This duty is sent after some time (config.time_to_send_watchtower_challenge number of blocks) passes after a kickoff was sent to chain.
    /// It denotes to the owner that it is time to send a watchtower challenge to the corresponding kickoff.
    WatchtowerChallenge {
        kickoff_data: KickoffData,
        deposit_data: DepositData,
    },
    /// This duty is only sent if a kickoff was challenged.
    /// This duty is sent only after latest blockhash is committed. Latest blockhash is committed after all watchtower challenges are sent
    /// or timed out so that it is certain no new watchtower challenges can be sent.
    /// The duty denotes that it is time to start sending operator asserts to the corresponding kickoff.
    /// It includes the all watchtower challenges and the payout blockhash so that they can be used in the proof.
    SendOperatorAsserts {
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        watchtower_challenges: HashMap<usize, Transaction>,
        payout_blockhash: Witness,
        latest_blockhash: Witness,
    },
    /// This duty is only sent if a kickoff was challenged.
    /// This duty is sent after all asserts and latest blockhash commit are finalized on chain, and all watchtower challenge
    /// utxos are spent.
    /// It denotes to the owner that it is time to send a disprove to the corresponding kickoff.
    /// It includes the operator asserts, operator acks and the payout blockhash so that they can be used in the disprove tx if the proof
    /// is invalid.
    VerifierDisprove {
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        operator_asserts: HashMap<usize, Witness>,
        operator_acks: HashMap<usize, Witness>,
        payout_blockhash: Witness,
        latest_blockhash: Witness,
    },
    /// This duty is only sent if a kickoff was challenged.
    /// This duty is sent after every watchtower challenge is either sent or timed out.
    /// It denotes to the owner that it is time to send a latest blockhash to the corresponding kickoff to be used in the proof.
    SendLatestBlockhash {
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        latest_blockhash: BlockHash,
    },
}

/// Result of handling a duty
#[derive(Debug, Clone)]
pub enum DutyResult {
    /// Duty was handled, no return value is necessary
    Handled,
    /// Result of checking if a kickoff contains if a challenge was sent because the kickoff was determined as malicious
    CheckIfKickoff { challenged: bool },
}

/// Owner trait with async handling and tx handler creation
#[async_trait]
pub trait Owner: Clone + NamedEntity {
    /// Handle a protocol-related duty
    async fn handle_duty(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        duty: Duty,
    ) -> Result<DutyResult, BridgeError>;

    /// Create the transactions for an instance of the L1 contract
    async fn create_txhandlers(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        tx_type: TransactionType,
        contract_context: ContractContext,
    ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError>;

    /// Handle a new finalized block
    async fn handle_finalized_block(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        block_height: u32,
        block_cache: Arc<block_cache::BlockCache>,
        _light_client_proof_wait_interval_secs: Option<u32>,
    ) -> Result<(), BridgeError>;

    /// Check if a kickoff is relevant for the owner
    /// For verifiers, all kickoffs are relevant
    /// For operators, only kickoffs of their own are relevant, which will be checked by a trait fn override
    fn is_kickoff_relevant_for_owner(&self, _kickoff_data: &KickoffData) -> bool {
        true
    }
}

/// Context for the state machine
/// Every state can access the context
#[derive(Debug, Clone)]
pub struct StateContext<T: Owner> {
    pub owner: Arc<T>,
    pub cache: Arc<block_cache::BlockCache>,
    pub new_round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
    pub new_kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
    pub errors: Vec<Arc<eyre::Report>>,
    pub config: BridgeConfig,
    pub owner_type: String,
    pub shared_dbtx: Arc<Mutex<sqlx::Transaction<'static, sqlx::Postgres>>>,
}

impl<T: Owner> StateContext<T> {
    pub fn new(
        shared_dbtx: Arc<Mutex<sqlx::Transaction<'static, sqlx::Postgres>>>,
        owner: Arc<T>,
        cache: Arc<block_cache::BlockCache>,
        config: BridgeConfig,
    ) -> Self {
        // Get the owner type string from the owner instance
        let owner_type = T::ENTITY_NAME.to_string();

        Self {
            shared_dbtx,
            owner,
            cache,
            new_round_machines: Vec::new(),
            new_kickoff_machines: Vec::new(),
            errors: Vec::new(),
            config,
            owner_type,
        }
    }

    pub async fn dispatch_duty(&self, duty: Duty) -> Result<DutyResult, BridgeError> {
        let mut guard = self.shared_dbtx.lock().await;
        self.owner.handle_duty(&mut guard, duty).await
    }

    /// Run an async closure and capture any errors in execution.
    ///
    /// It will store the error report in the context's `errors` field. The
    /// errors are later collected by the state manager and reported. This
    /// ensures that all errors are collected and reported in a single place.
    /// In general, it's expected that the closure attaches context about the
    /// state machine to the error report.  You may check
    /// `KickoffStateMachine::wrap_err` and `RoundStateMachine::wrap_err`
    /// for an example implementation of an error wrapper utility function.
    ///
    /// # Parameters
    /// * `fnc`: An async closure that takes a mutable reference to the state context and returns a result.
    ///
    /// # Returns
    /// * `()`
    pub async fn capture_error(
        &mut self,
        fnc: impl AsyncFnOnce(&mut Self) -> Result<(), eyre::Report>,
    ) {
        let result = fnc(self).await;
        if let Err(e) = result {
            self.errors.push(e.into());
        }
    }
}
