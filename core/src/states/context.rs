use crate::builder::transaction::DepositData;
use crate::config::protocol::ProtocolParamset;
use crate::database::DatabaseTransaction;
use crate::rpc::clementine::KickoffId;

use bitcoin::Txid;
use bitcoin::Witness;
use statig::awaitable::InitializedStateMachine;
use tonic::async_trait;

use std::collections::HashMap;
use std::sync::Arc;

use crate::database::Database;

use crate::builder::transaction::TxHandler;

use std::collections::BTreeMap;

use crate::builder::transaction::ContractContext;

use crate::builder::transaction::TransactionType;

use crate::errors::BridgeError;

use std::collections::HashSet;

use super::block_cache;
use super::kickoff;
use super::round;

// Duty types that can be dispatched
#[derive(Debug, Clone)]
pub enum Duty {
    NewReadyToReimburse {
        round_idx: u32,
        operator_idx: u32,
        used_kickoffs: HashSet<usize>,
    },
    WatchtowerChallenge {
        kickoff_id: KickoffId,
        deposit_data: DepositData,
    },
    SendOperatorAsserts {
        kickoff_id: KickoffId,
        deposit_data: DepositData,
        watchtower_challenges: HashMap<usize, Witness>,
        payout_blockhash: Witness,
    },
    VerifierDisprove {
        kickoff_id: KickoffId,
        deposit_data: DepositData,
        operator_asserts: HashMap<usize, Witness>,
        operator_acks: HashMap<usize, Witness>,
        payout_blockhash: Witness,
    },
    CheckIfKickoff {
        txid: Txid,
        block_height: u32,
        witness: Witness,
    },
}

/// Owner trait with async handling and tx handler creation
#[async_trait]
pub trait Owner: Send + Sync + Clone {
    /// A string identifier for this owner type used to distinguish between
    /// state machines with different owners in the database.
    ///
    /// ## Example
    /// "operator", "watchtower", "verifier", "user"
    const OWNER_TYPE: &'static str;

    /// Handle a duty
    async fn handle_duty(&self, duty: Duty) -> Result<(), BridgeError>;
    async fn create_txhandlers(
        &self,
        tx_type: TransactionType,
        contract_context: ContractContext,
    ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError>;

    async fn handle_finalized_block(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        block_height: u32,
        block_cache: Arc<block_cache::BlockCache>,
        _light_client_proof_wait_interval_secs: Option<u32>,
    ) -> Result<(), BridgeError>;
}

#[derive(Debug, Clone)]
pub struct StateContext<T: Owner> {
    pub db: Database,
    pub owner: Arc<T>,
    pub cache: Arc<block_cache::BlockCache>,
    pub new_round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
    pub new_kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
    pub errors: Vec<Arc<eyre::Report>>,
    pub paramset: &'static ProtocolParamset,
    pub owner_type: String,
}

impl<T: Owner> StateContext<T> {
    pub fn new(
        db: Database,
        owner: Arc<T>,
        cache: Arc<block_cache::BlockCache>,
        paramset: &'static ProtocolParamset,
    ) -> Self {
        // Get the owner type string from the owner instance
        let owner_type = T::OWNER_TYPE.to_string();

        Self {
            db,
            owner,
            cache,
            new_round_machines: Vec::new(),
            new_kickoff_machines: Vec::new(),
            errors: Vec::new(),
            paramset,
            owner_type,
        }
    }

    pub async fn dispatch_duty(&self, duty: Duty) -> Result<(), BridgeError> {
        self.owner.handle_duty(duty).await
    }

    /// Run an async closure and capture any errors in execution.
    ///
    /// It will store the error report in the context's `errors` field. The
    /// errors are later collected by the state manager and reported. This
    /// ensures that all errors are collected and reported in a single place.
    /// In general, it's expected that the closure attaches context about the
    /// state machine to the error report.  You may check
    /// [`KickoffStateMachine::wrap_err`] and [`RoundStateMachine::wrap_err`]
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
