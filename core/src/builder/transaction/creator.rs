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
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::operator::PublicHash;
use crate::rpc::clementine::KickoffId;
use bitcoin::secp256k1::SecretKey;
use bitcoin::XOnlyPublicKey;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::RoundTxInput;

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
    pub deposit_data: DepositData,
    pub paramset: &'static ProtocolParamset,
    actor_secret_key: SecretKey,
    winternitz_secret_key: Option<SecretKey>,
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
}

impl ReimburseDbCache {
    pub fn new(
        db: Database,
        operator_idx: u32,
        deposit_data: DepositData,
        config: &BridgeConfig,
    ) -> Self {
        Self {
            db,
            operator_idx,
            deposit_data,
            paramset: config.protocol_paramset(),
            actor_secret_key: config.secret_key,
            winternitz_secret_key: config.winternitz_secret_key,
            watchtower_challenge_hashes: None,
            kickoff_winternitz_keys: None,
            bitvm_assert_addr: None,
            bitvm_disprove_root_hash: None,
            challenge_ack_hashes: None,
        }
    }
    pub async fn watchtower_challenge_hash(&mut self) -> Result<&[[u8; 32]], BridgeError> {
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
                            self.deposit_data.deposit_outpoint,
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

#[tracing::instrument(skip_all, err, fields(deposit_data = ?db_cache.deposit_data, txtype = ?transaction_type, ?kickoff_id))]
pub async fn create_txhandlers(
    nofn_xonly_pk: XOnlyPublicKey,
    transaction_type: TransactionType,
    kickoff_id: KickoffId,
    operator_data: OperatorData,
    prev_ready_to_reimburse: Option<TxHandler>,
    db_cache: &mut ReimburseDbCache,
) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
    let mut txhandlers = BTreeMap::new();

    let ReimburseDbCache {
        deposit_data,
        paramset,
        actor_secret_key,
        winternitz_secret_key,
        ..
    } = db_cache.clone();

    // Create move_tx handler. This is unique for each deposit tx.
    // Technically this can be also given as a parameter because it is calculated repeatedly in streams
    let move_txhandler = builder::transaction::create_move_to_vault_txhandler(
        deposit_data.deposit_outpoint,
        deposit_data.evm_address,
        &deposit_data.recovery_taproot_address,
        nofn_xonly_pk,
        paramset.user_takes_after,
        paramset.bridge_amount,
        paramset.network,
    )?;
    txhandlers.insert(move_txhandler.get_transaction_type(), move_txhandler);

    let kickoff_winternitz_keys = db_cache.get_kickoff_winternitz_keys().await?;

    // create round tx, ready to reimburse tx, and unspent kickoff txs
    let round_txhandlers = create_round_txhandlers(
        paramset,
        kickoff_id.round_idx as usize,
        &operator_data,
        kickoff_winternitz_keys,
        prev_ready_to_reimburse,
    )?;

    for round_txhandler in round_txhandlers.into_iter() {
        txhandlers.insert(round_txhandler.get_transaction_type(), round_txhandler);
    }

    // get the next round txhandler (because reimburse connectors will be in it)
    let next_round_txhandler = create_round_txhandler(
        operator_data.xonly_pk,
        RoundTxInput::Prevout(
            get_txhandler(&txhandlers, TransactionType::ReadyToReimburse)?
                .get_spendable_output(0)?,
        ),
        kickoff_winternitz_keys.get_keys_for_round(kickoff_id.round_idx as usize + 1),
        paramset,
    )?;

    let num_asserts = ClementineBitVMPublicKeys::number_of_assert_txs();
    let public_hashes = db_cache.get_challenge_ack_hashes().await?.to_vec();
    let watchtower_challenge_hashes = db_cache.watchtower_challenge_hash().await?.to_vec();

    let kickoff_txhandler = if let TransactionType::MiniAssert(_) = transaction_type {
        // create scripts if any mini assert tx is specifically requested as it needs
        // the actual scripts to be able to spend
        let actor = Actor::new(actor_secret_key, winternitz_secret_key, paramset.network);

        // deposit_data.deposit_outpoint.txid

        let bitvm_pks =
            actor.generate_bitvm_pks_for_deposit(deposit_data.deposit_outpoint.txid, paramset)?;

        let assert_scripts = bitvm_pks.get_assert_scripts(operator_data.xonly_pk);

        let kickoff_txhandler = create_kickoff_txhandler(
            kickoff_id,
            deposit_data.deposit_outpoint,
            get_txhandler(&txhandlers, TransactionType::Round)?,
            nofn_xonly_pk,
            operator_data.xonly_pk,
            AssertScripts::AssertSpendableScript(assert_scripts),
            db_cache.get_bitvm_disprove_root_hash().await?,
            &watchtower_challenge_hashes,
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
            deposit_data.deposit_outpoint,
            get_txhandler(&txhandlers, TransactionType::Round)?,
            nofn_xonly_pk,
            operator_data.xonly_pk,
            AssertScripts::AssertScriptTapNodeHash(db_cache.get_bitvm_assert_hash().await?),
            &disprove_root_hash,
            &watchtower_challenge_hashes,
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
            get_txhandler(&txhandlers, TransactionType::Round)?,
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

        let actor = Actor::new(actor_secret_key, winternitz_secret_key, paramset.network);
        let public_key = actor.derive_winternitz_pk(path)?;

        let watchtower_challenge_txhandler =
            builder::transaction::create_watchtower_challenge_txhandler(
                get_txhandler(&txhandlers, TransactionType::Kickoff)?,
                watchtower_idx,
                nofn_xonly_pk,
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

/// Function to create next round txhandler, ready to reimburse txhandler,
/// and all unspentkickoff txhandlers for a specific operator
pub fn create_round_txhandlers(
    paramset: &'static ProtocolParamset,
    round_idx: usize,
    operator_data: &OperatorData,
    kickoff_winternitz_keys: &KickoffWinternitzKeys,
    prev_ready_to_reimburse: Option<TxHandler>,
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

    use crate::bitvm_client::ClementineBitVMPublicKeys;
    use crate::rpc::clementine::{self};
    use crate::{rpc::clementine::DepositParams, test::common::*, EVMAddress};
    use bitcoin::Txid;
    use futures::future::try_join_all;

    use crate::builder::transaction::TransactionType;
    use crate::rpc::clementine::{AssertRequest, KickoffId, TransactionRequest};
    use std::str::FromStr;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_deposit_and_sign_txs() {
        let mut config = create_test_config_with_thread_name(None).await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let paramset = config.protocol_paramset();
        let (mut verifiers, mut operators, mut aggregator, mut watchtowers, _cleanup) =
            create_actors(&config).await;

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
        txs_operator_can_sign.extend(
            (0..paramset.num_kickoffs_per_round).map(TransactionType::WatchtowerChallengeTimeout),
        );

        // try to sign everything for all operators
        let operator_task_handles: Vec<_> = operators
            .iter_mut()
            .enumerate()
            .map(|(operator_idx, operator_rpc)| {
                let txs_operator_can_sign = txs_operator_can_sign.clone();
                let deposit_params = deposit_params.clone();
                let mut operator_rpc = operator_rpc.clone();
                async move {
                    for round_idx in 0..paramset.num_round_txs {
                        for kickoff_idx in 0..paramset.num_kickoffs_per_round {
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
                            // TODO: run with release after bitvm optimization? all raw tx's don't fit 4mb (grpc limit) for now
                            #[cfg(debug_assertions)]
                            {
                                let _raw_assert_txs = operator_rpc
                                    .internal_create_assert_commitment_txs(AssertRequest {
                                        deposit_params: deposit_params.clone().into(),
                                        kickoff_id: Some(kickoff_id),
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
        let watchtower_task_handles: Vec<_> = watchtowers
            .iter_mut()
            .enumerate()
            .map(|(watchtower_idx, watchtower_rpc)| {
                let deposit_params = deposit_params.clone();
                let mut watchtower_rpc = watchtower_rpc.clone();
                async move {
                    for operator_idx in 0..config.num_operators {
                        for round_idx in 0..paramset.num_round_txs {
                            for kickoff_idx in 0..paramset.num_kickoffs_per_round {
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
        txs_verifier_can_sign.extend(
            (0..paramset.num_kickoffs_per_round).map(TransactionType::WatchtowerChallengeTimeout),
        );

        // try to sign everything for all verifiers
        // try signing verifier transactions
        let verifier_task_handles: Vec<_> = verifiers
            .iter_mut()
            .map(|verifier_rpc| {
                let txs_verifier_can_sign = txs_verifier_can_sign.clone();
                let deposit_params = deposit_params.clone();
                let mut verifier_rpc = verifier_rpc.clone();
                async move {
                    for operator_idx in 0..config.num_operators {
                        for round_idx in 0..paramset.num_round_txs {
                            for kickoff_idx in 0..paramset.num_kickoffs_per_round {
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
}
