use crate::actor::Actor;
use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder::transaction::TxHandler;
use crate::config::protocol::{ProtocolParamset, ProtocolParamsetExt as _};
use crate::database::{Database, DatabaseTransaction};
use crate::deposit::{DepositData, KickoffData, OperatorData};
use crate::protocol::create;
use crate::protocol::ids::TransactionType;
use bitcoin::{Address, OutPoint, TxOut, XOnlyPublicKey};
use bitvm::clementine::additional_disprove::create_additional_replacable_disprove_script_with_dummy;
use clementine_errors::{BridgeError, KickoffOperatorMismatch, TxError};
use clementine_primitives::{BridgeRound, EVMAddress, PublicHash, UTXO};
use eyre::{Context, OptionExt};
use std::collections::BTreeMap;

pub type TxCache = BTreeMap<TransactionType, TxHandler>;

fn insufficient_context() -> BridgeError {
    TxError::InsufficientContext.into()
}

#[derive(Debug, Clone)]
pub struct WithdrawalData {
    pub input_utxo: UTXO,
    pub output_txout: TxOut,
    pub operator_xonly_pk: XOnlyPublicKey,
}

#[derive(Debug, Clone)]
pub struct ReplacementDepositBuildData {
    pub old_move_txid: bitcoin::Txid,
    pub old_nofn_xonly_pk: XOnlyPublicKey,
    pub input_outpoint: OutPoint,
    pub security_council: crate::deposit::SecurityCouncil,
}

#[derive(Debug, Clone)]
pub struct DepositBuildContext {
    paramset: &'static ProtocolParamset,
    deposit_data: DepositData,
}

impl DepositBuildContext {
    pub fn new(paramset: &'static ProtocolParamset, deposit_data: DepositData) -> Self {
        Self {
            paramset,
            deposit_data,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoundBuildContext {
    paramset: &'static ProtocolParamset,
    round_idx: BridgeRound,
    operator_data: OperatorData,
    kickoff_keys: KickoffWinternitzKeys,
}

impl RoundBuildContext {
    pub fn new(
        paramset: &'static ProtocolParamset,
        round_idx: BridgeRound,
        operator_data: OperatorData,
        kickoff_keys: KickoffWinternitzKeys,
    ) -> Self {
        Self {
            paramset,
            round_idx,
            operator_data,
            kickoff_keys,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KickoffBuildContext {
    paramset: &'static ProtocolParamset,
    deposit_data: DepositData,
    kickoff_data: KickoffData,
    operator_data: OperatorData,
    kickoff_keys: KickoffWinternitzKeys,
    pub assert_script_hashes: Vec<[u8; 32]>,
    pub challenge_ack_hashes: Vec<PublicHash>,
    pub additional_disprove_script: Vec<u8>,
    pub disprove_root_hash: [u8; 32],
    pub operator_bitvm_keys: ClementineBitVMPublicKeys,
    pub move_to_vault_txid: bitcoin::Txid,
    challenger_evm_address: Option<EVMAddress>,
}

#[derive(Debug, Clone)]
pub struct KickoffSharedContext {
    paramset: &'static ProtocolParamset,
    deposit_data: DepositData,
    operator_data: OperatorData,
    kickoff_keys: KickoffWinternitzKeys,
    assert_script_hashes: Vec<[u8; 32]>,
    challenge_ack_hashes: Vec<PublicHash>,
    additional_disprove_script: Vec<u8>,
    disprove_root_hash: [u8; 32],
    operator_bitvm_keys: ClementineBitVMPublicKeys,
    move_to_vault_txid: bitcoin::Txid,
    challenger_evm_address: Option<EVMAddress>,
}

impl KickoffSharedContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        paramset: &'static ProtocolParamset,
        deposit_data: DepositData,
        operator_data: OperatorData,
        kickoff_keys: KickoffWinternitzKeys,
        assert_script_hashes: Vec<[u8; 32]>,
        challenge_ack_hashes: Vec<PublicHash>,
        additional_disprove_script: Vec<u8>,
        disprove_root_hash: [u8; 32],
        operator_bitvm_keys: ClementineBitVMPublicKeys,
        move_to_vault_txid: bitcoin::Txid,
        challenger_evm_address: Option<EVMAddress>,
    ) -> Self {
        Self {
            paramset,
            deposit_data,
            operator_data,
            kickoff_keys,
            assert_script_hashes,
            challenge_ack_hashes,
            additional_disprove_script,
            disprove_root_hash,
            operator_bitvm_keys,
            move_to_vault_txid,
            challenger_evm_address,
        }
    }

    pub fn for_kickoff(
        &self,
        kickoff_data: KickoffData,
    ) -> Result<KickoffBuildContext, BridgeError> {
        // Only the round/kickoff identity varies here; the hydrated operator/deposit
        // data and all BitVM-derived material are static for this operator+deposit pair.
        if kickoff_data.operator_xonly_pk != self.operator_data.xonly_pk {
            return Err(
                TxError::KickoffOperatorMismatch(Box::new(KickoffOperatorMismatch {
                    expected: self.operator_data.xonly_pk,
                    actual: kickoff_data.operator_xonly_pk,
                }))
                .into(),
            );
        }

        Ok(KickoffBuildContext::new(
            self.paramset,
            self.deposit_data.clone(),
            kickoff_data,
            self.operator_data.clone(),
            self.kickoff_keys.clone(),
            self.assert_script_hashes.clone(),
            self.challenge_ack_hashes.clone(),
            self.additional_disprove_script.clone(),
            self.disprove_root_hash,
            self.operator_bitvm_keys.clone(),
            self.move_to_vault_txid,
            self.challenger_evm_address,
        ))
    }
}

impl KickoffBuildContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        paramset: &'static ProtocolParamset,
        deposit_data: DepositData,
        kickoff_data: KickoffData,
        operator_data: OperatorData,
        kickoff_keys: KickoffWinternitzKeys,
        assert_script_hashes: Vec<[u8; 32]>,
        challenge_ack_hashes: Vec<PublicHash>,
        additional_disprove_script: Vec<u8>,
        disprove_root_hash: [u8; 32],
        operator_bitvm_keys: ClementineBitVMPublicKeys,
        move_to_vault_txid: bitcoin::Txid,
        challenger_evm_address: Option<EVMAddress>,
    ) -> Self {
        Self {
            paramset,
            deposit_data,
            kickoff_data,
            operator_data,
            kickoff_keys,
            assert_script_hashes,
            challenge_ack_hashes,
            additional_disprove_script,
            disprove_root_hash,
            operator_bitvm_keys,
            move_to_vault_txid,
            challenger_evm_address,
        }
    }

    pub fn challenger_evm_address(&self) -> Option<EVMAddress> {
        self.challenger_evm_address
    }

    pub fn kickoff_keys(&self) -> &KickoffWinternitzKeys {
        &self.kickoff_keys
    }
}

#[derive(Debug, Clone)]
pub struct WithdrawalBuildContext {
    paramset: &'static ProtocolParamset,
    deposit_data: Option<DepositData>,
    withdrawal: WithdrawalData,
}

impl WithdrawalBuildContext {
    pub fn new(
        paramset: &'static ProtocolParamset,
        deposit_data: Option<DepositData>,
        withdrawal: WithdrawalData,
    ) -> Self {
        Self {
            paramset,
            deposit_data,
            withdrawal,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplacementDepositBuildContext {
    paramset: &'static ProtocolParamset,
    deposit_data: DepositData,
    replacement_deposit: ReplacementDepositBuildData,
}

impl ReplacementDepositBuildContext {
    pub fn new(
        paramset: &'static ProtocolParamset,
        deposit_data: DepositData,
        replacement_deposit: ReplacementDepositBuildData,
    ) -> Self {
        Self {
            paramset,
            deposit_data,
            replacement_deposit,
        }
    }
}

pub trait BuildContextView {
    fn params(&self) -> &'static ProtocolParamset;

    fn deposit(&self) -> Result<&DepositData, BridgeError> {
        Err(insufficient_context())
    }

    fn deposit_mut(&mut self) -> Result<&mut DepositData, BridgeError> {
        Err(insufficient_context())
    }

    fn withdrawal(&self) -> Result<&WithdrawalData, BridgeError> {
        Err(insufficient_context())
    }

    fn operator(&self) -> Result<&OperatorData, BridgeError> {
        Err(insufficient_context())
    }

    fn operator_xonly_pk(&self) -> Result<XOnlyPublicKey, BridgeError> {
        Ok(self.operator()?.xonly_pk)
    }

    fn round_idx(&self) -> Result<BridgeRound, BridgeError> {
        Err(insufficient_context())
    }

    fn kickoff_data(&self) -> Result<KickoffData, BridgeError> {
        Err(insufficient_context())
    }

    fn kickoff(&self) -> Result<&KickoffBuildContext, BridgeError> {
        Err(insufficient_context())
    }

    fn kickoff_keys(&self) -> Result<&KickoffWinternitzKeys, BridgeError> {
        Err(insufficient_context())
    }

    fn replacement_deposit(&self) -> Result<&ReplacementDepositBuildData, BridgeError> {
        Err(insufficient_context())
    }

    fn move_to_vault_txid(&self) -> Result<bitcoin::Txid, BridgeError> {
        Err(insufficient_context())
    }

    fn challenger_evm_address(&self) -> Result<Option<EVMAddress>, BridgeError> {
        Err(insufficient_context())
    }

    fn watchtower_commit_data(&self) -> Result<&[u8], BridgeError> {
        Err(insufficient_context())
    }

    fn burn_change_address(&self) -> Result<&Address, BridgeError> {
        Err(insufficient_context())
    }
}

impl BuildContextView for DepositBuildContext {
    fn params(&self) -> &'static ProtocolParamset {
        self.paramset
    }

    fn deposit(&self) -> Result<&DepositData, BridgeError> {
        Ok(&self.deposit_data)
    }

    fn deposit_mut(&mut self) -> Result<&mut DepositData, BridgeError> {
        Ok(&mut self.deposit_data)
    }
}

impl BuildContextView for RoundBuildContext {
    fn params(&self) -> &'static ProtocolParamset {
        self.paramset
    }

    fn operator(&self) -> Result<&OperatorData, BridgeError> {
        Ok(&self.operator_data)
    }

    fn round_idx(&self) -> Result<BridgeRound, BridgeError> {
        Ok(self.round_idx)
    }

    fn kickoff_keys(&self) -> Result<&KickoffWinternitzKeys, BridgeError> {
        Ok(&self.kickoff_keys)
    }
}

impl BuildContextView for KickoffBuildContext {
    fn params(&self) -> &'static ProtocolParamset {
        self.paramset
    }

    fn deposit(&self) -> Result<&DepositData, BridgeError> {
        Ok(&self.deposit_data)
    }

    fn deposit_mut(&mut self) -> Result<&mut DepositData, BridgeError> {
        Ok(&mut self.deposit_data)
    }

    fn operator(&self) -> Result<&OperatorData, BridgeError> {
        Ok(&self.operator_data)
    }

    fn round_idx(&self) -> Result<BridgeRound, BridgeError> {
        Ok(self.kickoff_data.bridge_round)
    }

    fn kickoff_data(&self) -> Result<KickoffData, BridgeError> {
        Ok(self.kickoff_data)
    }

    fn kickoff(&self) -> Result<&KickoffBuildContext, BridgeError> {
        Ok(self)
    }

    fn kickoff_keys(&self) -> Result<&KickoffWinternitzKeys, BridgeError> {
        Ok(&self.kickoff_keys)
    }

    fn move_to_vault_txid(&self) -> Result<bitcoin::Txid, BridgeError> {
        Ok(self.move_to_vault_txid)
    }

    fn challenger_evm_address(&self) -> Result<Option<EVMAddress>, BridgeError> {
        Ok(self.challenger_evm_address)
    }
}

impl BuildContextView for WithdrawalBuildContext {
    fn params(&self) -> &'static ProtocolParamset {
        self.paramset
    }

    fn deposit(&self) -> Result<&DepositData, BridgeError> {
        self.deposit_data.as_ref().ok_or_else(insufficient_context)
    }

    fn deposit_mut(&mut self) -> Result<&mut DepositData, BridgeError> {
        self.deposit_data.as_mut().ok_or_else(insufficient_context)
    }

    fn withdrawal(&self) -> Result<&WithdrawalData, BridgeError> {
        Ok(&self.withdrawal)
    }
}

impl BuildContextView for ReplacementDepositBuildContext {
    fn params(&self) -> &'static ProtocolParamset {
        self.paramset
    }

    fn deposit(&self) -> Result<&DepositData, BridgeError> {
        Ok(&self.deposit_data)
    }

    fn deposit_mut(&mut self) -> Result<&mut DepositData, BridgeError> {
        Ok(&mut self.deposit_data)
    }

    fn replacement_deposit(&self) -> Result<&ReplacementDepositBuildData, BridgeError> {
        Ok(&self.replacement_deposit)
    }
}

/// Helper to load required data for building round/kickoff transactions.
pub struct TxContextLoader<'a> {
    db: Database,
    dbtx: Option<DatabaseTransaction<'a>>,
}

impl<'a> TxContextLoader<'a> {
    pub fn new(db: Database, dbtx: Option<DatabaseTransaction<'a>>) -> Self {
        Self { db, dbtx }
    }

    pub async fn load_round(
        &mut self,
        operator_xonly_pk: XOnlyPublicKey,
        round_idx: BridgeRound,
        paramset: &'static ProtocolParamset,
    ) -> Result<RoundBuildContext, BridgeError> {
        let operator_data = self.get_operator_data(operator_xonly_pk).await?;
        let kickoff_keys = self
            .get_kickoff_winternitz_keys(operator_xonly_pk, paramset)
            .await?;
        Ok(RoundBuildContext::new(
            paramset,
            round_idx,
            operator_data,
            kickoff_keys,
        ))
    }

    pub async fn load_kickoff(
        &mut self,
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        signer: Option<&Actor>,
        paramset: &'static ProtocolParamset,
    ) -> Result<KickoffBuildContext, BridgeError> {
        self.load_kickoff_shared(
            kickoff_data.operator_xonly_pk,
            deposit_data,
            signer,
            paramset,
        )
        .await?
        .for_kickoff(kickoff_data)
    }

    pub async fn load_kickoff_shared(
        &mut self,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_data: DepositData,
        signer: Option<&Actor>,
        paramset: &'static ProtocolParamset,
    ) -> Result<KickoffSharedContext, BridgeError> {
        let operator_data = self.get_operator_data(operator_xonly_pk).await?;
        let kickoff_keys = self
            .get_kickoff_winternitz_keys(operator_xonly_pk, paramset)
            .await?;
        let deposit_outpoint = deposit_data.get_deposit_outpoint();

        let (assert_script_hashes, disprove_root_hash) = self
            .get_bitvm_setup(operator_xonly_pk, deposit_outpoint)
            .await?;
        let challenge_ack_hashes = self
            .get_challenge_ack_hashes(operator_xonly_pk, deposit_outpoint)
            .await?;
        let operator_bitvm_keys = self
            .get_operator_bitvm_keys(operator_xonly_pk, deposit_outpoint)
            .await?;
        let additional_disprove_script = create_additional_replacable_disprove_script_with_dummy(
            *paramset.bridge_circuit_constant()?,
            operator_bitvm_keys.bitvm_pks.0[0].to_vec(),
            operator_bitvm_keys.latest_blockhash_pk.to_vec(),
            operator_bitvm_keys
                .challenge_sending_watchtowers_pk
                .to_vec(),
            challenge_ack_hashes.clone(),
        );
        let challenger_evm_address = signer.map(|actor| actor.get_evm_address()).transpose()?;

        let mut deposit_ctx = DepositBuildContext::new(paramset, deposit_data.clone());
        let move_to_vault_txid =
            create::build_tx(&mut deposit_ctx, TransactionType::MoveToVault)?.txid();

        Ok(KickoffSharedContext::new(
            paramset,
            deposit_data,
            operator_data,
            kickoff_keys,
            assert_script_hashes,
            challenge_ack_hashes,
            additional_disprove_script,
            disprove_root_hash,
            operator_bitvm_keys,
            move_to_vault_txid,
            challenger_evm_address,
        ))
    }

    async fn get_operator_data(
        &mut self,
        operator_xonly_pk: XOnlyPublicKey,
    ) -> Result<OperatorData, BridgeError> {
        self.db
            .get_operator(self.dbtx.as_deref_mut(), operator_xonly_pk)
            .await
            .wrap_err("Failed to get operator data from database")?
            .ok_or_eyre(format!(
                "Operator not found for xonly_pk {operator_xonly_pk}"
            ))
            .map_err(Into::into)
    }

    async fn get_kickoff_winternitz_keys(
        &mut self,
        operator_xonly_pk: XOnlyPublicKey,
        paramset: &'static ProtocolParamset,
    ) -> Result<KickoffWinternitzKeys, BridgeError> {
        let keys = self
            .db
            .get_operator_kickoff_winternitz_public_keys(
                self.dbtx.as_deref_mut(),
                operator_xonly_pk,
            )
            .await
            .wrap_err("Failed to get kickoff winternitz keys from database")?;
        KickoffWinternitzKeys::new(
            keys,
            paramset.num_kickoffs_per_round,
            paramset.num_round_txs,
        )
        .map_err(Into::into)
    }

    async fn get_bitvm_setup(
        &mut self,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
    ) -> Result<(Vec<[u8; 32]>, [u8; 32]), BridgeError> {
        let (assert_hashes, disprove_root_hash, _latest_blockhash_root_hash) = self
            .db
            .get_bitvm_setup(
                self.dbtx.as_deref_mut(),
                operator_xonly_pk,
                deposit_outpoint,
            )
            .await
            .wrap_err("Failed to get BitVM setup from database")?
            .ok_or(TxError::BitvmSetupNotFound(
                operator_xonly_pk,
                deposit_outpoint.txid,
            ))?;
        Ok((assert_hashes, disprove_root_hash))
    }

    async fn get_operator_bitvm_keys(
        &mut self,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
    ) -> Result<ClementineBitVMPublicKeys, BridgeError> {
        Ok(ClementineBitVMPublicKeys::from_flattened_vec(
            &self
                .db
                .get_operator_bitvm_keys(
                    self.dbtx.as_deref_mut(),
                    operator_xonly_pk,
                    deposit_outpoint,
                )
                .await?,
        ))
    }

    async fn get_challenge_ack_hashes(
        &mut self,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
    ) -> Result<Vec<PublicHash>, BridgeError> {
        self.db
            .get_operators_challenge_ack_hashes(
                self.dbtx.as_deref_mut(),
                operator_xonly_pk,
                deposit_outpoint,
            )
            .await
            .wrap_err("Failed to get challenge ack hashes from database")?
            .ok_or_else(|| {
                eyre::eyre!(
                    "Watchtower public hashes not found for operator {0:?} and deposit {1}",
                    operator_xonly_pk,
                    deposit_outpoint.txid,
                )
                .into()
            })
    }
}

pub trait TxCacheExt {
    fn prune_for_kickoff_loop(&mut self);

    fn get_required(&self, tx_type: TransactionType) -> Result<&TxHandler, BridgeError>;

    fn take_required(&mut self, tx_type: TransactionType) -> Result<TxHandler, BridgeError>;
}

impl TxCacheExt for TxCache {
    /// Prune the cache for the kickoff loop.
    /// A kickoff tx set is independent of other sets, so they are not required to be stored in the cache.
    /// This is for memory efficiency only.
    fn prune_for_kickoff_loop(&mut self) {
        self.retain(|tx_type, _| {
            matches!(
                tx_type,
                TransactionType::MoveToVault
                    | TransactionType::Round(_)
                    | TransactionType::ReadyToReimburse(_)
            )
        });
    }

    fn get_required(&self, tx_type: TransactionType) -> Result<&TxHandler, BridgeError> {
        self.get(&tx_type)
            .ok_or(TxError::TxHandlerNotFound(tx_type).into())
    }

    fn take_required(&mut self, tx_type: TransactionType) -> Result<TxHandler, BridgeError> {
        self.remove(&tx_type)
            .ok_or(TxError::TxHandlerNotFound(tx_type).into())
    }
}

#[derive(Debug, Clone)]
pub struct KickoffWinternitzKeys {
    keys: Vec<bitvm::signatures::winternitz::PublicKey>,
    num_kickoffs_per_round: usize,
    num_rounds: usize,
}

impl KickoffWinternitzKeys {
    pub fn new(
        keys: Vec<bitvm::signatures::winternitz::PublicKey>,
        num_kickoffs_per_round: usize,
        num_rounds: usize,
    ) -> Result<Self, TxError> {
        if keys.len() != num_kickoffs_per_round * (num_rounds + 1) {
            return Err(TxError::KickoffWinternitzKeysDBInconsistency);
        }
        Ok(Self {
            keys,
            num_kickoffs_per_round,
            num_rounds,
        })
    }

    pub fn get_keys_for_round(
        &self,
        round_idx: BridgeRound,
    ) -> Result<&[bitvm::signatures::winternitz::PublicKey], TxError> {
        if round_idx == BridgeRound::Collateral || round_idx.to_index() > self.num_rounds + 1 {
            return Err(TxError::InvalidRoundIndex(round_idx));
        }
        let start_idx = (round_idx.to_index())
            .checked_sub(1)
            .ok_or(TxError::IndexOverflow)?
            .checked_mul(self.num_kickoffs_per_round)
            .ok_or(TxError::IndexOverflow)?;
        let end_idx = start_idx
            .checked_add(self.num_kickoffs_per_round)
            .ok_or(TxError::IndexOverflow)?;
        Ok(&self.keys[start_idx..end_idx])
    }

    pub fn get_all_keys(self) -> Vec<bitvm::signatures::winternitz::PublicKey> {
        self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitvm_client::SECP;
    use crate::config::protocol::REGTEST_PARAMSET;
    use crate::deposit::{
        Actors, BaseDepositData, DepositData, DepositInfo, DepositType, SecurityCouncil,
    };
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::{PublicKey, SecretKey};
    use bitcoin::{Address, Network, OutPoint, Txid};
    use clementine_primitives::EVMAddress;

    fn xonly(seed: u8) -> bitcoin::XOnlyPublicKey {
        let secret_key = SecretKey::from_slice(&[seed; 32]).expect("seed must create secret key");
        bitcoin::XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &secret_key)).0
    }

    fn pubkey(seed: u8) -> PublicKey {
        SecretKey::from_slice(&[seed; 32])
            .expect("seed must create secret key")
            .public_key(&SECP)
    }

    fn sample_deposit_data() -> DepositData {
        DepositData {
            nofn_xonly_pk: Some(xonly(1)),
            deposit: DepositInfo {
                deposit_outpoint: OutPoint {
                    txid: Txid::from_byte_array([2; 32]),
                    vout: 0,
                },
                deposit_type: DepositType::BaseDeposit(BaseDepositData {
                    evm_address: EVMAddress([3; 20]),
                    recovery_taproot_address: Address::p2tr(
                        &SECP,
                        xonly(4),
                        None,
                        Network::Regtest,
                    )
                    .as_unchecked()
                    .clone(),
                }),
            },
            actors: Actors {
                verifiers: vec![pubkey(5)],
                watchtowers: vec![xonly(6)],
                operators: vec![xonly(7)],
            },
            security_council: SecurityCouncil {
                pks: vec![xonly(8)],
                threshold: 1,
            },
        }
    }

    #[test]
    fn prune_for_kickoff_loop_keeps_only_shared_static_transactions() {
        use crate::protocol::ids::{KickoffIdx, RoundIdx};

        let mut cache = TxCache::new();
        cache.insert(
            TransactionType::MoveToVault,
            crate::builder::transaction::TxHandlerBuilder::new(TransactionType::MoveToVault)
                .finalize(),
        );
        cache.insert(
            TransactionType::Round(RoundIdx::new(0)),
            crate::builder::transaction::TxHandlerBuilder::new(TransactionType::Round(
                RoundIdx::new(0),
            ))
            .finalize(),
        );
        cache.insert(
            TransactionType::ReadyToReimburse(RoundIdx::new(0)),
            crate::builder::transaction::TxHandlerBuilder::new(TransactionType::ReadyToReimburse(
                RoundIdx::new(0),
            ))
            .finalize(),
        );
        cache.insert(
            TransactionType::Kickoff(RoundIdx::new(0), KickoffIdx::new(0)),
            crate::builder::transaction::TxHandlerBuilder::new(TransactionType::Kickoff(
                RoundIdx::new(0),
                KickoffIdx::new(0),
            ))
            .finalize(),
        );

        cache.prune_for_kickoff_loop();

        assert!(cache.contains_key(&TransactionType::MoveToVault));
        assert!(cache.contains_key(&TransactionType::Round(RoundIdx::new(0))));
        assert!(cache.contains_key(&TransactionType::ReadyToReimburse(RoundIdx::new(0))));
        assert!(!cache.contains_key(&TransactionType::Kickoff(
            RoundIdx::new(0),
            KickoffIdx::new(0),
        )));
    }

    #[test]
    fn direct_context_construction_exposes_required_data() {
        let deposit_data = sample_deposit_data();
        let replacement = ReplacementDepositBuildData {
            old_move_txid: Txid::from_byte_array([9; 32]),
            old_nofn_xonly_pk: xonly(10),
            input_outpoint: OutPoint {
                txid: Txid::from_byte_array([11; 32]),
                vout: 1,
            },
            security_council: SecurityCouncil {
                pks: vec![xonly(12)],
                threshold: 1,
            },
        };
        let deposit_ctx = DepositBuildContext::new(&REGTEST_PARAMSET, deposit_data.clone());
        let replacement_ctx = ReplacementDepositBuildContext::new(
            &REGTEST_PARAMSET,
            deposit_data.clone(),
            replacement.clone(),
        );

        assert_eq!(deposit_ctx.params(), &REGTEST_PARAMSET);
        assert_eq!(deposit_ctx.deposit().unwrap(), &deposit_data);

        assert_eq!(replacement_ctx.params(), &REGTEST_PARAMSET);
        assert_eq!(replacement_ctx.deposit().unwrap(), &deposit_data);
        assert_eq!(
            replacement_ctx.replacement_deposit().unwrap().old_move_txid,
            replacement.old_move_txid
        );
    }

    #[test]
    fn shared_kickoff_context_derives_round_specific_contexts() {
        let deposit_data = sample_deposit_data();
        let operator_data = OperatorData {
            xonly_pk: xonly(13),
            reimburse_addr: Address::p2tr(&SECP, xonly(14), None, Network::Regtest),
            collateral_funding_outpoint: OutPoint {
                txid: Txid::from_byte_array([15; 32]),
                vout: 0,
            },
        };
        let kickoff_keys = KickoffWinternitzKeys::new(
            vec![bitvm::signatures::winternitz::PublicKey::default(); 2],
            1,
            1,
        )
        .unwrap();
        let shared = KickoffSharedContext::new(
            &REGTEST_PARAMSET,
            deposit_data.clone(),
            operator_data.clone(),
            kickoff_keys,
            vec![[16; 32]],
            vec![[17; 20]],
            vec![18],
            [19; 32],
            ClementineBitVMPublicKeys::create_replacable(),
            Txid::from_byte_array([20; 32]),
            Some(EVMAddress([21; 20])),
        );
        let kickoff_data = KickoffData {
            operator_xonly_pk: operator_data.xonly_pk,
            bridge_round: BridgeRound::Round(1),
            kickoff_idx: 0,
        };

        let kickoff_ctx = shared.for_kickoff(kickoff_data).unwrap();

        assert_eq!(kickoff_ctx.params(), &REGTEST_PARAMSET);
        assert_eq!(kickoff_ctx.deposit().unwrap(), &deposit_data);
        assert_eq!(kickoff_ctx.kickoff_data().unwrap(), kickoff_data);
        assert_eq!(
            kickoff_ctx.operator().unwrap().xonly_pk,
            operator_data.xonly_pk
        );
        assert_eq!(
            kickoff_ctx.move_to_vault_txid().unwrap(),
            Txid::from_byte_array([20; 32])
        );
    }

    #[test]
    fn shared_kickoff_context_rejects_operator_mismatch() {
        let shared_operator_xonly = xonly(13);
        let shared = KickoffSharedContext::new(
            &REGTEST_PARAMSET,
            sample_deposit_data(),
            OperatorData {
                xonly_pk: shared_operator_xonly,
                reimburse_addr: Address::p2tr(&SECP, xonly(14), None, Network::Regtest),
                collateral_funding_outpoint: OutPoint {
                    txid: Txid::from_byte_array([15; 32]),
                    vout: 0,
                },
            },
            KickoffWinternitzKeys::new(
                vec![bitvm::signatures::winternitz::PublicKey::default(); 2],
                1,
                1,
            )
            .unwrap(),
            vec![[16; 32]],
            vec![[17; 20]],
            vec![18],
            [19; 32],
            ClementineBitVMPublicKeys::create_replacable(),
            Txid::from_byte_array([20; 32]),
            None,
        );

        let err = shared
            .for_kickoff(KickoffData {
                operator_xonly_pk: xonly(99),
                bridge_round: BridgeRound::Round(1),
                kickoff_idx: 0,
            })
            .unwrap_err();

        assert!(matches!(
            err,
            BridgeError::Transaction(TxError::KickoffOperatorMismatch(mismatch))
                if mismatch.expected == shared_operator_xonly && mismatch.actual == xonly(99)
        ));
    }
}
