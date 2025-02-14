//! # Sighash Builder
//!
//! Sighash builder provides useful functions for building related SigHashes.
//! Sighash is the message that is signed by the private key of the signer. It is used to signal
//! under which conditions the input is signed. For more, see:
//! https://developer.bitcoin.org/devguide/transactions.html?highlight=sighash#signature-hash-types

use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::{
    create_txhandlers, DepositId, OperatorData, TransactionType, TxHandler,
};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::KickoffId;
use async_stream::try_stream;
use bitcoin::{Address, TapSighash, Txid, XOnlyPublicKey};
use futures_core::stream::Stream;

/// Returns the number of required signatures for N-of-N signing session.
pub fn calculate_num_required_nofn_sigs(config: &BridgeConfig) -> usize {
    let &BridgeConfig {
        num_operators,
        num_sequential_collateral_txs,
        num_kickoffs_per_sequential_collateral_tx,
        ..
    } = config;
    num_operators
        * num_sequential_collateral_txs
        * num_kickoffs_per_sequential_collateral_tx
        * calculate_num_required_nofn_sigs_per_kickoff(config)
}

// WIP: For now, this is equal to the number of sighashes we yield in create_operator_sighash_stream.
// This will change as we implement the system design.
pub fn calculate_num_required_operator_sigs(config: &BridgeConfig) -> usize {
    let &BridgeConfig {
        num_sequential_collateral_txs,
        num_kickoffs_per_sequential_collateral_tx,
        ..
    } = config;
    num_sequential_collateral_txs
        * num_kickoffs_per_sequential_collateral_tx
        * calculate_num_required_operator_sigs_per_kickoff()
}

pub fn calculate_num_required_nofn_sigs_per_kickoff(
    &BridgeConfig {
        num_watchtowers, ..
    }: &BridgeConfig,
) -> usize {
    13 + 2 * num_watchtowers
}

pub fn calculate_num_required_operator_sigs_per_kickoff() -> usize {
    4
}

#[derive(Copy, Clone, Debug)]
pub struct PartialSignatureInfo {
    pub operator_idx: usize,
    pub sequential_collateral_idx: usize,
    pub kickoff_utxo_idx: usize,
}

#[derive(Copy, Clone, Debug)]
pub struct SignatureInfo {
    pub operator_idx: usize,
    pub sequential_collateral_idx: usize,
    pub kickoff_utxo_idx: usize,
    pub signature_id: SignatureId,
}

impl PartialSignatureInfo {
    pub fn new(
        operator_idx: usize,
        sequential_collateral_idx: usize,
        kickoff_utxo_idx: usize,
    ) -> PartialSignatureInfo {
        PartialSignatureInfo {
            operator_idx,
            sequential_collateral_idx,
            kickoff_utxo_idx,
        }
    }
    pub fn complete(&self, signature_id: SignatureId) -> SignatureInfo {
        SignatureInfo {
            operator_idx: self.operator_idx,
            sequential_collateral_idx: self.sequential_collateral_idx,
            kickoff_utxo_idx: self.kickoff_utxo_idx,
            signature_id,
        }
    }
}

/// Refer to bridge design diagram to see which NofN signatures are needed (the ones marked with blue arrows).
/// These sighashes are needed in order to create the message to be signed later for MuSig2 of NofN.
/// WIP: Update if the design changes.
/// For a given deposit tx, for each operator and sequential_collateral tx, generates the sighash stream for:
/// - challenge_tx,
/// - start_happy_reimburse_tx,
/// - happy_reimburse_tx,
/// - watchtower_challenge_kickoff_tx,
/// - kickoff_timeout_tx,
/// - for each watchtower, operator_challenge_NACK_tx (for 2 inputs),
/// - assert_end_tx,
/// - disprove_timeout_tx (for 2 inputs),
/// - already_disproved_tx,
/// - reimburse_tx.
pub fn create_nofn_sighash_stream(
    db: Database,
    config: BridgeConfig,
    deposit_data: DepositId,
    nofn_xonly_pk: XOnlyPublicKey,
) -> impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>> {
    try_stream! {
        // Get operator details (for each operator, (X-Only Public Key, Address, Collateral Funding Txid))
        let operators: Vec<(XOnlyPublicKey, bitcoin::Address, Txid)> =
            db.get_operators(None).await?;
        if operators.len() < config.num_operators {
            Err(BridgeError::NotEnoughOperators)?;
        }

        for (operator_idx, (operator_xonly_pk, operator_reimburse_address, collateral_funding_txid)) in
            operators.iter().enumerate()
        {
            // Get all the watchtower challenge addresses for this operator. We have all of them here (for all the kickoff_utxos).
            let watchtower_all_challenge_addresses = (0..config.num_watchtowers)
                .map(|i| db.get_watchtower_challenge_addresses(None, i as u32, operator_idx as u32))
                .collect::<Vec<_>>();
            let watchtower_all_challenge_addresses = futures::future::try_join_all(watchtower_all_challenge_addresses).await?;

            let mut last_reimburse_generator: Option<TxHandler> = None;

            let operator_data = OperatorData {
                xonly_pk: *operator_xonly_pk,
                reimburse_addr: operator_reimburse_address.clone(),
                collateral_funding_txid: *collateral_funding_txid,
            };

            // For each sequential_collateral_tx, we have multiple kickoff_utxos as the connectors.
            for sequential_collateral_tx_idx in 0..config.num_sequential_collateral_txs {
                // For each kickoff_utxo, it connnects to a kickoff_tx that results in
                // either start_happy_reimburse_tx
                // or challenge_tx, which forces the operator to initiate BitVM sequence
                // (assert_begin_tx -> assert_end_tx -> either disprove_timeout_tx or already_disproven_tx).
                // If the operator is honest, the sequence will end with the operator being able to send the reimburse_tx.
                // Otherwise, by using the disprove_tx, the operator's sequential_collateral_tx burn connector will be burned.
                for kickoff_idx in 0..config.num_kickoffs_per_sequential_collateral_tx {
                    let partial = PartialSignatureInfo::new(operator_idx, sequential_collateral_tx_idx, kickoff_idx);

                    // Collect the challenge Winternitz pubkeys for this specific kickoff_utxo.
                    let watchtower_challenge_addresses = (0..config.num_watchtowers)
                    .map(|i| watchtower_all_challenge_addresses[i][sequential_collateral_tx_idx * config.num_kickoffs_per_sequential_collateral_tx + kickoff_idx].clone())
                    .collect::<Vec<_>>();

                    let mut txhandlers = create_txhandlers(
                        db.clone(),
                        config.clone(),
                        deposit_data.clone(),
                        nofn_xonly_pk,
                        TransactionType::AllNeededForVerifierDeposit,
                        KickoffId {
                            operator_idx: operator_idx as u32,
                            sequential_collateral_idx: sequential_collateral_tx_idx as u32,
                            kickoff_idx: kickoff_idx as u32,
                        },
                        operator_data.clone(),
                        Some(&watchtower_challenge_addresses),
                        last_reimburse_generator,
                    ).await?;

                    let mut sum = 0;
                    for (_, txhandler) in txhandlers.iter() {
                        let sighashes = txhandler.calculate_all_txins_sighash(EntityType::Verifier, partial)?;
                        sum += sighashes.len();
                        for sighash in sighashes {
                            yield sighash;
                        }
                    }
                    if sum != calculate_num_required_nofn_sigs_per_kickoff(&config) {
                        Err(BridgeError::NofNSighashMismatch(calculate_num_required_nofn_sigs_per_kickoff(&config), sum))?;
                    }
                    last_reimburse_generator = txhandlers.remove(&TransactionType::Reimburse);
                }
            }
        }
    }
}
/// These operator sighashes are needed so that each operator can share the signatures with each verifier, so that
/// verifiers have the ability to burn the burn connector of operators.
/// WIP: Update if the design changes.
/// This function generates Kickoff Timeout TX, Already Disproved TX,
/// and Disprove TX for each sequential_collateral_tx and kickoff_utxo. It yields the sighashes for these tx's for the input that has operators burn connector.
/// Possible future optimization: Each verifier already generates some of these TX's in create_operator_sighash_stream()
/// It is possible to for verifiers somehow return the required sighashes for operator signatures there too. But operators only needs to use sighashes included in this function.
pub fn create_operator_sighash_stream(
    db: Database,
    operator_idx: usize,
    collateral_funding_txid: Txid,
    operator_reimburse_addr: Address,
    operator_xonly_pk: XOnlyPublicKey,
    config: BridgeConfig,
    deposit_data: DepositId,
    nofn_xonly_pk: XOnlyPublicKey,
) -> impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>> {
    try_stream! {
        let operator_data = OperatorData {
            xonly_pk: operator_xonly_pk,
            reimburse_addr: operator_reimburse_addr,
            collateral_funding_txid,
        };

        // Get all the watchtower challenge addresses for this operator. We have all of them here (for all the kickoff_utxos).
        let watchtower_all_challenge_addresses = (0..config.num_watchtowers)
            .map(|i| db.get_watchtower_challenge_addresses(None, i as u32, operator_idx as u32))
            .collect::<Vec<_>>();
        let watchtower_all_challenge_addresses = futures::future::try_join_all(watchtower_all_challenge_addresses).await?;

        let mut last_reimburse_generator: Option<TxHandler> = None;

        // For each sequential_collateral_tx, we have multiple kickoff_utxos as the connectors.
        for sequential_collateral_tx_idx in 0..config.num_sequential_collateral_txs {
            for kickoff_idx in 0..config.num_kickoffs_per_sequential_collateral_tx {
                let partial = PartialSignatureInfo::new(operator_idx, sequential_collateral_tx_idx, kickoff_idx);

                // Collect the challenge Winternitz pubkeys for this specific kickoff_utxo.
                let watchtower_challenge_addresses = (0..config.num_watchtowers)
                .map(|i| watchtower_all_challenge_addresses[i][sequential_collateral_tx_idx * config.num_kickoffs_per_sequential_collateral_tx + kickoff_idx].clone())
                .collect::<Vec<_>>();

                let mut txhandlers = create_txhandlers(
                    db.clone(),
                    config.clone(),
                    deposit_data.clone(),
                    nofn_xonly_pk,
                    TransactionType::AllNeededForOperatorDeposit,
                    KickoffId {
                        operator_idx: operator_idx as u32,
                        sequential_collateral_idx: sequential_collateral_tx_idx as u32,
                        kickoff_idx: kickoff_idx as u32,
                    },
                    operator_data.clone(),
                    Some(&watchtower_challenge_addresses),
                    last_reimburse_generator,
                ).await?;

                let mut sum = 0;
                for (_, txhandler) in txhandlers.iter() {
                    let sighashes = txhandler.calculate_all_txins_sighash(EntityType::Operator, partial)?;
                    sum += sighashes.len();
                    for sighash in sighashes {
                        yield sighash;
                    }
                }
                if sum != calculate_num_required_operator_sigs_per_kickoff() {
                    Err(BridgeError::OperatorSighashMismatch(calculate_num_required_operator_sigs_per_kickoff(), sum))?;
                }
                last_reimburse_generator = txhandlers.remove(&TransactionType::Reimburse);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::builder::sighash::create_nofn_sighash_stream;
    use crate::builder::transaction::DepositId;
    use crate::extended_rpc::ExtendedRpc;
    use crate::operator::Operator;
    use crate::utils::BITVM_CACHE;
    use crate::watchtower::Watchtower;
    use crate::{builder, create_test_config_with_thread_name};
    use crate::{
        config::BridgeConfig, database::Database, initialize_database, utils::initialize_logger,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, ScriptBuf, TapSighash, Txid, XOnlyPublicKey};
    use futures::StreamExt;
    use std::pin::pin;

    #[tokio::test]
    #[ignore = "Not needed because checks are already done in stream functions now"]
    async fn calculate_num_required_nofn_sigs() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();
        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await
        .unwrap();

        let operator = Operator::new(config.clone(), rpc).await.unwrap();
        let watchtower = Watchtower::new(config.clone()).await.unwrap();

        // Dummy inputs for nofn_stream.
        let deposit_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0x45,
        };
        let evm_address = crate::EVMAddress([0x45; 20]);
        let recovery_taproot_address =
            builder::address::create_taproot_address(&[], None, bitcoin::Network::Regtest).0;
        let nofn_xonly_pk = XOnlyPublicKey::from_slice(&[0x45; 32]).unwrap();

        // Initialize database.
        let operator_xonly_pk = XOnlyPublicKey::from_slice(&[0x45; 32]).unwrap();
        let watchtower_xonly_pk = XOnlyPublicKey::from_slice(&[0x1F; 32]).unwrap();
        for i in 0..config.num_operators {
            db.set_operator(
                None,
                i.try_into().unwrap(),
                operator_xonly_pk,
                recovery_taproot_address.to_string(),
                Txid::all_zeros(),
            )
            .await
            .unwrap();
        }
        for i in 0..config.num_watchtowers {
            db.set_watchtower_xonly_pk(None, i.try_into().unwrap(), &watchtower_xonly_pk)
                .await
                .unwrap();
        }
        for i in 0..config.num_operators {
            db.set_operator_winternitz_public_keys(
                None,
                i.try_into().unwrap(),
                operator
                    .get_winternitz_public_keys(Txid::all_zeros())
                    .unwrap(),
            )
            .await
            .unwrap();
        }
        for i in 0..config.num_operators {
            for j in 0..config.num_watchtowers {
                db.set_watchtower_challenge_addresses(
                    None,
                    j.try_into().unwrap(),
                    i.try_into().unwrap(),
                    watchtower
                        .get_watchtower_challenge_addresses()
                        .await
                        .unwrap(),
                )
                .await
                .unwrap();
            }
        }
        let assert_len = BITVM_CACHE.intermediate_variables.len();
        for o in 0..config.num_operators {
            for t in 0..config.num_sequential_collateral_txs {
                for k in 0..config.num_kickoffs_per_sequential_collateral_tx {
                    db.set_bitvm_setup(
                        None,
                        o.try_into().unwrap(),
                        deposit_outpoint,
                        vec![ScriptBuf::default(); assert_len],
                        &[0x45; 32],
                    )
                    .await
                    .unwrap();
                }
            }
        }
        for o in 0..config.num_operators {
            for t in 0..config.num_sequential_collateral_txs {
                for k in 0..config.num_kickoffs_per_sequential_collateral_tx {
                    db.set_operator_challenge_ack_hashes(
                        None,
                        o.try_into().unwrap(),
                        deposit_outpoint,
                        &vec![[0x45; 20]; config.num_watchtowers],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let mut nofn_stream = pin!(create_nofn_sighash_stream(
            db,
            config.clone(),
            DepositId {
                deposit_outpoint,
                evm_address,
                recovery_taproot_address: recovery_taproot_address.as_unchecked().clone(),
            },
            nofn_xonly_pk,
        ));

        let mut challenge_tx_sighashes = Vec::<TapSighash>::new();
        let mut start_happy_reimburse_sighashes = Vec::<TapSighash>::new();
        let mut happy_reimburse_sighashes = Vec::<TapSighash>::new();
        let mut watchtower_challenge_kickoff_sighashes = Vec::<TapSighash>::new();
        let mut kickoff_timeout_sighashes = Vec::<TapSighash>::new();
        let mut operator_challenge_nack_sighashes = Vec::<TapSighash>::new();
        let mut assert_end_sighashes = Vec::<TapSighash>::new();
        let mut disprove_timeout_sighashes = Vec::<TapSighash>::new();
        let mut already_disproved_sighashes = Vec::<TapSighash>::new();
        let mut reimburse_sighashes = Vec::<TapSighash>::new();

        for _ in 0..config.num_operators {
            for _ in 0..config.num_sequential_collateral_txs {
                for _ in 0..config.num_kickoffs_per_sequential_collateral_tx {
                    challenge_tx_sighashes.push(nofn_stream.next().await.unwrap().unwrap().0);
                    start_happy_reimburse_sighashes
                        .push(nofn_stream.next().await.unwrap().unwrap().0);
                    happy_reimburse_sighashes.push(nofn_stream.next().await.unwrap().unwrap().0);
                    watchtower_challenge_kickoff_sighashes
                        .push(nofn_stream.next().await.unwrap().unwrap().0);
                    kickoff_timeout_sighashes.push(nofn_stream.next().await.unwrap().unwrap().0);

                    for _ in 0..config.num_watchtowers {
                        // Script spend.
                        operator_challenge_nack_sighashes
                            .push(nofn_stream.next().await.unwrap().unwrap().0);
                        // Pubkey spend.
                        operator_challenge_nack_sighashes
                            .push(nofn_stream.next().await.unwrap().unwrap().0);
                    }

                    assert_end_sighashes.push(nofn_stream.next().await.unwrap().unwrap().0);
                    // Pubkey spend.
                    disprove_timeout_sighashes.push(nofn_stream.next().await.unwrap().unwrap().0);
                    // Script spend.
                    disprove_timeout_sighashes.push(nofn_stream.next().await.unwrap().unwrap().0);
                    already_disproved_sighashes.push(nofn_stream.next().await.unwrap().unwrap().0);
                    reimburse_sighashes.push(nofn_stream.next().await.unwrap().unwrap().0);
                }
            }
        }
        assert!(nofn_stream.next().await.is_none());

        let sum = challenge_tx_sighashes.len()
            + start_happy_reimburse_sighashes.len()
            + happy_reimburse_sighashes.len()
            + watchtower_challenge_kickoff_sighashes.len()
            + kickoff_timeout_sighashes.len()
            + operator_challenge_nack_sighashes.len()
            + assert_end_sighashes.len()
            + disprove_timeout_sighashes.len()
            + already_disproved_sighashes.len()
            + reimburse_sighashes.len();
        assert_eq!(sum, super::calculate_num_required_nofn_sigs(&config));
    }
}
