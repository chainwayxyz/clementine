//! # Bitcoin Extended RPC Interface
//!
//! Extended RPC interface communicates with the Bitcoin node. It features some
//! common wrappers around typical RPC operations as well as direct
//! communication interface with the Bitcoin node.
//!
//! ## Tests
//!
//! In tests, Bitcoind node and client are usually created using
//! [`crate::test::common::create_regtest_rpc`]. Please refer to
//! [`crate::test::common`] for using [`ExtendedBitcoinRpc`] in tests.

// Re-export types from clementine-extended-rpc
pub use clementine_extended_rpc::{
    get_fee_rate_from_mempool_space, BitcoinRPCError, ExtendedBitcoinRpc, RetryConfig,
    RetryableError,
};

use async_trait::async_trait;
#[cfg(test)]
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoincore_rpc::RpcApi;
use eyre::eyre;
use eyre::Context;

use crate::builder::address::create_taproot_address;
use crate::builder::transaction::create_round_txhandlers;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::KickoffWinternitzKeys;
use crate::builder::transaction::TxHandler;
use crate::config::protocol::ProtocolParamset;
use crate::deposit::OperatorData;
use clementine_errors::BridgeError;
use clementine_errors::TransactionType;
use clementine_primitives::RoundIndex;

#[cfg(test)]
use crate::test::common::citrea::CitreaE2EData;
#[cfg(test)]
use crate::{
    citrea::CitreaClientT,
    test::common::{are_all_state_managers_synced, test_actors::TestActors},
};
#[cfg(test)]
type Result<T> = std::result::Result<T, BitcoinRPCError>;

#[cfg(test)]
pub const MINE_BLOCK_COUNT: u64 = 3;

/// Extension trait for bridge-specific RPC queries.
///
/// These methods are kept in clementine-core because they depend on
/// bridge-specific types like `KickoffWinternitzKeys` and `OperatorData`.
#[async_trait]
pub trait BridgeRpcQueries {
    /// Checks if an operator's collateral is valid and available for use.
    ///
    /// This function validates the operator's collateral by:
    /// 1. Verifying the collateral UTXO exists and has the correct amount
    /// 2. Creating the round transaction chain to track current collateral position
    /// 3. Determining if the current collateral UTXO in the chain is spent in a non-protocol tx, signaling the exit of operator from the protocol
    ///
    /// # Parameters
    ///
    /// * `operator_data`: Data about the operator including collateral funding outpoint
    /// * `kickoff_wpks`: Kickoff Winternitz public keys for round transaction creation
    /// * `paramset`: Protocol parameters
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the collateral is still usable, thus operator is still in protocol, `false` if the collateral is spent, thus operator is not in protocol anymore
    ///
    /// # Errors
    ///
    /// - [`BridgeError`]: If there was an error retrieving transaction data, creating round transactions,
    ///   or checking UTXO status
    async fn collateral_check(
        &self,
        operator_data: &OperatorData,
        kickoff_wpks: &KickoffWinternitzKeys,
        paramset: &'static ProtocolParamset,
    ) -> std::result::Result<bool, BridgeError>;
}

#[async_trait]
impl BridgeRpcQueries for ExtendedBitcoinRpc {
    async fn collateral_check(
        &self,
        operator_data: &OperatorData,
        kickoff_wpks: &KickoffWinternitzKeys,
        paramset: &'static ProtocolParamset,
    ) -> std::result::Result<bool, BridgeError> {
        // first check if the collateral utxo is on chain or mempool
        let tx = self
            .get_tx_of_txid(&operator_data.collateral_funding_outpoint.txid)
            .await
            .wrap_err(format!(
                "Failed to find collateral utxo in chain for outpoint {:?}",
                operator_data.collateral_funding_outpoint
            ))?;
        let collateral_outpoint = match tx
            .output
            .get(operator_data.collateral_funding_outpoint.vout as usize)
        {
            Some(output) => output,
            None => {
                tracing::warn!(
                    "No output at index {} for txid {} while checking for collateral existence",
                    operator_data.collateral_funding_outpoint.vout,
                    operator_data.collateral_funding_outpoint.txid
                );
                return Ok(false);
            }
        };

        if collateral_outpoint.value != paramset.collateral_funding_amount {
            tracing::error!(
                "Collateral amount for collateral {:?} is not correct: expected {}, got {}",
                operator_data.collateral_funding_outpoint,
                paramset.collateral_funding_amount,
                collateral_outpoint.value
            );
            return Ok(false);
        }

        let operator_tpr_address =
            create_taproot_address(&[], Some(operator_data.xonly_pk), paramset.network).0;

        if collateral_outpoint.script_pubkey != operator_tpr_address.script_pubkey() {
            tracing::error!(
                "Collateral script pubkey for collateral {:?} is not correct: expected {}, got {}",
                operator_data.collateral_funding_outpoint,
                operator_tpr_address.script_pubkey(),
                collateral_outpoint.script_pubkey
            );
            return Ok(false);
        }

        // we additionally check if collateral utxo is on chain (so not in mempool)
        // on mainnet we fail if collateral utxo is not on chain because if it is in mempool,
        // the txid of the utxo can change if the fee is bumped
        // on other networks, we allow collateral to be in mempool to not wait for collateral to be on chain to do deposits for faster testing
        let is_on_chain = self
            .is_tx_on_chain(&operator_data.collateral_funding_outpoint.txid)
            .await?;
        if !is_on_chain {
            return match paramset.network {
                bitcoin::Network::Bitcoin => Ok(false),
                _ => Ok(true),
            };
        }

        let mut current_collateral_outpoint: OutPoint = operator_data.collateral_funding_outpoint;
        let mut prev_ready_to_reimburse: Option<TxHandler> = None;
        // iterate over all rounds
        for round_idx in RoundIndex::iter_rounds(paramset.num_round_txs) {
            // create round and ready to reimburse txs for the round
            let txhandlers = create_round_txhandlers(
                paramset,
                round_idx,
                operator_data,
                kickoff_wpks,
                prev_ready_to_reimburse.as_ref(),
            )?;

            let mut round_txhandler_opt = None;
            let mut ready_to_reimburse_txhandler_opt = None;
            for txhandler in &txhandlers {
                match txhandler.get_transaction_type() {
                    TransactionType::Round => round_txhandler_opt = Some(txhandler),
                    TransactionType::ReadyToReimburse => {
                        ready_to_reimburse_txhandler_opt = Some(txhandler)
                    }
                    _ => {}
                }
            }
            if round_txhandler_opt.is_none() || ready_to_reimburse_txhandler_opt.is_none() {
                return Err(eyre!(
                    "Failed to create round and ready to reimburse txs for round {:?} for operator {}",
                    round_idx,
                    operator_data.xonly_pk
                ).into());
            }

            let round_txid = round_txhandler_opt
                .expect("Round txhandler should exist, checked above")
                .get_cached_tx()
                .compute_txid();
            let is_round_tx_on_chain = self.is_tx_on_chain(&round_txid).await?;
            if !is_round_tx_on_chain {
                break;
            }
            let block_hash = self.get_blockhash_of_tx(&round_txid).await?;
            let block_height = self
                .get_block_info(&block_hash)
                .await
                .wrap_err(format!(
                    "Failed to get block info for block hash {block_hash}"
                ))?
                .height;
            if block_height < paramset.start_height as usize {
                tracing::warn!(
                    "Collateral utxo of operator {operator_data:?} is spent in a block before paramset start height: {block_height} < {0}",
                    paramset.start_height
                );
                return Ok(false);
            }
            current_collateral_outpoint = OutPoint {
                txid: round_txid,
                vout: UtxoVout::CollateralInRound.get_vout(),
            };
            if round_idx == RoundIndex::Round(paramset.num_round_txs - 1) {
                // for the last round, only check round tx, as if the operator sent the ready to reimburse tx of last round,
                // it cannot create more kickoffs anymore
                break;
            }
            let ready_to_reimburse_txhandler = ready_to_reimburse_txhandler_opt
                .expect("Ready to reimburse txhandler should exist");
            let ready_to_reimburse_txid =
                ready_to_reimburse_txhandler.get_cached_tx().compute_txid();
            let is_ready_to_reimburse_tx_on_chain =
                self.is_tx_on_chain(&ready_to_reimburse_txid).await?;
            if !is_ready_to_reimburse_tx_on_chain {
                break;
            }

            current_collateral_outpoint = OutPoint {
                txid: ready_to_reimburse_txid,
                vout: UtxoVout::CollateralInReadyToReimburse.get_vout(),
            };

            prev_ready_to_reimburse = Some(ready_to_reimburse_txhandler.clone());
        }

        // if the collateral utxo we found latest in the round tx chain is spent, operators collateral is spent from Clementine
        // bridge protocol, thus it is unusable and operator cannot fulfill withdrawals anymore
        // if not spent, it should exist in chain, which is checked below
        Ok(!self.is_utxo_spent(&current_collateral_outpoint).await?)
    }
}

/// Extension trait for test-only RPC methods that depend on core test infrastructure.
#[cfg(test)]
#[async_trait]
pub trait TestRpcExtensions {
    /// A helper fn to safely mine blocks while waiting for all actors to be synced.
    async fn mine_blocks_while_synced<C: CitreaClientT>(
        &self,
        block_num: u64,
        actors: &TestActors<C>,
        e2e: Option<&CitreaE2EData<'_>>,
    ) -> Result<Vec<BlockHash>>;
}

#[cfg(test)]
#[async_trait]
impl TestRpcExtensions for ExtendedBitcoinRpc {
    async fn mine_blocks_while_synced<C: CitreaClientT>(
        &self,
        block_num: u64,
        actors: &TestActors<C>,
        e2e: Option<&CitreaE2EData<'_>>,
    ) -> Result<Vec<BlockHash>> {
        match e2e {
            Some(e2e) if e2e.bitcoin_nodes.iter().count() > 1 => {
                use bitcoin::secp256k1::rand::{thread_rng, Rng};
                e2e.bitcoin_nodes
                    .disconnect_nodes()
                    .await
                    .map_err(|e| eyre::eyre!("Failed to disconnect nodes: {}", e))?;
                let reorg_blocks =
                    thread_rng().gen_range(0..e2e.config.protocol_paramset().finality_depth as u64);
                let da0 = e2e.bitcoin_nodes.get(0).expect("node 0 should exist");
                let da1 = e2e.bitcoin_nodes.get(1).expect("node 1 should exist");

                let mut mined_blocks = Vec::new();
                while mined_blocks.len() < reorg_blocks as usize {
                    if !are_all_state_managers_synced(self, actors).await? {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        continue;
                    }
                    let num_mine_blocks =
                        std::cmp::min(MINE_BLOCK_COUNT, reorg_blocks - mined_blocks.len() as u64);
                    da0.generate(num_mine_blocks)
                        .await
                        .wrap_err("Failed to generate blocks")?;
                    let new_blocks = da1
                        .generate(num_mine_blocks)
                        .await
                        .wrap_err("Failed to generate blocks")?;
                    mined_blocks.extend(new_blocks);
                }
                mined_blocks.extend(
                    da1.generate(1)
                        .await
                        .wrap_err("Failed to generate blocks")?,
                );
                e2e.bitcoin_nodes
                    .connect_nodes()
                    .await
                    .map_err(|e| eyre::eyre!("Failed to connect nodes: {}", e))?;
                e2e.bitcoin_nodes
                    .wait_for_sync(None)
                    .await
                    .map_err(|e| eyre::eyre!("Failed to wait for sync: {}", e))?;
                while mined_blocks.len() != (reorg_blocks + block_num + 1) as usize {
                    if !are_all_state_managers_synced(self, actors).await? {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        continue;
                    }
                    let num_mine_blocks = std::cmp::min(
                        MINE_BLOCK_COUNT,
                        (reorg_blocks + block_num + 1) - mined_blocks.len() as u64,
                    );
                    mined_blocks.extend(self.mine_blocks(num_mine_blocks).await?);
                }
                Ok(mined_blocks)
            }
            _ => {
                let mut mined_blocks = Vec::new();
                while mined_blocks.len() < block_num as usize {
                    if !are_all_state_managers_synced(self, actors).await? {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        continue;
                    }
                    let num_mine_blocks =
                        std::cmp::min(MINE_BLOCK_COUNT, block_num - mined_blocks.len() as u64);
                    let new_blocks = self.mine_blocks(num_mine_blocks).await?;
                    mined_blocks.extend(new_blocks);
                }
                Ok(mined_blocks)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::actor::Actor;
    use crate::config::protocol::{ProtocolParamset, REGTEST_PARAMSET};
    use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
    use crate::test::common::{citrea, create_test_config_with_thread_name};
    use crate::{
        bitvm_client::SECP, extended_bitcoin_rpc::BitcoinRPCError, test::common::create_regtest_rpc,
    };
    use bitcoin::Amount;
    use bitcoin::{amount, key::Keypair, Address, FeeRate, XOnlyPublicKey};
    use bitcoincore_rpc::RpcApi;
    use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
    use citrea_e2e::config::{BitcoinConfig, TestCaseDockerConfig};
    use citrea_e2e::node::NodeKind;
    use citrea_e2e::test_case::TestCaseRunner;
    use citrea_e2e::Result;
    use citrea_e2e::{config::TestCaseConfig, framework::TestFramework, test_case::TestCase};
    use tonic::async_trait;

    #[tokio::test]
    async fn new_extended_rpc_with_clone() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        rpc.mine_blocks(101).await.unwrap();
        let height = rpc.get_block_count().await.unwrap();
        let hash = rpc.get_block_hash(height).await.unwrap();

        let cloned_rpc = rpc.clone_inner().await.unwrap();
        assert_eq!(cloned_rpc.get_block_count().await.unwrap(), height);
        assert_eq!(cloned_rpc.get_block_hash(height).await.unwrap(), hash);
    }

    #[tokio::test]
    async fn test_rpc_call_retry_with_invalid_credentials() {
        use crate::extended_bitcoin_rpc::RetryableError;
        use secrecy::SecretString;

        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;

        // Get a working connection first
        let working_rpc = regtest.rpc();
        let url = working_rpc.url().to_string();

        // Create connection with invalid credentials
        let invalid_user = SecretString::new("invalid_user".to_string().into());
        let invalid_password = SecretString::new("invalid_password".to_string().into());

        let res = ExtendedBitcoinRpc::connect(url, invalid_user, invalid_password, None).await;

        assert!(res.is_err());
        assert!(!res.unwrap_err().is_retryable());
    }

    #[tokio::test]
    async fn tx_checks_in_mempool_and_on_chain() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);

        let amount = amount::Amount::from_sat(10000);

        // Prepare a transaction.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        let tx = rpc.get_tx_of_txid(&utxo.txid).await.unwrap();
        let txid = tx.compute_txid();
        tracing::debug!("TXID: {}", txid);

        assert_eq!(tx.output[utxo.vout as usize].value, amount);
        assert_eq!(utxo.txid, txid);
        assert!(rpc
            .check_utxo_address_and_amount(&utxo, &address.script_pubkey(), amount)
            .await
            .unwrap());

        // In mempool.
        assert!(rpc.confirmation_blocks(&utxo.txid).await.is_err());
        assert!(rpc.get_blockhash_of_tx(&utxo.txid).await.is_err());
        assert!(!rpc.is_tx_on_chain(&txid).await.unwrap());
        assert!(rpc.is_utxo_spent(&utxo).await.is_err());

        rpc.mine_blocks(1).await.unwrap();
        let height = rpc.get_block_count().await.unwrap();
        assert_eq!(height as u32, rpc.get_current_chain_height().await.unwrap());
        let blockhash = rpc.get_block_hash(height).await.unwrap();

        // On chain.
        assert_eq!(rpc.confirmation_blocks(&utxo.txid).await.unwrap(), 1);
        assert_eq!(
            rpc.get_blockhash_of_tx(&utxo.txid).await.unwrap(),
            blockhash
        );
        assert_eq!(rpc.get_tx_of_txid(&txid).await.unwrap(), tx);
        assert!(rpc.is_tx_on_chain(&txid).await.unwrap());
        assert!(!rpc.is_utxo_spent(&utxo).await.unwrap());

        // Doesn't matter if in mempool or on chain.
        let txout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();
        assert_eq!(txout.value, amount);
        assert_eq!(rpc.get_tx_of_txid(&txid).await.unwrap(), tx);

        let height = rpc.get_current_chain_height().await.unwrap();
        let (hash, header) = rpc.get_block_info_by_height(height.into()).await.unwrap();
        assert_eq!(blockhash, hash);
        assert_eq!(rpc.get_block_header(&hash).await.unwrap(), header);
    }

    #[tokio::test]
    async fn bump_fee_with_fee_rate() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);

        let amount = amount::Amount::from_sat(10000);

        // Confirmed transaction cannot be fee bumped.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        rpc.mine_blocks(1).await.unwrap();
        assert!(rpc
            .bump_fee_with_fee_rate(utxo.txid, FeeRate::from_sat_per_vb(1).unwrap())
            .await
            .inspect_err(|e| {
                match e {
                    BitcoinRPCError::TransactionAlreadyInBlock(_) => {}
                    _ => panic!("Unexpected error: {e:?}"),
                }
            })
            .is_err());

        let current_fee_rate = FeeRate::from_sat_per_vb_unchecked(1);

        // Trying to bump a transaction with a fee rate that is already enough
        // should return the original txid.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        let txid = rpc
            .bump_fee_with_fee_rate(utxo.txid, current_fee_rate)
            .await
            .unwrap();
        assert_eq!(txid, utxo.txid);

        // A bigger fee rate should return a different txid.
        let new_fee_rate = FeeRate::from_sat_per_vb_unchecked(10000);
        let txid = rpc
            .bump_fee_with_fee_rate(utxo.txid, new_fee_rate)
            .await
            .unwrap();
        assert_ne!(txid, utxo.txid);
    }

    struct ReorgChecks;
    #[async_trait]
    impl TestCase for ReorgChecks {
        fn bitcoin_config() -> BitcoinConfig {
            BitcoinConfig {
                extra_args: vec![
                    "-txindex=1",
                    "-fallbackfee=0.000001",
                    "-rpcallowip=0.0.0.0/0",
                    "-dustrelayfee=0",
                ],
                ..Default::default()
            }
        }

        fn test_config() -> TestCaseConfig {
            TestCaseConfig {
                with_sequencer: true,
                with_batch_prover: false,
                n_nodes: HashMap::from([(NodeKind::Bitcoin, 2)]),
                docker: TestCaseDockerConfig {
                    bitcoin: true,
                    citrea: true,
                },
                ..Default::default()
            }
        }

        async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
            let (da0, da1) = (
                f.bitcoin_nodes.get(0).unwrap(),
                f.bitcoin_nodes.get(1).unwrap(),
            );

            let mut config = create_test_config_with_thread_name().await;
            const PARAMSET: ProtocolParamset = ProtocolParamset {
                finality_depth: DEFAULT_FINALITY_DEPTH as u32,
                ..REGTEST_PARAMSET
            };
            config.protocol_paramset = &PARAMSET;
            citrea::update_config_with_citrea_e2e_values(
                &mut config,
                da0,
                f.sequencer.as_ref().expect("Sequencer is present"),
                None,
            );

            let rpc = ExtendedBitcoinRpc::connect(
                config.bitcoin_rpc_url.clone(),
                config.bitcoin_rpc_user.clone(),
                config.bitcoin_rpc_password.clone(),
                None,
            )
            .await
            .unwrap();

            // Reorg starts here.
            f.bitcoin_nodes.disconnect_nodes().await?;

            let before_reorg_tip_height = rpc.get_block_count().await?;
            let before_reorg_tip_hash = rpc.get_block_hash(before_reorg_tip_height).await?;

            let address = Actor::new(config.secret_key, config.protocol_paramset.network).address;
            let tx = rpc
                .send_to_address(&address, Amount::from_sat(10000))
                .await?;

            assert!(!rpc.is_tx_on_chain(&tx.txid).await?);
            rpc.mine_blocks(1).await?;
            assert!(rpc.is_tx_on_chain(&tx.txid).await?);

            // Make the second branch longer and perform a reorg.
            let reorg_depth = 4;
            da1.generate(reorg_depth).await.unwrap();
            f.bitcoin_nodes.connect_nodes().await?;
            f.bitcoin_nodes.wait_for_sync(None).await?;

            // Check that reorg happened.
            let current_tip_height = rpc.get_block_count().await?;
            assert_eq!(
                before_reorg_tip_height + reorg_depth,
                current_tip_height,
                "Re-org did not occur"
            );
            let current_tip_hash = rpc.get_block_hash(current_tip_height).await?;
            assert_ne!(
                before_reorg_tip_hash, current_tip_hash,
                "Re-org did not occur"
            );

            assert!(!rpc.is_tx_on_chain(&tx.txid).await?);

            Ok(())
        }
    }

    #[tokio::test]
    async fn reorg_checks() -> Result<()> {
        TestCaseRunner::new(ReorgChecks).run().await
    }

    mod retry_config_tests {
        use crate::extended_bitcoin_rpc::RetryConfig;

        use std::time::Duration;

        #[test]
        fn test_retry_config_default() {
            let config = RetryConfig::default();
            assert_eq!(config.initial_delay_millis, 100);
            assert_eq!(config.max_delay, Duration::from_secs(30));
            assert_eq!(config.max_attempts, 5);
            assert_eq!(config.backoff_multiplier, 2);
            assert!(!config.is_jitter);
        }

        #[test]
        fn test_retry_config_custom() {
            let initial = 200;
            let max = Duration::from_secs(10);
            let attempts = 7;
            let backoff_multiplier = 3;
            let jitter = true;
            let config = RetryConfig::new(initial, max, attempts, backoff_multiplier, jitter);
            assert_eq!(config.initial_delay_millis, initial);
            assert_eq!(config.max_delay, max);
            assert_eq!(config.max_attempts, attempts);
            assert_eq!(config.backoff_multiplier, backoff_multiplier);
            assert!(config.is_jitter);
        }

        #[test]
        fn test_retry_strategy_initial_delay() {
            // Test that the first delay matches the expected initial_delay_millis
            // when initial_delay_millis is divisible by backoff_multiplier
            let initial_delay_millis = 100;
            let backoff_multiplier = 2;
            let config = RetryConfig::new(
                initial_delay_millis,
                Duration::from_secs(30),
                5,
                backoff_multiplier,
                false, // no jitter for predictable testing
            );

            let mut strategy = config.get_strategy();
            let first_delay = strategy.next().expect("Should have first delay");

            // The formula is: first_delay = base * factor
            // We set base = initial_delay_millis / backoff_multiplier
            // So: first_delay = (initial_delay_millis / backoff_multiplier) * backoff_multiplier = initial_delay_millis
            assert_eq!(
                first_delay,
                Duration::from_millis(initial_delay_millis),
                "First delay should match initial_delay_millis"
            );

            // Verify the second delay is approximately initial_delay_millis * backoff_multiplier
            let second_delay = strategy.next().expect("Should have second delay");
            assert_eq!(
                second_delay,
                Duration::from_millis(initial_delay_millis * backoff_multiplier),
                "Second delay should be initial_delay_millis * backoff_multiplier"
            );
        }
    }

    mod retryable_error_tests {
        use bitcoin::{hashes::Hash, BlockHash, Txid};

        use crate::extended_bitcoin_rpc::RetryableError;

        use super::*;
        use std::io::{Error as IoError, ErrorKind};

        #[test]
        fn test_bitcoin_rpc_error_retryable_io_errors() {
            let retryable_kinds = [
                ErrorKind::ConnectionRefused,
                ErrorKind::ConnectionReset,
                ErrorKind::ConnectionAborted,
                ErrorKind::NotConnected,
                ErrorKind::BrokenPipe,
                ErrorKind::TimedOut,
                ErrorKind::Interrupted,
                ErrorKind::UnexpectedEof,
            ];

            for kind in retryable_kinds {
                let io_error = IoError::new(kind, "test error");
                let rpc_error = bitcoincore_rpc::Error::Io(io_error);
                assert!(
                    rpc_error.is_retryable(),
                    "ErrorKind::{kind:?} should be retryable"
                );
            }
        }

        #[test]
        fn test_bitcoin_rpc_error_non_retryable_io_errors() {
            let non_retryable_kinds = [
                ErrorKind::PermissionDenied,
                ErrorKind::NotFound,
                ErrorKind::InvalidInput,
                ErrorKind::InvalidData,
            ];

            for kind in non_retryable_kinds {
                let io_error = IoError::new(kind, "test error");
                let rpc_error = bitcoincore_rpc::Error::Io(io_error);
                assert!(
                    !rpc_error.is_retryable(),
                    "ErrorKind::{kind:?} should not be retryable"
                );
            }
        }

        #[test]
        fn test_bitcoin_rpc_error_auth_not_retryable() {
            let auth_error = bitcoincore_rpc::Error::Auth("Invalid credentials".to_string());
            assert!(!auth_error.is_retryable());
        }

        #[test]
        fn test_bitcoin_rpc_error_url_parse_not_retryable() {
            let url_error = url::ParseError::EmptyHost;
            let rpc_error = bitcoincore_rpc::Error::UrlParse(url_error);
            assert!(!rpc_error.is_retryable());
        }

        #[test]
        fn test_bitcoin_rpc_error_invalid_cookie_not_retryable() {
            let rpc_error = bitcoincore_rpc::Error::InvalidCookieFile;
            assert!(!rpc_error.is_retryable());
        }

        #[test]
        fn test_bitcoin_rpc_error_returned_error_non_retryable_patterns() {
            let non_retryable_messages = [
                "insufficient funds",
                "transaction already in blockchain",
                "invalid transaction",
                "not found in mempool",
                "transaction conflict",
            ];

            for msg in non_retryable_messages {
                let rpc_error = bitcoincore_rpc::Error::ReturnedError(msg.to_string());
                assert!(
                    !rpc_error.is_retryable(),
                    "Message '{msg}' should not be retryable"
                );
            }
        }

        #[test]
        fn test_bitcoin_rpc_error_unexpected_structure_retryable() {
            let rpc_error = bitcoincore_rpc::Error::UnexpectedStructure;
            assert!(rpc_error.is_retryable());
        }

        #[test]
        fn test_bitcoin_rpc_error_serialization_errors_not_retryable() {
            use bitcoin::consensus::encode::Error as EncodeError;

            let serialization_errors = [
                bitcoincore_rpc::Error::BitcoinSerialization(EncodeError::Io(
                    IoError::other("test").into(),
                )),
                // bitcoincore_rpc::Error::Hex(HexToBytesError::InvalidChar(InvalidCharError{invalid: 0})),
                bitcoincore_rpc::Error::Json(serde_json::Error::io(IoError::other("test"))),
            ];

            for error in serialization_errors {
                assert!(
                    !error.is_retryable(),
                    "Serialization error should not be retryable"
                );
            }
        }

        #[test]
        fn test_bridge_rpc_error_retryable() {
            // Test permanent errors
            assert!(
                !BitcoinRPCError::TransactionAlreadyInBlock(BlockHash::all_zeros()).is_retryable()
            );
            assert!(!BitcoinRPCError::BumpFeeUTXOSpent(Default::default()).is_retryable());

            // Test potentially retryable errors
            let txid = Txid::all_zeros();
            let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);
            assert!(BitcoinRPCError::BumpFeeError(txid, fee_rate).is_retryable());

            // Test Other error with retryable patterns
            let retryable_other = BitcoinRPCError::Other(eyre::eyre!("timeout occurred"));
            assert!(retryable_other.is_retryable());

            let non_retryable_other = BitcoinRPCError::Other(eyre::eyre!("permission denied"));
            assert!(!non_retryable_other.is_retryable());
        }
    }

    mod rpc_call_retry_tests {

        use crate::extended_bitcoin_rpc::RetryableError;

        use super::*;
        use secrecy::SecretString;

        #[tokio::test]
        async fn test_rpc_call_retry_with_invalid_host() {
            let user = SecretString::new("user".to_string().into());
            let password = SecretString::new("password".to_string().into());
            let invalid_url = "http://nonexistent-host:8332".to_string();

            let res = ExtendedBitcoinRpc::connect(invalid_url, user, password, None).await;

            assert!(res.is_err());
            assert!(!res.unwrap_err().is_retryable());
        }
    }

    mod convenience_method_tests {
        use super::*;

        #[tokio::test]
        async fn test_get_block_hash_with_retry() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;
            let rpc = regtest.rpc();

            // Mine a block first
            rpc.mine_blocks(1).await.unwrap();
            let height = rpc.get_block_count().await.unwrap();

            let result = rpc.get_block_hash(height).await;
            assert!(result.is_ok());

            let expected_hash = rpc.get_block_hash(height).await.unwrap();
            assert_eq!(result.unwrap(), expected_hash);
        }

        #[tokio::test]
        async fn test_get_tx_out_with_retry() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;
            let rpc = regtest.rpc();

            // Create a transaction
            let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
            let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);
            let amount = Amount::from_sat(10000);

            let utxo = rpc.send_to_address(&address, amount).await.unwrap();

            let result = rpc.get_tx_of_txid(&utxo.txid).await;
            assert!(result.is_ok());

            let tx = result.unwrap();
            assert_eq!(tx.compute_txid(), utxo.txid);
        }

        #[tokio::test]
        async fn test_send_to_address_with_retry() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;
            let rpc = regtest.rpc();

            let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
            let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);
            let amount = Amount::from_sat(10000);

            let result = rpc.send_to_address(&address, amount).await;
            assert!(result.is_ok());

            let outpoint = result.unwrap();

            // Verify the transaction exists
            let tx = rpc.get_tx_of_txid(&outpoint.txid).await.unwrap();
            assert_eq!(tx.output[outpoint.vout as usize].value, amount);
        }

        #[tokio::test]
        async fn test_bump_fee_with_retry() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;
            let rpc = regtest.rpc();

            let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
            let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);
            let amount = Amount::from_sat(10000);

            // Create an unconfirmed transaction
            let utxo = rpc.send_to_address(&address, amount).await.unwrap();
            let new_fee_rate = FeeRate::from_sat_per_vb_unchecked(10000);

            let result = rpc.bump_fee_with_fee_rate(utxo.txid, new_fee_rate).await;
            assert!(result.is_ok());

            let new_txid = result.unwrap();
            // Should return a different txid since fee was actually bumped
            assert_ne!(new_txid, utxo.txid);
        }
    }
}
