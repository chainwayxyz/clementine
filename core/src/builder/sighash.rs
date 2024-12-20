use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::UTXO;
use crate::{actor::Actor, builder, database::Database, EVMAddress};
use async_stream::try_stream;
use bitcoin::{address::NetworkUnchecked, Address, Amount, OutPoint};
use bitcoin::{TapSighash, Transaction};
use futures_core::stream::Stream;

pub fn create_nofn_sighash_stream(
    db: Database,
    config: BridgeConfig,
    deposit_outpoint: OutPoint,
    evm_address: EVMAddress,
    recovery_taproot_address: Address<NetworkUnchecked>,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    user_takes_after: u64,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    try_stream! {
        // Collect kickoff transactions.
        let kickoff_txs = collect_kickoff_txs(db, config.clone(), nofn_xonly_pk, evm_address).await?;

        for tx in kickoff_txs {
            let kickoff_utxo = UTXO {
                outpoint: OutPoint {
                    txid: tx.compute_txid(),
                    vout: 0
                },
                txout: tx.output[0].clone()
            };
            let mut tx_handler = builder::transaction::create_watchtower_challenge_page_txhandler(
                &kickoff_utxo,
                nofn_xonly_pk,
                config.bridge_amount_sats,
                config.num_watchtowers as u32,
                config.network,
            );

            yield Actor::convert_tx_to_sighash_script_spend(&mut tx_handler, 0, 0)?;
        }

        // First iterate over operators
        // For each operator, iterate over time txs
        // For each time tx, create kickoff txid
        // using kickoff txid, create watchtower challenge page
        // yield watchtower challenge page sighash
        // yield watchtower challenge tx sighash per watchtower
        // yield sighash_single|anyonecanpay sighash for challenge tx
        // TBC

        // yield Actor::convert_tx_to_sighash_script_spend(&mut timeout_tx_handler, 0, 0)?;
    }
}

async fn collect_kickoff_txs(
    db: Database,
    config: BridgeConfig,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    user_evm_address: EVMAddress,
) -> Result<Vec<Transaction>, BridgeError> {
    let mut kickoff_txs: Vec<Transaction> = Vec::new();
    for operator in 0..config.num_operators {
        for time_tx in db.get_time_txs(None, operator as i32).await? {
            let time_tx_outpoint = OutPoint {
                txid: time_tx.1,
                vout: 2,
            };
            let kickoff_tx = builder::transaction::create_kickoff_tx(
                time_tx_outpoint,
                nofn_xonly_pk,
                user_evm_address,
            );

            kickoff_txs.push(kickoff_tx);
        }
    }

    Ok(kickoff_txs)
}

pub fn create_timout_tx_sighash_stream(
    operator_xonly_pk: secp256k1::XOnlyPublicKey,
    collateral_funding_txid: bitcoin::Txid,
    collateral_funding_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: i64,
    num_time_txs: usize,
    network: bitcoin::Network,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    let mut input_txid = collateral_funding_txid;
    let mut input_amunt = collateral_funding_amount;

    try_stream! {
        for _ in 0..num_time_txs {
            let time_tx = builder::transaction::create_time_tx(
                operator_xonly_pk,
                input_txid,
                input_amunt,
                timeout_block_count,
                max_withdrawal_time_block_count,
                network,
            );

            let mut timeout_tx_handler = builder::transaction::create_timeout_tx_handler(
                operator_xonly_pk,
                time_tx.compute_txid(),
                timeout_block_count,
                network,
            );

            yield Actor::convert_tx_to_sighash_script_spend(&mut timeout_tx_handler, 0, 0)?;

            let time2_tx = builder::transaction::create_time2_tx(
                operator_xonly_pk,
                time_tx.compute_txid(),
                input_amunt,
                network,
            );

            input_txid = time2_tx.compute_txid();
            input_amunt = time2_tx.output[0].value;
        }
    }
}
