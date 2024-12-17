use crate::errors::BridgeError;
use crate::{actor::Actor, builder, database::Database, EVMAddress};
use async_stream::try_stream;
use bitcoin::TapSighash;
use bitcoin::{address::NetworkUnchecked, Address, Amount, OutPoint};
use futures_core::stream::Stream;

pub fn create_nofn_sighash_stream(
    _db: Database,
    deposit_outpoint: OutPoint,
    evm_address: EVMAddress,
    recovery_taproot_address: Address<NetworkUnchecked>,
    user_takes_after: u64,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    network: bitcoin::Network,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    try_stream! {
        for i in 0..10 {
            let mut dummy_move_tx_handler = builder::transaction::create_move_tx_handler(
                deposit_outpoint,
                evm_address,
                &recovery_taproot_address,
                nofn_xonly_pk,
                network,
                user_takes_after as u32,
                Amount::from_sat(i as u64 + 1000000),
            );

            yield Actor::convert_tx_to_sighash_script_spend(&mut dummy_move_tx_handler, 0, 0)?;
        }
    }
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
