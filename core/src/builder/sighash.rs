use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::UTXO;
use crate::{actor::Actor, builder, database::Database, EVMAddress};
use async_stream::try_stream;
use bitcoin::hashes::Hash;
use bitcoin::{address::NetworkUnchecked, Address, Amount, OutPoint};
use bitcoin::{TapSighash, Transaction, Txid};
use bitvm::signatures::winternitz::{self, ListpickVerifier, TabledConverter};
use futures_core::stream::Stream;

pub async fn dummy(
    db: Database,
    config: BridgeConfig,
    deposit_outpoint: OutPoint,
    evm_address: EVMAddress,
    recovery_taproot_address: Address<NetworkUnchecked>,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    user_takes_after: u64,
    collateral_funding_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: i64,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> Result<(), BridgeError> {
    let move_tx = builder::transaction::create_move_tx(
        deposit_outpoint,
        nofn_xonly_pk,
        bridge_amount_sats,
        network,
    );
    let move_txid = move_tx.compute_txid();

    let operators: Vec<(secp256k1::XOnlyPublicKey, bitcoin::Address, Txid)> =
        db.get_operators(None).await?;

    if operators.len() < config.num_operators {
        panic!("Not enough operators");
    }

    for (operator_idx, (operator_xonly_pk, operator_reimburse_address, collateral_funding_txid)) in
        operators.iter().enumerate()
    {
        // get the watchtower winternitz pubkeys for this operator
        let watchtower_challenge_wots: Vec<_> = (0..config.num_watchtowers)
            .map(|i| db.get_winternitz_public_keys(None, i as u32, operator_idx as u32))
            .collect();
        let watchtower_challenge_wots =
            futures::future::try_join_all(watchtower_challenge_wots).await?;

        let mut input_txid = *collateral_funding_txid;
        let mut input_amunt = collateral_funding_amount;

        for time_tx_idx in 0..config.num_time_txs {
            let time_tx = builder::transaction::create_time_tx(
                *operator_xonly_pk,
                input_txid,
                input_amunt,
                timeout_block_count,
                max_withdrawal_time_block_count,
                network,
            );
            let time_txid = time_tx.compute_txid();

            // Now we have the time tx of interest here,

            let kickoff_tx = builder::transaction::create_kickoff_tx(
                time_txid,
                nofn_xonly_pk,
                move_txid,
                operator_idx as usize,
                network,
            );

            let kickoff_txid = kickoff_tx.compute_txid();

            let watchtower_wots = (0..config.num_watchtowers)
                .map(|i| watchtower_challenge_wots[i][time_tx_idx].clone())
                .collect::<Vec<_>>();

            let mut watchtower_challenge_page_tx_handler =
                builder::transaction::create_watchtower_challenge_page_txhandler(
                    kickoff_txid,
                    nofn_xonly_pk,
                    config.num_watchtowers as u32,
                    watchtower_wots.clone(),
                    network,
                );

            let _yield = Actor::convert_tx_to_sighash_pubkey_spend(
                &mut watchtower_challenge_page_tx_handler,
                0,
            )?;

            let wcp_txid = watchtower_challenge_page_tx_handler.tx.compute_txid();

            for i in 0..config.num_watchtowers {
                let mut watchtower_challenge_txhandler =
                    builder::transaction::create_watchtower_challenge_txhandler(
                        wcp_txid,
                        i,
                        watchtower_wots[i].clone(),
                        &[0u8; 20],
                        nofn_xonly_pk,
                        *operator_xonly_pk,
                        network,
                    );

                let _yield = Actor::convert_tx_to_sighash_script_spend(
                    &mut watchtower_challenge_txhandler,
                    0,
                    0,
                )?;
            }

            let time2_tx = builder::transaction::create_time2_tx(
                *operator_xonly_pk,
                time_txid,
                input_amunt,
                network,
            );

            input_txid = time2_tx.compute_txid();
            input_amunt = time2_tx.output[0].value;
        }
    }

    Ok(())
}

pub fn create_nofn_sighash_stream(
    db: Database,
    config: BridgeConfig,
    deposit_outpoint: OutPoint,
    evm_address: EVMAddress,
    recovery_taproot_address: Address<NetworkUnchecked>,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    user_takes_after: u64,
    collateral_funding_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: i64,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    try_stream! {
        let move_tx = builder::transaction::create_move_tx(
            deposit_outpoint,
            nofn_xonly_pk,
            bridge_amount_sats,
            network,
        );
        let move_txid = move_tx.compute_txid();

        let operators: Vec<(secp256k1::XOnlyPublicKey, bitcoin::Address, Txid)> =
            db.get_operators(None).await?;

        if operators.len() < config.num_operators {
            panic!("Not enough operators");
        }


        for (operator_idx, (operator_xonly_pk, operator_reimburse_address, collateral_funding_txid)) in
        operators.iter().enumerate()
    {
        // get the watchtower winternitz pubkeys for this operator
        let watchtower_challenge_wots: Vec<_> = (0..config.num_watchtowers)
            .map(|i| db.get_winternitz_public_keys(None, i as u32, operator_idx as u32))
            .collect();
        let watchtower_challenge_wots =
            futures::future::try_join_all(watchtower_challenge_wots).await?;

        let mut input_txid = *collateral_funding_txid;
        let mut input_amunt = collateral_funding_amount;

        for time_tx_idx in 0..config.num_time_txs {
            let time_tx = builder::transaction::create_time_tx(
                *operator_xonly_pk,
                input_txid,
                input_amunt,
                timeout_block_count,
                max_withdrawal_time_block_count,
                network,
            );
            let time_txid = time_tx.compute_txid();

            // Now we have the time tx of interest here,

            let kickoff_tx = builder::transaction::create_kickoff_tx(
                time_txid,
                nofn_xonly_pk,
                move_txid,
                operator_idx as usize,
                network,
            );

            let kickoff_txid = kickoff_tx.compute_txid();

            let watchtower_wots = (0..config.num_watchtowers)
                .map(|i| watchtower_challenge_wots[i][time_tx_idx].clone())
                .collect::<Vec<_>>();

            let mut watchtower_challenge_page_tx_handler =
                builder::transaction::create_watchtower_challenge_page_txhandler(
                    kickoff_txid,
                    nofn_xonly_pk,
                    config.num_watchtowers as u32,
                    watchtower_wots.clone(),
                    network,
                );

            yield Actor::convert_tx_to_sighash_pubkey_spend(
                &mut watchtower_challenge_page_tx_handler,
                0,
            )?;

            let wcp_txid = watchtower_challenge_page_tx_handler.tx.compute_txid();

            for i in 0..config.num_watchtowers {
                let mut watchtower_challenge_txhandler = builder::transaction::create_watchtower_challenge_txhandler(
                    wcp_txid,
                    i,
                    watchtower_wots[i].clone(),
                    &[0u8; 20],
                    nofn_xonly_pk,
                    *operator_xonly_pk,
                    network,
                );

                yield Actor::convert_tx_to_sighash_script_spend(
                    &mut watchtower_challenge_txhandler,
                    0,
                    0,
                )?;
            }

            let time2_tx = builder::transaction::create_time2_tx(
                *operator_xonly_pk,
                time_txid,
                input_amunt,
                network,
            );

            input_txid = time2_tx.compute_txid();
            input_amunt = time2_tx.output[0].value;
        }
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
