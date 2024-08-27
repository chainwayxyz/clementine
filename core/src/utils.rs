use crate::actor::Actor;
use crate::errors::BridgeError;
use crate::musig2::aggregate_partial_signatures;
use crate::musig2::create_key_agg_ctx;
use crate::musig2::MuSigAggNonce;
use crate::transaction_builder::TransactionBuilder;
use crate::transaction_builder::TxHandler;
use crate::EVMAddress;
use crate::UTXO;
use bitcoin;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::Address;
use bitcoin::OutPoint;
use bitcoin::XOnlyPublicKey;
use hex;
use std::borrow::BorrowMut;
use std::str::FromStr;

lazy_static::lazy_static! {
    /// Global secp context.
    pub static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    pub static ref UNSPENDABLE_PUBKEY: bitcoin::secp256k1::PublicKey =
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51".parse().unwrap();
}

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    pub static ref UNSPENDABLE_XONLY_PUBKEY: bitcoin::secp256k1::XOnlyPublicKey =
        XOnlyPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").unwrap();
}

lazy_static::lazy_static! {
    pub static ref NETWORK : bitcoin::Network = bitcoin::Network::Regtest;
}

pub fn parse_hex_to_btc_tx(
    tx_hex: &str,
) -> Result<bitcoin::blockdata::transaction::Transaction, bitcoin::consensus::encode::Error> {
    if let Ok(reader) = hex::decode(tx_hex) {
        bitcoin::blockdata::transaction::Transaction::consensus_decode(&mut &reader[..])
    } else {
        Err(bitcoin::consensus::encode::Error::ParseFailed(
            "Could not decode hex",
        ))
    }
}

pub fn handle_taproot_witness_new<T: AsRef<[u8]>>(
    tx: &mut TxHandler,
    witness_elements: &[T],
    txin_index: usize,
    script_index: usize,
) -> Result<(), BridgeError> {
    let mut sighash_cache = SighashCache::new(tx.tx.borrow_mut());

    let witness = sighash_cache
        .witness_mut(txin_index)
        .ok_or(BridgeError::TxInputNotFound)?;

    witness_elements
        .iter()
        .for_each(|element| witness.push(element));

    let spend_control_block = tx.taproot_spend_infos[txin_index]
        .control_block(&(
            tx.scripts[txin_index][script_index].clone(),
            LeafVersion::TapScript,
        ))
        .ok_or(BridgeError::ControlBlockError)?;

    witness.push(tx.scripts[txin_index][script_index].clone());
    witness.push(spend_control_block.serialize());

    Ok(())
}

pub fn aggregate_slash_or_take_partial_sigs(
    deposit_outpoint: OutPoint,
    kickoff_utxo: UTXO,
    verifiers_pks: Vec<secp256k1::PublicKey>,
    operator_xonly_pk: secp256k1::XOnlyPublicKey,
    operator_idx: usize,
    agg_nonce: &MuSigAggNonce,
    partial_sigs: Vec<[u8; 32]>,
    network: bitcoin::Network,
) -> Result<[u8; 64], BridgeError> {
    let key_agg_ctx = create_key_agg_ctx(verifiers_pks.clone(), None)?;
    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let (musig_agg_xonly_pubkey, _) = musig_agg_pubkey.x_only_public_key();
    let musig_agg_xonly_pubkey_wrapped =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();
    let mut tx = TransactionBuilder::create_slash_or_take_tx(
        deposit_outpoint,
        kickoff_utxo,
        &operator_xonly_pk,
        operator_idx,
        &musig_agg_xonly_pubkey_wrapped,
        network,
    );
    tracing::debug!("SLASH_OR_TAKE_TX: {:?}", tx);
    tracing::debug!("SLASH_OR_TAKE_TX weight: {:?}", tx.tx.weight());
    let message: [u8; 32] = Actor::convert_tx_to_sighash_script_spend(&mut tx, 0, 0)
        .unwrap()
        .to_byte_array();
    let final_sig: [u8; 64] = aggregate_partial_signatures(
        verifiers_pks.clone(),
        None,
        agg_nonce,
        partial_sigs,
        message,
    )?;

    Ok(final_sig)
}

pub fn aggregate_operator_takes_partial_sigs(
    deposit_outpoint: OutPoint,
    kickoff_utxo: UTXO,
    operator_xonly_pk: &XOnlyPublicKey,
    operator_idx: usize,
    verifiers_pks: Vec<secp256k1::PublicKey>,
    agg_nonce: &MuSigAggNonce,
    partial_sigs: Vec<[u8; 32]>,
    network: bitcoin::Network,
) -> Result<[u8; 64], BridgeError> {
    let key_agg_ctx = create_key_agg_ctx(verifiers_pks.clone(), None)?;
    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let (musig_agg_xonly_pubkey, _) = musig_agg_pubkey.x_only_public_key();
    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();

    let move_tx_handler = TransactionBuilder::create_move_tx(
        deposit_outpoint,
        &EVMAddress([0u8; 20]),
        Address::p2tr(&self::SECP, *self::UNSPENDABLE_XONLY_PUBKEY, None, network).as_unchecked(),
        &nofn_xonly_pk,
        network,
    );
    let bridge_fund_outpoint = OutPoint {
        txid: move_tx_handler.tx.compute_txid(),
        vout: 0,
    };
    let slash_or_take_tx_handler = TransactionBuilder::create_slash_or_take_tx(
        deposit_outpoint,
        kickoff_utxo,
        operator_xonly_pk,
        operator_idx,
        &nofn_xonly_pk,
        network,
    );
    let slash_or_take_utxo = UTXO {
        outpoint: OutPoint {
            txid: slash_or_take_tx_handler.tx.compute_txid(),
            vout: 0,
        },
        txout: slash_or_take_tx_handler.tx.output[0].clone(),
    };
    let mut tx = TransactionBuilder::create_operator_takes_tx(
        bridge_fund_outpoint,
        slash_or_take_utxo,
        operator_xonly_pk,
        &nofn_xonly_pk,
        network,
    );
    tracing::debug!("OPERATOR_TAKES_TX: {:?}", tx);
    tracing::debug!("OPERATOR_TAKES_TX weight: {:?}", tx.tx.weight());
    let message: [u8; 32] = Actor::convert_tx_to_sighash_pubkey_spend(&mut tx, 0)
        .unwrap()
        .to_byte_array();
    // println!("Message: {:?}", message);
    // println!("Partial sigs: {:?}", partial_sigs);
    // println!("Agg nonce: {:?}", agg_nonce);
    let final_sig: [u8; 64] = aggregate_partial_signatures(
        verifiers_pks.clone(),
        None,
        agg_nonce,
        partial_sigs,
        message,
    )?;

    Ok(final_sig)
}

pub fn aggregate_move_partial_sigs(
    deposit_outpoint: OutPoint,
    evm_address: &EVMAddress,
    recovery_taproot_address: &Address<NetworkUnchecked>,
    verifiers_pks: Vec<secp256k1::PublicKey>,
    agg_nonce: &MuSigAggNonce,
    partial_sigs: Vec<[u8; 32]>,
    network: bitcoin::Network,
) -> Result<[u8; 64], BridgeError> {
    let key_agg_ctx = create_key_agg_ctx(verifiers_pks.clone(), None)?;
    let musig_agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let (musig_agg_xonly_pubkey, _) = musig_agg_pubkey.x_only_public_key();
    let musig_agg_xonly_pubkey_wrapped =
        bitcoin::XOnlyPublicKey::from_slice(&musig_agg_xonly_pubkey.serialize()).unwrap();
    let mut tx = TransactionBuilder::create_move_tx(
        deposit_outpoint,
        evm_address,
        recovery_taproot_address,
        &musig_agg_xonly_pubkey_wrapped,
        network,
    );
    println!("MOVE_TX: {:?}", tx);
    println!("MOVE_TXID: {:?}", tx.tx.compute_txid());
    let message: [u8; 32] = Actor::convert_tx_to_sighash_script_spend(&mut tx, 0, 0)
        .unwrap()
        .to_byte_array();
    let final_sig: [u8; 64] = aggregate_partial_signatures(
        verifiers_pks.clone(),
        None,
        agg_nonce,
        partial_sigs,
        message,
    )?;

    Ok(final_sig)
}

pub fn get_claim_reveal_indices(depth: usize, count: u32) -> Vec<(usize, usize)> {
    assert!(count <= 2u32.pow(depth as u32));

    if count == 0 {
        return vec![(0, 0)];
    }

    let mut indices: Vec<(usize, usize)> = Vec::new();
    if count == 2u32.pow(depth as u32) {
        return indices;
    }

    if count % 2 == 1 {
        indices.push((depth, count as usize));
        indices.extend(get_claim_reveal_indices(depth - 1, (count + 1) / 2));
    } else {
        indices.extend(get_claim_reveal_indices(depth - 1, count / 2));
    }

    indices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_indices() {
        let test_cases = vec![
            ((0, 0), vec![(0, 0)]),
            ((0, 1), vec![]),
            ((1, 0), vec![(0, 0)]),
            ((1, 1), vec![(1, 1)]),
            ((1, 2), vec![]),
            ((2, 0), vec![(0, 0)]),
            ((2, 1), vec![(2, 1), (1, 1)]),
            ((2, 2), vec![(1, 1)]),
            ((2, 3), vec![(2, 3)]),
            ((2, 4), vec![]),
            ((3, 0), vec![(0, 0)]),
            ((3, 1), vec![(3, 1), (2, 1), (1, 1)]),
            ((3, 2), vec![(2, 1), (1, 1)]),
            ((3, 3), vec![(3, 3), (1, 1)]),
            ((3, 4), vec![(1, 1)]),
            ((3, 5), vec![(3, 5), (2, 3)]),
            ((3, 6), vec![(2, 3)]),
            ((3, 7), vec![(3, 7)]),
            ((3, 8), vec![]),
        ];

        for ((depth, index), expected) in test_cases {
            let indices = get_claim_reveal_indices(depth, index);
            assert_eq!(
                indices, expected,
                "Failed at get_indices({}, {})",
                depth, index
            );
        }
    }
}
