use bitcoin::{taproot::TaprootSpendInfo, Address, OutPoint, ScriptBuf};
use circuit_helpers::{config::BRIDGE_AMOUNT_SATS, constant::CONFIRMATION_BLOCK_COUNT};
use secp256k1::XOnlyPublicKey;

use crate::{errors::DepositError, extended_rpc::ExtendedRpc, transaction_builder::TransactionBuilder};

pub fn check_utxo_validity(
    rpc: &ExtendedRpc,
    tx_builder: &TransactionBuilder,
    outpoint: &OutPoint,
    return_address: &XOnlyPublicKey,
    amount_sats: u64,
) -> Result<(Address, TaprootSpendInfo), DepositError> {
    if rpc.confirmation_blocks(&outpoint.txid) < CONFIRMATION_BLOCK_COUNT {
        return Err(DepositError::NotFinalized);
    }

    let (deposit_address, deposit_taproot_spend_info) = tx_builder
    .generate_deposit_address(return_address);

    if !rpc.check_utxo_address_and_amount(
        &outpoint,
        &deposit_address.script_pubkey(),
        amount_sats,
    ) {
        return Err(DepositError::InvalidAddressOrAmount);
    }

    if rpc.is_utxo_spent(&outpoint) {
        return Err(DepositError::AlreadySpent);
    }
    return Ok((deposit_address, deposit_taproot_spend_info));
}
