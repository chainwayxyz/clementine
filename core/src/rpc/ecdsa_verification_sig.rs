//! # ECDSA Verification Signature
//!
//! This module contains the ECDSA verification signature for the Clementine protocol.
//! It is for additional verification that the request for optimistic payout and withdrawal is coming from the aggregator, which
//! is the owner of the address in operator/verifiers config.
//!
//! The address who signed the signature is retrieved by calculating the EIP-712 hash of the withdrawal params.
//! The address is then compared to the address in the config.
//!

use alloy::primitives::PrimitiveSignature;
use alloy::sol_types::Eip712Domain;
use bitcoin::hashes::Hash;
use bitcoin::{taproot, OutPoint};
use bitcoin::{Amount, ScriptBuf};
use eyre::{Context, Result};

use clementine_errors::BridgeError;

alloy_sol_types::sol! {
    #[derive(Debug)]
    struct OptimisticPayoutMessage {
        uint32 withdrawal_id;
        bytes input_signature;
        bytes32 input_outpoint_txid;
        uint32 input_outpoint_vout;
        bytes output_script_pubkey;
        uint64 output_amount;
    }

    #[derive(Debug)]
    struct OperatorWithdrawalMessage  {
        uint32 withdrawal_id;
        bytes input_signature;
        bytes32 input_outpoint_txid;
        uint32 input_outpoint_vout;
        bytes output_script_pubkey;
        uint64 output_amount;
    }
}

pub static CLEMENTINE_EIP712_DOMAIN: Eip712Domain = alloy_sol_types::eip712_domain! {
    name: "ClementineVerification",
    version: "1",
};

pub trait WithdrawalMessage {
    fn new(
        deposit_id: u32,
        input_signature: taproot::Signature,
        input_outpoint: OutPoint,
        output_script_pubkey: ScriptBuf,
        output_amount: Amount,
    ) -> Self;
}

impl WithdrawalMessage for OptimisticPayoutMessage {
    fn new(
        deposit_id: u32,
        input_signature: taproot::Signature,
        input_outpoint: OutPoint,
        output_script_pubkey: ScriptBuf,
        output_amount: Amount,
    ) -> Self {
        OptimisticPayoutMessage {
            withdrawal_id: deposit_id,
            input_signature: input_signature.serialize().to_vec().into(),
            input_outpoint_txid: input_outpoint.txid.to_byte_array().into(),
            input_outpoint_vout: input_outpoint.vout,
            output_script_pubkey: output_script_pubkey.as_bytes().to_vec().into(),
            output_amount: output_amount.to_sat(),
        }
    }
}

impl WithdrawalMessage for OperatorWithdrawalMessage {
    fn new(
        deposit_id: u32,
        input_signature: taproot::Signature,
        input_outpoint: OutPoint,
        output_script_pubkey: ScriptBuf,
        output_amount: Amount,
    ) -> Self {
        OperatorWithdrawalMessage {
            withdrawal_id: deposit_id,
            input_signature: input_signature.serialize().to_vec().into(),
            input_outpoint_txid: input_outpoint.txid.to_byte_array().into(),
            input_outpoint_vout: input_outpoint.vout,
            output_script_pubkey: output_script_pubkey.as_bytes().to_vec().into(),
            output_amount: output_amount.to_sat(),
        }
    }
}

/// Recover the address from the signature
/// EIP712 hash is calculated from optimistic payout params
/// Signature is the signature of the eip712 hash
///
/// Parameters:
/// - deposit_id: The id of the deposit
/// - input_signature: The signature of the withdrawal input
/// - input_outpoint: The outpoint of the withdrawal input
/// - output_script_pubkey: The script pubkey of the withdrawal output
/// - output_amount: The amount of the withdrawal output
/// - signature: The signature of the eip712 hash of the withdrawal params
///
/// Returns:
/// - The address recovered from the signature
pub fn recover_address_from_ecdsa_signature<M: WithdrawalMessage + alloy_sol_types::SolStruct>(
    deposit_id: u32,
    input_signature: taproot::Signature,
    input_outpoint: OutPoint,
    output_script_pubkey: ScriptBuf,
    output_amount: Amount,
    signature: PrimitiveSignature,
) -> Result<alloy::primitives::Address, BridgeError> {
    let params = M::new(
        deposit_id,
        input_signature,
        input_outpoint,
        output_script_pubkey,
        output_amount,
    );

    let eip712_hash = params.eip712_signing_hash(&CLEMENTINE_EIP712_DOMAIN);

    let address = signature
        .recover_address_from_prehash(&eip712_hash)
        .wrap_err("Invalid signature")?;
    Ok(address)
}
