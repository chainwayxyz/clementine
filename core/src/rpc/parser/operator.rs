use crate::{
    fetch_next_message_from_stream,
    rpc::{
        clementine::{operator_params, OperatorParams},
        error::expected_msg_got_none,
    },
};
use bitcoin::{hashes::Hash, Address, Txid, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use std::str::FromStr;
use tonic::Status;

/// Parses operator configuration from a given stream.
///
/// # Returns
///
/// A tuple, containing:
///
/// - Operator index
/// - Collateral Funding txid
/// - Operator's X-only public key
/// - Wallet reimburse address
pub async fn parse_operator_config(
    stream: &mut tonic::Streaming<OperatorParams>,
) -> Result<(u32, Txid, XOnlyPublicKey, Address), Status> {
    let operator_param = fetch_next_message_from_stream!(stream, response, "response")?;

    let operator_config =
        if let operator_params::Response::OperatorDetails(operator_config) = operator_param {
            operator_config
        } else {
            return Err(expected_msg_got_none("OperatorDetails")());
        };

    let operator_xonly_pk = XOnlyPublicKey::from_str(&operator_config.xonly_pk)
        .map_err(|_| Status::invalid_argument("Invalid operator xonly public key".to_string()))?;

    let collateral_funding_txid = Txid::from_byte_array(
        operator_config
            .collateral_funding_txid
            .try_into()
            .map_err(|e| {
                Status::invalid_argument(format!(
                    "Failed to convert collateral funding txid to Txid: {:?}",
                    e
                ))
            })?,
    );

    let wallet_reimburse_address = Address::from_str(&operator_config.wallet_reimburse_address)
        .map_err(|e| {
            Status::invalid_argument(format!("Failed to parse wallet reimburse address: {:?}", e))
        })?
        .assume_checked();

    Ok((
        operator_config.operator_idx,
        collateral_funding_txid,
        operator_xonly_pk,
        wallet_reimburse_address,
    ))
}

pub async fn parse_operator_challenge_ack_public_hash(
    stream: &mut tonic::Streaming<OperatorParams>,
) -> Result<[u8; 20], Status> {
    let operator_param = fetch_next_message_from_stream!(stream, response, "response")?;

    let digest = if let operator_params::Response::ChallengeAckDigests(digest) = operator_param {
        digest
    } else {
        return Err(Status::invalid_argument("Expected ChallengeAckDigests"));
    };

    // Ensure `digest.hash` is exactly 20 bytes
    if digest.hash.len() != 20 {
        return Err(Status::invalid_argument(
            "Digest hash length is not 20 bytes",
        ));
    }

    let public_hash: [u8; 20] = digest
        .hash
        .try_into()
        .map_err(|_| Status::invalid_argument("Failed to convert digest hash into PublicHash"))?;

    Ok(public_hash)
}

pub async fn parse_operator_winternitz_public_keys(
    stream: &mut tonic::Streaming<OperatorParams>,
) -> Result<winternitz::PublicKey, Status> {
    let operator_param = fetch_next_message_from_stream!(stream, response, "response")?;

    if let operator_params::Response::WinternitzPubkeys(wpk) = operator_param {
        Ok(wpk.try_into()?)
    } else {
        Err(expected_msg_got_none("WinternitzPubkeys")())
    }
}
