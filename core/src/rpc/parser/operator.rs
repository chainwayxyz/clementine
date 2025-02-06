use crate::{
    fetch_next_message_from_stream,
    operator::{Operator, PublicHash},
    rpc::{
        clementine::{
            self, operator_params, ChallengeAckDigest, DepositParams, DepositSignSession,
            NewWithdrawalSigParams, OperatorParams,
        },
        error::{self, expected_msg_got_none},
    },
};
use bitcoin::{
    hashes::Hash, secp256k1::schnorr::Signature, Address, Amount, OutPoint, ScriptBuf, Txid,
    XOnlyPublicKey,
};
use bitvm::signatures::winternitz;
use std::str::FromStr;
use tonic::Status;

impl From<Operator> for OperatorParams {
    fn from(operator: Operator) -> Self {
        let operator_config = clementine::OperatorConfig {
            operator_idx: operator.idx as u32,
            collateral_funding_txid: operator.collateral_funding_txid.to_byte_array().to_vec(),
            xonly_pk: operator.signer.xonly_public_key.to_string(),
            wallet_reimburse_address: operator.config.operator_wallet_addresses[operator.idx] // TODO: Fix this where the config will only have one address.
                .clone()
                .assume_checked()
                .to_string(),
        };

        OperatorParams {
            response: Some(operator_params::Response::OperatorDetails(operator_config)),
        }
    }
}

impl From<winternitz::PublicKey> for OperatorParams {
    fn from(winternitz_pubkey: winternitz::PublicKey) -> Self {
        OperatorParams {
            response: Some(operator_params::Response::WinternitzPubkeys(
                winternitz_pubkey.into(),
            )),
        }
    }
}

impl From<PublicHash> for OperatorParams {
    fn from(public_hash: PublicHash) -> Self {
        let hash = ChallengeAckDigest {
            hash: public_hash.to_vec(),
        };

        OperatorParams {
            response: Some(operator_params::Response::ChallengeAckDigests(hash)),
        }
    }
}

impl TryFrom<DepositSignSession> for DepositParams {
    type Error = Status;

    fn try_from(deposit_sign_session: DepositSignSession) -> Result<Self, Self::Error> {
        match deposit_sign_session.deposit_params {
            Some(deposit_params) => Ok(deposit_params),
            None => Err(expected_msg_got_none("Deposit Params")()),
        }
    }
}

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
pub async fn parse_details(
    stream: &mut tonic::Streaming<OperatorParams>,
) -> Result<(u32, Txid, XOnlyPublicKey, Address), Status> {
    let operator_param = fetch_next_message_from_stream!(stream, response)?;

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

pub async fn parse_challenge_ack_public_hash(
    stream: &mut tonic::Streaming<OperatorParams>,
) -> Result<[u8; 20], Status> {
    let operator_param = fetch_next_message_from_stream!(stream, response)?;

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

pub async fn parse_winternitz_public_keys(
    stream: &mut tonic::Streaming<OperatorParams>,
) -> Result<winternitz::PublicKey, Status> {
    let operator_param = fetch_next_message_from_stream!(stream, response)?;

    if let operator_params::Response::WinternitzPubkeys(wpk) = operator_param {
        Ok(wpk.try_into()?)
    } else {
        Err(expected_msg_got_none("WinternitzPubkeys")())
    }
}

pub async fn parse_withdrawal_sig_params(
    params: NewWithdrawalSigParams,
) -> Result<(u32, Signature, Option<OutPoint>, ScriptBuf, Amount), Status> {
    let user_sig = Signature::from_slice(&params.user_sig)
        .map_err(|e| error::invalid_argument("user_sig", "Can't convert input to Signature")(e))?;

    let users_intent_outpoint: Option<OutPoint> = if let Some(o) = params.users_intent_outpoint {
        Some(o.try_into()?)
    } else {
        None
    };

    let users_intent_script_pubkey = ScriptBuf::from_bytes(params.users_intent_script_pubkey);

    Ok((
        params.withdrawal_id,
        user_sig,
        users_intent_outpoint,
        users_intent_script_pubkey,
        Amount::from_sat(params.users_intent_amount),
    ))
}
