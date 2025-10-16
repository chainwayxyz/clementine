use crate::{
    citrea::CitreaClientT,
    errors::BridgeError,
    fetch_next_message_from_stream,
    operator::Operator,
    rpc::{
        clementine::{
            operator_params, DepositParams, DepositSignSession, OperatorConfig, OperatorParams,
            Outpoint, SchnorrSig, WithdrawParams, XOnlyPublicKeyRpc,
        },
        error::{self, expected_msg_got_none},
    },
};
use bitcoin::{
    address::NetworkUnchecked, secp256k1::schnorr::Signature, taproot, Address, Amount, OutPoint,
    ScriptBuf, TapSighashType, XOnlyPublicKey,
};
use bitvm::signatures::winternitz;
use eyre::Context;
use std::str::FromStr;
use tonic::Status;

impl<C> From<Operator<C>> for OperatorParams
where
    C: CitreaClientT,
{
    fn from(operator: Operator<C>) -> Self {
        let operator_config = OperatorConfig {
            collateral_funding_outpoint: Some(Outpoint {
                txid: Some(operator.collateral_funding_outpoint.txid.into()),
                vout: operator.collateral_funding_outpoint.vout,
            }),
            xonly_pk: operator.signer.xonly_public_key.to_string(),
            wallet_reimburse_address: operator.reimburse_addr.to_string(),
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

impl From<Signature> for OperatorParams {
    fn from(sig: Signature) -> Self {
        OperatorParams {
            response: Some(operator_params::Response::UnspentKickoffSig(SchnorrSig {
                schnorr_sig: sig.serialize().to_vec(),
            })),
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

impl From<XOnlyPublicKey> for XOnlyPublicKeyRpc {
    fn from(xonly_public_key: XOnlyPublicKey) -> Self {
        XOnlyPublicKeyRpc {
            xonly_public_key: xonly_public_key.serialize().to_vec(),
        }
    }
}

impl TryFrom<XOnlyPublicKeyRpc> for XOnlyPublicKey {
    type Error = BridgeError;

    fn try_from(xonly_public_key_rpc: XOnlyPublicKeyRpc) -> Result<Self, Self::Error> {
        Ok(
            XOnlyPublicKey::from_slice(&xonly_public_key_rpc.xonly_public_key)
                .wrap_err("Failed to parse XOnlyPublicKey")?,
        )
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
) -> Result<(OutPoint, XOnlyPublicKey, Address<NetworkUnchecked>), Status> {
    let operator_param = fetch_next_message_from_stream!(stream, response)?;

    let operator_config =
        if let operator_params::Response::OperatorDetails(operator_config) = operator_param {
            operator_config
        } else {
            return Err(expected_msg_got_none("OperatorDetails")());
        };

    let operator_xonly_pk = XOnlyPublicKey::from_str(&operator_config.xonly_pk)
        .map_err(|_| Status::invalid_argument("Invalid operator xonly public key".to_string()))?;

    let collateral_funding_outpoint = operator_config
        .collateral_funding_outpoint
        .ok_or(Status::invalid_argument(
            "Collateral funding outpoint not provided".to_string(),
        ))?
        .try_into()?;

    let wallet_reimburse_address = Address::from_str(&operator_config.wallet_reimburse_address)
        .map_err(|e| {
            Status::invalid_argument(format!("Failed to parse wallet reimburse address: {e:?}"))
        })?;

    Ok((
        collateral_funding_outpoint,
        operator_xonly_pk,
        wallet_reimburse_address,
    ))
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

pub async fn parse_schnorr_sig(
    stream: &mut tonic::Streaming<OperatorParams>,
) -> Result<Signature, Status> {
    let operator_param = fetch_next_message_from_stream!(stream, response)?;

    if let operator_params::Response::UnspentKickoffSig(wpk) = operator_param {
        Ok(wpk.try_into()?)
    } else {
        Err(expected_msg_got_none("UnspentKickoffSig")())
    }
}

#[allow(clippy::result_large_err)]
pub fn parse_withdrawal_sig_params(
    params: WithdrawParams,
) -> Result<(u32, taproot::Signature, OutPoint, ScriptBuf, Amount), Status> {
    let mut input_signature =
        taproot::Signature::from_slice(&params.input_signature).map_err(|e| {
            Status::invalid_argument(format!("Can't convert input to taproot Signature - {e}"))
        })?;

    // If the Taproot sighash type is Default (no explicit type attached; i.e. a 64-byte
    // signature without a sighash flag), normalize it to SinglePlusAnyoneCanPay.
    // Prior to v0.5 this was Clementine's implicit behavior; we retain it here for
    // backwards compatibility when a 64-byte signature is provided.
    if input_signature.sighash_type == TapSighashType::Default {
        tracing::warn!(
            "Input signature for withdrawal {} has sighash type default, setting to SinglePlusAnyoneCanPay", params.withdrawal_id,
        );
        input_signature.sighash_type = TapSighashType::SinglePlusAnyoneCanPay;
    }

    // enforce sighash type here
    if input_signature.sighash_type != TapSighashType::SinglePlusAnyoneCanPay {
        return Err(Status::invalid_argument(format!(
            "Input signature has wrong sighash type, SinglePlusAnyoneCanPay expected, got {}",
            input_signature.sighash_type
        )));
    }

    let input_outpoint: OutPoint = params
        .input_outpoint
        .ok_or_else(error::input_ended_prematurely)?
        .try_into()?;

    let users_intent_script_pubkey = ScriptBuf::from_bytes(params.output_script_pubkey);

    Ok((
        params.withdrawal_id,
        input_signature,
        input_outpoint,
        users_intent_script_pubkey,
        Amount::from_sat(params.output_amount),
    ))
}
