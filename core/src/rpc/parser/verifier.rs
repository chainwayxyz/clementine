use crate::{
    fetch_next_message_from_stream,
    rpc::{
        clementine::{
            self, verifier_deposit_finalize_params, NonceGenResponse, VerifierDepositFinalizeParams,
        },
        error::{self, invalid_argument},
    },
    EVMAddress,
};
use bitcoin::{address::NetworkUnchecked, secp256k1::schnorr};
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature};
use tonic::Status;

pub fn get_deposit_params(
    deposit_sign_session: clementine::DepositSignSession,
    verifier_idx: usize,
) -> Result<
    (
        bitcoin::OutPoint,
        EVMAddress,
        bitcoin::Address<NetworkUnchecked>,
        u16,
        u32,
    ),
    Status,
> {
    let deposit_params = deposit_sign_session
        .deposit_params
        .ok_or(Status::invalid_argument("No deposit outpoint received"))?;

    let deposit_outpoint: bitcoin::OutPoint = deposit_params
        .deposit_outpoint
        .ok_or(Status::invalid_argument("No deposit outpoint received"))?
        .try_into()?;
    let evm_address: EVMAddress = deposit_params.evm_address.try_into().map_err(|e| {
        Status::invalid_argument(format!(
            "Failed to convert evm_address to EVMAddress: {}",
            e
        ))
    })?;
    let recovery_taproot_address = deposit_params
        .recovery_taproot_address
        .parse::<bitcoin::Address<_>>()
        .map_err(|e| Status::internal(e.to_string()))?;
    let user_takes_after = deposit_params.user_takes_after;
    let session_id = deposit_sign_session.nonce_gen_first_responses[verifier_idx].id;

    Ok((
        deposit_outpoint,
        evm_address,
        recovery_taproot_address,
        super::convert_int_to_another("user_takes_after", user_takes_after, u16::try_from)?,
        session_id,
    ))
}

pub fn parse_partial_sigs(
    partial_sigs: Vec<Vec<u8>>,
) -> Result<Vec<MusigPartialSignature>, Status> {
    partial_sigs
        .iter()
        .enumerate()
        .map(|(idx, sig)| {
            MusigPartialSignature::from_slice(sig).map_err(|e| {
                error::invalid_argument(
                    "partial_sig",
                    format!("Verifier {idx} returned an invalid partial signature").as_str(),
                )(e)
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

pub async fn parse_next_deposit_finalize_param_schnorr_sig(
    stream: &mut tonic::Streaming<VerifierDepositFinalizeParams>,
) -> Result<Option<schnorr::Signature>, Status> {
    let sig = match fetch_next_message_from_stream!(stream, params) {
        Some(sig) => sig,
        None => return Ok(None),
    };

    let final_sig = match sig {
        verifier_deposit_finalize_params::Params::SchnorrSig(final_sig) => {
            schnorr::Signature::from_slice(&final_sig)
                .map_err(invalid_argument("FinalSig", "Invalid signature length"))?
        }
        _ => return Err(Status::internal("Expected FinalSig")),
    };

    Ok(Some(final_sig))
}

pub async fn parse_deposit_finalize_param_agg_nonce(
    stream: &mut tonic::Streaming<VerifierDepositFinalizeParams>,
) -> Result<MusigAggNonce, Status> {
    let sig = fetch_next_message_from_stream!(stream, params, "params")?;

    match sig {
        verifier_deposit_finalize_params::Params::MoveTxAggNonce(aggnonce) => {
            Ok(MusigAggNonce::from_slice(&aggnonce)
                .map_err(invalid_argument("MusigAggNonce", "failed to parse"))?)
        }
        _ => Err(Status::internal("Expected FinalSig")),
    }
}

pub async fn parse_nonce_gen_first_response(
    stream: &mut tonic::Streaming<NonceGenResponse>,
) -> Result<clementine::NonceGenFirstResponse, Status> {
    let nonce_gen_response = fetch_next_message_from_stream!(stream, response, "response")?;

    if let clementine::nonce_gen_response::Response::FirstResponse(nonce_gen_first_response) =
        nonce_gen_response
    {
        Ok(nonce_gen_first_response)
    } else {
        Err(Status::invalid_argument("Expected first_response"))
    }
}
