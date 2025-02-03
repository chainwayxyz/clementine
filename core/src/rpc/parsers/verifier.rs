use crate::{rpc::clementine, EVMAddress};
use bitcoin::address::NetworkUnchecked;
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
        super::convert_int_to_another(user_takes_after, u16::try_from)?,
        session_id,
    ))
}
