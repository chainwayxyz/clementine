use super::error;
use crate::rpc::clementine::DepositParams;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use std::fmt::{Debug, Display};
use std::num::TryFromIntError;
use tonic::Status;

pub mod verifier;

/// Converts an integer type in to another integer type. This is needed because
/// tonic defaults to wrong integer types for some parameters.
pub fn convert_int_to_another<SOURCE, TARGET>(
    field_name: &str,
    value: SOURCE,
    try_from: fn(SOURCE) -> Result<TARGET, TryFromIntError>,
) -> Result<TARGET, Status>
where
    SOURCE: Copy + Debug + Display,
{
    try_from(value)
        .map_err(|e| error::invalid_argument(field_name, "Given number is out of bounds")(e))
}

pub fn parse_deposit_params(
    deposit_params: DepositParams,
) -> Result<
    (
        bitcoin::OutPoint,
        EVMAddress,
        bitcoin::Address<NetworkUnchecked>,
        u16,
    ),
    Status,
> {
    let deposit_outpoint: bitcoin::OutPoint = deposit_params
        .deposit_outpoint
        .ok_or(Status::invalid_argument("No deposit outpoint received"))?
        .try_into()?;
    let evm_address: EVMAddress = deposit_params
        .evm_address
        .try_into()
        .map_err(|_| Status::invalid_argument("Could not parse deposit outpoint EVM address"))?;
    let recovery_taproot_address = deposit_params
        .recovery_taproot_address
        .parse::<bitcoin::Address<_>>()
        .map_err(|e| Status::internal(e.to_string()))?;
    let user_takes_after = deposit_params.user_takes_after;

    Ok((
        deposit_outpoint,
        evm_address,
        recovery_taproot_address,
        convert_int_to_another("user_takes_after", user_takes_after, u16::try_from)?,
    ))
}
