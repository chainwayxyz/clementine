use bitcoin::address::NetworkUnchecked;
use tonic::Status;
use crate::EVMAddress;
use crate::rpc::clementine::DepositParams;

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
    let evm_address: EVMAddress = deposit_params.evm_address.try_into().unwrap();
    let recovery_taproot_address = deposit_params
        .recovery_taproot_address
        .parse::<bitcoin::Address<_>>()
        .map_err(|e| Status::internal(e.to_string()))?;
    let user_takes_after = deposit_params.user_takes_after;
    Ok((
        deposit_outpoint,
        evm_address,
        recovery_taproot_address,
        u16::try_from(user_takes_after).map_err(|e| {
            Status::invalid_argument(format!(
                "user_takes_after is too big, failed to convert: {}",
                e
            ))
        })?,
    ))
}