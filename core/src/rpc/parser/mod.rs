use super::error;
use crate::rpc::clementine::DepositParams;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use std::fmt::{Debug, Display};
use std::num::TryFromIntError;
use tonic::Status;

pub mod operator;
pub mod verifier;
pub mod watchtower;

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

/// Fetches next message from a stream. There are 2 ways to use this macro,
/// depending on the next element:
///
/// 1. Next message **must** be present in the stream
/// 2. There might not be a next element: Stream has ended
///
/// # Parameters
///
/// - stream: [`tonic::Streaming`] typed input stream
/// - field: Input field ident (struct member) to look in the next message
/// - field_str: [`str`] form of the `field`. If this field is omitted, second
///   case will be in effect and an [`Option`] will be returned instead of a
///   [`Result`]
///
/// # Returns
///
/// In the first usage, a [`Result`] will be returned by the macro. In the
/// second usage however, an [`Option`] will be returned.
///
/// # Examples
///
/// ```no_run
/// // A response enum, that includes possible stream elements. This will panic
/// // if the stream has ended.
/// let operator_param: operator_params::Response = fetch_next_from_stream!(stream, response, "response").unwrap();
///
/// // A response enum wrapped around by an [`Option`], that includes possible
/// // stream elements. This won't panic if stream has ended.
/// let operator_param: Option<operator_params::Response> = fetch_next_from_stream!(stream, response);
/// ```
#[macro_export]
macro_rules! fetch_next_message_from_stream {
    ($stream:expr, $field:ident) => {
        $stream
            .message()
            .await?
            .ok_or($crate::rpc::error::input_ended_prematurely())?
            .$field
    };

    ($stream:expr, $field:ident, $field_str:literal) => {
        fetch_next_message_from_stream!($stream, $field)
            .ok_or($crate::rpc::error::expected_msg_got_none($field_str)())
    };
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
