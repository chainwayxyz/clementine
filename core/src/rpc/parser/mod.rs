use super::clementine::{Outpoint, WinternitzPubkey};
use super::error;
use crate::errors::BridgeError;
use crate::rpc::clementine::DepositParams;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use bitvm::signatures::winternitz;
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
/// ```text
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

impl TryFrom<Outpoint> for OutPoint {
    type Error = BridgeError;

    fn try_from(value: Outpoint) -> Result<Self, Self::Error> {
        let hash = match Hash::from_slice(&value.txid) {
            Ok(h) => h,
            Err(e) => return Err(BridgeError::FromSliceError(e)),
        };

        Ok(OutPoint {
            txid: Txid::from_raw_hash(hash),
            vout: value.vout,
        })
    }
}
impl From<OutPoint> for Outpoint {
    fn from(value: OutPoint) -> Self {
        Outpoint {
            txid: value.txid.to_byte_array().to_vec(),
            vout: value.vout,
        }
    }
}

impl TryFrom<WinternitzPubkey> for winternitz::PublicKey {
    type Error = BridgeError;

    fn try_from(value: WinternitzPubkey) -> Result<Self, Self::Error> {
        let inner = value.digit_pubkey;

        inner
            .into_iter()
            .enumerate()
            .map(|(i, inner_vec)| {
                inner_vec.try_into().map_err(|e: Vec<u8>| {
                    BridgeError::RPCParamMalformed(
                        format!("digit_pubkey.[{}]", i),
                        format!("Incorrect length {:?}, expected 20", e.len()),
                    )
                })
            })
            .collect::<Result<Vec<[u8; 20]>, BridgeError>>()
    }
}
impl From<winternitz::PublicKey> for WinternitzPubkey {
    fn from(value: winternitz::PublicKey) -> Self {
        {
            let digit_pubkey = value.into_iter().map(|inner| inner.to_vec()).collect();

            WinternitzPubkey { digit_pubkey }
        }
    }
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

#[cfg(test)]
mod tests {
    use crate::rpc::clementine::{Outpoint, WinternitzPubkey};
    use bitcoin::{hashes::Hash, OutPoint, Txid};
    use bitvm::signatures::winternitz;

    #[test]
    fn from_bitcoin_outpoint_to_proto_outpoint() {
        let og_outpoint = OutPoint {
            txid: Txid::from_raw_hash(Hash::from_slice(&[0x1F; 32]).unwrap()),
            vout: 0x45,
        };

        let proto_outpoint: Outpoint = og_outpoint.into();
        let bitcoin_outpoint: OutPoint = proto_outpoint.try_into().unwrap();
        assert_eq!(og_outpoint, bitcoin_outpoint);

        let proto_outpoint = Outpoint {
            txid: vec![0x1F; 32],
            vout: 0x45,
        };
        let bitcoin_outpoint: OutPoint = proto_outpoint.try_into().unwrap();
        assert_eq!(og_outpoint, bitcoin_outpoint);
    }

    #[test]
    fn from_proto_outpoint_to_bitcoin_outpoint() {
        let og_outpoint = Outpoint {
            txid: vec![0x1F; 32],
            vout: 0x45,
        };

        let bitcoin_outpoint: OutPoint = og_outpoint.clone().try_into().unwrap();
        let proto_outpoint: Outpoint = bitcoin_outpoint.into();
        assert_eq!(og_outpoint, proto_outpoint);

        let bitcoin_outpoint = OutPoint {
            txid: Txid::from_raw_hash(Hash::from_slice(&[0x1F; 32]).unwrap()),
            vout: 0x45,
        };
        let proto_outpoint: Outpoint = bitcoin_outpoint.into();
        assert_eq!(og_outpoint, proto_outpoint);
    }

    #[test]
    fn from_proto_winternitz_public_key_to_bitvm() {
        let og_wpk = vec![[0x45u8; 20]];

        let rpc_wpk: WinternitzPubkey = og_wpk.clone().into();
        let rpc_converted_wpk: winternitz::PublicKey =
            rpc_wpk.try_into().expect("encoded wpk has to be valid");
        assert_eq!(og_wpk, rpc_converted_wpk);
    }
}
