use super::clementine::{
    self, DepositParams, FeeType, Outpoint, RawSignedTx, SchnorrSig, TransactionRequest,
    WinternitzPubkey,
};
use super::error;
use crate::builder::transaction::sign::TransactionRequestData;
use crate::builder::transaction::{
    Actors, BaseDepositData, DepositData, DepositInfo, DepositType, ReplacementDepositData,
};
use crate::errors::BridgeError;
use crate::tx_sender::FeePayingType;
use bitcoin::hashes::{sha256d, FromSliceError, Hash};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Txid, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use eyre::Context;
use std::fmt::{Debug, Display};
use std::num::TryFromIntError;
use tonic::Status;

pub mod operator;
pub mod verifier;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ParserError {
    // RPC errors
    #[error("RPC function field {0} is required")]
    RPCRequiredParam(&'static str),
    #[error("RPC function parameter {0} is malformed")]
    RPCParamMalformed(String),
}

impl From<ParserError> for tonic::Status {
    fn from(value: ParserError) -> Self {
        match value {
            ParserError::RPCRequiredParam(field) => {
                Status::invalid_argument(format!("RPC function field {} is required.", field))
            }
            ParserError::RPCParamMalformed(field) => {
                Status::invalid_argument(format!("RPC function parameter {} is malformed.", field))
            }
        }
    }
}

#[allow(dead_code)]
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

/// Fetches the next message from a stream which is unwrapped and encapsulated
/// by a [`Result`].
///
/// # Parameters
///
/// - stream: [`tonic::Streaming`] typed input stream
/// - field: Input field ident (struct member) to look in the next message
///
/// # Returns
///
/// A [`Result`] containing the next message. Will return an [`Err`] variant if
/// stream has exhausted.
#[macro_export]
macro_rules! fetch_next_message_from_stream {
    ($stream:expr, $field:ident) => {
        $crate::fetch_next_optional_message_from_stream!($stream, $field).ok_or(
            $crate::rpc::error::expected_msg_got_none(stringify!($field))(),
        )
    };
}

/// Fetches next message from a stream.
///
/// # Parameters
///
/// - stream: [`tonic::Streaming`] typed input stream
/// - field: Input field ident (struct member) to look in the next message
///
/// # Returns
///
/// An [`Option`] containing the next message. Will return a [`None`] variant if
/// stream has exhausted.
#[macro_export]
macro_rules! fetch_next_optional_message_from_stream {
    ($stream:expr, $field:ident) => {
        $stream
            .message()
            .await?
            .ok_or($crate::rpc::error::input_ended_prematurely())?
            .$field
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
                inner_vec
                    .try_into()
                    .map_err(|e: Vec<_>| eyre::eyre!("Incorrect length {:?}, expected 20", e.len()))
                    .wrap_err_with(|| {
                        ParserError::RPCParamMalformed(format!("digit_pubkey.[{}]", i))
                    })
            })
            .collect::<Result<Vec<[u8; 20]>, eyre::Report>>()
            .map_err(Into::into)
    }
}

impl From<FeePayingType> for FeeType {
    fn from(value: FeePayingType) -> Self {
        match value {
            FeePayingType::CPFP => FeeType::Cpfp,
            FeePayingType::RBF => FeeType::Rbf,
        }
    }
}

impl TryFrom<FeeType> for FeePayingType {
    type Error = Status;

    fn try_from(value: FeeType) -> Result<Self, Self::Error> {
        match value {
            FeeType::Cpfp => Ok(FeePayingType::CPFP),
            FeeType::Rbf => Ok(FeePayingType::RBF),
            _ => Err(Status::invalid_argument("Invalid FeeType variant")),
        }
    }
}

impl TryFrom<SchnorrSig> for Signature {
    type Error = BridgeError;

    fn try_from(value: SchnorrSig) -> Result<Self, Self::Error> {
        Signature::from_slice(&value.schnorr_sig)
            .wrap_err("Failed to parse schnorr signature")
            .wrap_err_with(|| ParserError::RPCParamMalformed("schnorr_sig".to_string()))
            .map_err(Into::into)
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

macro_rules! serialize_keys_to_vec {
    ($pubkeys:expr) => {
        $pubkeys.iter().map(|pk| pk.serialize().to_vec()).collect()
    };
}

impl From<DepositInfo> for clementine::Deposit {
    fn from(value: DepositInfo) -> Self {
        clementine::Deposit {
            deposit_outpoint: Some(value.deposit_outpoint.into()),
            deposit_data: Some(value.deposit_type.into()),
        }
    }
}

impl TryFrom<clementine::Deposit> for DepositInfo {
    type Error = Status;

    fn try_from(value: clementine::Deposit) -> Result<Self, Self::Error> {
        let deposit_outpoint: OutPoint = value
            .deposit_outpoint
            .ok_or_else(|| Status::invalid_argument("No deposit outpoint received"))?
            .try_into()?;

        let deposit_type = value
            .deposit_data
            .ok_or_else(|| Status::invalid_argument("No deposit data received"))?
            .try_into()?;

        Ok(DepositInfo {
            deposit_outpoint,
            deposit_type,
        })
    }
}

impl From<DepositData> for DepositParams {
    fn from(value: DepositData) -> Self {
        let actors: clementine::Actors = value.actors.into();

        let deposit: clementine::Deposit = value.deposit.into();

        DepositParams {
            deposit: Some(deposit),
            actors: Some(actors),
        }
    }
}

impl TryFrom<DepositParams> for DepositData {
    type Error = Status;

    fn try_from(value: DepositParams) -> Result<Self, Self::Error> {
        let deposit: DepositInfo = value
            .deposit
            .ok_or(Status::invalid_argument("No deposit received"))?
            .try_into()?;
        let actors: Actors = value
            .actors
            .ok_or(Status::invalid_argument("No actors received"))?
            .try_into()?;

        Ok(DepositData {
            nofn_xonly_pk: None,
            deposit,
            actors,
        })
    }
}

impl TryFrom<clementine::deposit::DepositData> for DepositType {
    type Error = Status;

    fn try_from(value: clementine::deposit::DepositData) -> Result<Self, Self::Error> {
        match value {
            clementine::deposit::DepositData::BaseDeposit(data) => {
                Ok(DepositType::BaseDeposit(BaseDepositData {
                    evm_address: data.evm_address.try_into().map_err(|e| {
                        Status::invalid_argument(format!(
                            "Failed to convert evm_address to EVMAddress: {}",
                            e
                        ))
                    })?,
                    recovery_taproot_address: data
                        .recovery_taproot_address
                        .parse::<bitcoin::Address<_>>()
                        .map_err(|e| Status::internal(e.to_string()))?,
                }))
            }
            clementine::deposit::DepositData::ReplacementDeposit(data) => {
                Ok(DepositType::ReplacementDeposit(ReplacementDepositData {
                    old_move_txid: data
                        .old_move_txid
                        .ok_or(Status::invalid_argument("No move_txid received"))?
                        .try_into().map_err(|e| {
                            Status::invalid_argument(format!(
                                "Failed to convert replacement deposit move_txid to bitcoin::Txid: {}",
                                e
                            ))
                        })?,
                }))
            }
        }
    }
}

impl From<DepositType> for clementine::deposit::DepositData {
    fn from(value: DepositType) -> Self {
        match value {
            DepositType::BaseDeposit(data) => {
                clementine::deposit::DepositData::BaseDeposit(clementine::BaseDeposit {
                    evm_address: data.evm_address.0.to_vec(),
                    recovery_taproot_address: data
                        .recovery_taproot_address
                        .assume_checked()
                        .to_string(),
                })
            }
            DepositType::ReplacementDeposit(data) => {
                clementine::deposit::DepositData::ReplacementDeposit(
                    clementine::ReplacementDeposit {
                        old_move_txid: Some(data.old_move_txid.into()),
                    },
                )
            }
        }
    }
}

impl TryFrom<clementine::Actors> for Actors {
    type Error = Status;

    fn try_from(value: clementine::Actors) -> Result<Self, Self::Error> {
        let verifiers = parse_public_keys(&value.verifiers)?;
        let watchtowers = parse_xonly_public_keys(&value.watchtowers)?;
        let operators = parse_xonly_public_keys(&value.operators)?;

        Ok(Actors {
            verifiers,
            watchtowers,
            operators,
        })
    }
}

impl From<Actors> for clementine::Actors {
    fn from(value: Actors) -> Self {
        clementine::Actors {
            verifiers: serialize_keys_to_vec!(&value.verifiers),
            watchtowers: serialize_keys_to_vec!(&value.watchtowers),
            operators: serialize_keys_to_vec!(&value.operators),
        }
    }
}

impl TryFrom<RawSignedTx> for bitcoin::Transaction {
    type Error = Status;

    fn try_from(value: RawSignedTx) -> Result<Self, Self::Error> {
        bitcoin::consensus::encode::deserialize(&value.raw_tx)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse raw signed tx: {}", e)))
    }
}

impl From<&bitcoin::Transaction> for RawSignedTx {
    fn from(value: &bitcoin::Transaction) -> Self {
        RawSignedTx {
            raw_tx: bitcoin::consensus::encode::serialize(value),
        }
    }
}

impl From<Txid> for clementine::Txid {
    fn from(value: Txid) -> Self {
        {
            let txid = value.to_byte_array().to_vec();

            clementine::Txid { txid }
        }
    }
}
impl TryFrom<clementine::Txid> for Txid {
    type Error = FromSliceError;

    fn try_from(value: clementine::Txid) -> Result<Self, Self::Error> {
        {
            let txid = value.txid;

            Ok(Txid::from_raw_hash(sha256d::Hash::from_slice(&txid)?))
        }
    }
}

fn parse_xonly_public_keys(pk: &[Vec<u8>]) -> Result<Vec<XOnlyPublicKey>, Status> {
    pk.iter()
        .map(|pk| {
            XOnlyPublicKey::from_slice(pk).map_err(|e| {
                Status::invalid_argument(format!("Failed to parse xonly public key: {}", e))
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

fn parse_public_keys(pk: &[Vec<u8>]) -> Result<Vec<PublicKey>, Status> {
    pk.iter()
        .map(|pk| {
            PublicKey::from_slice(pk)
                .map_err(|e| Status::invalid_argument(format!("Failed to parse public key: {}", e)))
        })
        .collect::<Result<Vec<_>, _>>()
}

pub fn parse_transaction_request(
    request: TransactionRequest,
) -> Result<TransactionRequestData, Status> {
    let deposit_outpoint: OutPoint = request
        .deposit_outpoint
        .ok_or(Status::invalid_argument("No deposit params received"))?
        .try_into()?;

    let kickoff_id = request
        .kickoff_id
        .ok_or(Status::invalid_argument("No kickoff params received"))?;

    Ok(TransactionRequestData {
        deposit_outpoint,
        kickoff_data: kickoff_id.try_into()?,
    })
}

impl TryFrom<clementine::KickoffId> for crate::builder::transaction::KickoffData {
    type Error = Status;

    fn try_from(value: clementine::KickoffId) -> Result<Self, Self::Error> {
        let operator_xonly_pk =
            XOnlyPublicKey::from_slice(&value.operator_xonly_pk).map_err(|e| {
                Status::invalid_argument(format!("Failed to parse operator_xonly_pk: {}", e))
            })?;

        Ok(crate::builder::transaction::KickoffData {
            operator_xonly_pk,
            round_idx: value.round_idx,
            kickoff_idx: value.kickoff_idx,
        })
    }
}

impl From<crate::builder::transaction::KickoffData> for clementine::KickoffId {
    fn from(value: crate::builder::transaction::KickoffData) -> Self {
        clementine::KickoffId {
            operator_xonly_pk: value.operator_xonly_pk.serialize().to_vec(),
            round_idx: value.round_idx,
            kickoff_idx: value.kickoff_idx,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::clementine::{self, Outpoint, WinternitzPubkey};
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

    #[test]
    fn from_txid_to_proto_txid() {
        let og_txid = Txid::from_raw_hash(Hash::from_slice(&[0x1F; 32]).unwrap());

        let rpc_txid: clementine::Txid = og_txid.into();
        let rpc_converted_txid: Txid = rpc_txid.try_into().unwrap();
        assert_eq!(og_txid, rpc_converted_txid);
    }
}
