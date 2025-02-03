use crate::rpc::{
    clementine::{self, operator_params},
    error::expected_msg_got_none,
};
use bitcoin::{hashes::Hash, Address, Txid, XOnlyPublicKey};
use std::str::FromStr;
use tonic::Status;

/// Parses a [`clementine::operator_params::Response`] in to a tuple of operator
/// configurations, if the struct has
/// [`operator_params::Response::OperatorDetails`] enum type.
///
/// # Returns
///
/// A tuple, containing:
///
/// - Operator index
/// - Collateral Funding txid
/// - Operator's X-only public key
/// - Wallet reimburse address
pub fn parse_operator_config(
    config: clementine::operator_params::Response,
) -> Result<(u32, Txid, XOnlyPublicKey, Address), Status> {
    let operator_details =
        if let operator_params::Response::OperatorDetails(operator_config) = config {
            operator_config
        } else {
            return Err(expected_msg_got_none("OperatorDetails")());
        };

    let operator_xonly_pk = XOnlyPublicKey::from_str(&operator_details.xonly_pk)
        .map_err(|_| Status::invalid_argument("Invalid operator xonly public key".to_string()))?;

    let collateral_funding_txid = Txid::from_byte_array(
        operator_details
            .collateral_funding_txid
            .try_into()
            .map_err(|e| {
                Status::invalid_argument(format!(
                    "Failed to convert collateral funding txid to Txid: {:?}",
                    e
                ))
            })?,
    );

    let wallet_reimburse_address = Address::from_str(&operator_details.wallet_reimburse_address)
        .map_err(|e| {
            Status::invalid_argument(format!("Failed to parse wallet reimburse address: {:?}", e))
        })?
        .assume_checked();

    Ok((
        operator_details.operator_idx,
        collateral_funding_txid,
        operator_xonly_pk,
        wallet_reimburse_address,
    ))
}
