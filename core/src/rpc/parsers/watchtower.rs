use crate::rpc::{
    clementine::{self, watchtower_params},
    error,
};
use bitcoin::XOnlyPublicKey;
use bitvm::signatures::winternitz::PublicKey as WinternitzPublicKey;
use tonic::Status;

pub fn parse_watchtower_id(
    watchtower_param: clementine::watchtower_params::Response,
) -> Result<u32, Status> {
    if let watchtower_params::Response::WatchtowerId(watchtower_id) = watchtower_param {
        Ok(watchtower_id)
    } else {
        Err(Status::invalid_argument("Expected watchtower id"))
    }
}

pub fn parse_watchtower_winternitz_public_key(
    watchtower_param: clementine::watchtower_params::Response,
) -> Result<WinternitzPublicKey, Status> {
    if let watchtower_params::Response::WinternitzPubkeys(wpk) = watchtower_param {
        Ok(wpk.try_into()?)
    } else {
        Err(Status::invalid_argument("Expected WinternitzPubkeys"))
    }
}

pub fn parse_watchtower_xonly_pk(
    watchtower_param: clementine::watchtower_params::Response,
) -> Result<XOnlyPublicKey, Status> {
    if let watchtower_params::Response::XonlyPk(xonly_pk) = watchtower_param {
        let xonly_pk = XOnlyPublicKey::from_slice(&xonly_pk).map_err(|e| {
            error::invalid_argument("xonly_pk", "Can't convert bytes in to XOnlyPublicKey")(e)
        })?;

        Ok(xonly_pk)
    } else {
        Err(Status::invalid_argument("Expected x-only-pk")) // TODO: tell whats returned too
    }
}
