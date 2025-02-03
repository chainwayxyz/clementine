use crate::{
    fetch_next_from_stream,
    rpc::{
        clementine::{watchtower_params, WatchtowerParams},
        error,
    },
};
use bitcoin::XOnlyPublicKey;
use bitvm::signatures::winternitz::PublicKey as WinternitzPublicKey;
use tonic::Status;

pub async fn parse_watchtower_id(
    stream: &mut tonic::Streaming<WatchtowerParams>,
) -> Result<u32, Status> {
    let watchtower_param = fetch_next_from_stream!(stream)?;

    if let watchtower_params::Response::WatchtowerId(watchtower_id) = watchtower_param {
        Ok(watchtower_id)
    } else {
        Err(Status::invalid_argument("Expected watchtower id"))
    }
}

pub async fn parse_watchtower_winternitz_public_key(
    stream: &mut tonic::Streaming<WatchtowerParams>,
) -> Result<WinternitzPublicKey, Status> {
    let watchtower_param = fetch_next_from_stream!(stream)?;

    if let watchtower_params::Response::WinternitzPubkeys(wpk) = watchtower_param {
        Ok(wpk.try_into()?)
    } else {
        Err(Status::invalid_argument("Expected WinternitzPubkeys"))
    }
}

pub async fn parse_watchtower_xonly_pk(
    stream: &mut tonic::Streaming<WatchtowerParams>,
) -> Result<XOnlyPublicKey, Status> {
    let watchtower_param = fetch_next_from_stream!(stream)?;

    if let watchtower_params::Response::XonlyPk(xonly_pk) = watchtower_param {
        let xonly_pk = XOnlyPublicKey::from_slice(&xonly_pk).map_err(|e| {
            error::invalid_argument("xonly_pk", "Can't convert bytes in to XOnlyPublicKey")(e)
        })?;

        Ok(xonly_pk)
    } else {
        Err(Status::invalid_argument("Expected x-only-pk")) // TODO: tell whats returned too
    }
}
