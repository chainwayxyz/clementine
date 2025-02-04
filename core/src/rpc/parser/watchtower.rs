use crate::{
    fetch_next_message_from_stream,
    rpc::{
        clementine::{watchtower_params, WatchtowerParams},
        error,
    },
};
use bitcoin::XOnlyPublicKey;
use bitvm::signatures::winternitz::{self, PublicKey as WinternitzPublicKey};
use tonic::Status;

impl From<winternitz::PublicKey> for WatchtowerParams {
    fn from(value: winternitz::PublicKey) -> Self {
        let wpk = value.into();

        WatchtowerParams {
            response: Some(watchtower_params::Response::WinternitzPubkeys(wpk)),
        }
    }
}

impl From<XOnlyPublicKey> for WatchtowerParams {
    fn from(value: XOnlyPublicKey) -> Self {
        let xonly_pk = value.serialize().to_vec();

        WatchtowerParams {
            response: Some(watchtower_params::Response::XonlyPk(xonly_pk)),
        }
    }
}

pub async fn parse_id(stream: &mut tonic::Streaming<WatchtowerParams>) -> Result<u32, Status> {
    let watchtower_param = fetch_next_message_from_stream!(stream, response, "response")?;

    if let watchtower_params::Response::WatchtowerId(watchtower_id) = watchtower_param {
        Ok(watchtower_id)
    } else {
        Err(Status::invalid_argument("Expected watchtower id"))
    }
}

pub async fn parse_winternitz_public_key(
    stream: &mut tonic::Streaming<WatchtowerParams>,
) -> Result<WinternitzPublicKey, Status> {
    let watchtower_param = fetch_next_message_from_stream!(stream, response, "response")?;

    if let watchtower_params::Response::WinternitzPubkeys(wpk) = watchtower_param {
        Ok(wpk.try_into()?)
    } else {
        Err(Status::invalid_argument("Expected WinternitzPubkeys"))
    }
}

pub async fn parse_xonly_pk(
    stream: &mut tonic::Streaming<WatchtowerParams>,
) -> Result<XOnlyPublicKey, Status> {
    let watchtower_param = fetch_next_message_from_stream!(stream, response, "response")?;

    if let watchtower_params::Response::XonlyPk(xonly_pk) = watchtower_param {
        let xonly_pk = XOnlyPublicKey::from_slice(&xonly_pk).map_err(|e| {
            error::invalid_argument("xonly_pk", "Can't convert bytes in to XOnlyPublicKey")(e)
        })?;

        Ok(xonly_pk)
    } else {
        Err(Status::invalid_argument("Expected x-only-pk")) // TODO: tell whats returned too
    }
}
