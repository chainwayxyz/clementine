use super::clementine::{
    clementine_verifier_server::ClementineVerifier, Empty, NonceGenResponse, OperatorParams,
    PartialSig, VerifierDepositFinalizeParams, VerifierDepositSignParams, VerifierParams,
    VerifierPublicKeys, WatchtowerParams,
};
use crate::verifier::Verifier;
use bitcoin_mock_rpc::RpcApiWrapper;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};

#[async_trait]
impl<T> ClementineVerifier for Verifier<T>
where
    T: RpcApiWrapper,
{
    type NonceGenStream = ReceiverStream<Result<NonceGenResponse, Status>>;
    type DepositSignStream = ReceiverStream<Result<PartialSig, Status>>;

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(&self, _: Request<Empty>) -> Result<Response<VerifierParams>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_verifiers(
        &self,
        _request: Request<VerifierPublicKeys>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_operator(
        &self,
        _request: Request<OperatorParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_watchtower(
        &self,
        _request: Request<WatchtowerParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn nonce_gen(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::NonceGenStream>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn deposit_sign(
        &self,
        _request: Request<Streaming<VerifierDepositSignParams>>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn deposit_finalize(
        &self,
        _request: Request<Streaming<VerifierDepositFinalizeParams>>,
    ) -> Result<Response<PartialSig>, Status> {
        todo!()
    }
}
