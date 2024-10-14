#[allow(clippy::all)]
#[rustfmt::skip]
pub mod clementine;

use crate::{
    aggregator::Aggregator, operator::Operator, verifier::Verifier, watchtower::Watchtower,
};
use bitcoin_mock_rpc::RpcApiWrapper;
use clementine::{
    clementine_aggregator_server::ClementineAggregator,
    clementine_operator_server::ClementineOperator, clementine_verifier_server::ClementineVerifier,
    clementine_watchtower_server::ClementineWatchtower, DepositParams, DepositSignSession, Empty,
    NewWithdrawalSigParams, NewWithdrawalSigResponse, NonceGenResponse, OperatorBurnSig,
    OperatorParams, PartialSig, RawSignedMoveTx, VerifierDepositFinalizeParams,
    VerifierDepositSignParams, VerifierParams, VerifierPublicKeys, WatchtowerParams,
    WithdrawalFinalizedParams,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};

#[async_trait]
impl<T> ClementineOperator for Operator<T>
where
    T: RpcApiWrapper,
{
    type DepositSignStream = ReceiverStream<Result<OperatorBurnSig, Status>>;

    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OperatorParams>, Status> {
        todo!()
    }

    async fn deposit_sign(
        &self,
        _request: Request<DepositSignSession>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        todo!()
    }

    async fn new_withdrawal_sig(
        &self,
        _: Request<NewWithdrawalSigParams>,
    ) -> Result<Response<NewWithdrawalSigResponse>, Status> {
        todo!()
    }

    async fn withdrawal_finalized(
        &self,
        _: Request<WithdrawalFinalizedParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }
}

#[async_trait]
impl<T> ClementineVerifier for Verifier<T>
where
    T: RpcApiWrapper,
{
    type NonceGenStream = ReceiverStream<Result<NonceGenResponse, Status>>;
    type DepositSignStream = ReceiverStream<Result<PartialSig, Status>>;

    async fn get_params(&self, _: Request<Empty>) -> Result<Response<VerifierParams>, Status> {
        todo!()
    }

    async fn set_verifiers(
        &self,
        _request: Request<VerifierPublicKeys>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn set_operator(
        &self,
        _request: Request<OperatorParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn set_watchtower(
        &self,
        _request: Request<WatchtowerParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn nonce_gen(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::NonceGenStream>, Status> {
        todo!()
    }

    async fn deposit_sign(
        &self,
        _request: Request<Streaming<VerifierDepositSignParams>>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        todo!()
    }

    async fn deposit_finalize(
        &self,
        _request: Request<Streaming<VerifierDepositFinalizeParams>>,
    ) -> Result<Response<PartialSig>, Status> {
        todo!()
    }
}

#[async_trait]
impl<T> ClementineWatchtower for Watchtower<T>
where
    T: RpcApiWrapper,
{
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<WatchtowerParams>, Status> {
        todo!()
    }
}

#[async_trait]
impl ClementineAggregator for Aggregator {
    async fn setup(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn new_deposit(
        &self,
        _request: Request<DepositParams>,
    ) -> Result<Response<RawSignedMoveTx>, Status> {
        todo!()
    }
}
