use super::clementine::{
    clementine_operator_server::ClementineOperator, DepositSignSession, Empty, OperatorBurnSig,
    OperatorParams,
};
use crate::operator::Operator;
use bitcoin_mock_rpc::RpcApiWrapper;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl<T> ClementineOperator for Operator<T>
where
    T: RpcApiWrapper,
{
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

    #[doc = " Server streaming response type for the DepositSign method."]
    type DepositSignStream = ReceiverStream<Result<OperatorBurnSig, Status>>;
}
