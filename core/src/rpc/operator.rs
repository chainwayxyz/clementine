use super::clementine::{
    self, clementine_operator_server::ClementineOperator, DepositSignSession, Empty,
    NewWithdrawalSigParams, NewWithdrawalSigResponse, OperatorBurnSig, OperatorParams,
    WinternitzPubkey, WithdrawalFinalizedParams,
};
use crate::{errors::BridgeError, operator::Operator};
use bitcoin::{hashes::Hash, OutPoint};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineOperator for Operator {
    type DepositSignStream = ReceiverStream<Result<OperatorBurnSig, Status>>;

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OperatorParams>, Status> {
        let time_txs = self.db.get_time_txs(None, self.idx as i32).await?;

        if time_txs.is_empty() || time_txs[0].0 != 0 {
            return Err(BridgeError::Error("Time txs not found".to_string()).into());
        }

        let operator_config = clementine::OperatorConfig {
            operator_idx: self.idx as u32,
            collateral_funding_txid: time_txs[0].1.to_byte_array().to_vec(),
            xonly_pk: self.signer.xonly_public_key.to_string(),
            wallet_reimburse_address: self.config.operator_wallet_addresses[self.idx] // TODO: Fix this where the config will only have one address.
                .clone()
                .assume_checked()
                .to_string(),
        };

        // Generate Winternitz public keys and convert them to RPC type.
        let winternitz_pubkeys = self.get_winternitz_public_keys()?;
        let winternitz_pubkeys = winternitz_pubkeys
            .into_iter()
            .map(WinternitzPubkey::from_bitvm)
            .collect::<Vec<_>>();

        let operator_params = clementine::OperatorParams {
            operator_details: Some(operator_config),
            winternitz_pubkeys,
            assert_empty_public_key: vec![], // TODO: Implement this.
        };

        Ok(Response::new(operator_params))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn deposit_sign(
        &self,
        _request: Request<DepositSignSession>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn new_withdrawal_sig(
        &self,
        _: Request<NewWithdrawalSigParams>,
    ) -> Result<Response<NewWithdrawalSigResponse>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn withdrawal_finalized(
        &self,
        request: Request<WithdrawalFinalizedParams>,
    ) -> Result<Response<Empty>, Status> {
        // Decode inputs.
        let _withdrawal_idx: u32 = request.get_ref().withdrawal_id;
        let _deposit_outpoint: OutPoint = request
            .get_ref()
            .deposit_outpoint
            .clone()
            .ok_or(BridgeError::RPCRequiredParam("deposit_outpoint"))?
            .try_into()?;

        // self.withdrawal_proved_on_citrea(withdrawal_idx, deposit_outpoint)
        //     .await?; // TODO: Reuse this in the new design.

        Ok(Response::new(Empty {}))
    }
}
