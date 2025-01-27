use super::clementine::{
    self, clementine_operator_server::ClementineOperator, operator_params, ChallengeAckDigest,
    DepositSignSession, Empty, NewWithdrawalSigParams, NewWithdrawalSigResponse, OperatorBurnSig,
    OperatorParams, WinternitzPubkey, WithdrawalFinalizedParams,
};
use crate::{errors::BridgeError, operator::Operator};
use bitcoin::{hashes::Hash, OutPoint};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineOperator for Operator {
    type DepositSignStream = ReceiverStream<Result<OperatorBurnSig, Status>>;
    type GetParamsStream = ReceiverStream<Result<OperatorParams, Status>>;

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::GetParamsStream>, Status> {
        let sequential_collateral_txs = self
            .db
            .get_sequential_collateral_txs(None, self.idx as i32)
            .await?;
        let operator = self.clone();

        if sequential_collateral_txs.is_empty() || sequential_collateral_txs[0].0 != 0 {
            return Err(BridgeError::Error("Time txs not found".to_string()).into());
        }

        let (tx, rx) = mpsc::channel(1280);
        tokio::spawn(async move {
            let operator_config = clementine::OperatorConfig {
                operator_idx: operator.idx as u32,
                collateral_funding_txid: sequential_collateral_txs[0].1.to_byte_array().to_vec(),
                xonly_pk: operator.signer.xonly_public_key.to_string(),
                wallet_reimburse_address: operator.config.operator_wallet_addresses[operator.idx] // TODO: Fix this where the config will only have one address.
                    .clone()
                    .assume_checked()
                    .to_string(),
            };
            tx.send(Ok(OperatorParams {
                response: Some(operator_params::Response::OperatorDetails(operator_config)),
            }))
            .await
            .unwrap();

            let winternitz_pubkeys = operator.get_winternitz_public_keys().unwrap(); // TODO: Handle unwrap.
            let winternitz_pubkeys = winternitz_pubkeys
                .into_iter()
                .map(WinternitzPubkey::from_bitvm)
                .collect::<Vec<_>>();
            for wpk in winternitz_pubkeys {
                tx.send(Ok(OperatorParams {
                    response: Some(operator_params::Response::WinternitzPubkeys(wpk)),
                }))
                .await
                .unwrap();
            }

            let public_hashes = operator
                .generate_challenge_ack_preimages_and_hashes()
                .unwrap(); // TODO: Handle unwrap.
            let public_hashes = public_hashes
                .into_iter()
                .map(|hash| ChallengeAckDigest {
                    hash: hash.to_vec(),
                })
                .collect::<Vec<_>>();

            for hash in public_hashes {
                tx.send(Ok(OperatorParams {
                    response: Some(operator_params::Response::ChallengeAckDigests(hash)),
                }))
                .await
                .unwrap();
            }
        });

        let out_stream: Self::GetParamsStream = ReceiverStream::new(rx);
        Ok(Response::new(out_stream))
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
