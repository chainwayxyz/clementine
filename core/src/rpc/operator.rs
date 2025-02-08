use super::clementine::{
    clementine_operator_server::ClementineOperator, DepositSignSession, Empty,
    NewWithdrawalSigParams, NewWithdrawalSigResponse, OperatorBurnSig, OperatorParams,
    WithdrawalFinalizedParams,
};
use super::error::*;
use crate::builder::sighash::create_operator_sighash_stream;
use crate::rpc::parser;
use crate::{errors::BridgeError, operator::Operator};
use bitcoin::OutPoint;
use futures::StreamExt;
use std::pin::pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineOperator for Operator {
    type DepositSignStream = ReceiverStream<Result<OperatorBurnSig, Status>>;
    type GetParamsStream = ReceiverStream<Result<OperatorParams, Status>>;

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::GetParamsStream>, Status> {
        let operator = self.clone();
        let (tx, rx) = mpsc::channel(1280);
        let out_stream: Self::GetParamsStream = ReceiverStream::new(rx);

        tokio::spawn(async move {
            let operator_config: OperatorParams = operator.clone().into();
            tx.send(Ok(operator_config))
                .await
                .map_err(|_| output_stream_ended_prematurely())?;

            for winternitz_public_key in operator.get_winternitz_public_keys()? {
                let operator_winternitz_pubkey: OperatorParams = winternitz_public_key.into();
                tx.send(Ok(operator_winternitz_pubkey))
                    .await
                    .map_err(|_| output_stream_ended_prematurely())?;
            }

            for hash in operator.generate_challenge_ack_preimages_and_hashes()? {
                let hash: OperatorParams = hash.into();
                tx.send(Ok(hash))
                    .await
                    .map_err(|_| output_stream_ended_prematurely())?;
            }

            Ok::<(), Status>(())
        });

        Ok(Response::new(out_stream))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn deposit_sign(
        &self,
        request: Request<DepositSignSession>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        let operator = self.clone();
        let (tx, rx) = mpsc::channel(1280);
        let deposit_sign_session = request.into_inner();

        let (deposit_outpoint, evm_address, recovery_taproot_address, _user_takes_after) =
            parser::parse_deposit_params(deposit_sign_session.try_into()?)?;

        tokio::spawn(async move {
            let mut sighash_stream = pin!(create_operator_sighash_stream(
                operator.db,
                operator.idx,
                operator.collateral_funding_txid,
                operator.signer.xonly_public_key,
                operator.config.clone(),
                deposit_outpoint,
                evm_address,
                recovery_taproot_address,
                operator.nofn_xonly_pk,
            ));

            while let Some(sighash) = sighash_stream.next().await {
                let sighash = sighash?.0;

                // None because utxos that operators need to sign do not have scripts
                let sig = operator.signer.sign_with_tweak(sighash, None)?;
                let operator_burn_sig = OperatorBurnSig {
                    schnorr_sig: sig.serialize().to_vec(),
                };

                if tx.send(Ok(operator_burn_sig)).await.is_err() {
                    break;
                }
            }

            Ok::<_, BridgeError>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn new_withdrawal_sig(
        &self,
        _: Request<NewWithdrawalSigParams>,
    ) -> Result<Response<NewWithdrawalSigResponse>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
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
