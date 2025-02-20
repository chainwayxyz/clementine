use super::clementine::{
    clementine_operator_server::ClementineOperator, AssertRequest, ChallengeAckDigest,
    DepositParams, DepositSignSession, Empty, NewWithdrawalSigParams, NewWithdrawalSigResponse,
    OperatorBurnSig, OperatorKeys, OperatorParams, RawSignedTxs, SignedTxWithType,
    SignedTxsWithType, WithdrawalFinalizedParams,
};
use super::error::*;
use crate::builder::transaction::sign::create_and_sign_txs;
use crate::rpc::parser;
use crate::rpc::parser::{parse_assert_request, parse_deposit_params, parse_transaction_request};
use crate::{errors::BridgeError, operator::Operator};
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
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

        let mut wpk_receiver = operator.get_params().await?;

        tokio::spawn(async move {
            let operator_config: OperatorParams = operator.clone().into();
            tx.send(Ok(operator_config))
                .await
                .map_err(output_stream_ended_prematurely)?;

            while let Some(winternitz_public_key) = wpk_receiver.recv().await {
                let operator_winternitz_pubkey: OperatorParams = winternitz_public_key.into();
                tx.send(Ok(operator_winternitz_pubkey))
                    .await
                    .map_err(output_stream_ended_prematurely)?;
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
        let (tx, rx) = mpsc::channel(1280);
        let deposit_sign_session = request.into_inner();

        let deposit_data = parser::parse_deposit_params(deposit_sign_session.try_into()?)?;

        let mut deposit_signatures_rx = self.deposit_sign(deposit_data).await?;

        while let Some(sig) = deposit_signatures_rx.recv().await {
            let operator_burn_sig = OperatorBurnSig {
                schnorr_sig: sig.serialize().to_vec(),
            };

            if tx.send(Ok(operator_burn_sig)).await.is_err() {
                break;
            }
        }

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn new_withdrawal_sig(
        &self,
        request: Request<NewWithdrawalSigParams>,
    ) -> Result<Response<NewWithdrawalSigResponse>, Status> {
        let (
            withdrawal_id,
            user_sig,
            users_intent_outpoint,
            users_intent_script_pubkey,
            users_intent_amount,
        ) = parser::operator::parse_withdrawal_sig_params(request.into_inner()).await?;

        let withdrawal_txid = self
            .new_withdrawal_sig(
                withdrawal_id,
                user_sig,
                users_intent_outpoint,
                users_intent_script_pubkey,
                users_intent_amount,
            )
            .await?;

        Ok(Response::new(NewWithdrawalSigResponse {
            txid: withdrawal_txid.as_raw_hash().to_byte_array().to_vec(),
        }))
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

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn internal_create_assert_commitment_txs(
        &self,
        request: Request<AssertRequest>,
    ) -> Result<Response<RawSignedTxs>, Status> {
        let assert_request = request.into_inner();
        let assert_data = parse_assert_request(assert_request)?;

        let raw_txs = self
            .create_assert_commitment_txs(self.nofn_xonly_pk, assert_data)
            .await?;

        Ok(Response::new(raw_txs))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_deposit_keys(
        &self,
        request: Request<DepositParams>,
    ) -> Result<Response<OperatorKeys>, Status> {
        let deposit_req = request.into_inner();
        let deposit_data = parse_deposit_params(deposit_req)?;

        let winternitz_keys =
            self.generate_assert_winternitz_pubkeys(deposit_data.deposit_outpoint.txid)?;
        let hashes =
            self.generate_challenge_ack_preimages_and_hashes(deposit_data.deposit_outpoint.txid)?;

        Ok(Response::new(OperatorKeys {
            winternitz_pubkeys: winternitz_keys
                .into_iter()
                .map(|pubkey| pubkey.into())
                .collect(),
            challenge_ack_digests: hashes
                .into_iter()
                .map(|hash| ChallengeAckDigest { hash: hash.into() })
                .collect(),
        }))
    }

    async fn internal_create_signed_txs(
        &self,
        request: tonic::Request<super::TransactionRequest>,
    ) -> std::result::Result<tonic::Response<super::SignedTxsWithType>, tonic::Status> {
        let transaction_request = request.into_inner();
        let transaction_data = parse_transaction_request(transaction_request)?;
        let raw_txs = create_and_sign_txs(
            self.db.clone(),
            &self.signer,
            self.config.clone(),
            self.nofn_xonly_pk,
            transaction_data,
            Some([0u8; 20]), // dummy blockhash
        )
        .await?;

        Ok(Response::new(SignedTxsWithType {
            signed_txs: raw_txs
                .into_iter()
                .map(|(tx_type, signed_tx)| SignedTxWithType {
                    transaction_type: Some(tx_type.into()),
                    raw_tx: signed_tx.raw_tx,
                })
                .collect(),
        }))
    }
}
