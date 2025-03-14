use super::clementine::clementine_operator_server::ClementineOperator;
use super::clementine::{
    self, AssertRequest, ChallengeAckDigest, DepositParams, DepositSignSession, Empty,
    FinalizedPayoutParams, OperatorKeys, OperatorParams, SchnorrSig, SignedTxWithType,
    SignedTxsWithType, WithdrawParams, WithdrawResponse, WithdrawalFinalizedParams,
};
use super::error::*;
use crate::builder::transaction::sign::create_and_sign_txs;
use crate::errors::BridgeError;
use crate::operator::OperatorServer;
use crate::rpc::parser;
use crate::rpc::parser::{parse_assert_request, parse_deposit_params, parse_transaction_request};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineOperator for OperatorServer {
    type DepositSignStream = ReceiverStream<Result<SchnorrSig, Status>>;
    type GetParamsStream = ReceiverStream<Result<OperatorParams, Status>>;

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::GetParamsStream>, Status> {
        let operator = self.operator.clone();
        let (tx, rx) = mpsc::channel(1280);
        let out_stream: Self::GetParamsStream = ReceiverStream::new(rx);

        let (mut wpk_receiver, mut signature_receiver) = operator.get_params().await?;

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

            while let Some(operator_sig) = signature_receiver.recv().await {
                let unspent_kickoff_sig: OperatorParams = operator_sig.into();
                tx.send(Ok(unspent_kickoff_sig))
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

        let mut deposit_signatures_rx = self.operator.deposit_sign(deposit_data).await?;

        while let Some(sig) = deposit_signatures_rx.recv().await {
            let operator_burn_sig = SchnorrSig {
                schnorr_sig: sig.serialize().to_vec(),
            };

            if tx.send(Ok(operator_burn_sig)).await.is_err() {
                break;
            }
        }

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn withdraw(
        &self,
        request: Request<WithdrawParams>,
    ) -> Result<Response<WithdrawResponse>, Status> {
        let (withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount) =
            parser::operator::parse_withdrawal_sig_params(request.into_inner()).await?;

        let withdrawal_txid = self
            .operator
            .withdraw(
                withdrawal_id,
                input_signature,
                input_outpoint,
                output_script_pubkey,
                output_amount,
            )
            .await?;

        Ok(Response::new(WithdrawResponse {
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

        // self.operator.withdrawal_proved_on_citrea(withdrawal_idx, deposit_outpoint)
        //     .await?; // TODO: Reuse this in the new design.

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self, request), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn internal_create_assert_commitment_txs(
        &self,
        request: Request<AssertRequest>,
    ) -> std::result::Result<tonic::Response<super::SignedTxsWithType>, tonic::Status> {
        let assert_request = request.into_inner();
        let assert_data = parse_assert_request(assert_request)?;

        let raw_txs = self
            .operator
            .create_assert_commitment_txs(assert_data)
            .await?;

        Ok(Response::new(SignedTxsWithType {
            signed_txs: raw_txs
                .into_iter()
                .map(|(tx_type, signed_tx)| SignedTxWithType {
                    transaction_type: Some(tx_type.into()),
                    raw_tx: bitcoin::consensus::serialize(&signed_tx),
                })
                .collect(),
        }))
    }

    #[tracing::instrument(skip(self, request), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_deposit_keys(
        &self,
        request: Request<DepositParams>,
    ) -> Result<Response<OperatorKeys>, Status> {
        let start = std::time::Instant::now();
        let deposit_req = request.into_inner();
        let deposit_data = parse_deposit_params(deposit_req)?;

        let winternitz_keys = self
            .operator
            .generate_assert_winternitz_pubkeys(deposit_data.get_deposit_outpoint().txid)?;
        let hashes = self.operator.generate_challenge_ack_preimages_and_hashes(
            deposit_data.get_deposit_outpoint().txid,
        )?;
        tracing::info!("Generated deposit keys in {:?}", start.elapsed());

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
            self.operator.db.clone(),
            &self.operator.signer,
            self.operator.config.clone(),
            transaction_data,
            Some([0u8; 20]), // dummy blockhash
        )
        .await?;

        Ok(Response::new(SignedTxsWithType {
            signed_txs: raw_txs
                .into_iter()
                .map(|(tx_type, signed_tx)| SignedTxWithType {
                    transaction_type: Some(tx_type.into()),
                    raw_tx: bitcoin::consensus::serialize(&signed_tx),
                })
                .collect(),
        }))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn internal_finalized_payout(
        &self,
        request: Request<FinalizedPayoutParams>,
    ) -> Result<Response<clementine::Txid>, Status> {
        let payout_blockhash: [u8; 32] = request
            .get_ref()
            .payout_blockhash
            .clone()
            .try_into()
            .expect("Failed to convert payout blockhash to [u8; 32]");
        let deposit_outpoint = request
            .get_ref()
            .deposit_outpoint
            .clone()
            .expect("Failed to get deposit outpoint");
        let deposit_outpoint: OutPoint = deposit_outpoint
            .try_into()
            .expect("Failed to convert deposit outpoint to OutPoint");

        let mut dbtx = self.operator.db.begin_transaction().await?;
        let kickoff_txid = self
            .operator
            .handle_finalized_payout(
                &mut dbtx,
                deposit_outpoint,
                BlockHash::from_byte_array(payout_blockhash),
            )
            .await?;
        dbtx.commit().await.expect("Failed to commit transaction");

        Ok(Response::new(kickoff_txid.into()))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn internal_end_round(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Empty>, Status> {
        let mut dbtx = self.operator.db.begin_transaction().await?;
        self.operator.end_round(&mut dbtx).await?;
        dbtx.commit().await.expect("Failed to commit transaction");
        Ok(Response::new(Empty {}))
    }
}
