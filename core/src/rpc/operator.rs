use super::clementine::clementine_operator_server::ClementineOperator;
use super::clementine::{
    self, ChallengeAckDigest, DepositParams, DepositSignSession, Empty, FinalizedPayoutParams,
    OperatorKeys, OperatorParams, SchnorrSig, SignedTxWithType, SignedTxsWithType,
    TransactionRequest, VergenResponse, WithdrawParams, XOnlyPublicKeyRpc,
};
use super::error::*;
use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder::transaction::sign::{create_and_sign_txs, TransactionRequestData};
use crate::citrea::CitreaClientT;
use crate::constants::DEFAULT_CHANNEL_SIZE;
use crate::deposit::DepositData;
use crate::operator::OperatorServer;
use crate::rpc::parser;
use crate::utils::get_vergen_response;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint};
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use futures::TryFutureExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl<C> ClementineOperator for OperatorServer<C>
where
    C: CitreaClientT,
{
    type DepositSignStream = ReceiverStream<Result<SchnorrSig, Status>>;
    type GetParamsStream = ReceiverStream<Result<OperatorParams, Status>>;

    async fn vergen(&self, _request: Request<Empty>) -> Result<Response<VergenResponse>, Status> {
        Ok(Response::new(get_vergen_response()))
    }

    async fn restart_background_tasks(
        &self,
        _request: tonic::Request<super::Empty>,
    ) -> std::result::Result<tonic::Response<super::Empty>, tonic::Status> {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            self.start_background_tasks(),
        )
        .await;
        match result {
            Ok(Ok(_)) => Ok(tonic::Response::new(super::Empty {})),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(tonic::Status::deadline_exceeded(
                "Timed out while restarting background tasks. Recommended to restart the operator manually.",
            )),
        }
    }

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::GetParamsStream>, Status> {
        let operator = self.operator.clone();
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
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
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);

        let deposit_sign_session = request.into_inner();
        let deposit_params: DepositParams = deposit_sign_session.try_into()?;
        let deposit_data: DepositData = deposit_params.try_into()?;

        let expected_sigs = self
            .operator
            .config
            .get_num_required_operator_sigs(&deposit_data);

        let mut deposit_signatures_rx = self.operator.deposit_sign(deposit_data).await?;

        tokio::spawn(async move {
            let mut sent_sigs = 0;
            while let Some(sig) = deposit_signatures_rx.recv().await {
                let operator_burn_sig = SchnorrSig {
                    schnorr_sig: sig.serialize().to_vec(),
                };

                if tx
                    .send(Ok(operator_burn_sig))
                    .inspect_ok(|_| {
                        sent_sigs += 1;
                        tracing::debug!(
                            "Sent signature {}/{} in deposit_sign()",
                            sent_sigs,
                            expected_sigs
                        );
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn withdraw(&self, request: Request<WithdrawParams>) -> Result<Response<Empty>, Status> {
        let (withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount) =
            parser::operator::parse_withdrawal_sig_params(request.into_inner()).await?;

        // try to fulfill withdrawal only if automation is enabled
        #[cfg(feature = "automation")]
        {
            self.operator
                .withdraw(
                    withdrawal_id,
                    input_signature,
                    input_outpoint,
                    output_script_pubkey,
                    output_amount,
                )
                .await?;

            Ok(Response::new(Empty {}))
        }

        #[cfg(not(feature = "automation"))]
        {
            return Err(Status::unavailable(
                "Automation is not enabled. Operator will not fulfill withdrawals.",
            ));
        }
    }

    #[tracing::instrument(skip(self, request), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn internal_create_assert_commitment_txs(
        &self,
        request: Request<TransactionRequest>,
    ) -> std::result::Result<tonic::Response<super::SignedTxsWithType>, tonic::Status> {
        let tx_req = request.into_inner();
        let tx_req_data: TransactionRequestData = tx_req.try_into()?;

        let raw_txs = self
            .operator
            .create_assert_commitment_txs(
                tx_req_data,
                ClementineBitVMPublicKeys::get_assert_commit_data(
                    (
                        [[0u8; 32]; NUM_PUBS],
                        [[0u8; 32]; NUM_U256],
                        [[0u8; 16]; NUM_HASH],
                    ),
                    &[0u8; 20],
                ),
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

    #[tracing::instrument(skip(self, request), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_deposit_keys(
        &self,
        request: Request<DepositParams>,
    ) -> Result<Response<OperatorKeys>, Status> {
        let start = std::time::Instant::now();
        let deposit_params = request.into_inner();
        let deposit_data: DepositData = deposit_params.try_into()?;

        let winternitz_keys = self
            .operator
            .generate_assert_winternitz_pubkeys(deposit_data.get_deposit_outpoint())?;
        let hashes = self
            .operator
            .generate_challenge_ack_preimages_and_hashes(&deposit_data)?;
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
        let transaction_data: TransactionRequestData = transaction_request.try_into()?;
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
        if !cfg!(test) {
            return Err(Status::permission_denied(
                "This method is only available in tests",
            ));
        }

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
        #[cfg(feature = "automation")]
        {
            let mut dbtx = self.operator.db.begin_transaction().await?;

            self.operator.end_round(&mut dbtx).await?;

            dbtx.commit().await.expect("Failed to commit transaction");
            Ok(Response::new(Empty {}))
        }

        #[cfg(not(feature = "automation"))]
        Err(Status::unimplemented(
            "Automation is not enabled. Operator does not manage its rounds",
        ))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_x_only_public_key(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<XOnlyPublicKeyRpc>, Status> {
        let xonly_pk = self.operator.signer.xonly_public_key.serialize();
        Ok(Response::new(XOnlyPublicKeyRpc {
            xonly_public_key: xonly_pk.to_vec(),
        }))
    }

    async fn get_current_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<clementine::EntityStatus>, Status> {
        let status = self.get_current_status().await?;
        Ok(Response::new(status))
    }
}
