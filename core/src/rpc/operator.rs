use super::clementine::clementine_operator_server::ClementineOperator;
use super::clementine::{
    self, ChallengeAckDigest, DepositParams, DepositSignSession, Empty, FinalizedPayoutParams,
    OperatorKeys, OperatorParams, SchnorrSig, SignedTxWithType, SignedTxsWithType,
    TransactionRequest, VergenResponse, WithdrawParams, XOnlyPublicKeyRpc,
};
use super::error::*;
use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder::transaction::sign::{create_and_sign_txs, TransactionRequestData};
use crate::builder::transaction::ContractContext;
use crate::citrea::CitreaClientT;
use crate::compatibility::ActorWithConfig;
use crate::constants::{DEFAULT_CHANNEL_SIZE, RESTART_BACKGROUND_TASKS_TIMEOUT};
use crate::deposit::DepositData;
use crate::errors::BridgeError;
use crate::errors::ResultExt;
use crate::operator::OperatorServer;
use crate::rpc::clementine::{CompatibilityParamsRpc, RawSignedTx, WithdrawParamsWithSig};
use crate::rpc::ecdsa_verification_sig::{
    recover_address_from_ecdsa_signature, OperatorWithdrawalMessage,
};
use crate::rpc::parser;
use crate::utils::{get_vergen_response, monitor_standalone_task, timed_request};
use alloy::primitives::PrimitiveSignature;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint};
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use futures::TryFutureExt;
use std::str::FromStr;
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

    async fn get_compatibility_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<CompatibilityParamsRpc>, Status> {
        let params = self.operator.get_compatibility_params()?;
        Ok(Response::new(params.try_into().map_to_status()?))
    }

    async fn vergen(&self, _request: Request<Empty>) -> Result<Response<VergenResponse>, Status> {
        tracing::info!("Vergen rpc called");
        Ok(Response::new(get_vergen_response()))
    }

    async fn restart_background_tasks(
        &self,
        _request: tonic::Request<super::Empty>,
    ) -> std::result::Result<tonic::Response<super::Empty>, tonic::Status> {
        tracing::info!("Restarting background tasks rpc called");
        timed_request(
            RESTART_BACKGROUND_TASKS_TIMEOUT,
            "Restarting background tasks",
            self.start_background_tasks(),
        )
        .await?;
        tracing::info!("Restarting background tasks rpc completed");
        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::GetParamsStream>, Status> {
        tracing::info!("Get params rpc called");
        let operator = self.operator.clone();
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let out_stream: Self::GetParamsStream = ReceiverStream::new(rx);

        let (mut wpk_receiver, mut signature_receiver) = operator.get_params().await?;

        let handle = tokio::spawn(async move {
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
        monitor_standalone_task(handle, "Operator get_params");

        Ok(Response::new(out_stream))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn deposit_sign(
        &self,
        request: Request<DepositSignSession>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        tracing::info!("Deposit sign rpc called");
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);

        let deposit_sign_session = request.into_inner();
        let deposit_params: DepositParams = deposit_sign_session.try_into()?;
        let deposit_data: DepositData = deposit_params.try_into()?;
        tracing::info!(
            "Parsed deposit sign rpc params, deposit data: {:?}",
            deposit_data
        );

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
    async fn internal_withdraw(
        &self,
        request: Request<WithdrawParams>,
    ) -> Result<Response<RawSignedTx>, Status> {
        let (withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount) =
            parser::operator::parse_withdrawal_sig_params(request.into_inner())?;

        tracing::warn!("Called internal_withdraw with withdrawal id: {:?}, input signature: {:?}, input outpoint: {:?}, output script pubkey: {:?}, output amount: {:?}", withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount);

        let payout_tx = self
            .operator
            .withdraw(
                withdrawal_id,
                input_signature,
                input_outpoint,
                output_script_pubkey,
                output_amount,
            )
            .await?;

        Ok(Response::new(RawSignedTx::from(&payout_tx)))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn withdraw(
        &self,
        request: Request<WithdrawParamsWithSig>,
    ) -> Result<Response<RawSignedTx>, Status> {
        tracing::info!("Withdraw rpc called");
        let params = request.into_inner();
        let withdraw_params = params.withdrawal.ok_or(Status::invalid_argument(
            "Withdrawal params not found for withdrawal",
        ))?;
        let (withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount) =
            parser::operator::parse_withdrawal_sig_params(withdraw_params)?;

        tracing::warn!(
            "Parsed withdraw rpc params, withdrawal id: {:?}, input signature: {:?}, input outpoint: {:?}, output script pubkey: {:?}, output amount: {:?}, verification signature: {:?}", withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount, params.verification_signature
        );

        // if verification address is set in config, check if verification signature is valid
        if let Some(address_in_config) = self.operator.config.aggregator_verification_address {
            let verification_signature = params
                .verification_signature
                .map(|sig| {
                    PrimitiveSignature::from_str(&sig).map_err(|e| {
                        Status::invalid_argument(format!("Invalid verification signature: {}", e))
                    })
                })
                .transpose()?;
            // check if verification signature is provided by aggregator
            if let Some(verification_signature) = verification_signature {
                let address_from_sig =
                    recover_address_from_ecdsa_signature::<OperatorWithdrawalMessage>(
                        withdrawal_id,
                        input_signature,
                        input_outpoint,
                        output_script_pubkey.clone(),
                        output_amount,
                        verification_signature,
                    )?;

                // check if verification signature is signed by the address in config
                if address_from_sig != address_in_config {
                    return Err(BridgeError::InvalidECDSAVerificationSignature).map_to_status();
                }
            } else {
                // if verification signature is not provided, but verification address is set in config, return error
                return Err(BridgeError::ECDSAVerificationSignatureMissing).map_to_status();
            }
        }

        let payout_tx = self
            .operator
            .withdraw(
                withdrawal_id,
                input_signature,
                input_outpoint,
                output_script_pubkey,
                output_amount,
            )
            .await?;

        tracing::info!(
            "Withdraw rpc completed successfully for withdrawal id: {:?}",
            withdrawal_id
        );

        Ok(Response::new(RawSignedTx::from(&payout_tx)))
    }

    #[tracing::instrument(skip(self, request), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn internal_create_assert_commitment_txs(
        &self,
        request: Request<TransactionRequest>,
    ) -> std::result::Result<tonic::Response<super::SignedTxsWithType>, tonic::Status> {
        let tx_req = request.into_inner();
        let tx_req_data: TransactionRequestData = tx_req.try_into()?;
        tracing::warn!(
            "Called internal_create_assert_commitment_txs with transaction request data: {:?}",
            tx_req_data
        );
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
                None,
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
        tracing::warn!(
            "Called get_deposit_keys with deposit data: {:?}",
            deposit_data
        );
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
        tracing::warn!(
            "Called internal_create_signed_txs with transaction request data: {:?}",
            transaction_data
        );
        let (_, deposit_data) = self
            .operator
            .db
            .get_deposit_data(None, transaction_data.deposit_outpoint)
            .await?
            .ok_or(Status::invalid_argument("Deposit not found in database"))?;
        let context = ContractContext::new_context_for_kickoff(
            transaction_data.kickoff_data,
            deposit_data,
            self.operator.config.protocol_paramset(),
        );
        let raw_txs = create_and_sign_txs(
            self.operator.db.clone(),
            &self.operator.signer,
            self.operator.config.clone(),
            context,
            Some([0u8; 20]), // dummy blockhash
            None,
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

        tracing::info!(
            "Internal finalized payout rpc called with finalized payout params: {:?}",
            request.get_ref()
        );

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
        tracing::warn!("Internal end round rpc called");
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
        tracing::info!("Get xonly public key rpc called");
        let xonly_pk = self.operator.signer.xonly_public_key.serialize();
        Ok(Response::new(XOnlyPublicKeyRpc {
            xonly_public_key: xonly_pk.to_vec(),
        }))
    }

    async fn get_current_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<clementine::EntityStatus>, Status> {
        tracing::info!("Get current status rpc called");
        let status = self.get_current_status().await?;
        tracing::info!("Get current status rpc completed successfully");
        Ok(Response::new(status))
    }

    async fn get_reimbursement_txs(
        &self,
        request: Request<clementine::Outpoint>,
    ) -> Result<Response<SignedTxsWithType>, Status> {
        let deposit_outpoint: OutPoint = request.into_inner().try_into()?;
        tracing::warn!(
            "Get reimbursement txs rpc called with deposit outpoint: {:?}",
            deposit_outpoint
        );
        let txs = self
            .operator
            .get_reimbursement_txs(deposit_outpoint)
            .await?;
        Ok(Response::new(txs.into()))
    }
}
