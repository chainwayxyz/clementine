use super::clementine::{
    clementine_operator_server::ClementineOperator, AssertRequest, DepositSignSession, Empty,
    NewWithdrawalSigParams, NewWithdrawalSigResponse, OperatorBurnSig, OperatorParams, RawSignedTx,
    RawSignedTxs, TransactionRequest, WithdrawalFinalizedParams,
};
use super::error::*;
use crate::builder::sighash::create_operator_sighash_stream;
use crate::builder::transaction::sign::{create_and_sign_tx, create_assert_commitment_txs};
use crate::rpc::parser;
use crate::rpc::parser::{parse_assert_request, parse_transaction_request};
use crate::UTXO;
use crate::{errors::BridgeError, operator::Operator};
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, TxOut};
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

        let (deposit_outpoint, evm_address, recovery_taproot_address) =
            parser::parse_deposit_params(deposit_sign_session.try_into()?)?;

        tokio::spawn(async move {
            let mut sighash_stream = pin!(create_operator_sighash_stream(
                operator.db,
                operator.idx,
                operator.collateral_funding_txid,
                operator.reimburse_addr.clone(),
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
        request: Request<NewWithdrawalSigParams>,
    ) -> Result<Response<NewWithdrawalSigResponse>, Status> {
        let (
            withdrawal_id,
            user_sig,
            users_intent_outpoint,
            users_intent_script_pubkey,
            users_intent_amount,
        ) = parser::operator::parse_withdrawal_sig_params(request.into_inner()).await?;

        let input_prevout = self
            .rpc
            .get_txout_from_outpoint(&users_intent_outpoint)
            .await?;
        let input_utxo = UTXO {
            outpoint: users_intent_outpoint,
            txout: input_prevout,
        };
        let output_txout = TxOut {
            value: users_intent_amount,
            script_pubkey: users_intent_script_pubkey,
        };
        let withdrawal_txid = self
            .new_withdrawal_sig(withdrawal_id, user_sig, input_utxo, output_txout)
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
    async fn create_signed_tx(
        &self,
        request: Request<TransactionRequest>,
    ) -> Result<Response<RawSignedTx>, Status> {
        let transaction_request = request.into_inner();
        let transaction_data = parse_transaction_request(transaction_request)?;

        let raw_tx = create_and_sign_tx(
            self.db.clone(),
            &self.signer,
            self.config.clone(),
            self.nofn_xonly_pk,
            transaction_data,
        )
        .await?;

        Ok(Response::new(raw_tx))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn create_assert_commitment_txs(
        &self,
        request: Request<AssertRequest>,
    ) -> Result<Response<RawSignedTxs>, Status> {
        let assert_request = request.into_inner();
        let assert_data = parse_assert_request(assert_request)?;

        let raw_txs = create_assert_commitment_txs(
            self.db.clone(),
            &self.signer,
            self.config.clone(),
            self.nofn_xonly_pk,
            assert_data,
        )
        .await?;

        Ok(Response::new(raw_txs))
    }
}
