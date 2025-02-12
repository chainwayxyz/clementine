use super::clementine::{
    clementine_operator_server::ClementineOperator, DepositSignSession, Empty,
    NewWithdrawalSigParams, NewWithdrawalSigResponse, OperatorBurnSig, OperatorParams,
    WithdrawalFinalizedParams,
};
use super::error::*;
use crate::builder::sighash::create_operator_sighash_stream;
use crate::rpc::parser;
use crate::UTXO;
use crate::{errors::BridgeError, operator::Operator};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, TxOut};
use futures::{Stream, TryStreamExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineOperator for Operator {
    type DepositSignStream =
        Box<dyn Stream<Item = Result<OperatorBurnSig, Status>> + Send + Unpin + 'static>;
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

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR))]
    async fn deposit_sign(
        &self,
        request: Request<DepositSignSession>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        let operator = self.clone();
        let deposit_sign_session = request.into_inner();

        let (deposit_outpoint, evm_address, recovery_taproot_address, user_takes_after) =
            parser::parse_deposit_params(deposit_sign_session.try_into()?)?;

        let sighash_stream = Box::pin(create_operator_sighash_stream(
            operator.db,
            operator.idx,
            operator.collateral_funding_txid,
            operator.signer.xonly_public_key,
            operator.config.clone(),
            deposit_outpoint,
            evm_address,
            recovery_taproot_address,
            operator.nofn_xonly_pk,
            user_takes_after,
            Amount::from_sat(200_000_000), // TODO: Fix this.
            6,
            100,
            operator.config.bridge_amount_sats,
            operator.config.network,
        ));

        let signature_stream = sighash_stream
            .and_then({
                let signer = operator.signer.clone();
                move |(sighash, _)| {
                    let retval = signer
                        .sign_with_tweak(sighash, None)
                        .map(|sig| OperatorBurnSig {
                            schnorr_sig: sig.serialize().to_vec(),
                        });
                    // Signing process for the operator
                    futures::future::ready(retval)
                }
            })
            .map_err(Into::<Status>::into)
            .into_stream();

        Ok(Response::new(Box::new(signature_stream)))
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
}
