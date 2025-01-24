use super::clementine::{
    self, clementine_operator_server::ClementineOperator, operator_params, ChallengeAckDigest,
    DepositSignSession, Empty, NewWithdrawalSigParams, NewWithdrawalSigResponse, OperatorBurnSig,
    OperatorParams, WinternitzPubkey, WithdrawalFinalizedParams,
};
use crate::builder::sighash::create_operator_sighash_stream;
use crate::{errors::BridgeError, operator::Operator, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{hashes::Hash, Amount, OutPoint};
use futures::StreamExt;
use std::pin::pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};
use crate::rpc::parsers;

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
        let operator = self.clone();

        let (tx, rx) = mpsc::channel(1280);
        tokio::spawn(async move {
            let operator_config = clementine::OperatorConfig {
                operator_idx: self.idx as u32,
                collateral_funding_txid: self.collateral_funding_txid.to_byte_array().to_vec(),
                xonly_pk: self.signer.xonly_public_key.to_string(),
                wallet_reimburse_address: self.config.operator_wallet_addresses[self.idx] // TODO: Fix this where the config will only have one address.
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
        request: Request<DepositSignSession>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        let deposit_sign_session = request.into_inner();
        let (deposit_outpoint, evm_address, recovery_taproot_address, user_takes_after) =
            match deposit_sign_session.deposit_params {
                Some(deposit_params) => parsers::parse_deposit_params(deposit_params)?,
                _ => panic!("Expected Deposit Params"),
            };
        let (tx, rx) = mpsc::channel(1280);
        let operator = self.clone();
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
                user_takes_after,
                Amount::from_sat(200_000_000), // TODO: Fix this.
                6,
                100,
                operator.config.bridge_amount_sats,
                operator.config.network,
            ));
            while let Some(sighash_result) = sighash_stream.next().await {
                let sighash = sighash_result?;
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
