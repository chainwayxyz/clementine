use super::clementine::{self, clementine_operator_server::ClementineOperator, DepositParams, DepositSignSession, Empty, NewWithdrawalSigParams, NewWithdrawalSigResponse, OperatorBurnSig, OperatorParams, WinternitzPubkey, WithdrawalFinalizedParams};
use crate::builder::sighash::create_operator_sighash_stream;
use crate::errors::BridgeError::RPCParamMalformed;
use crate::{errors::BridgeError, operator::Operator, EVMAddress};
use bitcoin::{hashes::Hash, OutPoint, Amount};
use std::pin::pin;
use bitcoin::address::NetworkUnchecked;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

fn unpack_deposit_params(
    deposit_params: DepositParams,
) -> Result<
    (
        bitcoin::OutPoint,
        EVMAddress,
        bitcoin::Address<NetworkUnchecked>,
        u16,
    ),
    Status,
> {
    let deposit_outpoint: bitcoin::OutPoint = deposit_params
        .deposit_outpoint
        .ok_or(Status::invalid_argument("No deposit outpoint received"))?
        .try_into()?;
    let evm_address: EVMAddress = deposit_params.evm_address.try_into().unwrap();
    let recovery_taproot_address = deposit_params
        .recovery_taproot_address
        .parse::<bitcoin::Address<_>>()
        .map_err(|e| Status::internal(e.to_string()))?;
    let user_takes_after = deposit_params.user_takes_after;
    Ok((
        deposit_outpoint,
        evm_address,
        recovery_taproot_address,
        u16::try_from(user_takes_after).map_err(|e| {
            Status::invalid_argument(format!(
                "user_takes_after is too big, failed to convert: {}",
                e
            ))
        })?
    ))
}

#[async_trait]
impl ClementineOperator for Operator {
    type DepositSignStream = ReceiverStream<Result<OperatorBurnSig, Status>>;

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OperatorParams>, Status> {

        let operator_config = clementine::OperatorConfig {
            operator_idx: self.idx as u32,
            collateral_funding_txid: self.collateral_funding_txid.to_byte_array().to_vec(),
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
        request: Request<DepositSignSession>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        let deposit_sign_session = request.into_inner();
        let (
            deposit_outpoint,
            evm_address,
            recovery_taproot_address,
            user_takes_after,
        ) = match deposit_sign_session.deposit_params {
            Some(
                deposit_params,
            ) => unpack_deposit_params(deposit_params)?,
            _ => panic!("Expected Deposit Params"),
        };
        let (tx, rx) = mpsc::channel(1280);
        let mut sighash_stream = pin!(create_operator_sighash_stream(
            self.db.clone(),
            self.idx,
            self.collateral_funding_txid,
            self.signer.xonly_public_key.clone(),
            self.config.clone(),
            deposit_outpoint,
            evm_address,
            recovery_taproot_address,
            verifier.nofn_xonly_pk,
            user_takes_after,
            Amount::from_sat(200_000_000), // TODO: Fix this.
            6,
            100,
            self.config.bridge_amount_sats,
            self.config.network,
        ));

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
