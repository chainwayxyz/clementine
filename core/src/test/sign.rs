use crate::{
    config::BridgeConfig,
    rpc::{
        clementine::WithdrawParams,
        ecdsa_verification_sig::{WithdrawalMessage, CLEMENTINE_EIP712_DOMAIN},
    },
};
use alloy::primitives::PrimitiveSignature;
use alloy_sol_types::SolStruct;

/// Signs the optimistic payout verification signature for a given withdrawal params
/// using the private key in the test_params in the config.
pub fn sign_withdrawal_verification_signature<M: WithdrawalMessage + SolStruct>(
    config: &BridgeConfig,
    withdrawal_params: WithdrawParams,
) -> PrimitiveSignature {
    let signing_key = config
        .test_params
        .aggregator_verification_secret_key
        .clone()
        .unwrap();
    let (withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount) =
        crate::rpc::parser::operator::parse_withdrawal_sig_params(withdrawal_params).unwrap();

    let params = M::new(
        withdrawal_id,
        input_signature,
        input_outpoint,
        output_script_pubkey,
        output_amount,
    );

    let eip712_hash = params.eip712_signing_hash(&CLEMENTINE_EIP712_DOMAIN);

    let signature = signing_key
        .sign_prehash_recoverable(eip712_hash.as_slice())
        .unwrap();

    PrimitiveSignature::from(signature)
}
