use crate::{
    config::BridgeConfig,
    rpc::clementine::WithdrawParams,
    verifier::{ClementineOptimisticPayoutMessage, DOMAIN},
};
use alloy::primitives::PrimitiveSignature;
use alloy_sol_types::SolStruct;
use bitcoin::hashes::Hash;

/// Signs the optimistic payout verification signature for a given withdrawal params
/// using the private key in the test_params in the config.
pub fn sign_optimistic_payout_verification_signature(
    config: &BridgeConfig,
    withdrawal_params: WithdrawParams,
) -> PrimitiveSignature {
    let signing_key = config
        .test_params
        .opt_payout_verification_secret_key
        .clone()
        .unwrap();
    let (withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount) =
        crate::rpc::parser::operator::parse_withdrawal_sig_params(withdrawal_params).unwrap();

    let input_sig_bytes = input_signature.serialize().to_vec();
    let outpoint_txid_bytes = input_outpoint.txid.to_byte_array();
    let script_pubkey_bytes = output_script_pubkey.as_bytes().to_vec();
    let params = ClementineOptimisticPayoutMessage {
        withdrawal_id,
        input_signature: input_sig_bytes.into(),
        input_outpoint_txid: outpoint_txid_bytes.into(),
        input_outpoint_vout: input_outpoint.vout,
        output_script_pubkey: script_pubkey_bytes.into(),
        output_amount: output_amount.to_sat(),
    };

    let eip712_hash = params.eip712_signing_hash(&DOMAIN);

    let signature = signing_key
        .sign_prehash_recoverable(eip712_hash.as_slice())
        .unwrap();

    PrimitiveSignature::from(signature)
}
