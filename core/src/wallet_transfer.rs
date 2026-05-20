use crate::actor::Actor;
use crate::builder::transaction::custom::{
    builder, current_tx, input as custom_input, key_spend_descriptor, sign_with_actor,
    CustomSpendableTxIn, CustomUnspentTxOut,
};
use bitcoin::{OutPoint, Transaction, TxOut, Weight};
use clementine_errors::BridgeError;
use std::sync::Arc;

pub(crate) fn build_signed_wallet_transfer_tx(
    signer: &Actor,
    inputs: &[(OutPoint, TxOut)],
    output_txout: TxOut,
    network: bitcoin::Network,
) -> Result<(Transaction, Weight), BridgeError> {
    let (_, spendinfo) = crate::builder::address::create_taproot_address(
        &[],
        Some(signer.xonly_public_key),
        network,
    );
    let spendinfo = Arc::new(spendinfo);

    let mut txbuilder = builder(0).with_version(bitcoin::transaction::Version::TWO);

    for (idx, (outpoint, txout)) in inputs.iter().enumerate() {
        txbuilder = txbuilder.add_input(
            custom_input(idx),
            CustomSpendableTxIn::new(
                *outpoint,
                txout.clone(),
                vec![],
                vec![],
                Some(spendinfo.clone()),
            ),
            bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            key_spend_descriptor(bitcoin::TapSighashType::Default),
        );
    }

    let mut txhandler = txbuilder
        .add_output(
            crate::builder::transaction::custom::output(0),
            CustomUnspentTxOut::from_partial(output_txout),
        )
        .finalize();
    sign_with_actor(signer, &mut txhandler)?;

    Ok((
        current_tx(&txhandler).clone(),
        current_tx(&txhandler).weight(),
    ))
}
