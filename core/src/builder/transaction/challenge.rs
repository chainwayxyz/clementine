use crate::builder;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, DEFAULT_SEQUENCE};
use crate::builder::transaction::*;
use crate::constants::OPERATOR_CHALLENGE_AMOUNT;
use crate::errors::BridgeError;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::{Amount, ScriptBuf, Sequence, TxOut, XOnlyPublicKey};
use bitvm::signatures::winternitz;

/// Creates a [`TxHandler`] for the `watchtower_challenge_kickoff_tx`. This transaction can be sent by anyone.
/// When spent, the outputs of this transaction will reveal the Groth16 proofs with their public inputs for the longest
/// chain proof, signed by the corresponding watchtowers using WOTS.
pub fn create_watchtower_challenge_kickoff_txhandler(
    kickoff_tx_handler: &TxHandler,
    num_watchtowers: u32,
    watchtower_xonly_pks: &[XOnlyPublicKey],
    watchtower_challenge_winternitz_pks: &[Vec<[u8; 20]>],
    network: bitcoin::Network,
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new().add_input(
        kickoff_tx_handler
            .get_spendable_output(0)
            .ok_or(BridgeError::TxInputNotFound)?,
        DEFAULT_SEQUENCE,
    );

    let verifier =
        winternitz::Winternitz::<winternitz::ListpickVerifier, winternitz::TabledConverter>::new();
    let wots_params = winternitz::Parameters::new(240, 4);

    for i in 0..num_watchtowers {
        let mut x = verifier.checksig_verify(
            &wots_params,
            &watchtower_challenge_winternitz_pks[i as usize],
        );
        x = x.push_x_only_key(&watchtower_xonly_pks[i as usize]);
        x = x.push_opcode(OP_CHECKSIG); // TODO: Add checksig in the beginning
        let x = x.compile();
        let (watchtower_challenge_addr, watchtower_challenge_spend) =
            builder::address::create_taproot_address(&[x.clone()], None, network);
        builder = builder.add_output(UnspentTxOut::new(
            TxOut {
                value: Amount::from_sat(2000), // TOOD: Hand calculate this
                script_pubkey: watchtower_challenge_addr.script_pubkey(), // TODO: Add winternitz checks here
            },
            vec![x],
            Some(watchtower_challenge_spend),
        ));
    }

    Ok(builder
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize())
}

/// Creates a "simplified "[`TxHandler`] for the `watchtower_challenge_kickoff_tx`. The purpose of the simplification
/// is that when the verifiers are generating related sighashes, they only need to know the output addresses or the
/// input UTXOs. They do not need to know output scripts or spendinfos.
pub fn create_watchtower_challenge_kickoff_txhandler_simplified(
    kickoff_tx_handler: &TxHandler,
    num_watchtowers: u32,
    watchtower_challenge_addresses: &[ScriptBuf],
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new().add_input(
        kickoff_tx_handler
            .get_spendable_output(0)
            .ok_or(BridgeError::TxInputNotFound)?,
        DEFAULT_SEQUENCE,
    );
    for i in 0..num_watchtowers {
        builder = builder.add_output(UnspentTxOut::new(
            TxOut {
                value: Amount::from_sat(2000), // TODO: Hand calculate this
                script_pubkey: watchtower_challenge_addresses[i as usize].clone(),
            },
            vec![],
            None,
        ));
    }
    Ok(builder
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `watchtower_challenge_tx`. This transaction
/// is sent by the watchtowers to reveal their Groth16 proofs with their public
/// inputs for the longest chain proof, signed by the corresponding watchtowers
/// using WOTS. The output of this transaction can be spend by:
/// 1- the operator with revealing the preimage for the corresponding watchtower
/// 2- the NofN after 0.5 week `using kickoff_tx.output[2]`, which will also prevent
/// the operator from sending `assert_begin_tx`.
/// The revealed preimage will later be used to send `disprove_tx` if the operator
/// claims that the corresponding watchtower did not challenge them.
pub fn create_watchtower_challenge_txhandler(
    wcp_txhandler: &TxHandler,
    watchtower_idx: usize,
    operator_unlock_hash: &[u8; 20],
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new().add_input(
        wcp_txhandler
            .get_spendable_output(watchtower_idx)
            .ok_or(BridgeError::TxInputNotFound)?,
        DEFAULT_SEQUENCE,
    );

    let nofn_halfweek =
        builder::script::generate_checksig_relative_timelock_script(nofn_xonly_pk, 7 * 24 * 6 / 2); // 0.5 week
    let operator_with_preimage =
        builder::script::actor_with_preimage_script(operator_xonly_pk, operator_unlock_hash);
    let (op_or_nofn_halfweek, op_or_nofn_halfweek_spend) = builder::address::create_taproot_address(
        &[operator_with_preimage.clone(), nofn_halfweek.clone()],
        None,
        network,
    );

    Ok(builder
        .add_output(UnspentTxOut::new(
            TxOut {
                value: Amount::from_sat(1000), // TODO: Hand calculate this
                script_pubkey: op_or_nofn_halfweek.script_pubkey(),
            },
            vec![operator_with_preimage, nofn_halfweek],
            Some(op_or_nofn_halfweek_spend),
        ))
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `operator_challenge_NACK_tx`. This transaction will force
/// the operator to reveal the preimage for the corresponding watchtower since if they do not
/// reveal the preimage, the NofN will be able to spend the output after 0.5 week, which will
/// prevent the operator from sending `assert_begin_tx`.
pub fn create_operator_challenge_nack_txhandler(
    watchtower_challenge_txhandler: &TxHandler,
    kickoff_txhandler: &TxHandler,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new()
        .add_input(
            watchtower_challenge_txhandler
                .get_spendable_output(0)
                .ok_or(BridgeError::TxInputNotFound)?,
            Sequence::from_height(7 * 24 * 6 / 2),
        )
        .add_input(
            kickoff_txhandler
                .get_spendable_output(2)
                .ok_or(BridgeError::TxInputNotFound)?,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `already_disproved_tx`. This transaction will be sent by NofN, meaning
/// that the operator was malicious. This transaction "burns" the operator's burn connector, kicking the
/// operator out of the system.
pub fn create_already_disproved_txhandler(
    assert_end_txhandler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new()
        .add_input(
            assert_end_txhandler
                .get_spendable_output(1)
                .ok_or(BridgeError::TxInputNotFound)?,
            Sequence::from_height(7 * 24 * 6 * 2),
        )
        .add_input(
            sequential_collateral_txhandler
                .get_spendable_output(0)
                .ok_or(BridgeError::TxInputNotFound)?,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `disprove_tx`. This transaction will be sent by NofN, meaning
/// that the operator was malicious. This transaction burns the operator's burn connector, kicking the
/// operator out of the system.
pub fn create_disprove_txhandler(
    assert_end_txhandler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new()
        .add_input(
            assert_end_txhandler
                .get_spendable_output(0)
                .ok_or(BridgeError::TxInputNotFound)?,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            sequential_collateral_txhandler
                .get_spendable_output(0)
                .ok_or(BridgeError::TxInputNotFound)?,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `challenge`. This transaction is for covering
/// the operators' cost for a challenge to prevent people from maliciously
/// challenging them and causing them to lose money.
pub fn create_challenge_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_reimbursement_address: &bitcoin::Address,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new()
        .add_input(
            kickoff_txhandler
                .get_spendable_output(1)
                .ok_or(BridgeError::TxInputNotFound)?,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::new(
            TxOut {
                value: OPERATOR_CHALLENGE_AMOUNT,
                script_pubkey: operator_reimbursement_address.script_pubkey(),
            },
            vec![],
            None,
        ))
        .finalize())
}
