//! Kickoff transaction.
//!
//! This transaction initializes protocol state for a round after the operator
//! fronts a withdrawal and wants reimbursement. It creates all outputs needed
//! for challenge handling, reimbursement, blockhash commitment, BitVM asserts,
//! disprove, and watchtower flows.

use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder::transaction::{
    anchor_output, op_return_txout, DataSources, TxCache, TxCacheExt, UnspentTxOut,
    DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::{TapNodeHash, TaprootBuilder};
use bitcoin::{ScriptBuf, TapSighashType};
use bitvm::clementine::additional_disprove::replace_placeholders_in_script;
use circuits_lib::bridge_circuit::deposit_constant;
use clementine_errors::{BridgeError, TxError};
use clementine_primitives::BridgeRound;
use tx_builder::output::TapNodeSpec;
use tx_builder::script::SpendableScript;
use tx_builder::scripts::{
    CheckSig, OtherSpendable, PreimageRevealScript, TimelockScript, WinternitzCommit,
};

use super::{
    common::round_kickoff_from,
    round::{RoundLeaf, RoundOutput},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KickoffInput {
    Round,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KickoffOutput {
    Challenge,
    Finalizer,
    Reimburse,
    Disprove,
    LatestBlockhash,
    Assert(usize),
    WatchtowerChallenge(usize),
    WatchtowerChallengeAck(usize),
    OpReturn,
    Anchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KickoffLeaf {
    OperatorImmediate,
    OperatorTimeout,
    NofnSpend,
    DisproveTimeout,
    AdditionalDisprove,
    LatestBlockhashTimeout,
    LatestBlockhash,
    AssertTimeout,
    WatchtowerChallenge,
    ChallengeNackTimeout,
    WatchtowerAckTimeout,
    WatchtowerChallengeAck(usize),
}

pub(crate) fn spec(
    num_asserts: usize,
    num_watchtowers: usize,
) -> TxSpec<KickoffInput, KickoffOutput> {
    let mut outputs = vec![
        KickoffOutput::Challenge,
        KickoffOutput::Finalizer,
        KickoffOutput::Reimburse,
        KickoffOutput::Disprove,
        KickoffOutput::LatestBlockhash,
    ];
    for i in 0..num_asserts {
        outputs.push(KickoffOutput::Assert(i));
    }
    for i in 0..num_watchtowers {
        outputs.push(KickoffOutput::WatchtowerChallenge(i));
        outputs.push(KickoffOutput::WatchtowerChallengeAck(i));
    }
    outputs.push(KickoffOutput::OpReturn);
    outputs.push(KickoffOutput::Anchor);

    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![KickoffInput::Round],
        outputs,
    )
}

impl KickoffInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);

        match self {
            Self::Round => InputSpec::parent(
                TransactionType::Round(round),
                RoundOutput::Kickoff(kickoff.0),
                DEFAULT_SEQUENCE,
            )
            .leaf(
                RoundLeaf::BlockhashCommit,
                Actor::Operator,
                TapSighashType::Default,
            ),
        }
    }
}

impl From<KickoffInput> for Input {
    fn from(value: KickoffInput) -> Self {
        Input::Kickoff(value)
    }
}

impl KickoffOutput {
    pub(crate) fn materialize(
        self,
        tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        cache: &TxCache,
    ) -> Result<Option<UnspentTxOut>, BridgeError> {
        let (round, kickoff) = round_kickoff_from(tx_type);
        let paramset = datasources.params();
        let operator_xonly_pk = datasources.operator()?.xonly_pk;
        let (nofn_xonly_pk, watchtowers) = {
            let deposit = datasources.deposit_mut()?;
            (
                deposit.get_nofn_xonly_pk()?,
                deposit.get_watchtowers().to_vec(),
            )
        };

        match self {
            Self::Challenge => {
                let operator_script = CheckSig::new(operator_xonly_pk);
                let operator_1week = TimelockScript::new(
                    Some(operator_xonly_pk),
                    paramset.operator_challenge_timeout_timelock,
                );
                Ok(Some(UnspentTxOut::from_taptree(
                    paramset.default_utxo_amount(),
                    None,
                    vec![
                        TapNodeSpec::leaf(KickoffLeaf::OperatorImmediate.into(), operator_script),
                        TapNodeSpec::leaf(KickoffLeaf::OperatorTimeout.into(), operator_1week),
                    ],
                )))
            }
            Self::Finalizer | Self::Reimburse => {
                let nofn_script = CheckSig::new(nofn_xonly_pk);
                Ok(Some(UnspentTxOut::from_taptree(
                    paramset.default_utxo_amount(),
                    None,
                    vec![TapNodeSpec::leaf(
                        KickoffLeaf::NofnSpend.into(),
                        nofn_script,
                    )],
                )))
            }
            Self::Disprove => {
                let operator_5week = TimelockScript::new(
                    Some(operator_xonly_pk),
                    paramset.disprove_timeout_timelock,
                );

                let kickoff_data = datasources.kickoff()?;
                let payout_tx_blockhash_pk = datasources
                    .kickoff_keys()?
                    .get_keys_for_round(BridgeRound::Round(round.0))?
                    .get(kickoff.0)
                    .ok_or(TxError::IndexOverflow)?
                    .clone();

                let round_txhandler = cache.get_required(TransactionType::Round(round))?;

                let move_txid = *datasources.move_to_vault_txid()?.as_byte_array();
                let round_txid = *round_txhandler.txid_ref().as_byte_array();
                let vout = round_txhandler.output_index(RoundOutput::Kickoff(kickoff.0))?;
                let watchtower_challenge_start_idx = spec(
                    ClementineBitVMPublicKeys::number_of_assert_txs(),
                    watchtowers.len(),
                )
                .output_index(&Self::WatchtowerChallenge(0))
                .expect("watchtower challenge output must exist")
                    as u32;

                let secp = Secp256k1::verification_only();
                let watchtower_pubkeys = watchtowers
                    .iter()
                    .map(|xonly_pk| {
                        let nofn_2week = TimelockScript::new(
                            Some(nofn_xonly_pk),
                            paramset.watchtower_challenge_timeout_timelock,
                        );

                        let builder = TaprootBuilder::new();
                        let tweaked = builder
                            .add_leaf(0, nofn_2week.to_script_buf())
                            .expect("Valid script leaf")
                            .finalize(&secp, *xonly_pk)
                            .expect("taproot finalize must succeed");

                        tweaked.output_key().serialize()
                    })
                    .collect::<Vec<_>>();

                let deposit_constant = deposit_constant(
                    operator_xonly_pk.serialize(),
                    watchtower_challenge_start_idx,
                    &watchtower_pubkeys,
                    move_txid,
                    round_txid,
                    vout,
                    paramset.genesis_chain_state_hash,
                );

                let additional_disprove_script = replace_placeholders_in_script(
                    kickoff_data.additional_disprove_script.clone(),
                    payout_tx_blockhash_pk,
                    deposit_constant.0,
                );

                Ok(Some(UnspentTxOut::from_taptree(
                    paramset.default_utxo_amount(),
                    None,
                    vec![
                        TapNodeSpec::leaf(KickoffLeaf::DisproveTimeout.into(), operator_5week),
                        TapNodeSpec::branch(vec![
                            TapNodeSpec::leaf(
                                KickoffLeaf::AdditionalDisprove.into(),
                                OtherSpendable::new(ScriptBuf::from_bytes(
                                    additional_disprove_script,
                                )),
                            ),
                            TapNodeSpec::hidden(TapNodeHash::from_byte_array(
                                kickoff_data.disprove_root_hash,
                            )),
                        ]),
                    ],
                )))
            }
            Self::LatestBlockhash => {
                let nofn_latest_blockhash = TimelockScript::new(
                    Some(nofn_xonly_pk),
                    paramset.latest_blockhash_timeout_timelock,
                );

                let kickoff_data = datasources.kickoff()?;
                let latest_blockhash_script = WinternitzCommit::new(
                    vec![(
                        kickoff_data
                            .operator_bitvm_keys
                            .latest_blockhash_pk
                            .to_vec(),
                        40,
                    )],
                    operator_xonly_pk,
                    paramset.winternitz_log_d,
                );
                Ok(Some(UnspentTxOut::from_taptree(
                    paramset.default_utxo_amount(),
                    None,
                    vec![
                        TapNodeSpec::leaf(
                            KickoffLeaf::LatestBlockhashTimeout.into(),
                            nofn_latest_blockhash,
                        ),
                        TapNodeSpec::leaf(
                            KickoffLeaf::LatestBlockhash.into(),
                            latest_blockhash_script,
                        ),
                    ],
                )))
            }
            Self::Assert(idx) => {
                let nofn_4week =
                    TimelockScript::new(Some(nofn_xonly_pk), paramset.assert_timeout_timelock);

                let kickoff_data = datasources.kickoff()?;
                Ok(Some(UnspentTxOut::from_taptree(
                    paramset.default_utxo_amount(),
                    None,
                    vec![
                        TapNodeSpec::leaf(KickoffLeaf::AssertTimeout.into(), nofn_4week),
                        TapNodeSpec::hidden(TapNodeHash::from_byte_array(
                            kickoff_data.assert_script_hashes[idx],
                        )),
                    ],
                )))
            }
            Self::WatchtowerChallenge(watchtower_idx) => {
                let nofn_2week = TimelockScript::new(
                    Some(nofn_xonly_pk),
                    paramset.watchtower_challenge_timeout_timelock,
                );
                let watchtower_xonly_pk = watchtowers[watchtower_idx];
                Ok(Some(UnspentTxOut::from_taptree(
                    paramset.default_utxo_amount() * 2 + paramset.anchor_amount(),
                    Some(watchtower_xonly_pk),
                    vec![TapNodeSpec::leaf(
                        KickoffLeaf::WatchtowerChallenge.into(),
                        nofn_2week,
                    )],
                )))
            }
            Self::WatchtowerChallengeAck(watchtower_idx) => {
                let nofn_2week = TimelockScript::new(
                    Some(nofn_xonly_pk),
                    paramset.watchtower_challenge_timeout_timelock,
                );
                let nofn_3week = TimelockScript::new(
                    Some(nofn_xonly_pk),
                    paramset.operator_challenge_nack_timelock,
                );

                let kickoff_build_data = datasources.kickoff()?;
                let operator_unlock_hash = kickoff_build_data.challenge_ack_hashes[watchtower_idx];
                let operator_with_preimage =
                    PreimageRevealScript::new(operator_xonly_pk, operator_unlock_hash);

                Ok(Some(UnspentTxOut::from_taptree(
                    paramset.default_utxo_amount(),
                    None,
                    vec![
                        TapNodeSpec::leaf(KickoffLeaf::ChallengeNackTimeout.into(), nofn_3week),
                        TapNodeSpec::leaf(KickoffLeaf::WatchtowerAckTimeout.into(), nofn_2week),
                        TapNodeSpec::leaf(
                            KickoffLeaf::WatchtowerChallengeAck(watchtower_idx).into(),
                            operator_with_preimage,
                        ),
                    ],
                )))
            }
            Self::OpReturn => {
                let move_txid = datasources.move_to_vault_txid()?.as_byte_array().to_vec();

                let mut op_return_script = move_txid.to_vec();
                op_return_script.extend(operator_xonly_pk.serialize());
                let push_bytes =
                    PushBytesBuf::try_from(op_return_script).expect("Must fit pushbytesbuf");
                Ok(Some(UnspentTxOut::from_partial(op_return_txout(
                    push_bytes,
                ))))
            }
            Self::Anchor => Ok(Some(UnspentTxOut::from_partial(anchor_output(
                paramset.anchor_amount(),
            )))),
        }
    }
}

impl From<KickoffOutput> for Output {
    fn from(value: KickoffOutput) -> Self {
        Output::Kickoff(value)
    }
}
