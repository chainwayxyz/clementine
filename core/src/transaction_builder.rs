//! # Transaction Builder

use crate::{script_builder, utils, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::Network;
use bitcoin::{
    absolute,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use secp256k1::PublicKey;
use secp256k1::XOnlyPublicKey;

#[derive(Debug, Clone)]
pub struct TxHandler {
    pub tx: bitcoin::Transaction,
    pub prevouts: Vec<TxOut>,
    pub scripts: Vec<Vec<ScriptBuf>>,
    pub taproot_spend_infos: Vec<TaprootSpendInfo>,
}

pub type CreateAddressOutputs = (Address, TaprootSpendInfo);

#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    verifiers_xonly_pks: Vec<XOnlyPublicKey>,
    verifiers_pks: Vec<PublicKey>,
    network: Network,
}

// TODO: Move these constants to a config file
pub const MOVE_COMMIT_TX_MIN_RELAY_FEE: u64 = 305;
pub const MOVE_REVEAL_TX_MIN_RELAY_FEE: u64 = 305;
pub const WITHDRAWAL_TX_MIN_RELAY_FEE: u64 = 305;

impl TransactionBuilder {
    /// Creates a new `TransactionBuilder`.
    pub fn new(verifiers_pks: Vec<PublicKey>, network: Network) -> Self {
        let verifiers_xonly_pks: Vec<XOnlyPublicKey> = verifiers_pks
            .iter()
            .map(|pk| PublicKey::x_only_public_key(pk).0)
            .collect();
        Self {
            verifiers_xonly_pks,
            verifiers_pks,
            network,
        }
    }

    // ADDRESS BUILDERS

    pub fn create_taproot_address(
        scripts: &[ScriptBuf],
        internal_key: Option<XOnlyPublicKey>,
        network: bitcoin::Network,
    ) -> CreateAddressOutputs {
        let n = scripts.len();

        let taproot_builder = if n == 0 {
            TaprootBuilder::new()
        } else if n > 1 {
            let m: u8 = ((n - 1).ilog2() + 1) as u8; // m = ceil(log(n))
            let k = 2_usize.pow(m.into()) - n;
            (0..n).fold(TaprootBuilder::new(), |acc, i| {
                acc.add_leaf(m - ((i >= n - k) as u8), scripts[i].clone())
                    .unwrap()
            })
        } else {
            TaprootBuilder::new()
                .add_leaf(0, scripts[0].clone())
                .unwrap()
        };

        let tree_info = match internal_key {
            Some(xonly_pk) => taproot_builder.finalize(&utils::SECP, xonly_pk).unwrap(),
            None => taproot_builder
                .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
                .unwrap(),
        };

        let taproot_address = match internal_key {
            Some(xonly_pk) => {
                Address::p2tr(&utils::SECP, xonly_pk, tree_info.merkle_root(), network)
            }
            None => Address::p2tr(
                &utils::SECP,
                *utils::UNSPENDABLE_XONLY_PUBKEY,
                tree_info.merkle_root(),
                network,
            ),
        };

        (taproot_address, tree_info)
    }

    /// Generates a deposit address for the user. N-of-N or user takes after
    /// timelock script can be used to spend the funds.
    pub fn generate_deposit_address(
        nofn_xonly_pk: &XOnlyPublicKey,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        user_evm_address: &EVMAddress,
        amount: u64,
        user_takes_after: u32,
        network: bitcoin::Network,
    ) -> CreateAddressOutputs {
        let deposit_script =
            script_builder::create_deposit_script(nofn_xonly_pk, user_evm_address, amount);

        let recovery_script_pubkey = recovery_taproot_address
            .clone()
            .assume_checked()
            .script_pubkey();
        let recovery_extracted_xonly_pk =
            XOnlyPublicKey::from_slice(&recovery_script_pubkey.as_bytes()[2..34]).unwrap();

        let script_timelock = script_builder::generate_relative_timelock_script(
            &recovery_extracted_xonly_pk,
            user_takes_after,
        );

        TransactionBuilder::create_taproot_address(
            &[deposit_script, script_timelock],
            None,
            network,
        )
    }

    pub fn generate_move_commit_address(
        nofn_xonly_pk: &XOnlyPublicKey,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        user_evm_address: &EVMAddress,
        kickoff_utxos: &[OutPoint],
        relative_block_height_to_take_after: u32,
        network: bitcoin::Network,
    ) -> CreateAddressOutputs {
        let kickoffs_commit_script = script_builder::create_move_commit_script(
            nofn_xonly_pk,
            user_evm_address,
            kickoff_utxos,
        );

        let recovery_script_pubkey = recovery_taproot_address
            .clone()
            .assume_checked()
            .script_pubkey();
        let recovery_extracted_xonly_pk =
            XOnlyPublicKey::from_slice(&recovery_script_pubkey.as_bytes()[2..34]).unwrap();

        let timelock_script = script_builder::generate_relative_timelock_script(
            &recovery_extracted_xonly_pk,
            relative_block_height_to_take_after,
        );

        TransactionBuilder::create_taproot_address(
            &[kickoffs_commit_script, timelock_script],
            None,
            network,
        )
    }

    pub fn create_musig2_address(
        nofn_xonly_pk: XOnlyPublicKey,
        network: bitcoin::Network,
    ) -> CreateAddressOutputs {
        TransactionBuilder::create_taproot_address(&[], Some(nofn_xonly_pk), network)
    }

    // TX BUILDERS

    pub fn create_move_commit_tx(
        deposit_utxo: OutPoint,
        evm_address: &EVMAddress,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        deposit_user_takes_after: u32,
        nofn_xonly_pk: &XOnlyPublicKey,
        kickoff_utxos: &[OutPoint],
        relative_block_height_to_take_after: u32,
        network: bitcoin::Network,
    ) -> TxHandler {
        let anyone_can_spend_txout = script_builder::anyone_can_spend_txout();
        let (move_commit_address, _) = TransactionBuilder::generate_move_commit_address(
            nofn_xonly_pk,
            recovery_taproot_address,
            evm_address,
            kickoff_utxos,
            relative_block_height_to_take_after,
            network,
        );

        let (deposit_address, deposit_taproot_spend_info) =
            TransactionBuilder::generate_deposit_address(
                nofn_xonly_pk,
                recovery_taproot_address,
                evm_address,
                BRIDGE_AMOUNT_SATS,
                deposit_user_takes_after,
                network,
            );

        let move_commit_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                - Amount::from_sat(MOVE_COMMIT_TX_MIN_RELAY_FEE)
                - anyone_can_spend_txout.value,
            script_pubkey: move_commit_address.script_pubkey(),
        };

        let tx_ins = TransactionBuilder::create_tx_ins(vec![deposit_utxo]);

        let move_commit_tx = TransactionBuilder::create_btc_tx(
            tx_ins,
            vec![move_commit_txout, anyone_can_spend_txout],
        );

        let prevouts = vec![TxOut {
            script_pubkey: deposit_address.script_pubkey(),
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS),
        }];

        let deposit_script = vec![script_builder::create_deposit_script(
            nofn_xonly_pk,
            evm_address,
            BRIDGE_AMOUNT_SATS,
        )];

        TxHandler {
            tx: move_commit_tx,
            prevouts,
            scripts: vec![deposit_script],
            taproot_spend_infos: vec![deposit_taproot_spend_info],
        }
    }

    pub fn create_move_reveal_tx(
        move_commit_utxo: OutPoint,
        evm_address: &EVMAddress,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        nofn_xonly_pk: &XOnlyPublicKey,
        kickoff_utxos: &[OutPoint],
        relative_block_height_to_take_after: u32,
        network: Network,
    ) -> TxHandler {
        let (musig2_address, _) =
            TransactionBuilder::create_musig2_address(*nofn_xonly_pk, network);
        let (move_commit_address, move_commit_taproot_spend_info) =
            TransactionBuilder::generate_move_commit_address(
                nofn_xonly_pk,
                recovery_taproot_address,
                evm_address,
                kickoff_utxos,
                relative_block_height_to_take_after,
                network,
            );
        let move_reveal_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                - Amount::from_sat(MOVE_COMMIT_TX_MIN_RELAY_FEE)
                - Amount::from_sat(MOVE_REVEAL_TX_MIN_RELAY_FEE)
                - script_builder::anyone_can_spend_txout().value
                - script_builder::anyone_can_spend_txout().value,
            script_pubkey: musig2_address.script_pubkey(),
        };

        let tx_ins = TransactionBuilder::create_tx_ins(vec![move_commit_utxo]);

        let move_reveal_tx = TransactionBuilder::create_btc_tx(
            tx_ins,
            vec![move_reveal_txout, script_builder::anyone_can_spend_txout()],
        );

        let prevouts = vec![TxOut {
            script_pubkey: move_commit_address.script_pubkey(),
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS),
        }];

        let move_commit_script = vec![script_builder::create_move_commit_script(
            nofn_xonly_pk,
            evm_address,
            kickoff_utxos,
        )];

        TxHandler {
            tx: move_reveal_tx,
            prevouts,
            scripts: vec![move_commit_script],
            taproot_spend_infos: vec![move_commit_taproot_spend_info],
        }
    }

    /// Creates the kickoff_tx for the operator. It also returns the change utxo
    pub fn create_kickoff_tx(funding_utxo: &UTXO, address: &Address) -> TxHandler {
        let tx_ins = TransactionBuilder::create_tx_ins(vec![funding_utxo.outpoint]);

        let change_amount = funding_utxo.txout.value
            - Amount::from_sat(100_000)
            - script_builder::anyone_can_spend_txout().value;

        let tx_outs = TransactionBuilder::create_tx_outs(vec![
            (
                Amount::from_sat(100_000), // TODO: Change this to a constant
                address.script_pubkey(),
            ),
            (change_amount, address.script_pubkey()),
            (
                script_builder::anyone_can_spend_txout().value,
                script_builder::anyone_can_spend_txout().script_pubkey,
            ),
        ]);
        let tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
        let prevouts = vec![funding_utxo.txout.clone()];
        let scripts = vec![vec![]];
        let taproot_spend_infos = vec![];
        TxHandler {
            tx,
            prevouts,
            scripts,
            taproot_spend_infos,
        }
    }

    pub fn create_slash_or_take_tx(
        kickoff_outpoint: OutPoint,
        kickoff_txout: TxOut,
        operator_address: &XOnlyPublicKey,
        nofn_xonly_pk: &XOnlyPublicKey,
        network: bitcoin::Network,
    ) -> TxHandler {
        let ins = TransactionBuilder::create_tx_ins(vec![kickoff_outpoint]);
        let relative_timelock_script =
            script_builder::generate_relative_timelock_script(operator_address, 200); // TODO: Change this 200 to a config constant

        let slash_or_take_address = TransactionBuilder::create_taproot_address(
            &[relative_timelock_script.clone()],
            Some(*nofn_xonly_pk),
            network,
        );

        let outs = vec![
            TxOut {
                value: Amount::from_sat(kickoff_txout.value.to_sat() - 330),
                script_pubkey: slash_or_take_address.0.script_pubkey(),
            },
            script_builder::anyone_can_spend_txout(),
        ];
        let tx = TransactionBuilder::create_btc_tx(ins, outs);
        let prevouts = vec![kickoff_txout];
        let scripts = vec![vec![relative_timelock_script]];
        let taproot_spend_infos = vec![slash_or_take_address.1];
        TxHandler {
            tx,
            prevouts,
            scripts,
            taproot_spend_infos,
        }
    }

    pub fn create_operator_takes_tx(
        bridge_fund_outpoint: OutPoint,
        slash_or_take_outpoint: OutPoint,
        slash_or_take_txout: TxOut,
        operator_address: &Address,
        nofn_xonly_pk: &XOnlyPublicKey,
        network: bitcoin::Network,
    ) -> TxHandler {
        let ins =
            TransactionBuilder::create_tx_ins(vec![bridge_fund_outpoint, slash_or_take_outpoint]);

        let (musig2_address, musig2_spend_info) =
            TransactionBuilder::create_musig2_address(*nofn_xonly_pk, network);

        let relative_timelock_script = script_builder::generate_relative_timelock_script(
            &secp256k1::XOnlyPublicKey::from_slice(
                &operator_address.script_pubkey().as_bytes()[2..34],
            )
            .unwrap(),
            200,
        ); // TODO: Change this 200 to a config constant
        let (slash_or_take_address, slash_or_take_spend_info) =
            TransactionBuilder::create_taproot_address(
                &[relative_timelock_script.clone()],
                Some(*nofn_xonly_pk),
                network,
            );

        // Sanity check
        assert!(slash_or_take_address.script_pubkey() == slash_or_take_txout.script_pubkey);

        let outs = vec![
            TxOut {
                value: Amount::from_sat(slash_or_take_txout.value.to_sat())
                    + Amount::from_sat(BRIDGE_AMOUNT_SATS)
                    - Amount::from_sat(MOVE_COMMIT_TX_MIN_RELAY_FEE)
                    - Amount::from_sat(MOVE_REVEAL_TX_MIN_RELAY_FEE)
                    - script_builder::anyone_can_spend_txout().value
                    - script_builder::anyone_can_spend_txout().value
                    - script_builder::anyone_can_spend_txout().value,
                script_pubkey: operator_address.script_pubkey(),
            },
            script_builder::anyone_can_spend_txout(),
        ];
        let tx = TransactionBuilder::create_btc_tx(ins, outs);
        let prevouts = vec![
            TxOut {
                script_pubkey: musig2_address.script_pubkey(),
                value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                    - Amount::from_sat(MOVE_COMMIT_TX_MIN_RELAY_FEE)
                    - Amount::from_sat(MOVE_REVEAL_TX_MIN_RELAY_FEE)
                    - script_builder::anyone_can_spend_txout().value
                    - script_builder::anyone_can_spend_txout().value,
            },
            slash_or_take_txout,
        ];
        let scripts = vec![vec![], vec![relative_timelock_script]];
        let taproot_spend_infos = vec![musig2_spend_info, slash_or_take_spend_info];
        TxHandler {
            tx,
            prevouts,
            scripts,
            taproot_spend_infos,
        }
    }

    pub fn create_btc_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: absolute::LockTime::from_consensus(0),
            input: tx_ins,
            output: tx_outs,
        }
    }

    pub fn create_tx_ins(utxos: Vec<OutPoint>) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for utxo in utxos {
            tx_ins.push(TxIn {
                previous_output: utxo,
                sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
                script_sig: ScriptBuf::default(),
                witness: Witness::new(),
            });
        }

        tx_ins
    }

    pub fn create_tx_ins_with_sequence(utxos: Vec<OutPoint>, height: u16) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for utxo in utxos {
            tx_ins.push(TxIn {
                previous_output: utxo,
                sequence: bitcoin::transaction::Sequence::from_height(height),
                script_sig: ScriptBuf::default(),
                witness: Witness::new(),
            });
        }

        tx_ins
    }

    pub fn create_tx_outs(pairs: Vec<(Amount, ScriptBuf)>) -> Vec<TxOut> {
        let mut tx_outs = Vec::new();

        for pair in pairs {
            tx_outs.push(TxOut {
                value: pair.0,
                script_pubkey: pair.1,
            });
        }

        tx_outs
    }
}

// #[cfg(test)]
// mod tests {

//     use bitcoin::{Address, XOnlyPublicKey};
//     use secp256k1::PublicKey;

//     use crate::{config::BridgeConfig, transaction_builder::TransactionBuilder};
//     use std::str::FromStr;

//     #[test]
//     fn deposit_address() {
//         let config = BridgeConfig::new();

//         let secp = secp256k1::Secp256k1::new();

//         let verifier_pks_hex: Vec<&str> = vec![
//             "029bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964",
//             "02e37d58a1aae4ba059fd2503712d998470d3a2522f7e2335f544ef384d2199e02",
//             "02688466442a134ee312299bafb37058e385c98dd6005eaaf0f538f533efe5f91f",
//             "02337cca2171fdbfcfd657fa59881f46269f1e590b5ffab6023686c7ad2ecc2c1c",
//             "02a1f9821c983cfe80558fb0b56385c67c8df6824c17aed048c7cbd031549a2fa8",
//         ];
//         let verifier_pks: Vec<PublicKey> = verifier_pks_hex
//             .iter()
//             .map(|pk| PublicKey::from_str(pk).unwrap())
//             .collect();

//         let tx_builder = TransactionBuilder::new(verifier_pks, config.network);

//         let evm_address: [u8; 20] = hex::decode("1234567890123456789012345678901234567890")
//             .unwrap()
//             .try_into()
//             .unwrap();

//         let user_xonly_pk: XOnlyPublicKey = XOnlyPublicKey::from_str(
//             "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
//         )
//         .unwrap();

//         let recovery_taproot_address =
//             Address::p2tr(&secp, user_xonly_pk, None, bitcoin::Network::Regtest);

//         let deposit_address = TransactionBuilder::generate_deposit_address(
//             &user_xonly_pk,
//             recovery_taproot_address.as_unchecked(),
//             &crate::EVMAddress(evm_address),
//             10_000,
//             200,
//             bitcoin::Network::Regtest,
//         );
//         println!("deposit_address: {:?}", deposit_address.0);

//         assert_eq!(
//             deposit_address.0.to_string(),
//             "bcrt1prqxsjz7h5wt40w54vhmpvn6l2hu8mefmez6ld4p59vksllumskvqs8wvkh" // check this later
//         ) // Comparing it to the taproot address generated in bridge backend repo (using js)
//     }
// }
