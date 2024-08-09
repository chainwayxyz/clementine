//! # Transaction Builder

use crate::{script_builder, utils, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::Network;
use bitcoin::{
    absolute,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use secp256k1::XOnlyPublicKey;

#[derive(Debug, Clone)]
pub struct CreateTxOutputs {
    pub tx: bitcoin::Transaction,
    pub prevouts: Vec<TxOut>,
    pub scripts: Vec<Vec<ScriptBuf>>,
    pub taproot_spend_infos: Vec<TaprootSpendInfo>,
}

pub type CreateAddressOutputs = (Address, TaprootSpendInfo);

#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    verifiers_pks: Vec<XOnlyPublicKey>,
    network: Network,
}

pub const MOVE_TX_MIN_RELAY_FEE: u64 = 305;
pub const WITHDRAWAL_TX_MIN_RELAY_FEE: u64 = 305;

impl TransactionBuilder {
    /// Creates a new `TransactionBuilder`.
    pub fn new(verifiers_pks: Vec<XOnlyPublicKey>, network: Network) -> Self {
        Self {
            verifiers_pks,
            network,
        }
    }

    // ADDRESS BUILDERS
    pub fn create_taproot_address(
        scripts: &[ScriptBuf],
        network: bitcoin::Network,
    ) -> (Address, TaprootSpendInfo) {
        let n = scripts.len();
        let taproot_builder = if n > 1 {
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

        let tree_info = taproot_builder
            .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
            .unwrap();

        (
            Address::p2tr(
                &utils::SECP,
                *utils::UNSPENDABLE_XONLY_PUBKEY,
                tree_info.merkle_root(),
                network,
            ),
            tree_info,
        )
    }

    /// Generates a deposit address for the user. N-of-N or user takes after
    /// timelock script can be used to spend the funds.
    pub fn generate_deposit_address(
        verifiers_pks: &[XOnlyPublicKey],
        recovery_taproot_address: &Address<NetworkUnchecked>,
        user_evm_address: &EVMAddress,
        amount: u64,
        user_takes_after: u32,
    ) -> CreateAddressOutputs {
        let deposit_script =
            script_builder::create_deposit_script(verifiers_pks, user_evm_address, amount);

        let script_timelock =
            script_builder::generate_timelock_script(recovery_taproot_address, user_takes_after);

        TransactionBuilder::create_taproot_address(
            &[deposit_script, script_timelock],
            bitcoin::Network::Regtest,
        )
    }

    pub fn generate_move_commit_address(
        verifiers_pks: &[XOnlyPublicKey],
        recovery_taproot_address: &Address<NetworkUnchecked>,
        user_evm_address: &EVMAddress,
        kickoff_utxos: &[OutPoint],
        relative_block_height_to_take_after: u32,
    ) -> CreateAddressOutputs {
        let kickoffs_commit_script = script_builder::create_kickoff_commit_script(
            verifiers_pks,
            user_evm_address,
            kickoff_utxos,
        );
        let timelock_script = script_builder::generate_timelock_script(
            recovery_taproot_address,
            relative_block_height_to_take_after,
        );

        TransactionBuilder::create_taproot_address(
            &[kickoffs_commit_script, timelock_script],
            bitcoin::Network::Regtest,
        )
    }

    pub fn generate_musig_address(verifiers_pks: &[XOnlyPublicKey]) -> CreateAddressOutputs {
        // TODO: Fix this to use key spend path with Musig2 agg pubkey
        let script_n_of_n = script_builder::generate_script_n_of_n(verifiers_pks);

        TransactionBuilder::create_taproot_address(&[script_n_of_n], bitcoin::Network::Regtest)
    }

    // TX BUILDERS

    pub fn create_move_commit_tx(
        deposit_utxo: OutPoint,
        evm_address: &EVMAddress,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        deposit_user_takes_after: u32,
        verifiers_pks: &[XOnlyPublicKey],
        kickoff_utxos: &[OutPoint],
        relative_block_height_to_take_after: u32,
    ) -> CreateTxOutputs {
        let anyone_can_spend_txout = script_builder::anyone_can_spend_txout();
        let (move_commit_address, _) = TransactionBuilder::generate_move_commit_address(
            &verifiers_pks,
            recovery_taproot_address,
            evm_address,
            kickoff_utxos,
            relative_block_height_to_take_after,
        );

        let (deposit_address, deposit_taproot_spend_info) =
            TransactionBuilder::generate_deposit_address(
                verifiers_pks,
                recovery_taproot_address,
                evm_address,
                BRIDGE_AMOUNT_SATS,
                deposit_user_takes_after,
            );

        let move_commit_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
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
            verifiers_pks,
            evm_address,
            BRIDGE_AMOUNT_SATS,
        )];

        CreateTxOutputs {
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
        verifiers_pks: &[XOnlyPublicKey],
        kickoff_utxos: &[OutPoint],
        relative_block_height_to_take_after: u32,
    ) -> CreateTxOutputs {
        let (musig_addres, _) = TransactionBuilder::generate_musig_address(verifiers_pks);
        let (move_commit_address, move_commit_taproot_spend_info) =
            TransactionBuilder::generate_move_commit_address(
                verifiers_pks,
                recovery_taproot_address,
                evm_address,
                kickoff_utxos,
                relative_block_height_to_take_after,
            );
        let move_reveal_txout = TxOut {
            // TODO: Fix this
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
                - script_builder::anyone_can_spend_txout().value,
            script_pubkey: musig_addres.script_pubkey(),
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

        let move_commit_script = vec![script_builder::create_kickoff_commit_script(
            verifiers_pks,
            evm_address,
            kickoff_utxos,
        )];

        CreateTxOutputs {
            tx: move_reveal_tx,
            prevouts,
            scripts: vec![move_commit_script],
            taproot_spend_infos: vec![move_commit_taproot_spend_info],
        }
    }

    // pub fn create_withdraw_tx(
    //     &self,
    //     deposit_utxo: OutPoint,
    //     deposit_txout: TxOut,
    //     withdraw_address: &Address,
    // ) -> Result<CreateTxOutputs, BridgeError> {
    //     let anyone_can_spend_txout = script_builder::anyone_can_spend_txout();

    //     let (_, bridge_spend_info) = self.generate_bridge_address()?;

    //     let tx_ins = TransactionBuilder::create_tx_ins(vec![deposit_utxo]);
    //     let bridge_txout = TxOut {
    //         value: deposit_txout.value
    //             - Amount::from_sat(WITHDRAWAL_TX_MIN_RELAY_FEE)
    //             - anyone_can_spend_txout.value,
    //         script_pubkey: withdraw_address.script_pubkey(),
    //     };

    //     let withdraw_tx =
    //         TransactionBuilder::create_btc_tx(tx_ins, vec![bridge_txout, anyone_can_spend_txout]);

    //     let prevouts = vec![deposit_txout];

    //     let bridge_spend_script = vec![script_builder::generate_script_n_of_n(&self.verifiers_pks)];

    //     Ok(CreateTxOutputs {
    //         tx: withdraw_tx,
    //         prevouts,
    //         scripts: vec![bridge_spend_script],
    //         taproot_spend_infos: vec![bridge_spend_info],
    //     })
    // }

    /// Creates the kickoff_tx for the operator. It also returns the change output
    pub fn create_kickoff_tx(
        funding_utxo: OutPoint,
        funding_amount: Amount,
        address: &Address,
    ) -> (bitcoin::Transaction, OutPoint, Amount) {
        let tx_ins = TransactionBuilder::create_tx_ins(vec![funding_utxo]);

        let change_amount = funding_amount
            - Amount::from_sat(100_000)
            - script_builder::anyone_can_spend_txout().value;

        let tx_outs = TransactionBuilder::create_tx_outs(vec![
            (
                Amount::from_sat(100_000), // TODO: Change this to a constant
                address.script_pubkey(),
            ),
            (
                script_builder::anyone_can_spend_txout().value,
                script_builder::anyone_can_spend_txout().script_pubkey,
            ),
            (change_amount, address.script_pubkey()),
        ]);
        let tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
        let txid = tx.compute_txid();
        let change_utxo = OutPoint { txid, vout: 2 };
        (tx, change_utxo, change_amount)
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

#[cfg(test)]
mod tests {
    // use crate::{config::BridgeConfig, transaction_builder::TransactionBuilder};
    // use bitcoin::{Address, XOnlyPublicKey};
    // use std::str::FromStr;

    #[test]
    fn deposit_address() {
        // TODO: Add tests
        // let config = BridgeConfig::new();

        // let secp = secp256k1::Secp256k1::new();

        // let verifier_pks_hex: Vec<&str> = vec![
        //     "9bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964",
        //     "e37d58a1aae4ba059fd2503712d998470d3a2522f7e2335f544ef384d2199e02",
        //     "688466442a134ee312299bafb37058e385c98dd6005eaaf0f538f533efe5f91f",
        //     "337cca2171fdbfcfd657fa59881f46269f1e590b5ffab6023686c7ad2ecc2c1c",
        //     "a1f9821c983cfe80558fb0b56385c67c8df6824c17aed048c7cbd031549a2fa8",
        // ];
        // let verifier_pks: Vec<XOnlyPublicKey> = verifier_pks_hex
        //     .iter()
        //     .map(|pk| XOnlyPublicKey::from_str(pk).unwrap())
        //     .collect();

        // let tx_builder = TransactionBuilder::new(verifier_pks, config.network);

        // let evm_address: [u8; 20] = hex::decode("1234567890123456789012345678901234567890")
        //     .unwrap()
        //     .try_into()
        //     .unwrap();

        // let user_xonly_pk: XOnlyPublicKey = XOnlyPublicKey::from_str(
        //     "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
        // )
        // .unwrap();

        // let recovery_taproot_address =
        //     Address::p2tr(&secp, user_xonly_pk, None, bitcoin::Network::Regtest);

        // let deposit_address = tx_builder
        //     .generate_deposit_address(
        //         recovery_taproot_address.as_unchecked(),
        //         &crate::EVMAddress(evm_address),
        //         10_000,
        //         200,
        //     )
        //     .unwrap();
        // println!("deposit_address: {:?}", deposit_address.0);

        // assert_eq!(
        //     deposit_address.0.to_string(),
        //     "bcrt1prqxsjz7h5wt40w54vhmpvn6l2hu8mefmez6ld4p59vksllumskvqs8wvkh" // check this later
        // ) // Comparing it to the taproot address generated in bridge backend repo (using js)
    }
}
