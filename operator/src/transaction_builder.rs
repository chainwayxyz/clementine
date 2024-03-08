use std::str::FromStr;

use crate::{
    constants::{
        CONNECTOR_TREE_DEPTH, CONNECTOR_TREE_OPERATOR_TAKES_AFTER, DUST_VALUE, K_DEEP,
        MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS, MIN_RELAY_FEE, USER_TAKES_AFTER,
    },
    utils::calculate_claim_proof_root,
    ConnectorUTXOTree, EVMAddress, HashTree,
};
use bitcoin::{
    absolute,
    opcodes::all::{OP_EQUAL, OP_SHA256},
    script::Builder,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
};
use circuit_helpers::{
    constants::{BRIDGE_AMOUNT_SATS, NUM_ROUNDS},
    HashType, MerkleRoot, PreimageType,
};
use secp256k1::{Secp256k1, XOnlyPublicKey};

use crate::{errors::BridgeError, script_builder::ScriptBuilder, utils::calculate_amount};
use lazy_static::lazy_static;

// This is an unspendable pubkey
// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
lazy_static! {
    pub static ref INTERNAL_KEY: XOnlyPublicKey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    )
    .unwrap();
}

// pub type CreateTxOutputs = (bitcoin::Transaction, Vec<TxOut>, Vec<ScriptBuf>);
pub struct CreateTxOutputs {
    pub tx: bitcoin::Transaction,
    pub prevouts: Vec<TxOut>,
    pub scripts: Vec<ScriptBuf>,
    pub taproot_spend_infos: Vec<TaprootSpendInfo>,
}

pub type CreateAddressOutputs = (Address, TaprootSpendInfo);

#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    pub secp: Secp256k1<secp256k1::All>,
    pub verifiers_pks: Vec<XOnlyPublicKey>,
    pub script_builder: ScriptBuilder,
}

impl TransactionBuilder {
    pub fn new(verifiers_pks: Vec<XOnlyPublicKey>) -> Self {
        let secp = Secp256k1::new();
        let script_builder = ScriptBuilder::new(verifiers_pks.clone());
        Self {
            secp,
            verifiers_pks,
            script_builder,
        }
    }

    /// This function generates a deposit address for the user. N-of-N or User takes after timelock script can be used to spend the funds.
    pub fn generate_deposit_address(
        &self,
        user_pk: &XOnlyPublicKey,
    ) -> Result<CreateAddressOutputs, BridgeError> {
        let script_n_of_n_with_user_pk = self
            .script_builder
            .generate_script_n_of_n_with_user_pk(user_pk);
        let script_timelock = ScriptBuilder::generate_timelock_script(user_pk, USER_TAKES_AFTER);
        let taproot = TaprootBuilder::new()
            .add_leaf(1, script_n_of_n_with_user_pk.clone())?
            .add_leaf(1, script_timelock.clone())?;
        let tree_info = taproot.finalize(&self.secp, *INTERNAL_KEY)?;
        let address = Address::p2tr(
            &self.secp,
            *INTERNAL_KEY,
            tree_info.merkle_root(),
            bitcoin::Network::Regtest,
        );
        Ok((address, tree_info))
    }

    // This function generates bridge address. N-of-N script can be used to spend the funds.
    pub fn generate_bridge_address(&self) -> Result<CreateAddressOutputs, BridgeError> {
        let script_n_of_n = self.script_builder.generate_script_n_of_n();
        let taproot = TaprootBuilder::new().add_leaf(0, script_n_of_n.clone())?;
        let tree_info = taproot.finalize(&self.secp, *INTERNAL_KEY)?;
        let address = Address::p2tr(
            &self.secp,
            *INTERNAL_KEY,
            tree_info.merkle_root(),
            bitcoin::Network::Regtest,
        );
        Ok((address, tree_info))
    }

    /// This function creates the move tx, it's prevouts for signing and the script to be used for the signature.
    pub fn create_move_tx(
        &self,
        deposit_utxo: OutPoint,
        evm_address: &EVMAddress,
        return_address: &XOnlyPublicKey,
    ) -> Result<CreateTxOutputs, BridgeError> {
        let anyone_can_spend_txout = ScriptBuilder::anyone_can_spend_txout();
        let evm_address_inscription_txout = ScriptBuilder::op_return_txout(evm_address);
        println!(
            "evm_address_inscription_txout: {:?}",
            evm_address_inscription_txout
        );

        let (bridge_address, _) = self.generate_bridge_address()?;
        let (deposit_address, deposit_taproot_spend_info) =
            self.generate_deposit_address(return_address)?;

        let tx_ins = TransactionBuilder::create_tx_ins(vec![deposit_utxo]);
        let bridge_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                - Amount::from_sat(MIN_RELAY_FEE)
                - anyone_can_spend_txout.value
                - evm_address_inscription_txout.value,
            script_pubkey: bridge_address.script_pubkey(),
        };
        let move_tx = TransactionBuilder::create_btc_tx(
            tx_ins,
            vec![
                bridge_txout,
                evm_address_inscription_txout,
                anyone_can_spend_txout,
            ],
        );
        let prevouts = vec![TxOut {
            script_pubkey: deposit_address.script_pubkey(),
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS),
        }];
        let script_n_of_n_with_user_pk = vec![self
            .script_builder
            .generate_script_n_of_n_with_user_pk(return_address)];
        Ok(CreateTxOutputs {
            tx: move_tx,
            prevouts,
            scripts: script_n_of_n_with_user_pk,
            taproot_spend_infos: vec![deposit_taproot_spend_info],
        })
    }

    pub fn create_operator_claim_tx(
        &self,
        bridge_utxo: OutPoint,
        connector_utxo: OutPoint,
        operator_address: &Address,
        operator_xonly: &XOnlyPublicKey,
        hash: &HashType,
    ) -> Result<CreateTxOutputs, BridgeError> {
        let (connector_tree_leaf_address, connector_leaf_taproot_spend_info) =
            TransactionBuilder::create_connector_tree_node_address(
                &self.secp,
                operator_xonly,
                hash,
            )?;
        let (bridge_address, bridge_taproot_spend_info) = self.generate_bridge_address()?;

        let anyone_can_spend_txout: TxOut = ScriptBuilder::anyone_can_spend_txout();
        let evm_address_inscription_txout: TxOut =
            ScriptBuilder::op_return_txout(&EVMAddress::default());
        let tx_ins = TransactionBuilder::create_tx_ins(vec![bridge_utxo, connector_utxo]);
        let claim_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                - Amount::from_sat(MIN_RELAY_FEE * 2)
                - anyone_can_spend_txout.value * 2
                - evm_address_inscription_txout.value
                + Amount::from_sat(DUST_VALUE),
            script_pubkey: operator_address.script_pubkey(),
        };
        let claim_tx =
            TransactionBuilder::create_btc_tx(tx_ins, vec![claim_txout, anyone_can_spend_txout]);
        let prevouts =
            self.create_operator_claim_tx_prevouts(&bridge_address, &connector_tree_leaf_address)?;
        let scripts = vec![self.script_builder.generate_script_n_of_n()];

        Ok(CreateTxOutputs {
            tx: claim_tx,
            prevouts,
            scripts: scripts,
            taproot_spend_infos: vec![bridge_taproot_spend_info, connector_leaf_taproot_spend_info],
        })
    }

    fn create_operator_claim_tx_prevouts(
        &self,
        bridge_address: &Address,
        connector_tree_leaf_address: &Address,
    ) -> Result<Vec<TxOut>, BridgeError> {
        let anyone_can_spend_txout: TxOut = ScriptBuilder::anyone_can_spend_txout();
        Ok(vec![
            TxOut {
                value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                    - Amount::from_sat(MIN_RELAY_FEE)
                    - anyone_can_spend_txout.value,
                script_pubkey: bridge_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(DUST_VALUE),
                script_pubkey: connector_tree_leaf_address.script_pubkey(),
            },
        ])
    }

    /// TODO: Implement the igning part for the connecting to BitVM transactions
    /// This function creates the connector trees using the connector tree hashes.
    /// Starting from the first source UTXO, it creates the connector UTXO trees and
    /// returns the claim proof merkle roots, root utxos and the connector trees.
    pub fn create_all_connector_trees(
        &self,
        connector_tree_hashes: &Vec<HashTree>,
        first_source_utxo: &OutPoint,
        start_block_height: u64,
        peiod_relative_block_heights: &Vec<u32>,
    ) -> Result<(Vec<MerkleRoot>, Vec<OutPoint>, Vec<ConnectorUTXOTree>), BridgeError> {
        let single_tree_amount = calculate_amount(
            CONNECTOR_TREE_DEPTH,
            Amount::from_sat(DUST_VALUE),
            Amount::from_sat(MIN_RELAY_FEE),
        );
        let total_amount = Amount::from_sat((single_tree_amount.to_sat()) * NUM_ROUNDS as u64);

        let mut cur_connector_source_utxo = *first_source_utxo;
        let mut cur_amount = total_amount;
        println!("first_source_utxo: {:?}", first_source_utxo);

        let mut claim_proof_merkle_roots: Vec<[u8; 32]> = Vec::new();
        let mut root_utxos: Vec<OutPoint> = Vec::new();
        let mut utxo_trees: Vec<ConnectorUTXOTree> = Vec::new();

        for i in 0..NUM_ROUNDS {
            claim_proof_merkle_roots.push(calculate_claim_proof_root(
                CONNECTOR_TREE_DEPTH,
                &connector_tree_hashes[i],
            ));
            let (next_connector_source_address, _) = self.create_connector_tree_source_address(
                start_block_height
                    + (peiod_relative_block_heights[i + 1]
                        + MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS
                        + K_DEEP) as u64,
            )?;
            let (connector_bt_root_address, _) =
                TransactionBuilder::create_connector_tree_node_address(
                    &self.secp,
                    &self.verifiers_pks[self.verifiers_pks.len() - 1],
                    &connector_tree_hashes[i][0][0],
                )?;
            let curr_root_and_next_source_tx_ins =
                TransactionBuilder::create_tx_ins(vec![cur_connector_source_utxo]);

            let curr_root_and_next_source_tx_outs = TransactionBuilder::create_tx_outs(vec![
                (
                    cur_amount - single_tree_amount,
                    next_connector_source_address.script_pubkey(),
                ),
                (
                    single_tree_amount - Amount::from_sat(MIN_RELAY_FEE),
                    connector_bt_root_address.script_pubkey(),
                ),
            ]);

            let curr_root_and_next_source_tx = TransactionBuilder::create_btc_tx(
                curr_root_and_next_source_tx_ins,
                curr_root_and_next_source_tx_outs,
            );

            let txid = curr_root_and_next_source_tx.txid();

            cur_connector_source_utxo = OutPoint { txid, vout: 0 };

            let cur_connector_bt_root_utxo = OutPoint { txid, vout: 1 };

            let utxo_tree = self.create_connector_binary_tree(
                i,
                &self.verifiers_pks[self.verifiers_pks.len() - 1],
                &cur_connector_bt_root_utxo,
                CONNECTOR_TREE_DEPTH,
                connector_tree_hashes[i].clone(),
            )?;
            root_utxos.push(cur_connector_bt_root_utxo);
            utxo_trees.push(utxo_tree);
            cur_amount = cur_amount - single_tree_amount;
        }

        Ok((claim_proof_merkle_roots, root_utxos, utxo_trees))
    }

    fn create_btc_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: absolute::LockTime::from_consensus(0),
            input: tx_ins,
            output: tx_outs,
        }
    }

    fn create_tx_ins(utxos: Vec<OutPoint>) -> Vec<TxIn> {
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

    fn create_tx_ins_with_sequence(utxos: Vec<OutPoint>) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();
        for utxo in utxos {
            tx_ins.push(TxIn {
                previous_output: utxo,
                sequence: bitcoin::transaction::Sequence::from_height(
                    CONNECTOR_TREE_OPERATOR_TAKES_AFTER,
                ),
                script_sig: ScriptBuf::default(),
                witness: Witness::new(),
            });
        }
        tx_ins
    }

    fn create_tx_outs(pairs: Vec<(Amount, ScriptBuf)>) -> Vec<TxOut> {
        let mut tx_outs = Vec::new();
        for pair in pairs {
            tx_outs.push(TxOut {
                value: pair.0,
                script_pubkey: pair.1,
            });
        }
        tx_outs
    }

    fn create_taproot_address(
        secp: &Secp256k1<secp256k1::All>,
        scripts: Vec<ScriptBuf>,
    ) -> Result<(Address, TaprootSpendInfo), BridgeError> {
        let n = scripts.len();
        if n == 0 {
            return Err(BridgeError::InvalidPeriod);
        }
        let taproot_builder = if n > 1 {
            let m: u8 = ((n - 1).ilog2() + 1) as u8; // m = ceil(log(n))
            let k = 2_usize.pow(m.into()) - n;
            (0..n).fold(TaprootBuilder::new(), |acc, i| {
                acc.add_leaf(m - ((i >= n - k) as u8), scripts[i].clone())
                    .unwrap()
            })
        } else {
            TaprootBuilder::new().add_leaf(0, scripts[0].clone())?
        };
        // println!("taproot_builder: {:?}", taproot_builder);
        let internal_key = *INTERNAL_KEY;
        let tree_info = taproot_builder.finalize(secp, internal_key)?;
        Ok((
            Address::p2tr(
                secp,
                internal_key,
                tree_info.merkle_root(),
                bitcoin::Network::Regtest,
            ),
            tree_info,
        ))
    }

    pub fn create_connector_tree_source_address(
        &self,
        absolute_block_height_to_take_after: u64,
    ) -> Result<(Address, TaprootSpendInfo), BridgeError> {
        let timelock_script = ScriptBuilder::generate_absolute_timelock_script(
            &self.verifiers_pks[self.verifiers_pks.len() - 1],
            absolute_block_height_to_take_after as u32,
        );

        let script_n_of_n = self.script_builder.generate_script_n_of_n();
        let scripts = vec![timelock_script, script_n_of_n];

        let (address, tree_info) =
            TransactionBuilder::create_taproot_address(&self.secp, scripts).unwrap();
        Ok((address, tree_info))
    }

    pub fn create_connector_tree_node_address(
        secp: &Secp256k1<secp256k1::All>,
        actor_pk: &XOnlyPublicKey,
        hash: &HashType,
    ) -> Result<CreateAddressOutputs, BridgeError> {
        let timelock_script = ScriptBuilder::generate_timelock_script(
            actor_pk,
            CONNECTOR_TREE_OPERATOR_TAKES_AFTER as u32,
        );
        let preimage_script = Builder::new()
            .push_opcode(OP_SHA256)
            .push_slice(hash)
            .push_opcode(OP_EQUAL)
            .into_script();
        let (address, tree_info) = TransactionBuilder::create_taproot_address(
            secp,
            vec![timelock_script.clone(), preimage_script],
        )?;
        Ok((address, tree_info))
    }

    pub fn create_inscription_commit_address(
        &self,
        actor_pk: &XOnlyPublicKey,
        preimages_to_be_revealed: &Vec<PreimageType>,
    ) -> Result<(Address, TaprootSpendInfo, ScriptBuf), BridgeError> {
        let inscribe_preimage_script =
            ScriptBuilder::create_inscription_script_32_bytes(actor_pk, preimages_to_be_revealed);
        let (address, taproot_info) = TransactionBuilder::create_taproot_address(
            &self.secp,
            vec![inscribe_preimage_script.clone()],
        )?;
        Ok((address, taproot_info, inscribe_preimage_script))
    }

    pub fn create_inscription_reveal_tx(
        &self,
        commit_utxo: OutPoint,
        sender_xonly: &XOnlyPublicKey,
        preimages_to_be_revealed: &Vec<PreimageType>,
    ) -> Result<CreateTxOutputs, BridgeError> {
        let (commit_address, commit_tree_info, inscribe_preimage_script) =
            self.create_inscription_commit_address(sender_xonly, preimages_to_be_revealed)?;
        let tx = TransactionBuilder::create_btc_tx(
            TransactionBuilder::create_tx_ins(vec![commit_utxo]),
            vec![ScriptBuilder::anyone_can_spend_txout()],
        );

        let prevouts = vec![TxOut {
            script_pubkey: commit_address.script_pubkey(),
            value: Amount::from_sat(DUST_VALUE * 2),
        }];

        Ok(CreateTxOutputs {
            tx,
            prevouts,
            scripts: vec![inscribe_preimage_script],
            taproot_spend_infos: vec![commit_tree_info],
        })
    }

    pub fn create_connector_tree_tx(
        utxo: &OutPoint,
        depth: usize,
        first_address: Address,
        second_address: Address,
    ) -> bitcoin::Transaction {
        // UTXO value should be at least 2^depth * dust_value + (2^depth-1) * fee
        let tx_ins = TransactionBuilder::create_tx_ins_with_sequence(vec![*utxo]);
        let tx_outs = TransactionBuilder::create_tx_outs(vec![
            (
                calculate_amount(
                    depth,
                    Amount::from_sat(DUST_VALUE),
                    Amount::from_sat(MIN_RELAY_FEE),
                ),
                first_address.script_pubkey(),
            ),
            (
                calculate_amount(
                    depth,
                    Amount::from_sat(DUST_VALUE),
                    Amount::from_sat(MIN_RELAY_FEE),
                ),
                second_address.script_pubkey(),
            ),
        ]);
        TransactionBuilder::create_btc_tx(tx_ins, tx_outs)
    }

    // This function creates the connector binary tree for operator to be able to claim the funds that they paid out of their pocket.
    // Depth will be determined later.
    pub fn create_connector_binary_tree(
        &self,
        _period: usize,
        xonly_public_key: &XOnlyPublicKey,
        root_utxo: &OutPoint,
        depth: usize,
        connector_tree_hashes: Vec<Vec<[u8; 32]>>,
    ) -> Result<ConnectorUTXOTree, BridgeError> {
        // UTXO value should be at least 2^depth * dust_value + (2^depth-1) * fee
        let total_amount = calculate_amount(
            depth,
            Amount::from_sat(DUST_VALUE),
            Amount::from_sat(MIN_RELAY_FEE),
        );
        println!("total_amount: {:?}", total_amount);

        let (_root_address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.secp,
            xonly_public_key,
            &connector_tree_hashes[0][0],
        )?;

        let mut utxo_binary_tree: ConnectorUTXOTree = Vec::new();
        utxo_binary_tree.push(vec![*root_utxo]);

        for i in 0..depth {
            let mut utxo_tree_current_level: Vec<OutPoint> = Vec::new();
            let utxo_tree_previous_level = utxo_binary_tree.last().unwrap();

            for (j, utxo) in utxo_tree_previous_level.iter().enumerate() {
                let (first_address, _) = TransactionBuilder::create_connector_tree_node_address(
                    &self.secp,
                    xonly_public_key,
                    &connector_tree_hashes[i + 1][2 * j],
                )?;
                let (second_address, _) = TransactionBuilder::create_connector_tree_node_address(
                    &self.secp,
                    xonly_public_key,
                    &connector_tree_hashes[i + 1][2 * j + 1],
                )?;

                let tx = TransactionBuilder::create_connector_tree_tx(
                    utxo,
                    depth - i - 1,
                    first_address.clone(),
                    second_address.clone(),
                );
                let txid = tx.txid();
                utxo_tree_current_level.push(OutPoint { txid, vout: 0 });
                utxo_tree_current_level.push(OutPoint { txid, vout: 1 });
            }
            utxo_binary_tree.push(utxo_tree_current_level);
        }
        Ok(utxo_binary_tree)
    }
}
