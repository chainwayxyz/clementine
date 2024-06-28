//! # Transaction Builder

use crate::{errors::BridgeError, script_builder::ScriptBuilder};
use crate::{utils, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::Network;
use bitcoin::{
    absolute,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use secp256k1::XOnlyPublicKey;
use std::str::FromStr;

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
    pub script_builder: ScriptBuilder,
    verifiers_pks: Vec<XOnlyPublicKey>,
    network: Network,
}

pub const MOVE_TX_MIN_RELAY_FEE: u64 = 305;
pub const WITHDRAWAL_TX_MIN_RELAY_FEE: u64 = 305;

impl TransactionBuilder {
    /// Creates a new `TransactionBuilder`.
    pub fn new(verifiers_pks: Vec<XOnlyPublicKey>, network: Network) -> Self {
        let script_builder = ScriptBuilder::new(verifiers_pks.clone());

        Self {
            verifiers_pks,
            script_builder,
            network,
        }
    }

    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    fn get_internal_key() -> Result<XOnlyPublicKey, BridgeError> {
        match XOnlyPublicKey::from_str(
            "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
        ) {
            Ok(pk) => Ok(pk),
            Err(_) => Err(BridgeError::TaprootScriptError),
        }
    }

    /// Generates a deposit address for the user. N-of-N or user takes after
    /// timelock script can be used to spend the funds.
    pub fn generate_deposit_address(
        &self,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        user_evm_address: &EVMAddress,
        amount: u64,
    ) -> Result<CreateAddressOutputs, BridgeError> {
        let deposit_script = self
            .script_builder
            .create_deposit_script(user_evm_address, amount);

        let script_timelock = ScriptBuilder::generate_timelock_script(
            recovery_taproot_address,
            200, // TODO: Take from parameter
        );

        let taproot = TaprootBuilder::new()
            .add_leaf(1, deposit_script.clone())?
            .add_leaf(1, script_timelock.clone())?;
        let tree_info = taproot.finalize(&utils::SECP, TransactionBuilder::get_internal_key()?)?;

        let address = Address::p2tr(
            &utils::SECP,
            TransactionBuilder::get_internal_key()?,
            tree_info.merkle_root(),
            self.network,
        );

        Ok((address, tree_info))
    }

    /// Generates bridge address. N-of-N script can be used to spend the funds.
    pub fn generate_bridge_address(&self) -> Result<CreateAddressOutputs, BridgeError> {
        let script_n_of_n = self.script_builder.generate_script_n_of_n();

        let taproot = TaprootBuilder::new().add_leaf(0, script_n_of_n.clone())?;
        let tree_info = taproot.finalize(&utils::SECP, TransactionBuilder::get_internal_key()?)?;

        let address = Address::p2tr(
            &utils::SECP,
            TransactionBuilder::get_internal_key()?,
            tree_info.merkle_root(),
            self.network,
        );

        Ok((address, tree_info))
    }

    /// Creates the move tx, it's prevouts for signing and the script to be used
    /// for the signature.
    pub fn create_move_tx(
        &self,
        deposit_utxo: OutPoint,
        evm_address: &EVMAddress,
        recovery_taproot_address: &Address<NetworkUnchecked>,
    ) -> Result<CreateTxOutputs, BridgeError> {
        let anyone_can_spend_txout = ScriptBuilder::anyone_can_spend_txout();

        let (bridge_address, _) = self.generate_bridge_address()?;
        let (deposit_address, deposit_taproot_spend_info) = self.generate_deposit_address(
            recovery_taproot_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
        )?;

        let tx_ins = TransactionBuilder::create_tx_ins(vec![deposit_utxo]);
        let bridge_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
                - anyone_can_spend_txout.value,
            script_pubkey: bridge_address.script_pubkey(),
        };
        let move_tx =
            TransactionBuilder::create_btc_tx(tx_ins, vec![bridge_txout, anyone_can_spend_txout]);

        let prevouts = vec![TxOut {
            script_pubkey: deposit_address.script_pubkey(),
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS),
        }];

        let deposit_script = vec![self
            .script_builder
            .create_deposit_script(evm_address, BRIDGE_AMOUNT_SATS)];

        Ok(CreateTxOutputs {
            tx: move_tx,
            prevouts,
            scripts: vec![deposit_script],
            taproot_spend_infos: vec![deposit_taproot_spend_info],
        })
    }

    pub fn create_withdraw_tx(
        &self,
        deposit_utxo: OutPoint,
        deposit_txout: TxOut,
        withdraw_address: &Address,
    ) -> Result<CreateTxOutputs, BridgeError> {
        let anyone_can_spend_txout = ScriptBuilder::anyone_can_spend_txout();

        let (_, bridge_spend_info) = self.generate_bridge_address()?;

        let tx_ins = TransactionBuilder::create_tx_ins(vec![deposit_utxo]);
        let bridge_txout = TxOut {
            value: deposit_txout.value
                - Amount::from_sat(WITHDRAWAL_TX_MIN_RELAY_FEE)
                - anyone_can_spend_txout.value,
            script_pubkey: withdraw_address.script_pubkey(),
        };

        let withdraw_tx =
            TransactionBuilder::create_btc_tx(tx_ins, vec![bridge_txout, anyone_can_spend_txout]);

        let prevouts = vec![deposit_txout];

        let bridge_spend_script = vec![self.script_builder.generate_script_n_of_n()];

        Ok(CreateTxOutputs {
            tx: withdraw_tx,
            prevouts,
            scripts: vec![bridge_spend_script],
            taproot_spend_infos: vec![bridge_spend_info],
        })
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

    pub fn create_taproot_address(
        scripts: Vec<ScriptBuf>,
        network: bitcoin::Network,
    ) -> Result<(Address, TaprootSpendInfo), BridgeError> {
        let n = scripts.len();
        if n == 0 {
            return Err(BridgeError::TaprootScriptError);
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

        let internal_key = TransactionBuilder::get_internal_key()?;
        let tree_info = taproot_builder.finalize(&utils::SECP, internal_key)?;

        Ok((
            Address::p2tr(&utils::SECP, internal_key, tree_info.merkle_root(), network),
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
            TransactionBuilder::create_taproot_address(scripts, self.network).unwrap();

        Ok((address, tree_info))
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::BridgeConfig, transaction_builder::TransactionBuilder};
    use bitcoin::{Address, XOnlyPublicKey};
    use std::str::FromStr;

    #[test]
    fn deposit_address() {
        let config = BridgeConfig::new();

        let secp = secp256k1::Secp256k1::new();

        let verifier_pks_hex: Vec<&str> = vec![
            "9bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964",
            "e37d58a1aae4ba059fd2503712d998470d3a2522f7e2335f544ef384d2199e02",
            "688466442a134ee312299bafb37058e385c98dd6005eaaf0f538f533efe5f91f",
            "337cca2171fdbfcfd657fa59881f46269f1e590b5ffab6023686c7ad2ecc2c1c",
            "a1f9821c983cfe80558fb0b56385c67c8df6824c17aed048c7cbd031549a2fa8",
        ];
        let verifier_pks: Vec<XOnlyPublicKey> = verifier_pks_hex
            .iter()
            .map(|pk| XOnlyPublicKey::from_str(pk).unwrap())
            .collect();

        let tx_builder = TransactionBuilder::new(verifier_pks, config.network);

        let evm_address: [u8; 20] = hex::decode("1234567890123456789012345678901234567890")
            .unwrap()
            .try_into()
            .unwrap();

        let user_xonly_pk: XOnlyPublicKey = XOnlyPublicKey::from_str(
            "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
        )
        .unwrap();

        let recovery_taproot_address =
            Address::p2tr(&secp, user_xonly_pk, None, bitcoin::Network::Regtest);

        let deposit_address = tx_builder
            .generate_deposit_address(
                recovery_taproot_address.as_unchecked(),
                &crate::EVMAddress(evm_address),
                10_000,
            )
            .unwrap();
        println!("deposit_address: {:?}", deposit_address.0);

        assert_eq!(
            deposit_address.0.to_string(),
            "bcrt1prqxsjz7h5wt40w54vhmpvn6l2hu8mefmez6ld4p59vksllumskvqs8wvkh" // check this later
        ) // Comparing it to the taproot address generated in bridge backend repo (using js)
    }
}

#[cfg(feature = "poc")]
impl TransactionBuilder {
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
                self.config.network,
            )?;
        let (bridge_address, bridge_taproot_spend_info) = self.generate_bridge_address()?;

        let anyone_can_spend_txout: TxOut = ScriptBuilder::anyone_can_spend_txout();
        let evm_address_inscription_txout: TxOut =
            ScriptBuilder::op_return_txout(&EVMAddress::default());
        let tx_ins = TransactionBuilder::create_tx_ins(vec![bridge_utxo, connector_utxo]);
        let claim_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS)
                - Amount::from_sat(self.config.min_relay_fee * 2)
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
                    - Amount::from_sat(self.config.min_relay_fee)
                    - anyone_can_spend_txout.value,
                script_pubkey: bridge_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(DUST_VALUE),
                script_pubkey: connector_tree_leaf_address.script_pubkey(),
            },
        ])
    }

    /// TODO: Implement the signing part for the connecting to BitVM transactions
    /// This function creates the connector trees using the connector tree hashes.
    /// Starting from the first source UTXO, it creates the connector UTXO trees and
    /// returns the claim proof merkle roots, root utxos and the connector trees.
    pub fn create_all_connector_trees(
        &self,
        connector_tree_hashes: &Vec<HashTree>,
        first_source_utxo: &OutPoint,
        start_block_height: u64,
        peiod_relative_block_heights: &Vec<u32>,
    ) -> Result<
        (
            Vec<MerkleRoot>,
            Vec<OutPoint>,
            Vec<ConnectorUTXOTree>,
            Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
        ),
        BridgeError,
    > {
        let single_tree_amount = calculate_amount(
            CONNECTOR_TREE_DEPTH,
            Amount::from_sat(DUST_VALUE),
            Amount::from_sat(self.config.min_relay_fee),
        );
        let total_amount = Amount::from_sat((single_tree_amount.to_sat()) * NUM_ROUNDS as u64);

        let mut cur_connector_source_utxo = *first_source_utxo;
        let mut cur_amount = total_amount;
        // tracing::debug!("first_source_utxo: {:?}", first_source_utxo);

        let mut claim_proof_merkle_roots: Vec<[u8; 32]> = Vec::new();
        let mut claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>> = Vec::new();
        let mut root_utxos: Vec<OutPoint> = Vec::new();
        let mut utxo_trees: Vec<ConnectorUTXOTree> = Vec::new();

        for i in 0..NUM_ROUNDS {
            let mut claim_proof_merkle_tree_i: MerkleTree<CLAIM_MERKLE_TREE_DEPTH> =
                MerkleTree::new();
            for j in 0..(2_usize.pow(CONNECTOR_TREE_DEPTH as u32)) {
                let hash = get_claim_proof_tree_leaf(
                    CLAIM_MERKLE_TREE_DEPTH,
                    j,
                    &connector_tree_hashes[i],
                );
                // tracing::debug!("hash: {:?}", hash);
                claim_proof_merkle_tree_i.add(hash);
            }
            claim_proof_merkle_roots.push(claim_proof_merkle_tree_i.root());
            claim_proof_merkle_trees.push(claim_proof_merkle_tree_i);

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
                    self.config.network,
                )?;
            let curr_root_and_next_source_tx_ins =
                TransactionBuilder::create_tx_ins(vec![cur_connector_source_utxo]);

            let curr_root_and_next_source_tx_outs = TransactionBuilder::create_tx_outs(vec![
                (
                    cur_amount - single_tree_amount,
                    next_connector_source_address.script_pubkey(),
                ),
                (
                    single_tree_amount - Amount::from_sat(self.config.min_relay_fee),
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

        Ok((
            claim_proof_merkle_roots,
            root_utxos,
            utxo_trees,
            claim_proof_merkle_trees,
        ))
    }

    pub fn create_connector_tree_node_address(
        secp: &Secp256k1<secp256k1::All>,
        actor_pk: &XOnlyPublicKey,
        hash: &HashType,
        network: bitcoin::Network,
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
            network,
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
            self.config.network,
        )?;
        let mut hasher = Sha256::new();
        for elem in preimages_to_be_revealed {
            hasher.update(sha256_hash!(elem));
        }
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
        let tx_ins = TransactionBuilder::create_tx_ins_with_sequence(vec![*utxo]);
        let tx_outs = TransactionBuilder::create_tx_outs(vec![
            (
                calculate_amount(
                    depth,
                    Amount::from_sat(DUST_VALUE),
                    Amount::from_sat(self.config.min_relay_fee),
                ),
                first_address.script_pubkey(),
            ),
            (
                calculate_amount(
                    depth,
                    Amount::from_sat(DUST_VALUE),
                    Amount::from_sat(self.config.min_relay_fee),
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
        // Root UTXO value should be at least 2^depth * (dust_value + fee) - fee
        let _total_amount = calculate_amount(
            depth,
            Amount::from_sat(DUST_VALUE),
            Amount::from_sat(self.config.min_relay_fee),
        );

        let (_root_address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.secp,
            xonly_public_key,
            &connector_tree_hashes[0][0],
            self.config.network,
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
                    self.config.network,
                )?;
                let (second_address, _) = TransactionBuilder::create_connector_tree_node_address(
                    &self.secp,
                    xonly_public_key,
                    &connector_tree_hashes[i + 1][2 * j + 1],
                    self.config.network,
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
