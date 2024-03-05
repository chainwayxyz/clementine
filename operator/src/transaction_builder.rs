use std::{borrow::BorrowMut, str::FromStr};

use crate::{
    config::{BRIDGE_AMOUNT_SATS, CONNECTOR_TREE_OPERATOR_TAKES_AFTER, USER_TAKES_AFTER},
    constant::{ConnectorTreeUTXOs, Data, PreimageType, DUST_VALUE, MIN_RELAY_FEE},
};
use bitcoin::{
    absolute,
    opcodes::all::{OP_EQUAL, OP_SHA256},
    script::Builder,
    sighash::SighashCache,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Txid, Witness,
};
use circuit_helpers::constant::EVMAddress;
use secp256k1::{Secp256k1, XOnlyPublicKey};

use crate::{
    actor::Actor,
    errors::BridgeError,
    script_builder::ScriptBuilder,
    utils::{calculate_amount, handle_taproot_witness},
};
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
        deposit_address: &Address,
        return_address: &XOnlyPublicKey,
    ) -> Result<CreateTxOutputs, BridgeError> {
        let anyone_can_spend_txout = ScriptBuilder::anyone_can_spend_txout();
        let evm_address_inscription_txout = ScriptBuilder::op_return_txout(evm_address);
        println!(
            "evm_address_inscription_txout: {:?}",
            evm_address_inscription_txout
        );

        let (bridge_address, _) = self.generate_bridge_address()?;

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
        })
    }

    pub fn create_operator_claim_tx(
        bridge_utxo: OutPoint,
        connector_utxo: OutPoint,
        operator_address: &Address,
    ) -> bitcoin::Transaction {
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
        TransactionBuilder::create_btc_tx(tx_ins, vec![claim_txout, anyone_can_spend_txout])
    }

    pub fn create_operator_claim_tx_prevouts(
        &self,
        connector_tree_leaf_address: &Address,
    ) -> Result<Vec<TxOut>, BridgeError> {
        let (bridge_address, _) = self.generate_bridge_address()?;
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

    pub fn create_tx_ins_with_sequence(utxos: Vec<OutPoint>) -> Vec<TxIn> {
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

    pub fn create_move_tx_old(
        ins: Vec<OutPoint>,
        outs: Vec<(Amount, ScriptBuf)>,
    ) -> bitcoin::Transaction {
        let tx_ins = TransactionBuilder::create_tx_ins(ins);
        let tx_outs = TransactionBuilder::create_tx_outs(outs);
        TransactionBuilder::create_btc_tx(tx_ins, tx_outs)
    }

    pub fn create_taproot_address(
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

    pub fn create_utxo(txid: Txid, vout: u32) -> OutPoint {
        OutPoint { txid, vout }
    }

    pub fn create_connector_tree_root_address(
        &self,
        absolute_block_height_to_take_after: u64,
    ) -> Result<(Address, TaprootSpendInfo), BridgeError> {
        let timelock_script = ScriptBuilder::generate_absolute_timelock_script(
            &self.verifiers_pks[self.verifiers_pks.len() - 1],
            absolute_block_height_to_take_after as u32,
        );

        // let mut all_2_of_2_scripts: Vec<ScriptBuf> = self
        //     .verifiers_pks
        //     .iter()
        //     .map(|pk| ScriptBuilder::generate_2_of_2_script(&all_verifiers[all_verifiers.len() - 1], &pk))
        //     .collect();

        // push the timelock script to the beginning of the vector
        // all_2_of_2_scripts.insert(0, timelock_script.clone());

        let script_n_of_n = self.script_builder.generate_script_n_of_n();
        let scripts = vec![timelock_script, script_n_of_n];

        let (address, tree_info) =
            TransactionBuilder::create_taproot_address(&self.secp, scripts).unwrap();
        Ok((address, tree_info))
    }

    pub fn create_connector_tree_node_address(
        secp: &Secp256k1<secp256k1::All>,
        actor_pk: &XOnlyPublicKey,
        hash: Data,
    ) -> Result<(Address, TaprootSpendInfo), BridgeError> {
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
        _commit_tree_info: &TaprootSpendInfo,
        _preimages_to_be_revealed: &Vec<PreimageType>,
    ) -> bitcoin::Transaction {
        TransactionBuilder::create_btc_tx(
            TransactionBuilder::create_tx_ins(vec![commit_utxo]),
            vec![ScriptBuilder::anyone_can_spend_txout()],
        )
    }

    pub fn create_inscription_transactions(
        actor: &Actor,
        utxo: OutPoint,
        preimages: Vec<[u8; 32]>,
    ) -> Result<(bitcoin::Transaction, bitcoin::Transaction), BridgeError> {
        let inscribe_preimage_script =
            ScriptBuilder::create_inscription_script_32_bytes(&actor.xonly_public_key, &preimages);

        let (incription_address, inscription_tree_info) =
            TransactionBuilder::create_taproot_address(
                &actor.secp,
                vec![inscribe_preimage_script.clone()],
            )?;
        // println!("inscription tree merkle root: {:?}", inscription_tree_info.merkle_root());
        let commit_tx_ins = TransactionBuilder::create_tx_ins(vec![utxo]);
        let commit_tx_outs = TransactionBuilder::create_tx_outs(vec![(
            Amount::from_sat(DUST_VALUE) * 2,
            incription_address.script_pubkey(),
        )]);
        let mut commit_tx = TransactionBuilder::create_btc_tx(commit_tx_ins, commit_tx_outs);
        let commit_tx_prevouts = vec![TxOut {
            value: Amount::from_sat(DUST_VALUE) * 3,
            script_pubkey: actor.address.script_pubkey(),
        }];

        println!(
            "inscription merkle root: {:?}",
            inscription_tree_info.merkle_root()
        );
        println!(
            "inscription output key: {:?}",
            inscription_tree_info.output_key()
        );

        let commit_tx_sig =
            actor.sign_taproot_pubkey_spend_tx(&mut commit_tx, &commit_tx_prevouts, 0)?;
        let mut commit_tx_sighash_cache = SighashCache::new(commit_tx.borrow_mut());
        let witness = commit_tx_sighash_cache
            .witness_mut(0)
            .ok_or(BridgeError::TxInputNotFound)?;
        witness.push(commit_tx_sig.as_ref());

        let reveal_tx_ins =
            TransactionBuilder::create_tx_ins(vec![TransactionBuilder::create_utxo(
                commit_tx.txid(),
                0,
            )]);
        let reveal_tx_outs = TransactionBuilder::create_tx_outs(vec![(
            Amount::from_sat(DUST_VALUE),
            actor.address.script_pubkey(),
        )]);
        let mut reveal_tx = TransactionBuilder::create_btc_tx(reveal_tx_ins, reveal_tx_outs);

        let reveal_tx_prevouts = vec![TxOut {
            value: Amount::from_sat(DUST_VALUE) * 2,
            script_pubkey: incription_address.script_pubkey(),
        }];
        let reveal_tx_sig = actor.sign_taproot_script_spend_tx(
            &mut reveal_tx,
            &reveal_tx_prevouts,
            &inscribe_preimage_script,
            0,
        )?;
        let mut reveal_tx_witness_elements: Vec<&[u8]> = Vec::new();
        reveal_tx_witness_elements.push(reveal_tx_sig.as_ref());
        handle_taproot_witness(
            &mut reveal_tx,
            0,
            &reveal_tx_witness_elements,
            &inscribe_preimage_script,
            &inscription_tree_info,
        )?;

        Ok((commit_tx, reveal_tx))
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
    ) -> Result<ConnectorTreeUTXOs, BridgeError> {
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
            connector_tree_hashes[0][0],
        )?;

        let mut utxo_binary_tree: ConnectorTreeUTXOs = Vec::new();
        utxo_binary_tree.push(vec![*root_utxo]);

        for i in 0..depth {
            let mut utxo_tree_current_level: Vec<OutPoint> = Vec::new();
            let utxo_tree_previous_level = utxo_binary_tree.last().unwrap();

            for (j, utxo) in utxo_tree_previous_level.iter().enumerate() {
                let (first_address, _) = TransactionBuilder::create_connector_tree_node_address(
                    &self.secp,
                    xonly_public_key,
                    connector_tree_hashes[i + 1][2 * j],
                )?;
                let (second_address, _) = TransactionBuilder::create_connector_tree_node_address(
                    &self.secp,
                    xonly_public_key,
                    connector_tree_hashes[i + 1][2 * j + 1],
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
