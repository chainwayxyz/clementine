    // let circuit = Circuit::from_bristol("bristol/add.txt", None);

    // let paul = Actor::new();
    // let mut vicky = Actor::new();
    // let secp = Secp256k1::new();
    // let amt = 10_000;

    // let initial_fund = rpc
    //     .send_to_address(
    //         &paul.address,
    //         Amount::from_sat(amt),
    //         None,
    //         None,
    //         None,
    //         None,
    //         None,
    //         None,
    //     )
    //     .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));
    // let initial_tx = rpc
    //     .get_transaction(&initial_fund, None)
    //     .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));

    // println!("initial tx = {:?}", initial_tx);

    // // println!("Send {} satoshis to Public Key: {}", amt, paul.address);
    // // let txid: Txid = take_stdin("Enter txid: ")
    // //     .parse()
    // //     .expect("invalid txid format");
    // // let vout: u32 = take_stdin("Enter vout: ")
    // //     .trim()
    // //     .parse()
    // //     .expect("invalid vout format");

    // let challenge_hashes = vicky.generate_challenge_hashes(circuit.num_gates());

    // let (address, kickoff_taproot_info) = generate_challenge_address_and_info(
    //     &secp,
    //     &circuit,
    //     paul.public_key,
    //     vicky.public_key,
    //     &challenge_hashes,
    // );

    // let mut tx = Transaction {
    //     version: bitcoin::transaction::Version::TWO,
    //     lock_time: LockTime::from(Height::MIN),
    //     input: vec![TxIn {
    //         previous_output: OutPoint {
    //             txid: initial_fund,
    //             vout: initial_tx.details[0].vout,
    //         },
    //         script_sig: ScriptBuf::new(),
    //         sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
    //         witness: Witness::new(),
    //     }],
    //     output: vec![TxOut {
    //         script_pubkey: address.script_pubkey(),
    //         value: Amount::from_sat(amt - 500),
    //     }],
    // };

    // let prevouts = vec![TxOut {
    //     script_pubkey: paul.address.script_pubkey(),
    //     value: Amount::from_sat(amt),
    // }];

    // println!("prevout: {:?}", prevouts);
    // let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    // // TODO: add support for signing with a keypair
    // let sig_hash = sighash_cache
    //     .taproot_key_spend_signature_hash(
    //         0,
    //         &bitcoin::sighash::Prevouts::All(&prevouts),
    //         bitcoin::sighash::TapSighashType::Default,
    //     )
    //     .unwrap();

    // // Witness::from_slice(sigHash)
    // let sig = paul.sign_with_tweak(sig_hash, None);
    // let witness = sighash_cache.witness_mut(0).unwrap();
    // witness.push(sig.as_ref());

    // println!("txid : {:?}", serialize_hex(&tx));

    // let kickoff_tx = rpc
    //     .send_raw_transaction(&tx)
    //     .unwrap_or_else(|e| panic!("Failed to send raw transaction: {}", e));
    // println!("initial kickoff tx = {:?}", kickoff_tx);

    // // let mut txid_str: [u8];
    // // tx.consensus_encode().unwrap();

    // let wire_rcref = &circuit.wires[0];
    // let wire = wire_rcref.lock().unwrap();

    // let vout: u32 = 0;

    // let script = generate_anti_contradiction_script(wire.get_hash_pair(), vicky.public_key);

    // let mut tx = Transaction {
    //     version: bitcoin::transaction::Version::TWO,
    //     lock_time: LockTime::from(Height::MIN),
    //     input: vec![TxIn {
    //         previous_output: OutPoint {
    //             txid: kickoff_tx,
    //             vout,
    //         },
    //         script_sig: ScriptBuf::new(),
    //         sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
    //         witness: Witness::new(),
    //     }],
    //     output: vec![TxOut {
    //         script_pubkey: vicky.address.script_pubkey(),
    //         value: Amount::from_sat(9000),
    //     }],
    // };

    // let mut sighash_cache = SighashCache::new(tx.borrow_mut());

    // let prevouts = vec![TxOut {
    //     script_pubkey: address.script_pubkey(),
    //     value: Amount::from_sat(amt - 500),
    // }];

    // let sig_hash = sighash_cache
    //     .taproot_script_spend_signature_hash(
    //         vout as usize,
    //         &bitcoin::sighash::Prevouts::All(&prevouts),
    //         TapLeafHash::from_script(&script, LeafVersion::TapScript),
    //         bitcoin::sighash::TapSighashType::Default,
    //     )
    //     .unwrap();
    // let sig = vicky.sign(sig_hash);

    // let control_block = kickoff_taproot_info
    //     .control_block(&(script.clone(), LeafVersion::TapScript))
    //     .expect("Cannot create control block");

    // let witness = sighash_cache.witness_mut(0).unwrap();
    // witness.push(sig.as_ref());
    // witness.push(wire.preimages.unwrap().one);
    // witness.push(wire.preimages.unwrap().zero);
    // witness.push(script);
    // witness.push(&control_block.serialize());

    // println!("equivocation");
    // println!("txid : {:?}", tx.txid());
    // println!("txid : {:?}", serialize_hex(&tx));
    // let eqv_tx = rpc
    //     .send_raw_transaction(&tx)
    //     .unwrap_or_else(|e| panic!("Failed to send raw transaction: {}", e));
    // println!("eqv tx = {:?}", eqv_tx);

use std::borrow::BorrowMut;
use std::str::FromStr;

use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TapLeafHash;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::absolute::Height;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use bitcoin::script::Builder;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::XOnlyPublicKey;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::opcodes::all::*;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;

use crate::actor::Actor;

pub fn generate_n_of_n_script(
    verifiers_pks: Vec<XOnlyPublicKey>,
    hash: [u8; 32],
) -> ScriptBuf {
    let mut builder = Builder::new();
    for vpk in verifiers_pks {
        builder = builder.push_x_only_key(&vpk).push_opcode(OP_CHECKSIGVERIFY);
    }
    // builder = builder.push_x_only_key(&verifiers_pks[0]).push_opcode(OP_CHECKSIGVERIFY);
    builder = builder.push_opcode(OP_SHA256).push_slice(hash).push_opcode(OP_EQUAL);

    builder.into_script()
}

pub fn generate_timelock_script(actor_pk: XOnlyPublicKey, block_count: u32) -> ScriptBuf {
    Builder::new()
        .push_int(block_count as i64)
        .push_opcode(OP_CSV)
        .push_x_only_key(&actor_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn generate_dust_script(eth_address: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&eth_address)
        .into_script()
}

pub fn generate_deposit_address(
    secp: &Secp256k1<All>,
    verifiers_pks: Vec<XOnlyPublicKey>,
    user_pk: XOnlyPublicKey,
    hash: [u8; 32],
) -> (Address, TaprootSpendInfo) {
    let script_n_of_n = generate_n_of_n_script(verifiers_pks, hash);
    let script_timelock = generate_timelock_script(user_pk, 150);
    let taproot = TaprootBuilder::new().add_leaf(1, script_n_of_n.clone()).unwrap().add_leaf(1, script_timelock.clone()).unwrap();
    let internal_key = XOnlyPublicKey::from_str(
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
    )
    .unwrap();
    let tree_info = taproot.finalize(secp, internal_key).unwrap();
    let address = Address::p2tr(
        secp,
        internal_key,
        tree_info.merkle_root(),
        bitcoin::Network::Regtest,
    );
    (address, tree_info)
}

pub fn generate_dust_address(
    secp: &Secp256k1<All>,
    eth_address: [u8; 32],
) -> (Address, TaprootSpendInfo) {
    let script = generate_dust_script(eth_address);
    let taproot = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
    let internal_key = XOnlyPublicKey::from_str(
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
    )
    .unwrap();
    let tree_info = taproot.finalize(secp, internal_key).unwrap();
    let address = Address::p2tr(
        secp,
        internal_key,
        tree_info.merkle_root(),
        bitcoin::Network::Regtest,
    );
    (address, tree_info)
}

pub fn deposit_tx(rpc: &Client, depositor: Actor, eth_address: [u8; 32], other: &Actor, amount: u64, secp: &Secp256k1<All>, verifiers: &Vec<Actor>) -> bitcoin::Txid {

    let initial_fund = rpc
        .send_to_address(
            &depositor.address,
            Amount::from_sat(amount),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));
    let initial_tx = rpc
        .get_transaction(&initial_fund, None)
        .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));

    println!("initial tx = {:?}", initial_tx);

    let mut verifiers_pks = Vec::new();
    for v in verifiers.iter() {
        verifiers_pks.push(v.xonly_public_key);
    }

    let preimage = [0x7_u8; 32];
    let hash = sha256::Hash::hash(&preimage).to_byte_array();

    let (address, info) = generate_deposit_address(&secp, verifiers_pks.clone(), depositor.xonly_public_key, hash);

    let (dust_address, _dust_info) = generate_dust_address(&secp, eth_address);

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from(Height::MIN),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: initial_fund,
                vout: initial_tx.details[0].vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                script_pubkey: address.script_pubkey(),
                value: Amount::from_sat(amount - 1000),
            },
            TxOut {
                script_pubkey: dust_address.script_pubkey(),
                value: Amount::from_sat(500),
            }
        ],
    };

    let prevouts = vec![TxOut {
        script_pubkey: depositor.address.script_pubkey(),
        value: Amount::from_sat(amount),
    }];

    let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    let sig_hash = sighash_cache
        .taproot_key_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )
        .unwrap();

    // Witness::from_slice(sigHash)
    let sig = depositor.sign_with_tweak(sig_hash, None);
    let witness = sighash_cache.witness_mut(0).unwrap();
    witness.push(sig.as_ref());

    let kickoff_tx = rpc
        .send_raw_transaction(&tx)
        .unwrap_or_else(|e| panic!("Failed to send raw transaction: {}", e));
    println!("initial kickoff tx = {:?}", kickoff_tx);

    let new_address = rpc.get_new_address(None, None).unwrap().assume_checked();
    rpc.generate_to_address(160, &new_address).unwrap();

    let vout = 0;

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from(Height::MIN),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: kickoff_tx,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            script_pubkey: other.address.script_pubkey(),
            value: Amount::from_sat(amount - 1500),
        }],
    };
    
    let mut sighash_cache = SighashCache::new(tx.borrow_mut());

    let prevouts = vec![TxOut {
        script_pubkey: address.script_pubkey(),
        value: Amount::from_sat(amount - 1000),
    }];

    let script = generate_n_of_n_script(verifiers_pks, hash);

    let sig_hash = sighash_cache
        .taproot_script_spend_signature_hash(
            vout as usize,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            bitcoin::sighash::TapSighashType::Default,
        )
        .unwrap();

    let witness = sighash_cache.witness_mut(0).unwrap();

    witness.push(preimage);

    for v in verifiers.iter().rev() {
        let signature = v.sign(sig_hash);
        witness.push(signature.as_ref());
    }

    // let signature = verifiers[0].sign(sig_hash);
    // witness.push(signature.as_ref());


    let control_block = info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("Cannot create control block");

    witness.push(script);
    witness.push(&control_block.serialize());
    let tx_id = tx.txid();
    println!("equivocation");
    println!("txid : {:?}", tx_id);
    println!("txid : {:?}", serialize_hex(&tx));
    let eqv_tx = rpc
        .send_raw_transaction(&tx)
        .unwrap_or_else(|e| panic!("Failed to send raw transaction: {}", e));
    println!("eqv tx = {:?}", eqv_tx);
    return tx_id;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_tx() {
        let rpc = Client::new(
            "http://localhost:18443/wallet/admin",
            Auth::UserPass("admin".to_string(), "admin".to_string()),
        )
        .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));
        let depositor = Actor::new_with_seed(31);
        let eth_address = [0xf_u8; 32];
        let other = Actor::new();
        let amount: u64 = 10_000;
        let secp = Secp256k1::new();
        let mut verifiers = Vec::new();
        for i in 0..10 {
            verifiers.push(Actor::new_with_seed(i as u64));
        }

        deposit_tx(&rpc, depositor, eth_address, &other, amount, &secp, &verifiers);

    }
}
