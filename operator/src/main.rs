

use std::collections::{HashMap, HashSet};

use bitcoin::{secp256k1::rand::rngs::OsRng, Amount, OutPoint};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use circuit_helpers::{
    bitcoin::{get_script_hash, verify_script_hash_taproot_address},
    config::{BRIDGE_AMOUNT_SATS, CONNECTOR_TREE_DEPTH, NUM_ROUNDS, NUM_USERS, NUM_VERIFIERS},
    constant::{DUST_VALUE, HASH_FUNCTION_32, MIN_RELAY_FEE},
};
use operator::{
    operator::{Operator, PreimageType},
    user::User,
    utils::{
        calculate_amount, create_connector_binary_tree, create_utxo,
        handle_connector_binary_tree_script, mine_blocks,
    },
    verifier::Verifier,
};

fn main() {
    let mut bridge_funds: Vec<bitcoin::Txid> = Vec::new();
    let rpc = Client::new(
        "http://localhost:18443/wallet/admin",
        Auth::UserPass("admin".to_string(), "admin".to_string()),
    )
    .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

    let total_amount = calculate_amount(CONNECTOR_TREE_DEPTH, Amount::from_sat(DUST_VALUE), Amount::from_sat(MIN_RELAY_FEE));
    let mut operator = Operator::new(&mut OsRng, &rpc, NUM_VERIFIERS as u32);
    let mut users = Vec::new();
    for _ in 0..NUM_USERS {
        users.push(User::new(&mut OsRng, &rpc));
    }
    let verifiers_pks = operator.get_all_verifiers();
    for verifier in &mut operator.mock_verifier_access {
        verifier.set_verifiers(verifiers_pks.clone());
    }
    println!("verifiers_pks.len: {:?}", verifiers_pks.len());
    let mut verifiers_evm_addresses = operator.verifier_evm_addresses.clone();
    verifiers_evm_addresses.push(operator.signer.evm_address);
    let mut start_utxo_vec = Vec::new();
    let mut return_addresses = Vec::new();

    let (root_address, _) = handle_connector_binary_tree_script(
        &operator.signer.secp,
        operator.signer.xonly_public_key,
        operator.connector_tree_hashes[0][0],
    );
    let root_txid = operator
        .rpc
        .send_to_address(
            &root_address,
            total_amount,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    let root_tx = operator.rpc.get_raw_transaction(&root_txid, None).unwrap();
    // println!("resource_tx: {:?}", root_tx);

    let vout = root_tx
        .output
        .iter()
        .position(|x| x.value == total_amount)
        .unwrap();

    let root_utxo = create_utxo(root_txid, vout as u32);

    let mut preimages_verifier_track: HashSet<PreimageType> = HashSet::new();
    let mut utxos_verifier_track: HashMap<OutPoint, (u32, u32)> = HashMap::new();
    utxos_verifier_track.insert(root_utxo, (0, 0));

    let mut flag =
        operator.mock_verifier_access[0].did_connector_tree_process_start(root_utxo.clone());
    println!("flag: {:?}", flag);
    if flag {
        operator.mock_verifier_access[0].watch_connector_tree(
            operator.signer.xonly_public_key,
            &mut preimages_verifier_track,
            &mut utxos_verifier_track,
        );
    }

    // println!("resource_utxo: {:?}", root_utxo);

    let utxo_tree = create_connector_binary_tree(
        &rpc,
        &operator.signer.secp,
        operator.signer.xonly_public_key,
        root_utxo,
        CONNECTOR_TREE_DEPTH,
        operator.connector_tree_hashes.clone(),
    );

    operator.set_connector_tree_utxos(utxo_tree.clone());
    // println!(
    //     "operator.connector_tree_utxos: {:?}",
    //     operator.connector_tree_utxos
    // );
    for verifier in &mut operator.mock_verifier_access {
        verifier.set_connector_tree_utxos(utxo_tree.clone());
        verifier.set_connector_tree_hashes(operator.connector_tree_hashes.clone());
        // println!(
        //     "verifier.connector_tree_utxos: {:?}",
        //     verifier.connector_tree_utxos
        // );
    }

    let mut fund_utxos = Vec::new();

    for i in 0..NUM_USERS {
        let user = &users[i];
        let (start_utxo, start_amount) =
            user.create_start_utxo(&rpc, Amount::from_sat(BRIDGE_AMOUNT_SATS) + Amount::from_sat(MIN_RELAY_FEE));
        let hash = HASH_FUNCTION_32(operator.current_preimage_for_deposit_requests);

        let signatures = operator.new_deposit(
            start_utxo,
            i as u32,
            hash,
            user.signer.xonly_public_key.clone(),
            user.signer.evm_address,
        );

        mine_blocks(&rpc, 1);

        let (user_deposit_utxo, return_address) = user.deposit_tx(
            &user.rpc,
            start_utxo,
            Amount::from_sat(BRIDGE_AMOUNT_SATS),
            &user.secp,
            verifiers_pks.clone(),
            hash,
        );
        bridge_funds.push(user_deposit_utxo.txid);
        return_addresses.push(return_address);
        start_utxo_vec.push(start_utxo);
        mine_blocks(&rpc, 1);
        let fund =
            operator.deposit_happened(start_utxo, hash, user_deposit_utxo, return_addresses[i]);
        fund_utxos.push(fund);
        operator.change_preimage_for_deposit_requests(&mut OsRng);
    }

    flag = operator.mock_verifier_access[0].did_connector_tree_process_start(root_utxo.clone());
    println!("flag: {:?}", flag);
    if flag {
        operator.mock_verifier_access[0].watch_connector_tree(
            operator.signer.xonly_public_key,
            &mut preimages_verifier_track,
            &mut utxos_verifier_track,
        );
    }

    println!("utxos verifier track: {:?}", utxos_verifier_track);
    println!("preimages verifier track: {:?}", preimages_verifier_track);

    mine_blocks(&rpc, 3);

    let preimages = operator.reveal_connector_tree_preimages(3);
    let (commit_txid, reveal_txid) = operator.inscribe_connector_tree_preimages(3);
    println!("preimages revealed: {:?}", preimages);
    preimages_verifier_track = preimages.clone();
    let inscription_tx = operator.mock_verifier_access[0]
        .rpc
        .get_raw_transaction(&reveal_txid, None)
        .unwrap();
    println!("verifier reads inscription tx: {:?}", inscription_tx);

    let commit_tx = operator.mock_verifier_access[0]
        .rpc
        .get_raw_transaction(&commit_txid, None)
        .unwrap();
    println!("verifier reads commit tx: {:?}", commit_tx);
    let inscription_script_pubkey = &commit_tx.output[0].script_pubkey;
    let inscription_address_bytes: [u8; 32] = inscription_script_pubkey.as_bytes()[2..]
        .try_into()
        .unwrap();
    println!(
        "inscription address in bytes: {:?}",
        inscription_address_bytes
    );

    let witness_array = inscription_tx.input[0].witness.to_vec();
    println!("witness_array: {:?}", witness_array[1]);
    let inscribed_data = witness_array[1][36..witness_array[1].len() - 1].to_vec();
    println!("inscribed_data: {:?}", inscribed_data);
    println!("inscribed_data length: {:?}", inscribed_data.len());
    let mut verifier_got_preimages = Vec::new();
    for i in 0..(inscribed_data.len() / 33) {
        let preimage: [u8; 32] = inscribed_data[i * 33 + 1..(i + 1) * 33].try_into().unwrap();
        verifier_got_preimages.push(preimage);
    }

    println!("verifier_got_preimages: {:?}", verifier_got_preimages);

    let flattened_preimages: Vec<u8> = verifier_got_preimages
        .iter()
        .flat_map(|array| array.iter().copied())
        .collect();

    let flattened_slice: &[u8] = &flattened_preimages;

    // let mut test_hasher_1 = Sha256::new();
    // test_hasher_1.update([1u8]);
    // test_hasher_1.update([2u8]);
    // let test_hash_1: [u8; 32] = test_hasher_1.finalize().try_into().unwrap();
    // println!("test_hash_1: {:?}", test_hash_1);
    // let mut test_hasher_2 = Sha256::new();
    // test_hasher_2.update([1u8, 2u8]);
    // let test_hash_2: [u8; 32] = test_hasher_2.finalize().try_into().unwrap();
    // println!("test_hash_2: {:?}", test_hash_2);

    let calculated_merkle_root = get_script_hash(
        operator.signer.xonly_public_key.serialize(),
        flattened_slice,
        2,
    );
    println!("calculated_merkle_root: {:?}", calculated_merkle_root);
    let test_res = verify_script_hash_taproot_address(
        operator.signer.xonly_public_key.serialize(),
        flattened_slice,
        2,
        calculated_merkle_root,
        inscription_address_bytes,
    );
    println!("test_res: {:?}", test_res);

    for (i, utxo_level) in utxo_tree[0..utxo_tree.len() - 1].iter().enumerate() {
        for (j, utxo) in utxo_level.iter().enumerate() {
            let preimage = operator.connector_tree_preimages[i][j];
            println!("preimage: {:?}", preimage);
            operator.spend_connector_tree_utxo(*utxo, preimage, CONNECTOR_TREE_DEPTH);
            operator.mock_verifier_access[0].watch_connector_tree(
                operator.signer.xonly_public_key,
                &mut preimages_verifier_track,
                &mut utxos_verifier_track,
            );
            println!("utxos verifier track: {:?}", utxos_verifier_track);
            println!("preimages verifier track: {:?}", preimages_verifier_track);
        }
        mine_blocks(&rpc, 1);
    }

    operator.mock_verifier_access[0].watch_connector_tree(
        operator.signer.xonly_public_key,
        &mut preimages_verifier_track,
        &mut utxos_verifier_track,
    );
    println!("utxos verifier track: {:?}", utxos_verifier_track);
    println!("preimages verifier track: {:?}", preimages_verifier_track);

    // for (i, utxo_to_claim_with) in utxo_tree[utxo_tree.len() - 1].iter().enumerate() {

    //         let preimage = operator.connector_tree_preimages[utxo_tree.len() - 1][i];
    //         println!("preimage: {:?}", preimage);
    //         operator.claim_deposit(i as u32);
    // }

    mine_blocks(&rpc, 2);

    for i in 0..NUM_USERS {
        operator.claim_deposit(i);
    }
}
