use bitcoin::secp256k1::rand::rngs::OsRng;
use operator::config::{NUM_USERS, NUM_VERIFIERS};
use operator::errors::BridgeError;
use operator::{extended_rpc::ExtendedRpc, operator::Operator, user::User};

fn main() -> Result<(), BridgeError> {
    let rpc = ExtendedRpc::new();

    let mut operator = Operator::new(&mut OsRng, &rpc, NUM_VERIFIERS as u32);

    let verifiers_pks = operator.get_all_verifiers();
    for verifier in &mut operator.mock_verifier_access {
        verifier.set_verifiers(verifiers_pks.clone());
    }

    let mut users = Vec::new();
    for _ in 0..NUM_USERS {
        users.push(User::new(&rpc, verifiers_pks.clone()));
    }

    // Initial setup for connector roots
    let (first_source_utxo, start_blockheight) = operator.initial_setup().unwrap();

    let mut connector_tree_source_sigs = Vec::new();

    for verifier in &mut operator.mock_verifier_access {
        let sigs = verifier.connector_roots_created(
            &operator.connector_tree_hashes,
            start_blockheight,
            &first_source_utxo,
        );
        connector_tree_source_sigs.push(sigs);
    }

    println!("connector roots created, verifiers agree");
    // In the end, create BitVM

    // every user makes a deposit.
    for i in 0..NUM_USERS {
        let user = &users[i];
        // let user_evm_address = user.signer.evm_address;
        // println!("user_evm_address: {:?}", user_evm_address);
        // println!("move_utxo: {:?}", move_utxo);
        // let move_tx = rpc.get_raw_transaction(&move_utxo.txid, None).unwrap();
        // println!("move_tx: {:?}", move_tx);
        let (deposit_utxo, deposit_return_address, user_evm_address, user_sig) =
            user.deposit_tx().unwrap();
        rpc.mine_blocks(6)?;
        operator
            .new_deposit(
                deposit_utxo,
                &deposit_return_address,
                &user_evm_address,
                user_sig,
            )
            .unwrap();
        rpc.mine_blocks(1)?;
    }

    // make 3 withdrawals
    for i in 0..3 {
        operator.new_withdrawal(users[i].signer.address.clone())?;
        rpc.mine_blocks(1)?;
    }

    let inscription_output = operator.inscribe_connector_tree_preimages();
    println!("inscription_output: {:?}", inscription_output);

    // operator.prove();

    // for r in 0..NUM_ROUNDS {
    //     let mut preimages_verifier_track: HashSet<PreimageType> = HashSet::new();
    //     let mut utxos_verifier_track: HashMap<OutPoint, (u32, u32)> = HashMap::new();
    //     utxos_verifier_track.insert(connector_tree_root_utxos[r], (0, 0));

    //     let mut flag = operator.mock_verifier_access[r]
    //         .did_connector_tree_process_start(connector_tree_root_utxos[r].clone());
    //     println!("flag: {:?}", flag);
    //     if flag {
    //         operator.mock_verifier_access[r].watch_connector_tree(
    //             operator.signer.xonly_public_key,
    //             &mut preimages_verifier_track,
    //             &mut utxos_verifier_track,
    //         );
    //     }

    //     let mut fund_utxos = Vec::new();

    //     flag = operator.mock_verifier_access[r]
    //         .did_connector_tree_process_start(connector_tree_root_utxos[r].clone());
    //     println!("flag: {:?}", flag);
    //     if flag {
    //         operator.mock_verifier_access[r].watch_connector_tree(
    //             operator.signer.xonly_public_key,
    //             &mut preimages_verifier_track,
    //             &mut utxos_verifier_track,
    //         );
    //     }

    //     println!("utxos verifier track: {:?}", utxos_verifier_track);
    //     println!("preimages verifier track: {:?}", preimages_verifier_track);

    //     rpc.mine_blocks(3);

    //     let preimages = operator.reveal_connector_tree_preimages(r, 3);
    //     let (commit_txid, reveal_txid) = operator.inscribe_connector_tree_preimages(r, 3);
    //     println!("preimages revealed: {:?}", preimages);
    //     preimages_verifier_track = preimages.clone();
    //     let inscription_tx = operator.mock_verifier_access[r]
    //         .rpc
    //         .get_raw_transaction(&reveal_txid, None)
    //         .unwrap();
    //     println!("verifier reads inscription tx: {:?}", inscription_tx);

    //     let commit_tx = operator.mock_verifier_access[r]
    //         .rpc
    //         .get_raw_transaction(&commit_txid, None)
    //         .unwrap();
    //     println!("verifier reads commit tx: {:?}", commit_tx);
    //     let inscription_script_pubkey = &commit_tx.output[0].script_pubkey;
    //     let inscription_address_bytes: [u8; 32] = inscription_script_pubkey.as_bytes()[2..]
    //         .try_into()
    //         .unwrap();
    //     println!(
    //         "inscription address in bytes: {:?}",
    //         inscription_address_bytes
    //     );

    //     let witness_array = inscription_tx.input[0].witness.to_vec();
    //     println!("witness_array: {:?}", witness_array[1]);
    //     let inscribed_data = witness_array[1][36..witness_array[1].len() - 1].to_vec();
    //     println!("inscribed_data: {:?}", inscribed_data);
    //     println!("inscribed_data length: {:?}", inscribed_data.len());
    //     let mut verifier_got_preimages = Vec::new();
    //     for i in 0..(inscribed_data.len() / 33) {
    //         let preimage: [u8; 32] = inscribed_data[i * 33 + 1..(i + 1) * 33].try_into().unwrap();
    //         verifier_got_preimages.push(preimage);
    //     }

    //     println!("verifier_got_preimages: {:?}", verifier_got_preimages);

    //     let flattened_preimages: Vec<u8> = verifier_got_preimages
    //         .iter()
    //         .flat_map(|array| array.iter().copied())
    //         .collect();

    //     let flattened_slice: &[u8] = &flattened_preimages;

    //     let calculated_merkle_root = get_script_hash(
    //         operator.signer.xonly_public_key.serialize(),
    //         flattened_slice,
    //         2,
    //     );
    //     println!("calculated_merkle_root: {:?}", calculated_merkle_root);
    //     let test_res = verify_script_hash_taproot_address(
    //         operator.signer.xonly_public_key.serialize(),
    //         flattened_slice,
    //         2,
    //         calculated_merkle_root,
    //         inscription_address_bytes,
    //     );
    //     println!("test_res: {:?}", test_res);

    //     for (i, utxo_level) in operator.connector_tree_utxos[r]
    //         [0..operator.connector_tree_utxos.len() - 1]
    //         .iter()
    //         .enumerate()
    //     {
    //         for (j, utxo) in utxo_level.iter().enumerate() {
    //             let preimage = operator.connector_tree_preimages[r][i][j];
    //             println!("preimage: {:?}", preimage);
    //             operator.spend_connector_tree_utxo(r, *utxo, preimage, CONNECTOR_TREE_DEPTH);
    //             operator.mock_verifier_access[r].watch_connector_tree(
    //                 operator.signer.xonly_public_key,
    //                 &mut preimages_verifier_track,
    //                 &mut utxos_verifier_track,
    //             );
    //             println!("utxos verifier track: {:?}", utxos_verifier_track);
    //             println!("preimages verifier track: {:?}", preimages_verifier_track);
    //         }
    //         rpc.mine_blocks(1);
    //     }

    //     operator.mock_verifier_access[r].watch_connector_tree(
    //         operator.signer.xonly_public_key,
    //         &mut preimages_verifier_track,
    //         &mut utxos_verifier_track,
    //     );
    //     println!("utxos verifier track: {:?}", utxos_verifier_track);
    //     println!("preimages verifier track: {:?}", preimages_verifier_track);

    //     for i in 0..3 {
    //         operator.new_withdrawal(users[i].signer.address.clone());
    //         rpc.mine_blocks(1);
    //     }

    //     //k-deep assumption
    //     rpc.mine_blocks(10);

    //     let chain_info = rpc.get_blockchain_info().unwrap();
    //     let total_work_bytes = chain_info.chain_work;
    //     let total_work: U256 = U256::from_be_bytes(total_work_bytes.try_into().unwrap());
    //     let curr_blockheight = rpc.get_block_count().unwrap();
    //     let curr_block_hash = rpc.get_best_block_hash().unwrap();
    //     println!("curr_block_height: {:?}", curr_blockheight);
    //     println!("curr_block_hash: {:?}", curr_block_hash);
    //     println!("total_work: {:?}", total_work);

    //     let done_wd_pi_inscription_blockheight: u64;
    //     let mut wd_blockheight = 0;

    //     for wd_txid in operator.withdrawals_payment_txids.clone() {
    //         // println!("for withdrawal txid: {:?}", wd_txid);
    //         let wd_tx = rpc.get_raw_transaction(&wd_txid, None).unwrap();
    //         // println!("wd_tx: {:?}", wd_tx);
    //         wd_blockheight = rpc
    //             .get_transaction(&wd_txid, None)
    //             .unwrap()
    //             .info
    //             .blockheight
    //             .unwrap() as u64;
    //         println!("wd blockheight: {:?}", wd_blockheight);
    //     }

    //     done_wd_pi_inscription_blockheight = wd_blockheight;
    //     println!(
    //         "prover done with withdrawals and preimages inscription, blockheight: {:?}",
    //         done_wd_pi_inscription_blockheight
    //     );
    //     // let done_wd_pi_inscription_blockhash = rpc.get_block_hash(done_wd_pi_inscription_blockheight as u64).unwrap();

    //     let wanted_work = rpc.calculate_total_work_between_blocks(
    //         done_wd_pi_inscription_blockheight,
    //         curr_blockheight,
    //     );
    //     let wanted_blockhash = curr_block_hash;
    //     let wanted_blockheight = curr_blockheight;

    //     println!("wanted_work: {:?}", wanted_work);
    //     println!("wanted_blockhash: {:?}", wanted_blockhash);
    //     println!("wanted_blockheight: {:?}", wanted_blockheight);
    //     // println!("test: {:?}", test);

    //     // for i in 0..NUM_USERS * r {
    //     //     operator.claim_deposit(r, i);
    //     // }
    // }
    Ok(())
}
