use crate::bitvm_verifier::verify_bitvm;
use crate::guests::NetworkGuests;
use crate::sp1::{prove, verify, Backend, GuestInput};
use crate::structs::{BridgeCircuitBitvmInputs, BridgeCircuitHostParams};
use ark_bn254::Bn254;
use bitcoin::Transaction;
use borsh;
use circuits_lib::bridge_circuit::merkle_tree::BitcoinMerkleTree;
use circuits_lib::bridge_circuit::spv::SPV;
use circuits_lib::bridge_circuit::structs::BridgeCircuitInput;
use circuits_lib::bridge_circuit::transaction::CircuitTransaction;
use circuits_lib::common::verification_mode::GuestVerificationMode;
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use eyre::{eyre, OptionExt, Result, WrapErr};

use circuits_lib::header_chain::mmr_native::MMRNative;

/// Proves the network's bridge guest and returns a Groth16 proof for BitVM.
///
/// The host first checks the header chain proof, the light client proof and the SPV
/// inclusion, so that invalid inputs fail before proving. With [`Backend::Mock`], the
/// guest is executed and a development Groth16 proof is created instead. Either proof
/// is checked against the BitVM verifying key of the bridge program.
///
/// Returns the Groth16 proof and the values the operator commits for BitVM, whose
/// [`BridgeCircuitBitvmInputs::groth16_public_input`] is the proof's public input.
pub async fn prove_bridge_circuit(
    bridge_circuit_host_params: BridgeCircuitHostParams,
    backend: Backend,
) -> Result<(ark_groth16::Proof<Bn254>, BridgeCircuitBitvmInputs)> {
    let network = bridge_circuit_host_params.network.0;
    eyre::ensure!(
        network != bitcoin::Network::Bitcoin || backend != Backend::Mock,
        "Mock SP1 proving is forbidden on mainnet"
    );
    let guests = NetworkGuests::for_network(network).ok_or_eyre("Unsupported network")?;
    tracing::info!("Starting bridge circuit proof generation");
    let bridge_circuit_input = bridge_circuit_host_params.bridge_circuit_input()?;

    tracing::debug!(target: "ci", "Watchtower challenges: {:?}",
        bridge_circuit_input.watchtower_inputs);

    // Verify light client proof
    verify(
        &bridge_circuit_host_params.lcp_receipt,
        guests.light_client,
        network != bitcoin::Network::Bitcoin,
    )
    .await
    .map_err(|_| eyre!("Light client proof verification failed"))?;

    // Check for headerchain receipt
    if verify(
        &bridge_circuit_host_params.headerchain_receipt,
        guests.header_chain.key,
        backend == Backend::Mock,
    )
    .await
    .is_err()
    {
        return Err(eyre!("Header chain receipt verification failed"));
    }

    // SPV verification
    if !bridge_circuit_input.payout_spv.verify(
        bridge_circuit_input
            .hcp
            .chain_state
            .block_hashes_mmr
            .clone(),
    ) {
        return Err(eyre!("SPV verification failed"));
    }

    // Make sure the L1 block hash of the LightClientCircuitOutput matches the payout tx block hash
    let lc_output: LightClientCircuitOutput = borsh::from_slice(
        bridge_circuit_host_params
            .lcp_receipt
            .journal
            .bytes
            .as_slice(),
    )
    .wrap_err("Failed to deserialize light client circuit output")?;

    let lc_l1_block_hash = lc_output.latest_da_state.block_hash;

    let spv_l1_block_hash = bridge_circuit_input
        .payout_spv
        .block_header
        .compute_block_hash();

    if lc_l1_block_hash != spv_l1_block_hash {
        return Err(eyre!(
            "L1 block hash mismatch: expected {:?}, got {:?}",
            lc_l1_block_hash,
            spv_l1_block_hash
        ));
    }

    let bitvm_inputs = BridgeCircuitBitvmInputs::from_input(&bridge_circuit_input)?;

    let input = bridge_guest_input(&bridge_circuit_input, &bridge_circuit_host_params)?;
    let receipt = prove(&guests.bridge, input, backend).await?;
    eyre::ensure!(
        receipt.journal.bytes.as_slice() == bitvm_inputs.public_values().as_slice(),
        "Bridge public values mismatch"
    );
    let proof = receipt.groth16_proof()?;
    verify_bitvm(
        &guests.bridge.key.groth16,
        &proof,
        bitvm_inputs.groth16_public_input(),
    )?;

    tracing::debug!(target: "ci", "Circuit debug info: {bitvm_inputs:?}");

    Ok((proof, bitvm_inputs))
}

/// Bridge guest input with its header chain and light client assumptions. The guest does not
/// verify a mock light client proof, so it gets no assumption.
fn bridge_guest_input(
    bridge_circuit_input: &BridgeCircuitInput,
    params: &BridgeCircuitHostParams,
) -> Result<GuestInput> {
    let input =
        GuestInput::new(bridge_circuit_input)?.with_assumption(&params.headerchain_receipt)?;
    match bridge_circuit_input.lcp.verification_mode {
        GuestVerificationMode::Verify => input.with_assumption(&params.lcp_receipt),
        GuestVerificationMode::SkipForTesting => Ok(input),
    }
}

/// Constructs an SPV (Simplified Payment Verification) proof.
///
/// This function processes block headers, constructs an MMR (Merkle Mountain Range)
/// for block header commitment, and generates a Merkle proof for the payout transaction's
/// inclusion in the block.
///
/// # Arguments
///
/// * `payout_tx` - The payout transaction to prove inclusion for.
/// * `block_hash_bytes` - A slice of block hashes, each 32 bytes long.
/// * `payment_block` - The block containing the payout transaction.
/// * `payment_block_height` - The height of the payment block in the blockchain.
/// * `genesis_block_height` - The height of the genesis block.
/// * `payment_tx_index` - The index of the payout transaction in the block's transaction list.
///
/// # Returns
///
/// Returns a `Result<SPV>` containing:
/// - The payout transaction wrapped in a `CircuitTransaction`.
/// - A Merkle proof of the transaction's inclusion in the block.
/// - The block header.
/// - An MMR proof of the block header's inclusion in the MMR.
///
/// # Errors
///
/// This function will return an error if:
/// - Input parameters are invalid or out of bounds.
/// - MMR proof generation fails.
/// - Merkle tree construction fails.
/// - Payment block height is less than genesis block height.
/// - Payment transaction index is out of bounds.
///
pub fn create_spv(
    payout_tx: Transaction,
    block_hash_bytes: &[[u8; 32]],
    payment_block: bitcoin::Block,
    payment_block_height: u32,
    genesis_block_height: u32,
    payment_tx_index: u32,
) -> Result<SPV> {
    // Input validation
    if payment_block_height < genesis_block_height {
        return Err(eyre!(
            "Payment block height ({}) cannot be less than genesis block height ({})",
            payment_block_height,
            genesis_block_height
        ));
    }

    if payment_tx_index as usize >= payment_block.txdata.len() {
        return Err(eyre!(
            "Payment transaction index ({}) out of bounds (block has {} transactions)",
            payment_tx_index,
            payment_block.txdata.len()
        ));
    }

    let mut mmr_native = MMRNative::new();
    for block_hash in block_hash_bytes {
        mmr_native.append(*block_hash);
    }

    let block_txids: Vec<CircuitTransaction> = payment_block
        .txdata
        .iter()
        .map(|tx| CircuitTransaction(tx.clone()))
        .collect();

    let mmr_inclusion_proof = mmr_native
        .generate_proof(payment_block_height - genesis_block_height)
        .wrap_err("Failed to generate MMR inclusion proof")?;

    let block_mt = BitcoinMerkleTree::new_mid_state(&block_txids);

    let payout_tx_proof = block_mt.generate_proof(payment_tx_index);

    let spv = SPV::new(
        CircuitTransaction(payout_tx.clone()),
        payout_tx_proof.clone(),
        payment_block.header.into(),
        mmr_inclusion_proof.1.clone(),
    );

    let mmr_guest = mmr_native.to_guest_mmr();

    // Verify the SPV proof to ensure correctness
    if !spv.verify(mmr_guest) {
        return Err(eyre!(
            "SPV verification failed during creation, please check inputs"
        ));
    }

    Ok(spv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_zkvm::MockZkvmGuest;
    #[cfg(feature = "use-test-vk")]
    use crate::utils::total_work_from_wt_tx;
    #[cfg(not(feature = "use-test-vk"))]
    use bitcoin::{
        hashes::Hash as _,
        key::Secp256k1,
        opcodes::all::OP_PUSHNUM_1,
        script::{Builder, PushBytesBuf},
        secp256k1::{Keypair, Message, SecretKey},
        sighash::{Prevouts, SighashCache},
        Network, ScriptBuf, TapSighashType, Witness,
    };

    use borsh::BorshDeserialize;
    #[cfg(not(feature = "use-test-vk"))]
    use circuits_lib::bridge_circuit::structs::CircuitWitness;
    #[cfg(feature = "use-test-vk")]
    use circuits_lib::bridge_circuit::{
        structs::ChallengeSendingWatchtowers, total_work_and_watchtower_flags,
    };
    #[cfg(not(feature = "use-test-vk"))]
    use circuits_lib::{bridge_circuit::groth16::CircuitGroth16Proof, common::sp1::Receipt};
    use circuits_lib::{
        bridge_circuit::structs::{TotalWork, WorkOnlyCircuitInput, WorkOnlyCircuitOutput},
        common::programs,
        header_chain::{
            header_chain_circuit, BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader,
            HeaderChainCircuitInput, HeaderChainPrevProofType,
        },
    };

    const TESTNET4_HEADERS: &[u8] = include_bytes!("../bin-files/testnet4-headers.bin");
    const MAINNET_HEADERS: &[u8] = include_bytes!("../bin-files/mainnet-headers.bin");

    #[cfg(not(feature = "use-test-vk"))]
    fn p2tr_data_script(data: &[u8]) -> ScriptBuf {
        let data = PushBytesBuf::try_from(data.to_vec()).expect("32-byte data push is valid");
        Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(data)
            .into_script()
    }

    /// Executes the network's bridge guest with the fixture's header chain and light client
    /// receipts.
    async fn execute_bridge(params: &BridgeCircuitHostParams) -> Result<Vec<u8>> {
        crate::sp1::execute_with_mock_assumptions(
            crate::guests::REGTEST.bridge.elf,
            bridge_guest_input(&params.bridge_circuit_input()?, params)?,
        )
        .await
    }

    #[test]
    fn test_header_chain_circuit() {
        let headers = MAINNET_HEADERS
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        let input = HeaderChainCircuitInput {
            method_id: [0; 8],
            prev_proof: HeaderChainPrevProofType::GenesisBlock(ChainState::genesis_state()),
            block_headers: headers[..50].to_vec(),
        };
        let guest = MockZkvmGuest::new(&input);
        header_chain_circuit(&guest);
        let output = BlockHeaderCircuitOutput::try_from_slice(&guest.journal()).unwrap();

        let newinput = HeaderChainCircuitInput {
            method_id: [0; 8],
            prev_proof: HeaderChainPrevProofType::PrevProof(output),
            block_headers: headers[50..100].to_vec(),
        };
        let new_guest = MockZkvmGuest::new(&newinput);
        header_chain_circuit(&new_guest);
        let new_output = BlockHeaderCircuitOutput::try_from_slice(&new_guest.journal()).unwrap();

        println!("Output: {new_output:?}");
    }

    /// Please use SP1_PROVER=mock to run the following tests.
    #[tokio::test]
    #[allow(clippy::print_literal)]
    #[cfg(feature = "use-test-vk")]
    async fn test_varying_total_works() {
        eprintln!("\x1b[31mPlease update test data if the elf files are changed. Run the tests on bridge_circuit_test_data.rs to update the test data.\x1b[0m");
        let bridge_circuit_host_params_serialized =
            include_bytes!("../bin-files/bch_params_varying_total_works.bin");
        let bridge_circuit_host_params: BridgeCircuitHostParams =
            borsh::BorshDeserialize::try_from_slice(bridge_circuit_host_params_serialized)
                .expect("Failed to deserialize BridgeCircuitHostParams");

        let bridge_circuit_inputs = bridge_circuit_host_params.bridge_circuit_input().unwrap();

        for watchtower_input in &bridge_circuit_inputs.watchtower_inputs {
            println!(
                "Watchtower input: {:?}",
                watchtower_input.watchtower_challenge_tx.output[2]
            );
        }

        let journal = execute_bridge(&bridge_circuit_host_params).await.unwrap();

        let public_values = BridgeCircuitBitvmInputs::from_input(&bridge_circuit_inputs)
            .unwrap()
            .public_values();

        assert_eq!(journal, public_values, "Bridge public values mismatch");
    }

    #[tokio::test]
    #[allow(clippy::print_literal)]
    #[cfg(feature = "use-test-vk")]
    async fn test_insufficient_total_work() {
        eprintln!("\x1b[31mPlease update test data if the elf files are changed. Run the tests on bridge_circuit_test_data.rs to update the test data.\x1b[0m");
        let bridge_circuit_host_params_serialized = include_bytes!(
            "../bin-files/bch_params_varying_total_works_insufficient_total_work.bin"
        );
        let bridge_circuit_host_params: BridgeCircuitHostParams =
            borsh::BorshDeserialize::try_from_slice(bridge_circuit_host_params_serialized)
                .expect("Failed to deserialize BridgeCircuitHostParams");

        let bridge_circuit_inputs = bridge_circuit_host_params.bridge_circuit_input().unwrap();

        for watchtower_input in &bridge_circuit_inputs.watchtower_inputs {
            println!(
                "Watchtower input: {:?}",
                watchtower_input.watchtower_challenge_tx.output[2]
            );
        }

        let (challenge_work, _) = total_work_and_watchtower_flags(
            &bridge_circuit_inputs,
            &programs::REGTEST.work_only.groth16,
        );
        let header_work: TotalWork = bridge_circuit_inputs.hcp.chain_state.total_work[16..32]
            .try_into()
            .unwrap();
        assert!(
            header_work <= challenge_work,
            "Fixture must have insufficient work"
        );
        assert!(execute_bridge(&bridge_circuit_host_params).await.is_err());
    }

    #[cfg(feature = "use-test-vk")]
    #[test]
    #[allow(clippy::print_literal)]
    fn test_varying_total_works_first_two_valid() {
        eprintln!("{}Please update test data if the elf files are changed. Run the tests on bridge_circuit_test_data.rs to update the test data.{}", "\x1b[31m", "\x1b[0m");
        let bridge_circuit_host_params_serialized =
            include_bytes!("../bin-files/bch_params_varying_total_works_first_two_valid.bin");
        let bridge_circuit_host_params: BridgeCircuitHostParams =
            borsh::BorshDeserialize::try_from_slice(bridge_circuit_host_params_serialized)
                .expect("Failed to deserialize BridgeCircuitHostParams");

        let bridge_circuit_input = bridge_circuit_host_params.bridge_circuit_input().unwrap();

        let mut total_works: Vec<[u8; 16]> =
            Vec::with_capacity(bridge_circuit_input.watchtower_inputs.len());

        for watchtower_input in &bridge_circuit_input.watchtower_inputs {
            println!(
                "Watchtower input: {:?}",
                watchtower_input.watchtower_challenge_tx.output[2]
            );

            let total_work = total_work_from_wt_tx(&watchtower_input.watchtower_challenge_tx);
            total_works.push(total_work);
        }

        let (total_work, challenge_sending_wts) = total_work_and_watchtower_flags(
            &bridge_circuit_input,
            &programs::REGTEST.work_only.groth16,
        );

        println!(
            "Total work: {total_work:?}, Challenge sending watchtowers: {challenge_sending_wts:?}"
        );

        total_works.sort();

        let expected_total_work = TotalWork(total_works[1]);
        let expected_challenge_sending_wts = ChallengeSendingWatchtowers([
            15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        assert_eq!(total_work, expected_total_work, "Total work mismatch");
        assert_eq!(
            challenge_sending_wts, expected_challenge_sending_wts,
            "Challenge sending watchtowers mismatch"
        );
    }

    #[tokio::test]
    #[ignore = "This test is too slow and only runs in x86_64."]
    async fn work_only_from_header_chain_test() {
        let guests = &crate::guests::TESTNET4;
        let headers = TESTNET4_HEADERS
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        // Prepare the input for the circuit
        let header_chain_input = HeaderChainCircuitInput {
            method_id: guests.header_chain.key.recursion,
            prev_proof: HeaderChainPrevProofType::GenesisBlock(ChainState::genesis_state()),
            block_headers: headers[..10].to_vec(),
        };

        let header_chain_receipt = prove(
            &guests.header_chain,
            GuestInput::new(&header_chain_input).unwrap(),
            Backend::Mock,
        )
        .await
        .unwrap();

        // Extract journal of receipt
        let header_chain_output =
            BlockHeaderCircuitOutput::try_from_slice(&header_chain_receipt.journal.bytes).unwrap();

        println!("Output: {header_chain_output:?}");

        let work_only_input = WorkOnlyCircuitInput {
            header_chain_circuit_output: header_chain_output.clone(),
        };

        let work_only_output = WorkOnlyCircuitOutput::try_from_slice(
            &crate::sp1::execute_with_mock_assumptions(
                guests.work_only.elf,
                GuestInput::new(&work_only_input)
                    .unwrap()
                    .with_assumption(&header_chain_receipt)
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .unwrap();

        println!("Output: {work_only_output:?}");
    }

    /// Operator work used after a real watchtower Groth16 is produced. Must stay strictly
    /// between 0 and the watchtower's work so Groth16 success is a guest panic and Groth16
    /// failure is not.
    #[cfg(not(feature = "use-test-vk"))]
    const OPERATOR_WORK_BELOW_WATCHTOWER: [u8; 16] = {
        let mut work = [0u8; 16];
        work[15] = 1;
        work
    };

    /// Packs a watchtower Groth16 commit into a signed challenge and executes the production
    /// operator guest. Operator HCP/LCP stay mock; only the watchtower commit is the variable.
    #[cfg(not(feature = "use-test-vk"))]
    async fn run_operator_bridge_circuit_with_watchtower_commit(
        compressed_g16_proof: [u8; 128],
        watchtower_work: [u8; 16],
        genesis_state_hash: [u8; 32],
    ) -> Result<Vec<u8>> {
        assert!(
            watchtower_work > OPERATOR_WORK_BELOW_WATCHTOWER,
            "watchtower work must exceed the lowered operator work"
        );

        let commit_data: [u8; 144] = [compressed_g16_proof.as_slice(), watchtower_work.as_slice()]
            .concat()
            .try_into()
            .unwrap();

        let input_bytes = include_bytes!("../bin-files/bch_params_varying_total_works.bin");
        let mut bridge_params: BridgeCircuitHostParams = borsh::from_slice(input_bytes).unwrap();

        // One honest challenger. Remaining registered public keys stay in the deposit
        // constant, but no other challenge input is needed.
        bridge_params.watchtower_inputs.truncate(1);
        let watchtower_idx = bridge_params.watchtower_inputs[0].watchtower_idx as usize;
        let challenge_input_idx =
            bridge_params.watchtower_inputs[0].watchtower_challenge_input_idx as usize;

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[42; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (watchtower_pubkey, _) = keypair.x_only_public_key();
        bridge_params.all_tweaked_watchtower_pubkeys[watchtower_idx] =
            watchtower_pubkey.serialize();

        let challenge_connector_vout = bridge_params.watchtower_inputs[0]
            .watchtower_challenge_tx
            .input[challenge_input_idx]
            .previous_output
            .vout as usize;
        bridge_params.kickoff_tx.output[challenge_connector_vout].script_pubkey =
            p2tr_data_script(&watchtower_pubkey.serialize());
        let challenge_prevout = bridge_params.kickoff_tx.output[challenge_connector_vout].clone();
        let kickoff_txid = bridge_params.kickoff_tx.compute_txid();

        {
            let watchtower_input = &mut bridge_params.watchtower_inputs[0];
            watchtower_input.annex_digest = None;
            watchtower_input.watchtower_challenge_tx.input[challenge_input_idx]
                .previous_output
                .txid = kickoff_txid;
            watchtower_input.watchtower_challenge_utxos[challenge_input_idx].0 = challenge_prevout;
            watchtower_input.watchtower_challenge_tx.output[0].script_pubkey =
                p2tr_data_script(&commit_data[0..32]);
            watchtower_input.watchtower_challenge_tx.output[1].script_pubkey =
                p2tr_data_script(&commit_data[32..64]);
            let remaining = PushBytesBuf::try_from(commit_data[64..].to_vec()).unwrap();
            watchtower_input.watchtower_challenge_tx.output[2].script_pubkey =
                ScriptBuf::new_op_return(remaining);
        }

        let challenge_sighash = {
            let watchtower_input = &bridge_params.watchtower_inputs[0];
            let prevouts = watchtower_input
                .watchtower_challenge_utxos
                .iter()
                .map(|utxo| utxo.0.clone())
                .collect::<Vec<_>>();
            SighashCache::new(&watchtower_input.watchtower_challenge_tx.0)
                .taproot_key_spend_signature_hash(
                    challenge_input_idx,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .unwrap()
        };
        let signature = secp.sign_schnorr(
            &Message::from_digest(*challenge_sighash.as_byte_array()),
            &keypair,
        );
        bridge_params.watchtower_inputs[0].watchtower_challenge_witness =
            CircuitWitness::from(Witness::from_slice(&[signature.as_ref()]));

        // Operator HCP/LCP stay mock. Lower operator work so only a verifying
        // watchtower Groth16 can fail the guest.
        let mut operator_hcp = bridge_params.bridge_circuit_input().unwrap().hcp;
        operator_hcp.genesis_state_hash = genesis_state_hash;
        operator_hcp.chain_state.total_work[16..].copy_from_slice(&OPERATOR_WORK_BELOW_WATCHTOWER);
        bridge_params.headerchain_receipt = Receipt::mock(
            programs::REGTEST.header_chain.recursion,
            borsh::to_vec(&operator_hcp).unwrap(),
        );
        bridge_params.lcp_receipt = Receipt::mock(
            programs::REGTEST.light_client.recursion,
            bridge_params.lcp_receipt.journal.bytes.clone(),
        );

        execute_bridge(&bridge_params).await
    }

    /// The production regtest bridge guest accepts mock header chain and light client proofs
    /// in mock execution, and ignores an invalid watchtower proof.
    #[cfg(not(feature = "use-test-vk"))]
    #[tokio::test]
    async fn production_bridge_guest_runs_with_mock_header_chain_and_light_client_proofs() {
        let params: BridgeCircuitHostParams = borsh::from_slice(include_bytes!(
            "../bin-files/bch_params_varying_total_works.bin"
        ))
        .unwrap();
        let mut watchtower_work = [0u8; 16];
        watchtower_work[15] = 2;
        run_operator_bridge_circuit_with_watchtower_commit(
            [0; 128],
            watchtower_work,
            params
                .bridge_circuit_input()
                .unwrap()
                .hcp
                .genesis_state_hash,
        )
        .await
        .unwrap();
    }

    /// Proves a real watchtower challenge and checks that the production regtest bridge guest
    /// accepts it with the accelerated in-guest Groth16 verifier.
    #[cfg(feature = "use-test-vk")]
    #[tokio::test]
    #[ignore = "requires a real SP1 prover; run by the dedicated CI job"]
    async fn operator_verifies_real_sp1_watchtower_challenge() {
        panic!("this test requires the production Groth16 VK; do not enable use-test-vk");
    }

    #[cfg(not(feature = "use-test-vk"))]
    #[tokio::test]
    #[ignore = "requires a real SP1 prover; run by the dedicated CI job"]
    async fn operator_verifies_real_sp1_watchtower_challenge() {
        use circuits_lib::bridge_circuit::groth16_verifier::CircuitGroth16WithTotalWork;

        let backend = Backend::from_env()
            .and_then(crate::sp1::check_programs)
            .unwrap();
        let guests = &crate::guests::REGTEST;
        let work_only_key = guests.work_only.key;

        // One regtest header is enough to produce non-zero, honestly accumulated work while
        // keeping the real header-chain proof small enough for a CPU-only test server.
        let genesis_state = ChainState::genesis_state();
        let genesis_header =
            CircuitBlockHeader::from(bitcoin::constants::genesis_block(Network::Regtest).header);
        let header_chain_input = HeaderChainCircuitInput {
            method_id: guests.header_chain.key.recursion,
            prev_proof: HeaderChainPrevProofType::GenesisBlock(genesis_state.clone()),
            block_headers: vec![genesis_header],
        };
        let header_chain_receipt = prove(
            &guests.header_chain,
            GuestInput::new(&header_chain_input).unwrap(),
            backend,
        )
        .await
        .unwrap();
        verify(&header_chain_receipt, guests.header_chain.key, false)
            .await
            .unwrap();

        let header_chain_output =
            BlockHeaderCircuitOutput::try_from_slice(&header_chain_receipt.journal.bytes).unwrap();
        assert_eq!(
            header_chain_output.genesis_state_hash,
            genesis_state.to_hash()
        );

        let work_only_input = WorkOnlyCircuitInput {
            header_chain_circuit_output: header_chain_output,
        };
        let work_only_receipt = prove(
            &guests.work_only,
            GuestInput::new(&work_only_input)
                .unwrap()
                .with_assumption(&header_chain_receipt)
                .unwrap(),
            backend,
        )
        .await
        .unwrap();
        verify(&work_only_receipt, work_only_key, false)
            .await
            .unwrap();

        let work_only_output =
            WorkOnlyCircuitOutput::try_from_slice(&work_only_receipt.journal.bytes).unwrap();
        assert_ne!(work_only_output.work_u128, [0; 16]);

        let groth16_proof = CircuitGroth16Proof::from(work_only_receipt.groth16_proof().unwrap());
        // The watchtower check and Bitcoin's folded key must agree on the real proof.
        let key = crate::bitvm_verifier::program_verifying_key(&work_only_key.groth16).unwrap();
        assert!(ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(
            &ark_groth16::prepare_verifying_key(&key),
            &groth16_proof.into(),
            &[circuits_lib::common::sp1::groth16::public_input(
                &work_only_receipt.journal.bytes
            )],
        )
        .unwrap());
        assert!(CircuitGroth16WithTotalWork::new(
            groth16_proof,
            work_only_output.work_u128,
            work_only_output.genesis_state_hash
        )
        .verify(&work_only_key.groth16));

        let compressed_proof = groth16_proof.to_compressed().unwrap();
        let expected_insufficient_work = format!(
            "Insufficient total work: Total Work {:?} - Max Total Work: {:?}",
            TotalWork(OPERATOR_WORK_BELOW_WATCHTOWER),
            TotalWork(work_only_output.work_u128),
        );
        let real_proof_err = run_operator_bridge_circuit_with_watchtower_commit(
            compressed_proof,
            work_only_output.work_u128,
            work_only_output.genesis_state_hash,
        )
        .await
        .expect_err("a verifying watchtower Groth16 must fail the operator work comparison")
        .to_string();
        assert!(
            real_proof_err.contains(&expected_insufficient_work),
            "expected `{expected_insufficient_work}` in guest error, got `{real_proof_err}`"
        );

        let mut tampered_proof = compressed_proof;
        tampered_proof[0] ^= 1;
        run_operator_bridge_circuit_with_watchtower_commit(
            tampered_proof,
            work_only_output.work_u128,
            work_only_output.genesis_state_hash,
        )
        .await
        .expect("a 1-byte-tampered Groth16 must be ignored so the operator's tiny work still wins");
    }

    #[tokio::test]
    #[cfg(feature = "use-test-vk")]
    async fn test_bridge_circuit_with_annex() {
        eprintln!("\x1b[31mPlease update test data if the elf files are changed. Run the tests on bridge_circuit_test_data.rs to update the test data.\x1b[0m");
        let input_bytes: &[u8] =
            include_bytes!("../bin-files/bch_params_challenge_tx_with_annex.bin");
        let bridge_circuit_host_params: BridgeCircuitHostParams = borsh::from_slice(input_bytes)
            .expect("Failed to deserialize BridgeCircuitHostParams from file");

        let (proof, bitvm_inputs) = prove_bridge_circuit(bridge_circuit_host_params, Backend::Mock)
            .await
            .unwrap();
        println!("Proof: {proof:?}");
        println!("BitVM Inputs: {bitvm_inputs:?}");
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid witness length, expected 1 element")]
    #[cfg(feature = "use-test-vk")]
    async fn test_bridge_circuit_with_large_input() {
        eprintln!("\x1b[31mPlease update test data if the elf files are changed. Run the tests on bridge_circuit_test_data.rs to update the test data.\x1b[0m");
        let input_bytes: &[u8] =
            include_bytes!("../bin-files/bch_params_challenge_tx_with_large_annex.bin");
        let mut bridge_circuit_host_params: BridgeCircuitHostParams =
            borsh::from_slice(input_bytes)
                .expect("Failed to deserialize BridgeCircuitHostParams from file");

        // Now add the removed witness element back to the watchtower inputs
        for watchtower_input in &mut bridge_circuit_host_params.watchtower_inputs {
            let large_data: Vec<u8> = vec![0x80; 3999000];
            watchtower_input
                .watchtower_challenge_witness
                .push(large_data);
        }
        let (_, _) = prove_bridge_circuit(bridge_circuit_host_params, Backend::Mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "use-test-vk")]
    async fn test_bridge_circuit_with_large_output() {
        eprintln!("\x1b[31mPlease update test data if the elf files are changed. Run the tests on bridge_circuit_test_data.rs to update the test data.\x1b[0m");
        let input_bytes: &[u8] =
            include_bytes!("../bin-files/bch_params_challenge_tx_with_large_output.bin");
        let bridge_circuit_host_params: BridgeCircuitHostParams = borsh::from_slice(input_bytes)
            .expect("Failed to deserialize BridgeCircuitHostParams from file");

        let (proof, bitvm_inputs) = prove_bridge_circuit(bridge_circuit_host_params, Backend::Mock)
            .await
            .unwrap();
        println!("Proof: {proof:?}");
        println!("BitVM Inputs: {bitvm_inputs:?}");
    }

    #[tokio::test]
    #[cfg(feature = "use-test-vk")]
    async fn test_bridge_circuit_with_large_input_and_output() {
        eprintln!("\x1b[31mPlease update test data if the elf files are changed. Run the tests on bridge_circuit_test_data.rs to update the test data.\x1b[0m");
        let input_bytes: &[u8] =
            include_bytes!("../bin-files/bch_params_challenge_tx_with_large_annex_and_output.bin");
        let bridge_circuit_host_params: BridgeCircuitHostParams = borsh::from_slice(input_bytes)
            .expect("Failed to deserialize BridgeCircuitHostParams from file");

        let (proof, bitvm_inputs) = prove_bridge_circuit(bridge_circuit_host_params, Backend::Mock)
            .await
            .unwrap();
        println!("Proof: {proof:?}");
        println!("BitVM Inputs: {bitvm_inputs:?}");
    }
}
