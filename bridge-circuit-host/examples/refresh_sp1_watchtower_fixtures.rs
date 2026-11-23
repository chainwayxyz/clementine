//! Refresh development watchtower proofs and signatures after SP1 program-key changes.
//! Run with --features use-test-vk and pass the bch_params fixture paths.
use bitcoin::{
    hashes::Hash,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighash, TapSighashType},
    ScriptBuf, Witness,
};
use bridge_circuit_host::structs::BridgeCircuitHostParams;
use circuits_lib::{
    bridge_circuit::{
        groth16::CircuitGroth16Proof, parse_op_return_data, sp1_test_prover, structs::*,
        taproot_encode_signing_data_to_with_annex_digest,
    },
    common::{
        programs::REGTEST,
        sp1::{groth16 as sp1, Receipt},
    },
    header_chain::BlockHeaderCircuitOutput,
};

fn p2tr(bytes: &[u8]) -> ScriptBuf {
    ScriptBuf::from_bytes([&[0x51, 0x20][..], bytes].concat())
}
fn opreturn(bytes: &[u8]) -> ScriptBuf {
    ScriptBuf::new_op_return(bitcoin::script::PushBytesBuf::try_from(bytes.to_vec()).unwrap())
}
fn refresh_lc(receipt: &Receipt) -> Receipt {
    let mut output: citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();
    output.light_client_proof_method_id = REGTEST.light_client.recursion;
    Receipt::mock(
        REGTEST.light_client.recursion,
        borsh::to_vec(&output).unwrap(),
    )
}
fn header_chain_receipt(output: &mut BlockHeaderCircuitOutput) -> Receipt {
    output.method_id = REGTEST.header_chain.recursion;
    Receipt::mock(
        REGTEST.header_chain.recursion,
        borsh::to_vec(output).unwrap(),
    )
}
fn main() {
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[42; 32]).unwrap());
    let xonly_pubkey = key.x_only_public_key().0;
    let pubkey = xonly_pubkey.serialize();
    for name in std::env::args().skip(1) {
        if name.ends_with("first_1.bin") {
            let receipt: Receipt = borsh::from_slice(&std::fs::read(&name).unwrap()).unwrap();
            let mut output: BlockHeaderCircuitOutput =
                borsh::from_slice(&receipt.journal.bytes).unwrap();
            let receipt = header_chain_receipt(&mut output);
            std::fs::write(&name, borsh::to_vec(&receipt).unwrap()).unwrap();
            println!("Refreshed {name}");
            continue;
        }
        if name.ends_with("lcp_receipt.bin") {
            let receipt: Receipt = borsh::from_slice(&std::fs::read(&name).unwrap()).unwrap();
            std::fs::write(&name, borsh::to_vec(&refresh_lc(&receipt)).unwrap()).unwrap();
            println!("Refreshed {name}");
            continue;
        }
        let mut p: BridgeCircuitHostParams =
            borsh::from_slice(&std::fs::read(&name).unwrap()).unwrap();
        let mut header_chain_output: BlockHeaderCircuitOutput =
            borsh::from_slice(&p.headerchain_receipt.journal.bytes).unwrap();
        p.headerchain_receipt = header_chain_receipt(&mut header_chain_output);
        p.lcp_receipt = refresh_lc(&p.lcp_receipt);
        for wt in &p.watchtower_inputs {
            p.all_tweaked_watchtower_pubkeys[wt.watchtower_idx as usize] = pubkey;
            let i = wt.watchtower_challenge_input_idx as usize;
            let vout = wt.watchtower_challenge_tx.input[i].previous_output.vout as usize;
            p.kickoff_tx.output[vout].script_pubkey = p2tr(&pubkey);
        }
        let mut works: Vec<[u8; 16]> = p
            .watchtower_inputs
            .iter()
            .map(|wt| {
                let tx = &wt.watchtower_challenge_tx;
                let idx = if tx.output[0].script_pubkey.is_op_return() {
                    0
                } else {
                    2
                };
                let data = parse_op_return_data(&tx.output[idx].script_pubkey).unwrap();
                data[data.len() - 16..].try_into().unwrap()
            })
            .collect();
        works.sort();
        let second_lowest = works[1];
        let kickoff_txid = p.kickoff_tx.compute_txid();
        for wt in &mut p.watchtower_inputs {
            let tx = &mut wt.watchtower_challenge_tx;
            let single = tx.output[0].script_pubkey.is_op_return();
            let out_idx = if single { 0 } else { 2 };
            let data = parse_op_return_data(&tx.output[out_idx].script_pubkey).unwrap();
            let work: [u8; 16] = data[data.len() - 16..].try_into().unwrap();
            let output = WorkOnlyCircuitOutput {
                work_u128: work,
                genesis_state_hash: header_chain_output.genesis_state_hash,
            };
            let proof = sp1_test_prover::prove(
                &REGTEST.work_only.groth16,
                sp1::public_input(&borsh::to_vec(&output).unwrap()),
            )
            .unwrap();
            let mut compressed = CircuitGroth16Proof::new(proof.a, proof.b, proof.c)
                .to_compressed()
                .unwrap();
            if name.contains("first_two_valid") && work > second_lowest {
                compressed[0] ^= 1;
            }
            if single {
                tx.output[0].script_pubkey = opreturn(&[&compressed[..], &work].concat());
            } else {
                tx.output[0].script_pubkey = p2tr(&compressed[..32]);
                tx.output[1].script_pubkey = p2tr(&compressed[32..64]);
                tx.output[2].script_pubkey = opreturn(&[&compressed[64..], &work].concat());
            }
            let i = wt.watchtower_challenge_input_idx as usize;
            let vout = tx.input[i].previous_output.vout as usize;
            tx.input[i].previous_output.txid = kickoff_txid;
            wt.watchtower_challenge_utxos[i].0 = p.kickoff_tx.output[vout].clone();
            let prevouts: Vec<_> = wt
                .watchtower_challenge_utxos
                .iter()
                .map(|x| x.0.clone())
                .collect();
            let mut engine = TapSighash::engine();
            taproot_encode_signing_data_to_with_annex_digest(
                &mut SighashCache::new(&tx.0),
                &mut engine,
                i,
                &Prevouts::All(&prevouts),
                wt.annex_digest,
                None,
                TapSighashType::Default,
            );
            let msg = Message::from_digest(TapSighash::from_engine(engine).to_byte_array());
            let signature = secp.sign_schnorr_no_aux_rand(&msg, &key);
            wt.watchtower_challenge_witness =
                CircuitWitness(Witness::from_slice(&[signature.as_ref()]));
        }
        std::fs::write(&name, borsh::to_vec(&p).unwrap()).unwrap();
        println!("Refreshed {name}");
    }
}
