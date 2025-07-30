use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use bitcoin::{opcodes, script::Instruction, Transaction};
use risc0_circuit_recursion::control_id::BN254_IDENTITY_CONTROL_ID;
use risc0_zkvm::{sha::Digestible, SuccinctReceiptVerifierParameters, SystemState};
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// This is the test Verifying Key of the STARK-to-BitVM2 Groth16 proof Circom circuit.
pub fn get_ark_verifying_key_prod() -> ark_groth16::VerifyingKey<Bn254> {
    let alpha_g1 = G1Affine::new(
        Fq::from_str(
            "20491192805390485299153009773594534940189261866228447918068658471970481763042",
        )
        .unwrap(),
        Fq::from_str(
            "9383485363053290200918347156157836566562967994039712273449902621266178545958",
        )
        .unwrap(),
    );

    let beta_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "6375614351688725206403948262868962793625744043794305715222011528459656738731",
            )
            .unwrap(),
            Fq::from_str(
                "4252822878758300859123897981450591353533073413197771768651442665752259397132",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "10505242626370262277552901082094356697409835680220590971873171140371331206856",
            )
            .unwrap(),
            Fq::from_str(
                "21847035105528745403288232691147584728191162732299865338377159692350059136679",
            )
            .unwrap(),
        ),
    );

    let gamma_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .unwrap(),
            Fq::from_str(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            )
            .unwrap(),
            Fq::from_str(
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
        ),
    );

    let delta_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "19928663713463533589216209779412278386769407450988172849262535478593422929698",
            )
            .unwrap(),
            Fq::from_str(
                "19916519943909223643323234301580053157586699704876134064841182937085943926141",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "4584600978911428195337731119171761277167808711062125916470525050324985708782",
            )
            .unwrap(),
            Fq::from_str(
                "903010326261527050999816348900764705196723158942686053018929539519969664840",
            )
            .unwrap(),
        ),
    );

    let gamma_abc_g1 = vec![
        G1Affine::new(
            Fq::from_str(
                "6698887085900109660417671413804888867145870700073340970189635830129386206569",
            )
            .unwrap(),
            Fq::from_str(
                "10431087902009508261375793061696708147989126018612269070732549055898651692604",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "20225609417084538563062516991929114218412992453664808591983416996515711931386",
            )
            .unwrap(),
            Fq::from_str(
                "3236310410959095762960658876334609343091075204896196791007975095263664214628",
            )
            .unwrap(),
        ),
    ];

    VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    }
}

/// This is the risc0 dev mode Verifying Key of the STARK-to-BitVM2 Groth16 proof Circom circuit.
/// The circuit doesn't verify the succinct proof.
pub fn get_ark_verifying_key_dev_mode_bridge() -> ark_groth16::VerifyingKey<Bn254> {
    let alpha_g1 = G1Affine::new(
        Fq::from_str(
            "16428432848801857252194528405604668803277877773566238944394625302971855135431",
        )
        .unwrap(),
        Fq::from_str(
            "16846502678714586896801519656441059708016666274385668027902869494772365009666",
        )
        .unwrap(),
    );

    let beta_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "16348171800823588416173124589066524623406261996681292662100840445103873053252",
            )
            .unwrap(),
            Fq::from_str(
                "3182164110458002340215786955198810119980427837186618912744689678939861918171",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "19687132236965066906216944365591810874384658708175106803089633851114028275753",
            )
            .unwrap(),
            Fq::from_str(
                "4920802715848186258981584729175884379674325733638798907835771393452862684714",
            )
            .unwrap(),
        ),
    );

    let gamma_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .unwrap(),
            Fq::from_str(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            )
            .unwrap(),
            Fq::from_str(
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
        ),
    );

    let delta_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "10344314270577662144722843760227508818741873611994191144741344525392186054338",
            )
            .unwrap(),
            Fq::from_str(
                "8978205513343000086769980417601674188045305036608293363718735995778381961042",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "6146189823045836375835894813061243921076479945213547666722317462322308723161",
            )
            .unwrap(),
            Fq::from_str(
                "2284851597903171792019116404381013452010819014851726552415237662410982114085",
            )
            .unwrap(),
        ),
    );

    let gamma_abc_g1 = vec![
        G1Affine::new(
            Fq::from_str(
                "16750568820360300560824181364652256812515534588114371155103059323541578267",
            )
            .unwrap(),
            Fq::from_str(
                "5696152291317012726307566910263567359492805895110755470946585143294904791489",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "21186587675978507462548352788288327905178369542654940794501214693473789853405",
            )
            .unwrap(),
            Fq::from_str(
                "9059307258716845325004258585264983974929512424027765090293033859278411111397",
            )
            .unwrap(),
        ),
    ];

    VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    }
}

// Clementine do not use the runtime option to determine dev mode which is newly added in risc0_zkvm.
// Instead, it uses the environment variable RISC0_DEV_MODE to determine if it is in dev mode.
// However is_dev_mode function from risc0_zkvm is deprecated.
// So we implement our own version of is_dev_mode.
pub fn is_dev_mode() -> bool {
    std::env::var("RISC0_DEV_MODE")
        .ok()
        .map(|x| x.to_lowercase())
        .filter(|x| x == "1" || x == "true" || x == "yes")
        .is_some()
}

pub fn get_verifying_key() -> ark_groth16::VerifyingKey<Bn254> {
    if is_dev_mode() {
        get_ark_verifying_key_dev_mode_bridge()
    } else {
        get_ark_verifying_key_prod()
    }
}

/// Sha256(control_root, pre_state_digest, post_state_digest, id_bn254_fr)
pub fn calculate_succinct_output_prefix(method_id: &[u8]) -> [u8; 32] {
    let succinct_verifier_params = SuccinctReceiptVerifierParameters::default();
    let succinct_control_root = succinct_verifier_params.control_root;
    let mut succinct_control_root_bytes: [u8; 32] =
        succinct_control_root.as_bytes().try_into().unwrap();
    for byte in succinct_control_root_bytes.iter_mut() {
        *byte = byte.reverse_bits();
    }
    let pre_state_bytes = method_id.to_vec();
    let control_id_bytes: [u8; 32] = BN254_IDENTITY_CONTROL_ID.into();

    // Expected post state for an execution that halted successfully
    let post_state: SystemState = risc0_binfmt::SystemState {
        pc: 0,
        merkle_root: risc0_zkp::core::digest::Digest::default(),
    };
    let post_state_bytes: [u8; 32] = post_state.digest().into();

    let mut hasher = Sha256::new();
    hasher.update(succinct_control_root_bytes);
    hasher.update(pre_state_bytes);
    hasher.update(post_state_bytes);
    hasher.update(control_id_bytes);
    let result: [u8; 32] = hasher.finalize().into();

    result
}

pub fn total_work_from_wt_tx(wt_tx: &Transaction) -> [u8; 16] {
    let output = wt_tx.output[2].clone();
    let mut instructions = output.script_pubkey.instructions();
    if let Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) = instructions.next() {
        if let Some(Ok(Instruction::PushBytes(data))) = instructions.next() {
            let data_bytes = data.as_bytes();
            let total_work: [u8; 16] = data_bytes[64..]
                .try_into()
                .expect("Expected total work data to be exactly 16 bytes long after OP_RETURN");
            return total_work;
        }
        panic!("Expected OP_RETURN followed by data");
    }
    panic!("Expected OP_RETURN instruction in the transaction output script");
}
