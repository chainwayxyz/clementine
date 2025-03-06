use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use risc0_circuit_recursion::control_id::BN254_IDENTITY_CONTROL_ID;
use risc0_zkvm::{SuccinctReceiptVerifierParameters, SystemState, sha::Digestible};
use sha2::{Digest, Sha256};
use std::str::FromStr;

pub fn reverse_bits_and_copy(input: &[u8], output: &mut [u8]) {
    for i in 0..8 {
        let temp = u32::from_be_bytes(input[4 * i..4 * i + 4].try_into().unwrap()).reverse_bits();
        output[4 * i..4 * i + 4].copy_from_slice(&temp.to_le_bytes());
    }
}

pub fn get_ark_verifying_key() -> ark_groth16::VerifyingKey<Bn254> {
    // Alpha in G1
    let alpha_g1_x = Fq::from_str("20491192805390485299153009773594534940189261866228447918068658471970481763042").unwrap();
    let alpha_g1_y = Fq::from_str("9383485363053290200918347156157836566562967994039712273449902621266178545958").unwrap();
    let alpha_g1 = G1Affine::new(alpha_g1_x, alpha_g1_y);

    // Beta in G2
    let beta_g2_c0_re = Fq::from_str("6375614351688725206403948262868962793625744043794305715222011528459656738731").unwrap();
    let beta_g2_c0_im = Fq::from_str("4252822878758300859123897981450591353533073413197771768651442665752259397132").unwrap();
    let beta_g2_c1_re = Fq::from_str("10505242626370262277552901082094356697409835680220590971873171140371331206856").unwrap();
    let beta_g2_c1_im = Fq::from_str("21847035105528745403288232691147584728191162732299865338377159692350059136679").unwrap();
    
    let beta_g2_c0 = Fq2::new(beta_g2_c0_re, beta_g2_c0_im);
    let beta_g2_c1 = Fq2::new(beta_g2_c1_re, beta_g2_c1_im);
    let beta_g2 = G2Affine::new(beta_g2_c0, beta_g2_c1);

    // Gamma in G2
    let gamma_g2_c0_re = Fq::from_str("10857046999023057135944570762232829481370756359578518086990519993285655852781").unwrap();
    let gamma_g2_c0_im = Fq::from_str("11559732032986387107991004021392285783925812861821192530917403151452391805634").unwrap();
    let gamma_g2_c1_re = Fq::from_str("8495653923123431417604973247489272438418190587263600148770280649306958101930").unwrap();
    let gamma_g2_c1_im = Fq::from_str("4082367875863433681332203403145435568316851327593401208105741076214120093531").unwrap();
    
    let gamma_g2_c0 = Fq2::new(gamma_g2_c0_re, gamma_g2_c0_im);
    let gamma_g2_c1 = Fq2::new(gamma_g2_c1_re, gamma_g2_c1_im);
    let gamma_g2 = G2Affine::new(gamma_g2_c0, gamma_g2_c1);

    // Delta in G2
    let delta_g2_c0_re = Fq::from_str("17373390530484628175439079012547601221793532405373183847591328903803405586286").unwrap();
    let delta_g2_c0_im = Fq::from_str("4625210858552158309405374705253571552256748541870661454419080699362567957226").unwrap();
    let delta_g2_c1_re = Fq::from_str("20292316235570350162741350858895467611317790503850491347042646354236531519055").unwrap();
    let delta_g2_c1_im = Fq::from_str("17004339328415633000851435380698565994375131307744525391751714344270706811231").unwrap();
    
    let delta_g2_c0 = Fq2::new(delta_g2_c0_re, delta_g2_c0_im);
    let delta_g2_c1 = Fq2::new(delta_g2_c1_re, delta_g2_c1_im);
    let delta_g2 = G2Affine::new(delta_g2_c0, delta_g2_c1);

    // Gamma ABC in G1 (first two elements)
    let mut gamma_abc_g1 = Vec::new();
    
    // First element
    let g1_x = Fq::from_str("19647329884141636868838662743921462850093495460601527910594807780507527498755").unwrap();
    let g1_y = Fq::from_str("11866587864098764425295475199808859787294133529274334392579829950494218737898").unwrap();
    gamma_abc_g1.push(G1Affine::new(g1_x, g1_y));
    
    // Second element
    let g1_x = Fq::from_str("2244061991313498397063727186076860978321484653259630566498796511714519280220").unwrap();
    let g1_y = Fq::from_str("3313153727619754321539238199327739757956770721532533603738719136366368438484").unwrap();
    gamma_abc_g1.push(G1Affine::new(g1_x, g1_y));

    // Create the VerifyingKey
    VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    }
}

/// Sha256(control_root, pre_state_digest, post_state_digest, id_bn254_fr)
/// TODO: This function may be the same with something that is already here
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
    hasher.update(&succinct_control_root_bytes);
    hasher.update(&pre_state_bytes);
    hasher.update(&post_state_bytes);
    hasher.update(&control_id_bytes);
    let result: [u8; 32] = hasher
        .finalize()
        .try_into()
        .expect("SHA256 should produce a 32-byte output");

    result
}