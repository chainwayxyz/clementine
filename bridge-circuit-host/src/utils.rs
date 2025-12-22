use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use risc0_circuit_recursion::control_id::BN254_IDENTITY_CONTROL_ID;
use risc0_zkvm::{sha::Digestible, SuccinctReceiptVerifierParameters, SystemState};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::str::FromStr;

use eyre::{eyre, Context, Result};
use num_bigint::BigUint;
use num_traits::Num;
use risc0_core::field::baby_bear::BabyBearElem;
use risc0_zkp::core::{
    digest::{Digest as Risc0Digest, DIGEST_WORDS},
    hash::poseidon_254::digest_to_fr,
};

use crate::seal_format::{IopType, K_SEAL_ELEMS, K_SEAL_TYPES, K_SEAL_WORDS};

/// This is the production Verifying Key of the STARK-to-BitVM2 Groth16 proof Circom circuit.
pub fn get_ark_verifying_key_prod() -> ark_groth16::VerifyingKey<Bn254> {
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
                "17296777349791701671871010047490559682924748762983962242018229225890177681165",
            )
            .unwrap(),
            Fq::from_str(
                "18786665442134809547367793008388252094276956707083189371748822844215202271178",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "7214627676570978956115414107903354102221009447018809863680303520130992055423",
            )
            .unwrap(),
            Fq::from_str(
                "21546884238630900902634517213362010321565339505810557359182294051078510536811",
            )
            .unwrap(),
        ),
    );

    let gamma_abc_g1 = vec![
        G1Affine::new(
            Fq::from_str(
                "1396989810128049774239906514097458055670219613079348950494410066757721605523",
            )
            .unwrap(),
            Fq::from_str(
                "20069629286434534534516684991063672335613842540347999544849171590987775766961",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "19282603452922066135228857769519044667044696173320493211119861249451600114594",
            )
            .unwrap(),
            Fq::from_str(
                "11966256187809052800087108088094647243345273965264062329687482664981607072161",
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

pub fn total_work_from_wt_tx(wt_tx: &bitcoin::Transaction) -> [u8; 16] {
    use circuits_lib::bridge_circuit::parse_op_return_data;
    match wt_tx.output.as_slice() {
        // Single OP_RETURN output with 144 bytes
        [op_return_output, ..] if op_return_output.script_pubkey.is_op_return() => {
            // If the first output is OP_RETURN, we expect a single output with 144 bytes
            let Some(Ok(whole_output)) = parse_op_return_data(&op_return_output.script_pubkey)
                .map(TryInto::<[u8; 144]>::try_into)
            else {
                panic!("Failed to parse OP_RETURN data");
            };
            whole_output[128..144]
                .try_into()
                .expect("Cannot fail: slicing 16 bytes from 144-byte array")
        }
        // Otherwise, we expect three outputs:
        // 1. [out1, out2, out3] where out1 and out2 are P2TR outputs
        //    and out3 is an OP_RETURN output with 80 bytes
        [out1, out2, out3, ..]
            if out1.script_pubkey.is_p2tr()
                && out2.script_pubkey.is_p2tr()
                && out3.script_pubkey.is_op_return() =>
        {
            let Some(Ok(third_output)) =
                parse_op_return_data(&out3.script_pubkey).map(TryInto::<[u8; 80]>::try_into)
            else {
                panic!("Failed to parse OP_RETURN data");
            };

            // Borsh deserialization of the final 16 bytes is functionally redundant in this context,
            // as it does not alter the byte content. It is retained here for consistency and defensive safety.
            borsh::from_slice(&third_output[64..])
                .expect("Cannot fail: deserializing 16 bytes from 16-byte slice")
        }
        _ => panic!("Invalid watchtower challenge transaction output format"),
    }
}

/// Convert a recursion VM seal (i.e. succinct receipt) into a JSON format compatible with the
/// `stark_verify` witness generator. Taken from risc0-groth16 v2.3.2.
/// This function will be removed once Risc Zero publishes a new version that exposes this function publicly.
pub fn to_json<R: Read, W: Write>(mut reader: R, mut writer: W) -> Result<()> {
    let mut iop = vec![0u32; K_SEAL_WORDS];
    reader
        .read_exact(bytemuck::cast_slice_mut(&mut iop))
        .context("Failed to read seal data from reader")?;

    writeln!(writer, "{{\n  \"iop\" : [").context("Failed to write JSON header")?;

    let mut pos = 0;
    for (index, seal_type) in K_SEAL_TYPES.iter().take(K_SEAL_ELEMS).enumerate() {
        if pos != 0 {
            writeln!(writer, ",").context("Failed to write JSON separator")?;
        }
        match seal_type {
            IopType::Fp => {
                let value = BabyBearElem::new_raw(iop[pos]).as_u32();
                pos += 1;
                writeln!(writer, "    \"{value}\"")
                    .with_context(|| format!("Failed to write Fp value at index {index}"))?;
            }
            _ => {
                if pos + DIGEST_WORDS > iop.len() {
                    return Err(eyre!(
                        "Not enough data for digest at position {}: need {} words, have {} remaining",
                        pos,
                        DIGEST_WORDS,
                        iop.len() - pos
                    ));
                }
                let digest = Risc0Digest::try_from(&iop[pos..pos + DIGEST_WORDS])
                    .with_context(|| format!("Failed to create digest at position {pos}"))?;
                let value = digest_to_decimal(&digest).with_context(|| {
                    format!("Failed to convert digest to decimal at index {index}")
                })?;
                pos += 8;
                writeln!(writer, "    \"{value}\"")
                    .with_context(|| format!("Failed to write digest value at index {index}",))?;
            }
        }
    }
    write!(writer, "  ]\n}}").context("Failed to write JSON footer")?;

    Ok(())
}

fn digest_to_decimal(digest: &Risc0Digest) -> Result<String> {
    to_decimal(&format!("{:?}", digest_to_fr(digest)))
        .ok_or_else(|| eyre!("Failed to convert digest to decimal format"))
}

fn to_decimal(s: &str) -> Option<String> {
    s.strip_prefix("Fr(0x")
        .and_then(|s| s.strip_suffix(')'))
        .and_then(|stripped| BigUint::from_str_radix(stripped, 16).ok())
        .map(|n| n.to_str_radix(10))
}
