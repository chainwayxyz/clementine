use crate::actor::WinternitzDerivationPath;
use crate::config::protocol::ProtocolParamset;
use bitcoin::Witness;
use eyre::{Context, Result};

fn from_minimal_to_u32_le_bytes(minimal: &[u8]) -> Result<[u8; 4]> {
    if minimal.len() > 4 {
        return Err(eyre::eyre!("u32 bytes length is greater than 4"));
    }
    let mut bytes = [0u8; 4];
    bytes[..minimal.len()].copy_from_slice(minimal);
    Ok(bytes)
}

pub fn extract_winternitz_commits(
    witness: Witness,
    wt_derive_paths: &[WinternitzDerivationPath],
    paramset: &'static ProtocolParamset,
) -> Result<Vec<Vec<u8>>> {
    if paramset.winternitz_log_d != 4 {
        return Err(eyre::eyre!("Only winternitz_log_d = 4 is supported"));
    }
    let mut commits = Vec::new();
    let mut cur_witness_iter = witness.into_iter().skip(1);

    for wt_path in wt_derive_paths.iter().rev() {
        let wt_params = wt_path.get_params();
        let message_digits =
            (wt_params.message_byte_len() * 8).div_ceil(paramset.winternitz_log_d) as usize;
        let checksum_digits = wt_params.total_digit_len() as usize - message_digits;

        let mut elements: Vec<&[u8]> = cur_witness_iter
            .by_ref()
            .skip(1)
            .step_by(2)
            .take(message_digits)
            .collect();
        elements.reverse();
        cur_witness_iter.by_ref().nth(checksum_digits * 2 - 1);

        commits.push(
            elements
                .chunks_exact(2)
                .map(|digits| {
                    let first_digit = u32::from_le_bytes(from_minimal_to_u32_le_bytes(digits[0])?);
                    let second_digit = u32::from_le_bytes(from_minimal_to_u32_le_bytes(digits[1])?);

                    let first_u8 = u8::try_from(first_digit)
                        .wrap_err("Failed to convert first digit to u8")?;
                    let second_u8 = u8::try_from(second_digit)
                        .wrap_err("Failed to convert second digit to u8")?;

                    Ok(second_u8 * (1 << paramset.winternitz_log_d) + first_u8)
                })
                .collect::<Result<Vec<_>>>()?,
        );
    }

    commits.reverse();
    Ok(commits)
}

pub fn extract_winternitz_commits_with_sigs(
    witness: Witness,
    wt_derive_paths: &[WinternitzDerivationPath],
    paramset: &'static ProtocolParamset,
) -> Result<Vec<Vec<Vec<u8>>>> {
    if paramset.winternitz_log_d != 4 {
        return Err(eyre::eyre!("Only winternitz_log_d = 4 is supported"));
    }

    let mut commits_with_sig = Vec::new();
    let mut cur_witness_iter = witness.into_iter().skip(1);

    for wt_path in wt_derive_paths.iter().rev() {
        let wt_params = wt_path.get_params();
        let message_digits =
            (wt_params.message_byte_len() * 8).div_ceil(paramset.winternitz_log_d) as usize;
        let checksum_digits = wt_params.total_digit_len() as usize - message_digits;

        commits_with_sig.push(
            cur_witness_iter
                .by_ref()
                .take((message_digits + checksum_digits) * 2)
                .map(|x| x.to_vec())
                .collect(),
        );
    }

    Ok(commits_with_sig)
}
