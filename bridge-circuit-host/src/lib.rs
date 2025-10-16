use eyre::bail;
use risc0_zkvm::{InnerReceipt, Receipt};

pub mod bridge_circuit_host;
pub mod docker;
pub mod mock_zkvm;
mod seal_format;
pub mod structs;
pub mod utils;

/// Converts an `InnerReceipt` into a `Receipt`, ensuring all required fields are present.
///
/// # Arguments
/// * `inner` - The `InnerReceipt` to extract data from.
///
/// # Returns
/// Returns a `Receipt` if all required fields are found, otherwise returns an error.
///
/// # Errors
/// This function can return an error in the following cases:
/// * If `inner.claim()` is empty.
/// * If `claim.value()` is empty.
/// * If `claim.output.value()` is empty.
/// * If `output` is `None`.
/// * If `output.journal.value()` is empty.
pub fn receipt_from_inner(inner: InnerReceipt) -> eyre::Result<Receipt> {
    let mb_claim = inner.claim().or_else(|_| bail!("Claim is empty"))?;
    let claim = mb_claim
        .value()
        .or_else(|_| bail!("Claim content is empty"))?;
    let output = claim
        .output
        .value()
        .or_else(|_| bail!("Output content is empty"))?;
    let Some(output) = output else {
        bail!("Output body is empty");
    };
    let journal = output
        .journal
        .value()
        .or_else(|_| bail!("Journal content is empty"))?;
    Ok(Receipt::new(inner, journal))
}
