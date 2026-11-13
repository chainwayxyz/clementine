//! Real proofs shared between test actors.

use bridge_circuit_host::guests::Guest;
use bridge_circuit_host::sp1::Backend;
use circuits_lib::common::sp1::Receipt;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::sync::OnceCell;

type Proofs = Mutex<HashMap<Vec<u8>, Arc<OnceCell<Receipt>>>>;
static PROOFS: LazyLock<Proofs> = LazyLock::new(Default::default);

/// Runs `proof` of `guest` for `input`, unless an actor already proved the same input with a
/// real backend. Actors run in one process with separate databases and often prove the same
/// chain. Concurrent identical requests wait for the first proof.
///
/// The receipt depends only on the program and the input, not on which receipts of the
/// assumptions were used, so the input is the whole key.
pub fn share<F>(
    guest: &Guest,
    backend: Backend,
    input: &impl borsh::BorshSerialize,
    proof: F,
) -> impl Future<Output = eyre::Result<Receipt>>
where
    F: Future<Output = eyre::Result<Receipt>>,
{
    let key = borsh::to_vec(&(guest.key.groth16, input));
    async move {
        if backend == Backend::Mock {
            return proof.await;
        }
        let shared = PROOFS
            .lock()
            .expect("test proof cache poisoned")
            .entry(key?)
            .or_default()
            .clone();
        let mut proved = false;
        let receipt = shared
            .get_or_try_init(|| {
                proved = true;
                proof
            })
            .await?;
        if !proved {
            tracing::info!("Reusing the same proof from another test actor");
        }
        Ok(receipt.clone())
    }
}
