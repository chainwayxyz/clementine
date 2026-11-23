use std::sync::Mutex;

use circuits_lib::common::zkvm::ZkvmGuest;

/// Runs guest code natively: reads a fixed input and records the committed bytes. Proof
/// verification is skipped.
#[derive(Debug, Default)]
pub struct MockZkvmGuest {
    input: Vec<u8>,
    journal: Mutex<Vec<u8>>,
}

impl MockZkvmGuest {
    pub fn new(input: &impl borsh::BorshSerialize) -> Self {
        Self {
            input: borsh::to_vec(input).unwrap(),
            journal: Mutex::default(),
        }
    }

    /// The bytes the guest has committed so far.
    pub fn journal(&self) -> Vec<u8> {
        self.journal.lock().unwrap().clone()
    }
}

impl ZkvmGuest for MockZkvmGuest {
    fn read_from_host<T: borsh::BorshDeserialize>(&self) -> T {
        T::try_from_slice(&self.input).unwrap()
    }

    fn commit<T: borsh::BorshSerialize>(&self, item: &T) {
        self.journal
            .lock()
            .unwrap()
            .extend(borsh::to_vec(item).unwrap());
    }

    fn verify<T: borsh::BorshSerialize>(&self, _method_id: [u32; 8], _journal: &T) {
        tracing::warn!("This is a mock zkvm guest, no real verification is done.");
    }
}
