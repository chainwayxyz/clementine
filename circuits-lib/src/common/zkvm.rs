//! # ZkVM Module
//! This module defines the `ZkvmGuest` trait for reading from the host, committing data and
//! verifying proofs inside a guest. The `SP1Guest` struct in [`super::sp1`] implements it for
//! the SP1 zkVM.

/// Guest I/O and proof verification, implemented by the SP1 guest and by native test mocks.
pub trait ZkvmGuest {
    fn read_from_host<T: borsh::BorshDeserialize>(&self) -> T;
    fn commit<T: borsh::BorshSerialize>(&self, item: &T);
    fn verify<T: borsh::BorshSerialize>(&self, method_id: [u32; 8], journal: &T);
}
