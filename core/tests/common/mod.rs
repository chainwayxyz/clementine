//! # Common Utilities for Integration Tests

mod deposit;

pub use deposit::*;

#[path = "../../src/mock_macro.rs"]
mod mock_macro;
