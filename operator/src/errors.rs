#[derive(Debug)]
pub enum OperatorError {
    PendingDeposit,
    InvalidUtxo,
    DuplicateDeposit,
    ValidationFailure(String), // You can still use a String for dynamic error messages
    ResourceExhaustion,
    // Add more error types as needed
}
use std::fmt;

impl fmt::Display for OperatorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            OperatorError::PendingDeposit => write!(f, "Pending deposit"),
            OperatorError::InvalidUtxo => write!(f, "Invalid UTXO"),
            OperatorError::DuplicateDeposit => write!(f, "Duplicate deposit"),
            OperatorError::ValidationFailure(ref msg) => write!(f, "Validation failure: {}", msg),
            OperatorError::ResourceExhaustion => write!(f, "Resource exhaustion"),
            // Handle other errors as needed
        }
    }
}
