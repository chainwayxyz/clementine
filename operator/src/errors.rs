#[derive(Debug)]
pub enum BridgeError {
    OperatorPendingDeposit,
    InvalidPeriod,
}
use std::fmt;

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BridgeError::OperatorPendingDeposit => write!(f, "Pending deposit"),
            BridgeError::InvalidPeriod => write!(f, "Invalid period"),
        }
    }
}
