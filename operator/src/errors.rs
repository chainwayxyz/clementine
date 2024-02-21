#[derive(Debug)]
pub enum BridgeError {
    OperatorPendingDeposit,
    InvalidPeriod,
    Error,
}
use std::fmt;

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BridgeError::OperatorPendingDeposit => write!(f, "Pending deposit"),
            BridgeError::InvalidPeriod => write!(f, "Invalid period"),
            BridgeError::Error => write!(f, "Internal error"),
        }
    }
}

#[derive(Debug)]
pub enum DepositError {
    NotFinalized,
    InvalidAddressOrAmount,
    AlreadySpent,
}

impl fmt::Display for DepositError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DepositError::NotFinalized => write!(f, "Deposit utxo not finalized yet"),
            DepositError::InvalidAddressOrAmount => write!(f, "Deposit utxo address or amount not valid"),
            DepositError::AlreadySpent => write!(f, "Deposit utxo already spent"),
        }
    }
}