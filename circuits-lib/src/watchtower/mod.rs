use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WatchtowerCircuitInput {}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WatchtowerCircuitOutput {}
