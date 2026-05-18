use crate::protocol::ids::{Actor, Input, Leaf, Output, TransactionType};
use bitcoin::Sequence;
use tx_builder::spec::{
    InputSource as RuntimeInputSource, InputSpec as RuntimeInputSpec,
    SpendSpec as RuntimeSpendSpec, TxSpec as RuntimeTxSpec,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExternalInput {
    DepositOutpoint,
    WithdrawalUtxo,
    OperatorCollateral,
}

pub type TxSpec<I = Input, O = Output> = RuntimeTxSpec<I, O>;
pub type InputSource = RuntimeInputSource<TransactionType, Output, ExternalInput>;
pub type SpendSpec = RuntimeSpendSpec<Leaf, Actor>;
pub type InputSpec =
    RuntimeInputSpec<TransactionType, Output, ExternalInput, Leaf, Actor, Sequence>;
