use bitcoincore_rpc::Error;

pub(crate) fn is_not_found_error(err: &Error) -> bool {
    let s = err.to_string();
    s.contains("No such mempool or blockchain transaction")
        || s.contains("No such mempool transaction")
        || s.contains("No such transaction")
}

pub(crate) fn is_mempool_not_found_error(err: &Error) -> bool {
    let s = err.to_string();
    s.contains("Transaction not in mempool")
}
