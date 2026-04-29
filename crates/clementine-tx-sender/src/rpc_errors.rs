use bitcoincore_rpc::Error;

pub(crate) fn is_not_found_error(err: &Error) -> bool {
    let s = err.to_string();
    // Keep this narrow: Bitcoin Core also prefixes txindex-disabled and
    // txindex-still-indexing errors with "No such mempool transaction". Those
    // are node-readiness/configuration errors, not definitive absence.
    s.contains("No such mempool or blockchain transaction")
        || s.contains("No such transaction found in the provided block")
}

pub(crate) fn is_mempool_not_found_error(err: &Error) -> bool {
    let s = err.to_string();
    s.contains("Transaction not in mempool")
}

pub(crate) fn is_rejecting_replacement_error(s: &str) -> bool {
    s.contains("insufficient fee, rejecting replacement")
}
