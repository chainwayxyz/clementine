use bitcoin::{absolute, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness};

/// Creates a Bitcoin V3 transaction with no locktime, using given inputs and
/// outputs.
pub fn create_btc_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version(3),
        lock_time: absolute::LockTime::from_consensus(0),
        input: tx_ins,
        output: tx_outs,
    }
}

pub struct TxInArgs(pub Vec<(OutPoint, Option<u16>)>);

impl From<Vec<OutPoint>> for TxInArgs {
    fn from(outpoints: Vec<OutPoint>) -> TxInArgs {
        TxInArgs(
            outpoints
                .into_iter()
                .map(|outpoint| (outpoint, None))
                .collect(),
        )
    }
}

impl From<Vec<(OutPoint, Option<u16>)>> for TxInArgs {
    fn from(value: Vec<(OutPoint, Option<u16>)>) -> TxInArgs {
        TxInArgs(value)
    }
}

/// Creates a Vec of TxIn from a TxInArgs (helper struct to represent args)
/// If only a Vec of OutPoints are provided there are no relative locktimes
/// If at least one TxIn requires a locktime, a Vec of (OutPoint, Option<u16>) is required
/// Option represents Some(locktime) or None if there is no locktime for that TxIn
pub fn create_tx_ins(tx_in_args: TxInArgs) -> Vec<TxIn> {
    tx_in_args
        .0
        .into_iter()
        .map(|(outpoint, height)| TxIn {
            previous_output: outpoint,
            sequence: match height {
                Some(h) => bitcoin::transaction::Sequence::from_height(h),
                None => bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            },
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        })
        .collect()
}

pub fn create_tx_outs(pairs: Vec<(Amount, ScriptBuf)>) -> Vec<TxOut> {
    let mut tx_outs = Vec::new();

    for pair in pairs {
        tx_outs.push(TxOut {
            value: pair.0,
            script_pubkey: pair.1,
        });
    }

    tx_outs
}
