use bitcoin::{taproot::TaprootSpendInfo, Amount, ScriptBuf, TxOut};

#[derive(Debug, Clone)]
pub struct UnspentTxOut {
    pub txout: TxOut,
    pub scripts: Vec<ScriptBuf>, // TODO: Remove either scripts or spendinfo
    pub spendinfo: Option<TaprootSpendInfo>,
}

impl UnspentTxOut {
    pub fn new(
        txout: TxOut,
        scripts: Vec<ScriptBuf>,
        spendinfo: Option<TaprootSpendInfo>,
    ) -> UnspentTxOut {
        UnspentTxOut {
            txout,
            scripts,
            spendinfo,
        }
    }
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
