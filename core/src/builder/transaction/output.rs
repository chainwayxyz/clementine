use bitcoin::{taproot::TaprootSpendInfo, Amount, ScriptBuf, TxOut};

#[derive(Debug, Clone)]
pub struct UnspentTxOut {
    txout: TxOut,
    scripts: Vec<ScriptBuf>, // TODO: Remove either scripts or spendinfo
    spendinfo: Option<TaprootSpendInfo>,
}

impl UnspentTxOut {
    pub fn from_partial(txout: TxOut) -> UnspentTxOut {
        UnspentTxOut {
            txout,
            scripts: vec![],
            spendinfo: None,
        }
    }
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

    pub fn txout(&self) -> &TxOut {
        &self.txout
    }

    pub fn scripts(&self) -> &Vec<ScriptBuf> {
        &self.scripts
    }

    pub fn spendinfo(&self) -> &Option<TaprootSpendInfo> {
        &self.spendinfo
    }

    pub fn set_spendinfo(&mut self, spendinfo: Option<TaprootSpendInfo>) {
        self.spendinfo = spendinfo;
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
