use crate::builder::address::create_taproot_address;
use crate::builder::script::SpendableScript;
use bitcoin::{taproot::TaprootSpendInfo, Amount, ScriptBuf, TxOut, XOnlyPublicKey};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct UnspentTxOut {
    txout: TxOut,
    scripts: Vec<Arc<dyn SpendableScript>>, // TODO: Remove either scripts or spendinfo
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
        scripts: Vec<Arc<dyn SpendableScript>>,
        spendinfo: Option<TaprootSpendInfo>,
    ) -> UnspentTxOut {
        UnspentTxOut {
            txout,
            scripts,
            spendinfo,
        }
    }

    pub fn from_scripts(
        value: Amount,
        scripts: Vec<Arc<dyn SpendableScript>>,
        key_path: Option<XOnlyPublicKey>,
        network: bitcoin::Network,
    ) -> UnspentTxOut {
        let script_bufs : Vec<ScriptBuf> = scripts
            .iter()
            .map(|script| script.clone().to_script_buf())
            .collect();
        let (addr, spend_info) = create_taproot_address(&script_bufs, key_path, network);
        Self::new(
            TxOut {
                value,
                script_pubkey: addr.script_pubkey(),
            },
            scripts,
            Some(spend_info),
        )
    }

    pub fn txout(&self) -> &TxOut {
        &self.txout
    }

    pub fn scripts(&self) -> &Vec<Arc<dyn SpendableScript>> {
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
