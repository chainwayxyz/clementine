use crate::errors::BridgeError;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::{
    taproot::TaprootSpendInfo, ScriptBuf, TapLeafHash, TapSighash, TapSighashType, TxOut, Txid,
};

/// Verbose information about a transaction.
#[derive(Debug, Clone)]
pub struct TxHandler {
    /// Transaction itself.
    pub tx: bitcoin::Transaction,
    /// Txid of the transaction, saved here to not repeatedly calculate it.
    pub txid: Txid,
    /// Previous outputs in [`TxOut`] format.
    pub prevouts: Vec<TxOut>,
    /// Taproot scripts for each previous output.
    pub prev_scripts: Vec<Vec<ScriptBuf>>,
    /// Taproot spend information for each previous output.
    pub prev_taproot_spend_infos: Vec<Option<TaprootSpendInfo>>,
    /// Taproot scripts for each tx output.
    pub out_scripts: Vec<Vec<ScriptBuf>>,
    /// Taproot spend information for each tx output.
    pub out_taproot_spend_infos: Vec<Option<TaprootSpendInfo>>,
}

impl TxHandler {
    /// Calculates the sighash for a given transaction input for key spend path.
    /// See [`bitcoin::sighash::SighashCache::taproot_key_spend_signature_hash`] for more details.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn calculate_pubkey_spend_sighash(
        &mut self,
        txin_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<TapSighash, BridgeError> {
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut self.tx);
        let prevouts = &match sighash_type {
            Some(TapSighashType::SinglePlusAnyoneCanPay)
            | Some(TapSighashType::AllPlusAnyoneCanPay)
            | Some(TapSighashType::NonePlusAnyoneCanPay) => {
                bitcoin::sighash::Prevouts::One(txin_index, self.prevouts[txin_index].clone())
            }
            _ => bitcoin::sighash::Prevouts::All(&self.prevouts),
        };

        let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
            txin_index,
            prevouts,
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        Ok(sig_hash)
    }

    /// Calculates the sighash for a given transaction input for script spend path.
    /// See [`bitcoin::sighash::SighashCache::taproot_script_spend_signature_hash`] for more details.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn calculate_script_spend_sighash(
        &mut self,
        txin_index: usize,
        script_index: usize,
        sighash_type: Option<TapSighashType>,
    ) -> Result<TapSighash, BridgeError> {
        let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
            SighashCache::new(&mut self.tx);

        let prevouts = &match sighash_type {
            Some(TapSighashType::SinglePlusAnyoneCanPay)
            | Some(TapSighashType::AllPlusAnyoneCanPay)
            | Some(TapSighashType::NonePlusAnyoneCanPay) => {
                bitcoin::sighash::Prevouts::One(txin_index, self.prevouts[txin_index].clone())
            }
            _ => bitcoin::sighash::Prevouts::All(&self.prevouts),
        };
        let leaf_hash = TapLeafHash::from_script(
            self.prev_scripts
                .get(txin_index)
                .ok_or(BridgeError::NoScriptsForTxIn(txin_index))?
                .get(script_index)
                .ok_or(BridgeError::NoScriptAtIndex(script_index))?,
            LeafVersion::TapScript,
        );
        let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
            txin_index,
            prevouts,
            leaf_hash,
            sighash_type.unwrap_or(TapSighashType::Default),
        )?;

        Ok(sig_hash)
    }
}
