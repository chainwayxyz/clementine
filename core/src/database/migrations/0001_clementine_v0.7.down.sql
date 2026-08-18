DROP INDEX IF EXISTS bitcoin_syncer_txs_txid_idx;
DROP INDEX IF EXISTS bitcoin_syncer_spent_utxos_txid_vout_idx;

-- Reverse the sat/vB -> sat/kWU conversion of effective_fee_rate.
UPDATE tx_sender_try_to_send_txs
SET effective_fee_rate = effective_fee_rate / 250
WHERE effective_fee_rate IS NOT NULL;
