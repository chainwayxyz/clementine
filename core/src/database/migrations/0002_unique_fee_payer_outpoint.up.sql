-- Prevent two protocol transactions from aliasing the same fee payer outpoint.
CREATE UNIQUE INDEX IF NOT EXISTS tx_sender_fee_payer_utxos_outpoint_idx
    ON tx_sender_fee_payer_utxos (fee_payer_txid, vout);
