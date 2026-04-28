-- Drop legacy tx_sender cancel/activate helper tables.
DROP TABLE IF EXISTS tx_sender_cancel_try_to_send_txids;
DROP TABLE IF EXISTS tx_sender_cancel_try_to_send_outpoints;
DROP TABLE IF EXISTS tx_sender_activate_try_to_send_outpoints;

-- Migrate existing round state machines in round_tx state to include
-- the possible_kickoffs and kickoff_finalizers_spent tracking fields.
UPDATE state_machines
SET state_json = (
    jsonb_set(
        state_json::jsonb,
        '{state,RoundTx}',
        (state_json::jsonb -> 'state' -> 'RoundTx')
            || '{"possible_kickoffs": {}, "kickoff_finalizers_spent": []}'::jsonb
    )
)::text
WHERE machine_type = 'round'
  AND state_json::jsonb -> 'state' ? 'RoundTx';

-- Track repeated "inputs unavailable" checks and stop retrying permanently
-- stuck transactions after a bounded number of attempts.
ALTER TABLE IF EXISTS tx_sender_try_to_send_txs
ADD COLUMN IF NOT EXISTS input_unspent_failures INT NOT NULL DEFAULT 0;

ALTER TABLE IF EXISTS tx_sender_try_to_send_txs
ADD COLUMN IF NOT EXISTS input_unspent_timed_out BOOLEAN NOT NULL DEFAULT FALSE;
