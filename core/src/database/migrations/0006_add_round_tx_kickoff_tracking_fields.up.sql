-- Migrate existing round state machines in round_tx state to include
-- the new possible_kickoffs and kickoff_finalizers_spent fields.
-- These fields are local state parameters added to the round_tx state
-- function for tracking possible kickoffs and their finalizer spend status.
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
