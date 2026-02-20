-- Remove possible_kickoffs and kickoff_finalizers_spent from round_tx state.
UPDATE state_machines
SET state_json = (
    jsonb_set(
        state_json::jsonb,
        '{state,RoundTx}',
        (state_json::jsonb -> 'state' -> 'RoundTx')
            - 'possible_kickoffs'
            - 'kickoff_finalizers_spent'
    )
)::text
WHERE machine_type = 'round'
  AND state_json::jsonb -> 'state' ? 'RoundTx';

ALTER TABLE IF EXISTS tx_sender_try_to_send_txs
DROP COLUMN IF EXISTS input_unspent_timed_out;

ALTER TABLE IF EXISTS tx_sender_try_to_send_txs
DROP COLUMN IF EXISTS input_unspent_failures;
