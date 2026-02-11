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
