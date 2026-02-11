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
