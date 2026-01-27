-- Remove last_processed_lcp column from state_manager_status table
ALTER TABLE state_manager_status DROP COLUMN IF EXISTS last_processed_lcp;