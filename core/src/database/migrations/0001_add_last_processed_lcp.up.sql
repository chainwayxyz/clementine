-- Add last_processed_lcp column to state_manager_status table
ALTER TABLE state_manager_status
ADD COLUMN IF NOT EXISTS last_processed_lcp INT DEFAULT NULL;