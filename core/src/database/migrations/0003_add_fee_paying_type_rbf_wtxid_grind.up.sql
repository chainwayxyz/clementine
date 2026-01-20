-- Add new fee paying strategy for tx-sender
DO $$ BEGIN -- Adding an enum value is idempotent in PG 15+ with IF NOT EXISTS.
-- (We still wrap in DO $$ for compatibility with older scripts.)
ALTER TYPE fee_paying_type
ADD VALUE IF NOT EXISTS 'rbf_wtxid_grind';
END $$;