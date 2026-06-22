TRUNCATE TABLE lcp_for_asserts;

ALTER TABLE lcp_for_asserts
    DROP COLUMN IF EXISTS lcp_receipt;

ALTER TABLE lcp_for_asserts
    ADD COLUMN IF NOT EXISTS lcp_input bytea NOT NULL;
