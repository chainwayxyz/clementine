TRUNCATE TABLE lcp_for_asserts;

ALTER TABLE lcp_for_asserts
    DROP COLUMN IF EXISTS lcp_input;

ALTER TABLE lcp_for_asserts
    ADD COLUMN lcp_receipt bytea NOT NULL;
