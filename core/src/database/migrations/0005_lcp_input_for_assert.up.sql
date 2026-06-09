ALTER TABLE lcp_for_asserts
    ADD COLUMN IF NOT EXISTS lcp_input bytea;

ALTER TABLE lcp_for_asserts
    ALTER COLUMN lcp_receipt DROP NOT NULL;
