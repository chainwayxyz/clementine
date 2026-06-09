DELETE FROM lcp_for_asserts
WHERE lcp_receipt IS NULL;

ALTER TABLE lcp_for_asserts
    ALTER COLUMN lcp_receipt SET NOT NULL;

ALTER TABLE lcp_for_asserts
    DROP COLUMN IF EXISTS lcp_input;
