-- Soft-deleted API key tombstone rows cannot be restored; their contents
-- were already scrubbed before this migration removed them.
SELECT 1;
