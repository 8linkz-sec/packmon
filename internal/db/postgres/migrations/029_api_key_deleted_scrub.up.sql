UPDATE api_keys
SET name = '',
    key_hash = 'deleted:' || id::text
WHERE deleted_at IS NOT NULL;
