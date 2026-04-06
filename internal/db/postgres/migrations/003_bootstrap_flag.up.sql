-- 003_bootstrap_flag.up.sql
-- Adds a flag to track whether the admin password is still the initial
-- bootstrap value from PACKMON_ADMIN_INITIAL_PASSWORD. The admin
-- dashboard shows a warning when this is true.

ALTER TABLE admin_auth
    ADD COLUMN password_is_bootstrap BOOLEAN NOT NULL DEFAULT TRUE;
