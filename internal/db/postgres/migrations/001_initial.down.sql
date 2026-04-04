-- 001_initial.down.sql
-- Reverse of 001_initial.up.sql. Drop in dependency order.

DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS admin_audit_log;
DROP TABLE IF EXISTS admin_auth;
DROP TABLE IF EXISTS scan_log;
DROP TABLE IF EXISTS refresh_queue;
DROP TABLE IF EXISTS feed_sync_status;
DROP TABLE IF EXISTS package_check_status;
DROP TABLE IF EXISTS malicious_findings;
DROP TABLE IF EXISTS affected_packages;
DROP TABLE IF EXISTS vulnerability_references;
DROP TABLE IF EXISTS vulnerability_sources;
DROP TABLE IF EXISTS vulnerability_aliases;
DROP TABLE IF EXISTS vulnerabilities;
