-- Cobe News: the restore test's throwaway database and its own role (app/restore_test.py; docs/BETRIEB.md: Rücksicherungs-Test).
-- Run by db-init.sh as the superuser – only when POSTGRES_RESTORE_PASSWORD is set; idempotent.
-- The role cobe_news_restore owns the database cobe_news_restore_test and nothing else: no superuser, no new roles or
-- databases, no member of cobe_news_app, and no connection to the app's database (REVOKE … FROM PUBLIC in app-role.sql;
-- checked below). The app's own role gets no right here: a restore test can never touch the real data.
SET search_path = pg_catalog, pg_temp;  -- as app-role.sql
\getenv restore_password POSTGRES_RESTORE_PASSWORD
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cobe_news_restore') AS missing \gset
\if :missing
CREATE ROLE cobe_news_restore NOLOGIN;
\echo 'db-init: role cobe_news_restore created'
\endif
ALTER ROLE cobe_news_restore WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 3 PASSWORD :'restore_password';
-- never a member of another role (or another role of it)
SELECT format('REVOKE %I FROM cobe_news_restore', r.rolname) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
 WHERE m.member = 'cobe_news_restore'::regrole \gexec
SELECT NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'cobe_news_restore_test') AS missing_db \gset
\if :missing_db
-- the same byte order as the app's database (docker-compose.yml: builtin C.UTF-8)
CREATE DATABASE cobe_news_restore_test OWNER cobe_news_restore TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8';
\echo 'db-init: database cobe_news_restore_test created'
\endif
ALTER DATABASE cobe_news_restore_test OWNER TO cobe_news_restore;
REVOKE ALL ON DATABASE cobe_news_restore_test FROM PUBLIC;
-- the app's database stays closed to it (app-role.sql revokes PUBLIC's rights; nothing may have granted it one)
REVOKE ALL ON DATABASE :"DBNAME" FROM cobe_news_restore;
SELECT has_database_privilege('cobe_news_restore', :'DBNAME', 'CONNECT') AS leaks \gset
\if :leaks
\echo 'db-init: cobe_news_restore may connect to the app database – refused'
SELECT 1/0;
\endif
\echo 'db-init: cobe_news_restore ready (owner of cobe_news_restore_test only)'
