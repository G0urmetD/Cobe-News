-- Cobe News: the database lock of the audit log (Protokoll, table public.audit_log). Run by db-init.sh as the superuser
-- at every start of the database image, after app-role.sql; idempotent. docs/BETRIEB.md: Protokoll, Datenbank-Sperre.
--
-- The table belongs to its own role, cobe_news_audit (NOLOGIN: nobody signs in as it, nobody is a member of it), and so
-- does the schema public – the app (cobe_news_app) keeps the database, its own tables and the right to create in
-- public, but can no longer drop, alter, empty or change the audit log: it may read it and add entries (SELECT,
-- INSERT), and seal an entry (UPDATE of the chain's columns, only while the entry is unsealed). Deleting goes through
-- two functions of the lock role only (SECURITY DEFINER): prune() – entries in chain order that are older than the
-- retention, never than 90 days – and set_aside() for a restore, which moves the entries into
-- cobe_news_audit.audit_log_replaced instead of deleting them. A trigger refuses everything else, also for an owner.
--
-- What it protects against: a compromised app, a stolen app password, an SQL injection. Not against the superuser or
-- someone with access to Docker on the host (both can lift the lock).
--
-- A new database (the app has not made its tables yet): only the role and the functions now – the lock follows when
-- cobe-news-db.sh sees the table (it runs this file again then), else at the next start of the database. Without this image (a PostgreSQL of one's own) nothing of it exists: the app works
-- as before and shows the lock as not active.
SET client_min_messages = warning;
SET search_path = pg_catalog, pg_temp;  -- as app-role.sql: nothing of the app's runs here as the superuser
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cobe_news_audit') AS missing \gset
\if :missing
CREATE ROLE cobe_news_audit NOLOGIN;
\echo 'db-init: role cobe_news_audit created'
\endif
ALTER ROLE cobe_news_audit WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
-- never a member of another role, and no role a member of it
SELECT format('REVOKE %I FROM %I', r.rolname, u.rolname) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
 WHERE m.member = 'cobe_news_audit'::regrole OR m.roleid = 'cobe_news_audit'::regrole \gexec

-- each part in one transaction: an app that is connected meanwhile (a restart of the database alone) never sees a
-- right taken away and not yet given again
BEGIN;
CREATE SCHEMA IF NOT EXISTS cobe_news_audit AUTHORIZATION cobe_news_audit;
ALTER SCHEMA cobe_news_audit OWNER TO cobe_news_audit;
REVOKE ALL ON SCHEMA cobe_news_audit FROM PUBLIC;
GRANT USAGE ON SCHEMA cobe_news_audit TO cobe_news_app;

SET ROLE cobe_news_audit;

-- what a restore set aside (set_aside below): the entries as they were, kept – never deleted but by the retention
CREATE TABLE IF NOT EXISTS cobe_news_audit.audit_log_replaced (
  replaced_at timestamptz NOT NULL DEFAULT now(),
  id bigint NOT NULL,
  at timestamptz NOT NULL,
  entry jsonb NOT NULL,
  PRIMARY KEY (replaced_at, id)
);

-- the trigger on public.audit_log: UPDATE, DELETE, TRUNCATE refused – but sealing (an unsealed entry gets its place in
-- the chain, its hash and perhaps a mark; nothing else of it changes) and the deletions of the two functions below
CREATE OR REPLACE FUNCTION cobe_news_audit.guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $guard$
DECLARE
  chain CONSTANT text[] := ARRAY['seq', 'prev_hash', 'hash', 'details', 'notable'];
BEGIN
  IF TG_OP = 'DELETE' AND TG_LEVEL = 'ROW' AND current_user = 'cobe_news_audit' THEN
    RETURN OLD;  -- prune() or set_aside(): only they run as this role
  END IF;
  IF TG_OP = 'UPDATE' AND TG_LEVEL = 'ROW' THEN
    IF OLD.seq IS NULL AND NEW.seq IS NOT NULL
       AND (to_jsonb(NEW) - chain) = (to_jsonb(OLD) - chain)
       AND (NEW.details - 'anomalies') = (OLD.details - 'anomalies')
       AND (NEW.notable OR NOT OLD.notable) THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'the audit log is locked: % refused', TG_OP
    USING ERRCODE = 'insufficient_privilege', HINT = 'docs/BETRIEB.md: Protokoll, Datenbank-Sperre';
END
$guard$;

-- the retention: entries in chain order up to position p_upto – refused when one of them is still within the
-- retention (p_keep_days, never fewer than 90 days; an entry more than a day in the future does not count, as in
-- audit.prune). Also what a restore set aside, older than the same limit. Returns the entries deleted.
CREATE OR REPLACE FUNCTION cobe_news_audit.prune(p_upto bigint, p_keep_days integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $prune$
DECLARE
  cut timestamptz := now() - make_interval(days => greatest(coalesce(p_keep_days, 0), 90));
  n bigint;
BEGIN
  IF EXISTS (SELECT 1 FROM public.audit_log a WHERE a.seq <= p_upto AND a.at >= cut AND a.at <= now() + interval '1 day') THEN
    RAISE EXCEPTION 'audit log prune refused: entries up to position % are not all older than % days', p_upto, greatest(coalesce(p_keep_days, 0), 90)
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  DELETE FROM public.audit_log a WHERE a.seq <= p_upto;
  GET DIAGNOSTICS n = ROW_COUNT;
  DELETE FROM cobe_news_audit.audit_log_replaced r WHERE r.at < cut;
  RETURN n;
END
$prune$;

-- a restore (app/backup.py): the entries of the log set aside – copied into audit_log_replaced, then removed – before
-- the backup's entries come in. In the restore's one transaction: a failed restore keeps them where they were.
CREATE OR REPLACE FUNCTION cobe_news_audit.set_aside() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $aside$
DECLARE
  n bigint;
BEGIN
  INSERT INTO cobe_news_audit.audit_log_replaced (id, at, entry) SELECT a.id, a.at, to_jsonb(a) FROM public.audit_log a;
  GET DIAGNOSTICS n = ROW_COUNT;
  DELETE FROM public.audit_log;
  -- a WARNING (in the server's log and to the caller): the app calls it only in a restore – anyone else with the app's
  -- password could call it too (the entries are kept, the Protokoll shows their number)
  RAISE WARNING 'cobe_news_audit: set_aside() moved % audit log entries to cobe_news_audit.audit_log_replaced (a restore – if none ran now, someone used the app''s password)', n;
  RETURN n;
END
$aside$;

-- after the backup's entries came in: the identity sequence behind the highest id (the app may not set it itself)
CREATE OR REPLACE FUNCTION cobe_news_audit.restored() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $restored$
DECLARE
  top bigint := (SELECT max(a.id) FROM public.audit_log a);
BEGIN
  PERFORM setval(pg_get_serial_sequence('public.audit_log', 'id'), coalesce(top, 1), top IS NOT NULL);
  RETURN coalesce(top, 0);
END
$restored$;

RESET ROLE;

REVOKE ALL ON TABLE cobe_news_audit.audit_log_replaced FROM PUBLIC;
GRANT SELECT ON TABLE cobe_news_audit.audit_log_replaced TO cobe_news_app;
REVOKE ALL ON FUNCTION cobe_news_audit.guard(), cobe_news_audit.prune(bigint, integer), cobe_news_audit.set_aside(), cobe_news_audit.restored() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cobe_news_audit.prune(bigint, integer), cobe_news_audit.set_aside(), cobe_news_audit.restored() TO cobe_news_app;
COMMIT;

SELECT to_regclass('public.audit_log') IS NULL AS no_table \gset
\if :no_table
\echo 'db-init: audit log lock follows once the app has made the table at its first start (cobe-news-db.sh watches for it) – else at the next start of the database'
\quit
\endif

-- the table handed over – only as the migrations make it: no trigger, rule or row security of anyone else (code of
-- the app that would then run as cobe_news_audit). Otherwise it stays as it is (not locked) and the log says why.
-- Checked and handed over in one transaction, the table locked meanwhile: nothing can be added between the two.
BEGIN;
LOCK TABLE public.audit_log IN ACCESS EXCLUSIVE MODE;
SELECT concat_ws(', ',
         (SELECT 'triggers ' || string_agg(t.tgname, ' ') FROM pg_trigger t WHERE t.tgrelid = 'public.audit_log'::regclass AND NOT t.tgisinternal
             AND t.tgname NOT IN ('cobe_news_audit_lock', 'cobe_news_audit_lock_truncate')),
         (SELECT 'rules ' || string_agg(r.rulename, ' ') FROM pg_rewrite r WHERE r.ev_class = 'public.audit_log'::regclass),
         (SELECT 'policies ' || string_agg(p.polname, ' ') FROM pg_policy p WHERE p.polrelid = 'public.audit_log'::regclass),
         (SELECT 'row security' FROM pg_class c WHERE c.oid = 'public.audit_log'::regclass AND (c.relrowsecurity OR c.relforcerowsecurity)),
         (SELECT 'owner ' || pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'public.audit_log'::regclass
             AND pg_get_userbyid(c.relowner) NOT IN ('cobe_news_app', 'cobe_news_audit'))
       ) AS odd \gset
SELECT :'odd' <> '' AS refused \gset
\if :refused
\echo 'db-init: WARNING – audit log NOT locked, unexpected on public.audit_log:' :odd '(docs/BETRIEB.md: Protokoll, Datenbank-Sperre)'
ROLLBACK;
\quit
\endif

-- the table's shape of migrations 0032 and 0033, as they make it: locked, the app's migrations leave audit_log alone
-- (audit_lock.ddl_skipped) – an install from before 0.1.50 (revision 0017 … 0031) updating straight to this image gets
-- the columns here, before the handover (without them the GRANT below fails and the database never becomes ready)
SELECT NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'public.audit_log'::regclass AND attname = 'seq' AND NOT attisdropped) AS before_0032 \gset
\if :before_0032
ALTER TABLE public.audit_log
  ADD COLUMN actor_role text, ADD COLUMN auth_method text, ADD COLUMN session_ref text, ADD COLUMN ua_family text,
  ADD COLUMN ua_version text, ADD COLUMN ua_os text, ADD COLUMN req_method text, ADD COLUMN req_path text,
  ADD COLUMN request_id text, ADD COLUMN req_via text, ADD COLUMN app_version text, ADD COLUMN prev_hash text,
  ADD COLUMN hash text, ADD COLUMN actor_emergency boolean, ADD COLUMN notable boolean DEFAULT false NOT NULL,
  ADD COLUMN seq bigint;
UPDATE public.audit_log SET notable = true WHERE action IN ('login.locked', 'login.ip_blocked', 'login.emergency_slowed',
  'role.changed', 'token.created', 'token.revoked', 'sessions.revoked', 'backup.restored', 'audit.exported',
  'passkey.sign_count_warning', 'setup.completed');
CREATE INDEX ix_audit_log_kind ON public.audit_log (actor_kind, at) WHERE actor_kind <> 'user';
CREATE INDEX ix_audit_log_ip ON public.audit_log (ip, at) WHERE ip IS NOT NULL;
CREATE INDEX ix_audit_log_session ON public.audit_log (session_ref, at) WHERE session_ref IS NOT NULL;
CREATE INDEX ix_audit_log_notable ON public.audit_log (at, id) WHERE notable;
CREATE UNIQUE INDEX ux_audit_log_seq ON public.audit_log (seq) WHERE seq IS NOT NULL;
CREATE INDEX ix_audit_log_unsealed ON public.audit_log (id) WHERE seq IS NULL;
\echo 'db-init: audit_log brought to the shape of migration 0032 before the lock'
\endif
-- 0033 – only with pg_trgm there (since migration 0002; the app owns the extension and could drop it, and that must
-- not stop the database from starting)
SELECT to_regclass('public.ix_audit_log_search') IS NULL AND EXISTS (SELECT 1 FROM pg_opclass WHERE opcname = 'gin_trgm_ops' AND opcnamespace = 'public'::regnamespace) AS before_0033 \gset
\if :before_0033
CREATE INDEX ix_audit_log_search ON public.audit_log USING gin
  (lower(actor_name || ' ' || actor_display || ' ' || action || ' ' || coalesce(target_label, '') || ' ' || coalesce(target_id, '') || ' ' || coalesce(ip, '')) public.gin_trgm_ops);
\endif

ALTER TABLE public.audit_log OWNER TO cobe_news_audit;  -- its indexes and its identity sequence with it
REVOKE ALL ON TABLE public.audit_log FROM PUBLIC, cobe_news_app;
GRANT SELECT, INSERT ON TABLE public.audit_log TO cobe_news_app;
GRANT UPDATE (seq, prev_hash, hash, details, notable) ON TABLE public.audit_log TO cobe_news_app;
SELECT format('REVOKE ALL ON SEQUENCE %s FROM PUBLIC, cobe_news_app', pg_get_serial_sequence('public.audit_log', 'id')) \gexec
SELECT format('GRANT USAGE, SELECT ON SEQUENCE %s TO cobe_news_app', pg_get_serial_sequence('public.audit_log', 'id')) \gexec
CREATE OR REPLACE TRIGGER cobe_news_audit_lock BEFORE UPDATE OR DELETE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION cobe_news_audit.guard();
CREATE OR REPLACE TRIGGER cobe_news_audit_lock_truncate BEFORE TRUNCATE ON public.audit_log FOR EACH STATEMENT EXECUTE FUNCTION cobe_news_audit.guard();
-- also with session_replication_role = replica (only a superuser may set it)
ALTER TABLE public.audit_log ENABLE ALWAYS TRIGGER cobe_news_audit_lock;
ALTER TABLE public.audit_log ENABLE ALWAYS TRIGGER cobe_news_audit_lock_truncate;
-- the schema too: its owner could drop any table in it (DROP TABLE, DROP SCHEMA … CASCADE) – the app keeps creating
-- its own tables there (CREATE) and dropping them (as their owner)
ALTER SCHEMA public OWNER TO cobe_news_audit;
REVOKE ALL ON SCHEMA public FROM cobe_news_app;
GRANT USAGE, CREATE ON SCHEMA public TO cobe_news_app;
GRANT USAGE ON SCHEMA public TO PUBLIC;
COMMIT;
\echo 'db-init: audit log locked (owner cobe_news_audit – cobe_news_app may read and add entries, not change or delete them)'
