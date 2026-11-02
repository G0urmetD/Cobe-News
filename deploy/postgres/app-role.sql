-- Cobe News: the role the app connects with – owner of the database and its tables, but no superuser: it cannot run
-- programs on the database server (COPY … TO PROGRAM), read its files, create untrusted extensions or other roles.
-- Idempotent; run by db-init.sh as the superuser. docs/BETRIEB.md: PostgreSQL, Rollen.
\getenv app_password POSTGRES_APP_PASSWORD
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cobe_news_app') AS missing \gset
\if :missing
CREATE ROLE cobe_news_app LOGIN;
\echo 'db-init: role cobe_news_app created'
\endif
ALTER ROLE cobe_news_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT 50 PASSWORD :'app_password';
ALTER DATABASE :"DBNAME" OWNER TO cobe_news_app;
-- only the owner (and the superuser) may connect or create in it
REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
-- the schema public as PostgreSQL makes it: owned by pg_database_owner (= the owner of the database). A restore of up
-- to 0.1.21 re-created it as the superuser's, without usage for anyone else – the app would not even see its tables.
ALTER SCHEMA public OWNER TO pg_database_owner;
GRANT USAGE ON SCHEMA public TO PUBLIC;
COMMENT ON SCHEMA public IS 'standard public schema';
-- everything the superuser created so far (up to 0.1.21 the app ran as the superuser): tables with their indexes and
-- identity sequences, other sequences, views, functions and types – not the objects of an extension (pg_trgm).
DO $own$
DECLARE r record; n int := 0;
BEGIN
  FOR r IN
    SELECT c.oid::regclass AS obj, CASE c.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END AS kind
      FROM pg_class c
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
       AND c.relowner <> 'cobe_news_app'::regrole
       AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype IN ('e', 'i', 'a'))
  LOOP
    EXECUTE format('ALTER %s %s OWNER TO cobe_news_app', r.kind, r.obj);
    n := n + 1;
  END LOOP;
  FOR r IN
    SELECT p.oid::regprocedure AS obj, CASE p.prokind WHEN 'p' THEN 'PROCEDURE' WHEN 'a' THEN 'AGGREGATE' ELSE 'FUNCTION' END AS kind
      FROM pg_proc p
     WHERE p.pronamespace = 'public'::regnamespace AND p.proowner <> 'cobe_news_app'::regrole
       AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
  LOOP
    EXECUTE format('ALTER %s %s OWNER TO cobe_news_app', r.kind, r.obj);
    n := n + 1;
  END LOOP;
  FOR r IN
    SELECT t.oid::regtype AS obj
      FROM pg_type t
     WHERE t.typnamespace = 'public'::regnamespace AND t.typrelid = 0 AND t.typcategory <> 'A' AND t.typowner <> 'cobe_news_app'::regrole
       AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e')
  LOOP
    EXECUTE format('ALTER TYPE %s OWNER TO cobe_news_app', r.obj);
    n := n + 1;
  END LOOP;
  IF n > 0 THEN
    RAISE NOTICE 'db-init: % object(s) handed over to cobe_news_app', n;
  END IF;
END
$own$;
SELECT 'db-init: cobe_news_app ready (owner of ' || current_database() || ', superuser: ' || rolsuper || ')' AS status FROM pg_roles WHERE rolname = 'cobe_news_app' \gset
\echo :status
