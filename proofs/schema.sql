-- Tenant isolation enforced by PostgreSQL, not by application code.
--
-- Run as the master user. Creates two roles, three tables and the policies that
-- make cross-tenant reads impossible for the role the application logs in as.

-- ---------------------------------------------------------------- roles ----
--
-- Three separate identities, and the separation is the whole point.
--
--   master     runs migrations. Owns nothing at runtime.
--   app_owner  owns the tables. Nothing logs in as this.
--   app_rw     the role the application connects as. Owns nothing, and is
--              NOBYPASSRLS, which is the default but worth being explicit
--              about because a role with BYPASSRLS silently ignores every
--              policy below.
--
-- If the application connects as the table owner, row-level security does
-- nothing at all unless the table is FORCEd. That single fact is the most
-- common way an RLS setup turns out to have never been enforcing anything.

-- Idempotent teardown. DROP OWNED BY is the part people miss: dropping a role
-- fails while it still holds a privilege anywhere, and a GRANT on a schema
-- counts.
DROP TABLE IF EXISTS invoices, invoices_unforced CASCADE;

-- On RDS the master user is not a superuser, and since PostgreSQL 16 dropping
-- what a role owns requires holding that role, so grant it first. This is the
-- same principle the rest of this file relies on: nobody, including the master
-- user, gets privileges they were not explicitly given.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_rw') THEN
        EXECUTE format('GRANT app_rw TO %I', CURRENT_USER);
        EXECUTE 'DROP OWNED BY app_rw';
        EXECUTE 'DROP ROLE app_rw';
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_owner') THEN
        EXECUTE format('GRANT app_owner TO %I', CURRENT_USER);
        EXECUTE 'DROP OWNED BY app_owner';
        EXECUTE 'DROP ROLE app_owner';
    END IF;
END $$;

CREATE ROLE app_owner NOLOGIN;
CREATE ROLE app_rw LOGIN PASSWORD '__APP_PASSWORD__' NOBYPASSRLS;

-- The master user needs to be a member of app_owner to create objects owned
-- by it. RDS master is not a superuser, so this grant is required.
GRANT app_owner TO CURRENT_USER;

-- Since PostgreSQL 15 the public schema is no longer writable by every role,
-- only by the database owner, so app_owner needs this explicitly.
GRANT CREATE, USAGE ON SCHEMA public TO app_owner;
GRANT USAGE ON SCHEMA public TO app_rw;

-- ------------------------------------------------------------- the table ---
SET ROLE app_owner;

CREATE TABLE invoices (
    id           bigserial PRIMARY KEY,
    tenant_id    text   NOT NULL,
    customer     text   NOT NULL,
    amount_cents bigint NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX invoices_tenant_idx ON invoices (tenant_id);

-- ENABLE turns policies on for everyone except the table owner.
-- FORCE removes that exception. Both lines are needed.
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE  ROW LEVEL SECURITY;

-- USING filters what a query can see.
-- WITH CHECK filters what a write is allowed to produce, which is what stops a
-- tenant from inserting a row labelled with somebody else's tenant_id.
--
-- current_setting(..., true) returns NULL rather than raising when the setting
-- is absent, and `tenant_id = NULL` is NULL, so a connection that never set a
-- tenant sees nothing. The failure mode is an empty result, not a full table.
CREATE POLICY tenant_isolation ON invoices
    USING      (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON invoices TO app_rw;
GRANT USAGE, SELECT ON SEQUENCE invoices_id_seq TO app_rw;

-- ------------------------------------------- the same table, without FORCE --
--
-- Identical in every way except the missing FORCE. Exists only so the proof
-- script can show what that omission costs.
CREATE TABLE invoices_unforced (LIKE invoices INCLUDING ALL);
ALTER TABLE invoices_unforced ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON invoices_unforced
    USING      (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON invoices_unforced TO app_rw;

RESET ROLE;

-- ------------------------------------------------------------------ seed ---
--
-- Inserted by the master user, which is a member of app_owner and therefore
-- subject to FORCE. Disable the policy for the length of the seed rather than
-- pretending the seeding path is tenant-scoped.
SET ROLE app_owner;
ALTER TABLE invoices NO FORCE ROW LEVEL SECURITY;

INSERT INTO invoices (tenant_id, customer, amount_cents) VALUES
    ('acme',   'Northwind Traders',  128000),
    ('acme',   'Contoso Ltd',         94500),
    ('acme',   'Fabrikam Inc',        31200),
    ('globex', 'Initech',            770000),
    ('globex', 'Umbrella Corp',      215000),
    ('globex', 'Soylent Industries', 189900),
    ('globex', 'Cyberdyne Systems',   64000);

INSERT INTO invoices_unforced SELECT * FROM invoices;

ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
RESET ROLE;
