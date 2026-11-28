-- Rename the waitlist and keepalive objects from vulnpilot_* to relvet_*.
--
-- One-off migration for databases created before the project was renamed
-- (CLI 0.2.0). waitlist.sql and keepalive.sql already describe the state
-- after it; new databases only need those files. public.cli_runs keeps its
-- name.
--
-- Order: apply this just before the renamed site goes live, because the site
-- inserts into relvet_waitlist and the keepalive workflow calls
-- relvet_keepalive. The site under the old name stops accepting signups at
-- that point.
--
-- RENAME keeps the table's rows, RLS setting, column grants and policy, and
-- the function's grants (privileges belong to the object, not its name). The
-- grants are restated below anyway so the result matches waitlist.sql and
-- keepalive.sql exactly. Runs in one transaction; re-running it after success
-- fails harmlessly on the first statement.
--
-- Apply with the Supabase SQL editor (as the postgres role).

begin;

alter table public.vulnpilot_waitlist rename to relvet_waitlist;

alter index public.vulnpilot_waitlist_email_lower_idx
  rename to relvet_waitlist_email_lower_idx;

-- Constraints named after the table when it was created, so that the result
-- matches a database created from waitlist.sql. Renaming the primary key
-- constraint also renames its index.
alter table public.relvet_waitlist
  rename constraint vulnpilot_waitlist_pkey to relvet_waitlist_pkey;
alter table public.relvet_waitlist
  rename constraint vulnpilot_waitlist_email_check to relvet_waitlist_email_check;
alter table public.relvet_waitlist
  rename constraint vulnpilot_waitlist_consent_check to relvet_waitlist_consent_check;
alter table public.relvet_waitlist
  rename constraint vulnpilot_waitlist_source_check to relvet_waitlist_source_check;
alter table public.relvet_waitlist
  rename constraint vulnpilot_waitlist_company_size_check to relvet_waitlist_company_size_check;

alter policy "vulnpilot_waitlist_anon_insert"
  on public.relvet_waitlist
  rename to "relvet_waitlist_anon_insert";

alter function public.vulnpilot_keepalive() rename to relvet_keepalive;

-- Same privileges as waitlist.sql: column-level INSERT for anon only.
revoke all on table public.relvet_waitlist from anon, authenticated;
grant insert (email, consent, source, company_size)
  on table public.relvet_waitlist to anon;

-- Same privileges as keepalive.sql: EXECUTE for anon only.
revoke all on function public.relvet_keepalive() from public, anon, authenticated;
grant execute on function public.relvet_keepalive() to anon;

commit;

-- Make the REST API see the new names immediately.
notify pgrst, 'reload schema';
