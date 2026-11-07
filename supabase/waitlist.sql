-- Vulnpilot waitlist (landing page in site/).
--
-- The landing page sends one row per signup via the Supabase REST API
-- (POST /rest/v1/vulnpilot_waitlist, Prefer: return=minimal) using the
-- project's anon key: email, consent, source, company_size.
-- id and created_at are filled in by the database.
--
-- Security model (same as supabase/telemetry.sql): the anon role may INSERT
-- rows (only those four columns) and nothing else. There is no
-- SELECT/UPDATE/DELETE policy, so the anon key cannot read back, enumerate or
-- modify signups. A duplicate email (case-insensitive) is rejected by the
-- unique index with HTTP 409; the page shows that as success so it never
-- reveals whether an address is registered. Read the table from the Supabase
-- dashboard or with the service role.
--
-- Note: this is unrelated to the project's existing public.waitlist table.
--
-- Apply with the Supabase SQL editor or `supabase db push`. Safe to re-run.

create table if not exists public.vulnpilot_waitlist (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  email text not null
    check (char_length(email) <= 254
           and email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'),
  consent boolean not null check (consent),
  source text
    check (source ~ '^[a-z0-9._-]{1,32}$'),
  company_size text
    check (company_size in ('1', '2-10', '11-50', '51-250', '250+'))
);

create unique index if not exists vulnpilot_waitlist_email_lower_idx
  on public.vulnpilot_waitlist (lower(email));

alter table public.vulnpilot_waitlist enable row level security;

-- Start from zero privileges for API roles, then grant column-level INSERT only.
revoke all on table public.vulnpilot_waitlist from anon, authenticated;
grant insert (email, consent, source, company_size)
  on table public.vulnpilot_waitlist to anon;

drop policy if exists "vulnpilot_waitlist_anon_insert"
  on public.vulnpilot_waitlist;
create policy "vulnpilot_waitlist_anon_insert"
  on public.vulnpilot_waitlist
  for insert
  to anon
  with check (consent);

-- Intentionally no SELECT, UPDATE or DELETE policies: RLS denies them.
