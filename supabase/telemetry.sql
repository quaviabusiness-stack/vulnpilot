-- Vulnpilot CLI anonymous telemetry.
--
-- The CLI sends exactly five fields per successful scan via the Supabase REST
-- API (POST /rest/v1/cli_runs) using the project's anon key:
--   cli_version, os, dep_count, result_bucket, kev_count_bucket
-- id and created_at are filled in by the database.
--
-- Security model: the anon role may INSERT rows (only those five columns) and
-- nothing else. There is no SELECT/UPDATE/DELETE policy, so the anon key
-- cannot read back or modify any data. Read the table with the service role
-- or from the Supabase dashboard.
--
-- Apply with the Supabase SQL editor or `supabase db push`. Safe to re-run.

create table if not exists public.cli_runs (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  cli_version text not null
    check (cli_version ~ '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'
           and char_length(cli_version) <= 32),
  os text not null
    check (os in ('aix', 'android', 'darwin', 'freebsd', 'linux', 'openbsd',
                  'sunos', 'win32', 'other')),
  dep_count integer not null check (dep_count between 0 and 1000000),
  result_bucket text not null
    check (result_bucket in ('likely_applies', 'likely_out_of_scope', 'unclear')),
  kev_count_bucket text not null
    check (kev_count_bucket in ('0', '1', '2-5', '6+'))
);

alter table public.cli_runs enable row level security;

-- Start from zero privileges for API roles, then grant column-level INSERT only.
revoke all on table public.cli_runs from anon, authenticated;
grant insert (cli_version, os, dep_count, result_bucket, kev_count_bucket)
  on table public.cli_runs to anon;

drop policy if exists "cli_runs_anon_insert" on public.cli_runs;
create policy "cli_runs_anon_insert"
  on public.cli_runs
  for insert
  to anon
  with check (true);

-- Intentionally no SELECT, UPDATE or DELETE policies: RLS denies them.

create index if not exists cli_runs_created_at_idx
  on public.cli_runs (created_at);
