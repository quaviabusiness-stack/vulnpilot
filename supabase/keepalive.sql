-- Keep the Supabase project awake.
--
-- Free-plan projects are paused when they get too little database activity
-- over a week. When that happens the waitlist form and CLI telemetry stop
-- working silently. .github/workflows/keepalive.yml calls this function every
-- three hours (POST /rest/v1/rpc/vulnpilot_keepalive with the anon key) so the
-- database sees a few requests each day, and fails loudly if the project is
-- unreachable.
--
-- The function takes no input, reads no table and returns a constant, so
-- exposing it to the anon role reveals nothing.
--
-- Apply with the Supabase SQL editor or `supabase db push`. Safe to re-run.

create or replace function public.vulnpilot_keepalive()
returns integer
language sql
stable
set search_path = ''
as $$
  select 1;
$$;

revoke all on function public.vulnpilot_keepalive() from public, anon, authenticated;
grant execute on function public.vulnpilot_keepalive() to anon;
