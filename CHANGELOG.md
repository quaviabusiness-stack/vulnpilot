# Changelog

## 0.2.0 (unreleased)

### Renamed: Vulnpilot is now Relvet

The project, npm package and command are now `relvet` (`npx relvet`). The
repository moved to
[quaviabusiness-stack/relvet](https://github.com/quaviabusiness-stack/relvet)
and the website to [relvet.vercel.app](https://relvet.vercel.app). The
`vulnpilot` package on npm receives no further releases.

Scanner behaviour and the report format are unchanged apart from names:

- JSON report: `tool.name` is now `"relvet"`. The schema's `$id` is
  `https://github.com/quaviabusiness-stack/relvet/blob/main/schema/report-v1.schema.json`;
  `schemaVersion` stays `1.0.0`. Consumers that check `tool.name` against
  `"vulnpilot"` need updating.
- Text output and messages say `Relvet`.
- Environment variables use the `RELVET_` prefix: `RELVET_TELEMETRY`,
  `RELVET_CACHE_DIR`, `RELVET_MOCK`, and at build time `RELVET_SUPABASE_URL`,
  `RELVET_SUPABASE_ANON_KEY`, `RELVET_WAITLIST_URL`.
- `VULNPILOT_TELEMETRY` and `VULNPILOT_CACHE_DIR` still work as fallbacks and
  print a deprecation warning on stderr. `VULNPILOT_TELEMETRY=0` keeps
  telemetry off even if `RELVET_TELEMETRY` is set to something else. The
  build scripts and the publish and keepalive workflows fall back to
  `VULNPILOT_SUPABASE_URL`, `VULNPILOT_SUPABASE_ANON_KEY` and
  `VULNPILOT_WAITLIST_URL`. The fallbacks will be removed in a later release.
- Cache and config directories are named `relvet`. The old `vulnpilot` cache is
  not migrated (it refills within a day). If the telemetry notice was already
  shown under the old `vulnpilot` config directory, it is not shown again.
- The website downloads reports as `relvet-report-<date>.json`.
- Supabase objects are renamed to `relvet_waitlist`, `relvet_keepalive()` and
  matching index and policy names; `cli_runs` is unchanged. Existing
  databases apply `supabase/2026-11-28-rename-to-relvet.sql` once.
