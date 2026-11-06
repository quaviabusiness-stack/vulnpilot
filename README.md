# Vulnpilot

Run one command in your project and within seconds learn:

1. whether the **EU Cyber Resilience Act (CRA)** likely applies to you,
2. which **known vulnerabilities** your dependencies have (OSV.dev), and
3. which of them are **actively exploited** (CISA KEV), ranked by exploit likelihood (FIRST EPSS).

```sh
npx vulnpilot
```

The CRA screen is a transparent, rule-based first pass. It is **not legal advice**.

## Status and requirements

Node.js 26 LTS (26.13.0 pinned for development) and pnpm 12.16.1. The package is named `vulnpilot`: on November 5, 2026, `npm view cra-check` returned the existing version `0.2.0`, while `npm view vulnpilot` returned E404. Availability is not a reservation; recheck before publishing. If both unscoped names become unavailable, use `@vulnpilot/cli` after obtaining the npm scope. No version has been published yet.

## Usage

```sh
npx vulnpilot                               # scan the lockfile in the current directory
npx vulnpilot --path ./apps/web             # another directory, or a lockfile path
npx vulnpilot --sbom firmware.cdx.json      # CycloneDX SBOM (firmware, non-npm projects)
npx vulnpilot --json > vulnpilot.json       # machine-readable report
```

In CI, give the three CRA answers as flags and pick a failure threshold:

```sh
npx vulnpilot --non-interactive --eu-distribution yes --commercial yes --product-type app --fail-on kev
```

| Flag                         | Meaning                                                                                |
| ---------------------------- | -------------------------------------------------------------------------------------- |
| `--path <path>`              | Project directory (lockfile auto-detected) or a specific lockfile. Default `.`.        |
| `--sbom <file>`              | Scan a CycloneDX JSON SBOM instead of a lockfile.                                      |
| `--json`                     | Print the versioned JSON report to stdout; skips prompts.                              |
| `--fail-on <level>`          | `critical`, `high` or `kev`: exit 1 only for issues at that level. Default: any issue. |
| `--offline`                  | Use only cached data (no network). Cached entries of any age are accepted.             |
| `--non-interactive`          | Skip prompts; unanswered questions become `unknown`.                                   |
| `--eu-distribution <answer>` | Made available on the EU market? `yes`, `no`, `unknown`.                               |
| `--commercial <answer>`      | Supplied as part of a commercial activity? `yes`, `no`, `unknown`.                     |
| `--product-type <type>`      | `app`, `library`, `firmware`, `saas`, `saas-with-client`, `unknown`.                   |
| `--no-color`                 | Plain output (also respected: `NO_COLOR`).                                             |
| `--no-telemetry`             | Disable anonymous usage telemetry.                                                     |
| `--version`, `--help`        | Print the version or help.                                                             |

Prompts are skipped when `--json`/`--non-interactive` is used, `CI` is set, or stdin/stdout is not a terminal. In interactive mode the network lookups start before the questions, so they overlap.

### Exit codes

| Code | Meaning                                                                                                                                                                                                |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `0`  | No issues (or none matching `--fail-on`).                                                                                                                                                              |
| `1`  | Issues found (matching `--fail-on` if given).                                                                                                                                                          |
| `2`  | Error: bad flags, no/unsupported/unparseable input, cancelled questions, or **incomplete data** — OSV could not be reached (or, with `--fail-on kev`, the KEV feed), so "no issues" cannot be claimed. |

Issues already found still exit `1` even if a source failed. A missing EPSS score never changes the exit code.

## Inputs

The lockfile is auto-detected in `--path`. If none is found the CLI exits 2 and lists the supported names; if several exist it asks you to pick one.

| Input               | Formats                                                    |
| ------------------- | ---------------------------------------------------------- |
| `package-lock.json` | lockfileVersion 1, 2, 3                                    |
| `pnpm-lock.yaml`    | lockfileVersion 5.x, 6.x, 9.x (peer suffixes stripped)     |
| `yarn.lock`         | Yarn Classic (v1) and Berry (v2+)                          |
| `--sbom`            | CycloneDX JSON, any spec version; nested components walked |

Packages are deduplicated by ecosystem + name + version. Development and transitive dependencies are included. npm aliases (`npm:real@x`) resolve to the real package. Entries without an exact registry version (workspace/`link:`/`file:` packages, git and tarball dependencies, Yarn patches) are skipped and counted as "skipped" in the output.

SBOM components are matched by **purl**. Supported purl types map to OSV ecosystems: `npm`, `pypi`, `maven`, `golang`, `cargo`, `gem`, `nuget`, `composer`, `hex`, `pub`, `conan`; `deb` and `apk` purls are sent to OSV as purls. Components without a purl (e.g. CPE-only firmware parts) or with `pkg:generic` are skipped and counted.

## Vulnerability data and privacy

| Source                                                                        | What is sent                                        | Used for                                           |
| ----------------------------------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------- |
| [OSV.dev](https://osv.dev) `POST /v1/querybatch`                              | Package ecosystem, name and exact version (or purl) | Vulnerability IDs per package (≤1,000 per request) |
| OSV.dev `GET /v1/vulns/{id}`                                                  | Advisory ID                                         | Summary, aliases (CVE IDs), CVSS, fixed versions   |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) feed | Nothing (full catalog download)                     | "Actively exploited" flag for CVE aliases          |
| [FIRST EPSS](https://www.first.org/epss/) API                                 | CVE IDs (≤100 per request)                          | Exploit-likelihood score                           |

Advisory details are fetched with at most 10 requests in flight. Every request has a timeout (10 s; 20 s for the ~2 MB KEV feed) and up to two retries with exponential backoff for network errors, timeouts, HTTP 429 and 5xx. Redirects are refused. If a source fails, the scan continues with the others and the report names the unavailable source; OSV being unavailable is never reported as "no vulnerabilities". The CLI reads only the lockfile/SBOM: no source code, manifests or file paths leave your machine. OSV does see the dependency names you query, including private package names.

**Severity**: the CVSS v3.x base score is computed from the advisory's vector. For advisories with only a CVSS v4 vector or none, the advisory's own label (e.g. GitHub's `HIGH`/`MODERATE`) is used and no numeric score is shown. Advisories for the same package that share an ID or alias (e.g. a PYSEC and a GHSA record for one CVE) are merged into one issue.

**Fix version**: the fixed version of the affected range that contains your installed version, falling back to the nearest higher fixed version.

**Ranking**: actively exploited (KEV) first, then EPSS (highest first), then CVSS (highest first). The text output shows the top 10; `--json` contains all issues.

### Cache

Responses are cached for 24 hours in the OS cache directory: `%LOCALAPPDATA%\vulnpilot\Cache` on Windows, `~/Library/Caches/vulnpilot` on macOS, `$XDG_CACHE_HOME/vulnpilot` (default `~/.cache/vulnpilot`) elsewhere; override with `VULNPILOT_CACHE_DIR`. Each cache file holds one OSV package result, OSV advisory, EPSS score or the trimmed KEV catalog. Stale entries are refreshed online; `--offline` uses cached entries of any age and reports what is missing. If the KEV download fails, the last cached catalog is used and its date is shown.

## CRA applicability

`src/cra.ts` holds a small, ordered rule list; the first matching rule wins and its ID is included in the report. **Every rule is a draft marked for legal review.**

| Rule                         | Condition                                                                   | Verdict               |
| ---------------------------- | --------------------------------------------------------------------------- | --------------------- |
| `not-on-eu-market`           | Not made available on the EU market                                         | `likely_out_of_scope` |
| `pure-saas`                  | Pure SaaS, nothing downloadable                                             | `likely_out_of_scope` |
| `non-commercial-open-source` | Not part of a commercial activity (mentions the open-source steward regime) | `likely_out_of_scope` |
| `commercial-eu-product`      | EU market + commercial + app/library/firmware                               | `likely_applies`      |
| `saas-with-client`           | SaaS with an app, desktop client, agent or firmware                         | `unclear`             |
| `insufficient-information`   | Anything else (e.g. any answer "not sure")                                  | `unclear`             |

Every result shows the reason, the three answers and the key dates: reporting obligations for actively exploited vulnerabilities and severe incidents apply from **11 September 2026** (early warning within 24 hours); full obligations including CE marking apply from **11 December 2027**. When the CRA likely applies and a KEV-listed vulnerability is found, the output adds: "Under the CRA, actively exploited vulnerabilities in your product must be reported within 24 hours."

The rules do not cover sectoral exclusions (medical devices, vehicles, aviation, marine, defence), importer/distributor roles, or important/critical product classes. Zero known vulnerabilities is not a security guarantee.

## JSON output

`--json` prints a report validated against [`schema/report-v1.schema.json`](schema/report-v1.schema.json) (shipped in the npm package). `schemaVersion` is `1.0.0`; minor versions only add optional fields and a breaking change bumps the major version. Top-level keys: `schemaVersion`, `tool`, `generatedAt`, `durationMs`, `mock`, `input`, `cra`, `summary`, `sources`, `issues`. Warnings about unavailable sources go to stderr so stdout stays parseable.

## Telemetry

Telemetry is off unless a build embeds a Supabase project (see below); the default build, and any build without those settings, sends nothing. When enabled, each completed scan inserts one row into the `cli_runs` table via the Supabase REST API (`POST {SUPABASE_URL}/rest/v1/cli_runs`, `apikey`/`Authorization: Bearer <anon key>`, `Prefer: return=minimal`). The body is exactly:

```json
{
  "cli_version": "0.1.0",
  "os": "linux",
  "dep_count": 1091,
  "result_bucket": "likely_applies",
  "kev_count_bucket": "0"
}
```

- `os`: Node's platform (`linux`, `darwin`, `win32`, …) or `other`.
- `dep_count`: number of scanned dependencies.
- `result_bucket`: the CRA verdict (`likely_applies`, `likely_out_of_scope`, `unclear`).
- `kev_count_bucket`: actively exploited issues bucketed as `0`, `1`, `2-5` or `6+`.

No identifiers, timestamps (the database adds `created_at`), package names, versions, paths, answers or vulnerability details are sent. The receiving server sees the connection's IP address, as with any HTTPS request; it is not stored in the table.

Opt out with `--no-telemetry`, `VULNPILOT_TELEMETRY=0`, or by setting `CI` (any value). Mock runs, `--help`/`--version`, errors and cancelled questionnaires send nothing. Delivery has a 1.5-second timeout, follows no redirects, never retries and never fails a scan. Before the first event, a one-line notice is printed to stderr and a marker file containing `1` is saved under `XDG_CONFIG_HOME/vulnpilot`, `%APPDATA%\vulnpilot` on Windows, or `~/.config/vulnpilot`; if it cannot be saved, telemetry is skipped.

### Supabase setup

1. Run [`supabase/telemetry.sql`](supabase/telemetry.sql) in the project's SQL editor. It creates `cli_runs(id, created_at, cli_version, os, dep_count, result_bucket, kev_count_bucket)` with check constraints, enables RLS, grants the `anon` role column-level `INSERT` only, and adds an insert-only policy. There are no select/update/delete policies, so the anon key cannot read or change rows; query them with the service role or the dashboard.
2. Set the GitHub repository **variables** `VULNPILOT_SUPABASE_URL` (e.g. `https://xyz.supabase.co`) and `VULNPILOT_SUPABASE_ANON_KEY`. The anon key is public by design; the RLS policy is what protects the table. These are embedded at build time only; runtime environment variables cannot enable telemetry in a published build.

## Waitlist link

If `VULNPILOT_WAITLIST_URL` is set at build time (repository variable of the same name), the text output ends with one line: "Get continuous monitoring and ready-to-send 24h report drafts: `<url>?utm_source=cli`". It never appears in `--json` output or in builds without the variable.

## Local development

```sh
npm install --global pnpm@12.16.1
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

`pnpm dev` rebuilds on change; run `node dist/cli.js` in another terminal. `pnpm format` applies Prettier.

Offline smoke test with bundled mock data (synthetic `CVE-2099-*` IDs, clearly marked as MOCK in every report; no network, cache or telemetry):

```sh
VULNPILOT_MOCK=1 node dist/cli.js --path test/fixtures/projects/npm
VULNPILOT_MOCK=1 node dist/cli.js --sbom test/fixtures/sbom/cyclonedx.json --json
```

PowerShell:

```powershell
$env:VULNPILOT_MOCK = '1'
node dist/cli.js --path test/fixtures/projects/pnpm
Remove-Item Env:VULNPILOT_MOCK
```

Fixtures live in `test/fixtures/projects/{npm,pnpm,yarn-v1,yarn-berry}`, `test/fixtures/sbom` and `test/fixtures/mock` (OSV, KEV and EPSS responses). Tests never touch the network: `test/setup.ts` replaces the global `fetch` with one that throws, and sources are exercised through injected fetch mocks.

## Dependencies

Two direct runtime dependencies, both bundled into `dist/cli.js`:

- `commander`: argument parsing, choices validation, help/version output.
- `@clack/prompts`: the three interactive questions.

HTTP uses Node's built-in `fetch`; lockfiles are read with small line-based parsers, so there is no YAML dependency. Development dependencies: `typescript`, `@types/node`, `tsup` (bundling), `vitest` (tests), `ajv` (validates JSON output against the published schema in tests), `eslint`, `@eslint/js`, `typescript-eslint`, `prettier`.

## Contributing

Use the pinned Node and pnpm versions and run `pnpm lint`, `pnpm typecheck`, `pnpm test` and `pnpm build` before opening a PR. Tests must use fixtures or injected fetch mocks. Keep runtime dependencies minimal, read only lockfiles/SBOMs, keep the telemetry payload allowlist, and keep CRA rule changes behind legal review.

## Publishing setup

1. Create an npm account, confirm name availability, and obtain publish access to `vulnpilot` (or your fallback scope).
2. The public repository is [quaviabusiness-stack/vulnpilot](https://github.com/quaviabusiness-stack/vulnpilot), and its URL is configured in `package.json`. If you fork it or choose another owner or repository name, update that metadata to match its actual case-sensitive path. This metadata is required for npm provenance; the publish workflow checks it before publishing.
3. Create a publish-capable token in your [npm access-token settings](https://www.npmjs.com/settings/quavia/tokens) and add it as the repository Actions secret `NPM_TOKEN`. A successful `npm login` is a local session and does not configure this secret. Use `gh secret set NPM_TOKEN --repo quaviabusiness-stack/vulnpilot` and enter the token at its prompt; never commit the token or paste it into a chat. Configure the token/account permissions for automated publishing, including the appropriate 2FA policy and expiration.
4. Optionally set the repository variables `VULNPILOT_SUPABASE_URL`, `VULNPILOT_SUPABASE_ANON_KEY` and `VULNPILOT_WAITLIST_URL` (see Telemetry and Waitlist link). Unset variables produce a build without telemetry or CTA.
5. Run the checks, update the package version, and push a matching version tag such as `v0.1.0`. The publish workflow reruns the checks, builds with the variables above, and runs `npm publish --provenance --access public`.

CI runs install, lint, typecheck, tests, build, and a packed-CLI smoke test with mock data on pushes and pull requests. MIT licensed; see [LICENSE](LICENSE).
