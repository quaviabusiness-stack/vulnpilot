# Vulnpilot

Vulnpilot reads a dependency lockfile, checks known vulnerabilities through the free OSV.dev API, and asks three questions for a preliminary EU Cyber Resilience Act (CRA) screen. This open-source CLI skeleton supports npm lockfiles today; pnpm and Yarn parsers are TODOs, and GitHub App and paid SaaS features are future work.

## Status and requirements

Use Node.js 26 LTS (26.13.0 pinned for development) and pnpm 12.16.1. The package is named `vulnpilot`: on November 5, 2026, `npm view cra-check` returned the existing version `0.2.0`, while `npm view vulnpilot` returned E404. Availability is not a reservation; recheck before publishing. If both unscoped names become unavailable, use `@vulnpilot/cli` after obtaining the npm scope.

## Usage

After the first npm publication:

```sh
npx vulnpilot --path /path/to/project
```

For CI, provide the three answers as flags:

```sh
npx vulnpilot --path /path/to/project --json --non-interactive --eu-distribution yes --commercial yes --product-type app --no-telemetry
```

| Flag                         | Meaning                                                                  |
| ---------------------------- | ------------------------------------------------------------------------ |
| `--path <path>`              | Project directory or a specific supported lockfile; defaults to `.`.     |
| `--json`                     | Print a JSON report to stdout and skip prompts.                          |
| `--non-interactive`          | Skip prompts; missing answers become `unknown`.                          |
| `--eu-distribution <answer>` | Do you sell or distribute in the EU? `yes`, `no`, or `unknown`.          |
| `--commercial <answer>`      | Is the product part of a commercial activity? `yes`, `no`, or `unknown`. |
| `--product-type <type>`      | `app`, `library`, `firmware`, or `unknown`.                              |
| `--no-telemetry`             | Disable anonymous usage telemetry.                                       |
| `--version`                  | Print the CLI version.                                                   |
| `--help`                     | Show help.                                                               |

Prompts are also skipped when `CI` is set or input/output is not a terminal. Unanswered questions produce `needs-review`; they never silently become "no". Invalid flags, unsupported lockfiles, failed OSV requests, and cancelled questions exit with status 1. Findings do not change the success exit status. Diagnostics and telemetry notices go to stderr.

Only `package-lock.json` versions 1, 2 and 3 are implemented. The parser includes development and transitive dependencies and deduplicates exact name/version pairs. Local/workspace links, git references and other entries without exact npm versions are skipped; this is not a complete inventory of every dependency kind. Multiple lockfiles require an explicit file path. Selecting `pnpm-lock.yaml` or `yarn.lock` currently fails with a TODO error rather than producing an empty scan.

OSV requests contain only dependency names, exact versions and the npm ecosystem, with at most 1,000 queries per request, a 10-second timeout per request and per-query pagination. The CLI does not read project source files, traverse source directories, or upload lockfiles or manifests. OSV sees dependency identifiers, including any private package names present in the lockfile. Vulnerability counts are distinct OSV IDs; aliases across advisories are not merged into a single CVE count. Errors fail the scan rather than implying zero vulnerabilities.

## Local development

```sh
npm install --global pnpm@12.16.1
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm dev
```

`pnpm dev` watches and rebuilds; run `node dist/cli.js` in another terminal. `pnpm format` applies Prettier. The pnpm configuration allows only esbuild's install script, which validates its platform binary.

Offline fixture smoke test (POSIX shells):

```sh
OSV_MOCK=1 node dist/cli.js --path test/fixtures --json
pnpm pack
OSV_MOCK=1 npx --yes ./vulnpilot-0.1.0.tgz --path test/fixtures --json
```

PowerShell:

```powershell
$env:OSV_MOCK = '1'
node dist/cli.js --path test/fixtures --json
pnpm pack
npx --yes ./vulnpilot-0.1.0.tgz --path test/fixtures --json
Remove-Item Env:OSV_MOCK
```

`OSV_MOCK=1` uses bundled fixture data with an intentionally synthetic vulnerability ID and performs no OSV requests. Only dependencies matching the fixture name/version pairs receive mock findings; all reports clearly identify mock data. The real scan should never be evaluated using this mock count. Fixtures are bundled into the entry point so the tarball needs no test directory at runtime.

## Telemetry

By default, no telemetry endpoint is configured, so telemetry is a no-op. An endpoint can be embedded only at build time by setting `VULNPILOT_TELEMETRY_ENDPOINT` to an HTTPS URL before `pnpm build`; setting it at runtime cannot enable telemetry in an existing build. The supplied publish workflow does not configure an endpoint.

When enabled, each successful scan sends at most one event with exactly these JSON fields:

```json
{
  "cliVersion": "0.1.0",
  "os": "win32",
  "dependencyCount": 2,
  "resultBucket": "needs-review"
}
```

`os` is Node's platform identifier (for example `linux`, `darwin` or `win32`). The result bucket is `likely-applies`, `likely-out-of-scope` or `needs-review`. There are no run/user identifiers, timestamps, code, package names, versions of dependencies, file paths, raw answers, or vulnerability details in the event. As with any HTTPS request, the receiving server sees the connection's IP address; this is not a payload field.

Disable telemetry with `--no-telemetry`, `VULNPILOT_TELEMETRY=0`, or by setting the `CI` environment variable (any value, including an empty string). Help/version commands, failed runs, and cancelled questionnaires do not send events. Delivery has a 1.5-second timeout, follows no redirects and never retries; delivery errors do not fail scans.

When a configured endpoint is enabled, the CLI prints a one-line notice to stderr before its first event. It saves a notice marker under `XDG_CONFIG_HOME/vulnpilot`, or `APPDATA/vulnpilot` on Windows, or `~/.config/vulnpilot` elsewhere (Windows falls back to the home directory if APPDATA is absent). The marker contains only `1`, never an identifier. If the marker cannot be saved, that run skips telemetry. No notice or state is created while telemetry is disabled or no endpoint is configured.

## Not legal advice

The CRA result is placeholder screening, **not legal advice**, a compliance decision, or a certification. The provisional heuristic returns `likely-applies` for EU distribution plus commercial activity plus a known product type, `likely-out-of-scope` when EU distribution is explicitly "no", and `needs-review` otherwise. Noncommercial projects, libraries, exclusions and other special cases need human review; three questions cannot resolve CRA scope. Zero known vulnerabilities is not a security guarantee.

## Dependencies

Only two direct runtime dependencies are used:

- `commander`: parses arguments, validates answer choices, and provides help/version output.
- `@clack/prompts`: supplies the three interactive questions and cancellation handling.

Development dependencies each have a specific role:

- `typescript`: strict type checking; pinned to the 5.9 line supported by this lint toolchain.
- `@types/node`: types for Node built-ins; no HTTP client dependency is needed because Node provides fetch.
- `tsup`: bundles an ESM executable while preserving the shebang.
- `vitest`: fixture-based unit and integration tests.
- `eslint`: static analysis.
- `@eslint/js`: ESLint's recommended JavaScript rules.
- `typescript-eslint`: TypeScript parsing and recommended lint rules.
- `prettier`: consistent formatting, checked by the lint script.

There is no YAML parser dependency while pnpm and Yarn remain stubs. `pnpm-lock.yaml` pins the resolved dependency tree.

## Contributing

Use the pinned Node and pnpm versions, install dependencies, and run `pnpm lint`, `pnpm typecheck`, `pnpm test` and `pnpm build` before opening a PR. Tests must use fixtures or injected fetch mocks: the test setup rejects accidental network calls. Keep runtime dependencies minimal, read only dependency manifests/lockfiles, and preserve the telemetry payload allowlist. The two skipped parser tests document unfinished work; implement and enable them when adding format support.

## Publishing setup

1. Create an npm account, confirm name availability, and obtain publish access to `vulnpilot` (or your fallback scope).
2. The public repository is [quaviabusiness-stack/vulnpilot](https://github.com/quaviabusiness-stack/vulnpilot), and its URL is configured in `package.json`. If you fork it or choose another owner or repository name, update that metadata to match its actual case-sensitive path. This metadata is required for npm provenance; the publish workflow checks it before publishing.
3. Create a publish-capable token in your [npm access-token settings](https://www.npmjs.com/settings/quavia/tokens) and add it as the repository Actions secret `NPM_TOKEN`. A successful `npm login` is a local session and does not configure this secret. Use `gh secret set NPM_TOKEN --repo quaviabusiness-stack/vulnpilot` and enter the token at its prompt; never commit the token or paste it into a chat. Configure the token/account permissions for automated publishing, including the appropriate 2FA policy and expiration.
4. Run the checks, update the package version, and push a matching version tag such as `v0.1.0`. The separate publish workflow reruns the checks and uses `npm publish --provenance --access public` with OIDC permission for provenance.

CI runs install, lint, typecheck, tests, build, and a packed-CLI smoke check on pushes and pull requests. The repository is set up; the publishing secret must be configured before the first version tag is pushed. No npm version was published during initial setup. MIT licensed; see [LICENSE](LICENSE).
