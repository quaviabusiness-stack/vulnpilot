# site-tools

Build, proof capture and tests for the website in [`site/`](../site). A private
workspace package: it is not published, and the CLI package, its runtime
dependencies and the `npm pack` contents do not depend on it.

Vercel deploys `site/` as it is, with no build step. Everything generated is
committed, and the `Site` workflow regenerates it and fails if anything
differs.

## Layout

| Path                      | What it is                                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `site/*.html`             | Hand-written pages. Only the asset references, the `<!-- generated:… -->` regions and `data-proof` values are rewritten by the build. |
| `site-src/`               | Sources of the stylesheet, the home page script, the fonts and the shared header and footer. Served only as hashed copies.            |
| `site/assets/`            | Generated: content-hashed CSS, JS and fonts (served `immutable`) and the scanner bundle.                                              |
| `site/api/kev.mjs`        | Generated: the one Vercel Function, `GET /api/kev`, from `api/kev.ts` and the CLI's `src/kev.ts`.                                     |
| `site/samples/`           | Generated: a copy of `test/fixtures/sbom/cyclonedx.json` for "Try the sample SBOM".                                                   |
| `scanner/`                | The `/scan` page (TypeScript, DOM APIs only), its parse worker and the scanner core. Bundled with tsup from the CLI's own `src/`.     |
| `proof/`                  | The captured CLI output shown on the home page and in `/docs`. Written only by `scripts/capture-proof.mjs`.                           |
| `docs/report-fields.json` | Descriptions of the JSON report fields for `/docs`, keyed by schema path.                                                             |
| `server/serve.ts`         | A local server that behaves like the deployment: clean URLs, `404.html`, the headers from `site/vercel.json`, and `/api/kev`.         |
| `checks/`                 | Static checks: proof, links, size budgets, `security.txt`, robots and sitemap, HTML validation.                                       |
| `e2e/`                    | Playwright tests, accessibility (axe) and visual baselines.                                                                           |

## Commands

```sh
pnpm --filter site-tools build          # regenerate everything in site/
pnpm --filter site-tools check          # static checks
pnpm --filter site-tools test           # unit tests (the KEV function, rendering)
pnpm --filter site-tools e2e            # Playwright: pages, scanner, equality with the CLI, axe
pnpm --filter site-tools serve          # http://localhost:4173 with the deployment's headers
pnpm --filter site-tools lighthouse     # Lighthouse CI against the local server
```

Install the browsers once with `pnpm --filter site-tools exec playwright install`.

## Refreshing the proof

The scan excerpts on the home page and the `--help` text in `/docs` are real output of
the published CLI. Refreshing them is a deliberate act:

```sh
pnpm --filter site-tools capture-proof        # installs relvet@<package.json version> from npm, runs it with an empty cache
pnpm --filter site-tools build                # puts the capture into the pages
git diff site/ site-tools/proof/              # review, then commit
```

Before a version is on npm (for example right after a rename), capture a packed
build instead: run `pnpm build` and `pnpm pack` in the repository root with the
release's `RELVET_WAITLIST_URL` set, then
`pnpm --filter site-tools capture-proof --tarball ../relvet-<version>.tgz`.
`meta.json` then records the tarball's own integrity hash and
`"source": "packed build (not from the npm registry)"`. Recapture from npm once
the version is published.

The generator omits the captured CRA reporting warning from the excerpts and
the page provides current reporting guidance separately. The `check` command
compares the displayed output with the corresponding lines of the capture. If the output
changes shape (for example no skipped entries), the build stops and asks for a
decision instead of guessing how to annotate it.

## Visual baselines

Baselines are generated on Linux in CI so that font rendering matches the
comparison runs: start the `Site` workflow by hand with **update snapshots**,
download the `visual-baselines` artifact, review the images, and commit them
to `e2e/__screenshots__/`.
