// Compares the browser scanner on a deployment with the CLI, both live.
//
//   BASE=https://… SHARE=<_vercel_share token, for protected previews> \
//     pnpm --filter site-tools exec tsx scripts/compare-live.ts [lockfile …]
//
// For each file, the CLI (dist/cli.js, empty cache) and the deployed /scan
// page scan it against the real OSV.dev, FIRST EPSS and CISA KEV (the page
// through /api/kev) within seconds of each other. Prints, per file, whether
// the JSON reports match apart from generatedAt and durationMs, and every
// field that differs. Also records what the page sent before and after the
// Scan button, and any console errors.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { chromium } from '@playwright/test';
import { ROOT } from '../build/paths.js';

const BASE = process.env.BASE;
if (!BASE) throw new Error('Set BASE to the deployment URL.');
const files = (
  process.argv.slice(2).length > 0
    ? process.argv.slice(2)
    : [
        'test/fixtures/projects/npm/package-lock.json',
        'test/fixtures/projects/pnpm/pnpm-lock.yaml',
        'test/fixtures/projects/yarn-v1/yarn.lock',
        'test/fixtures/projects/yarn-berry/yarn.lock',
        'test/fixtures/sbom/cyclonedx.json',
        'pnpm-lock.yaml',
      ]
).map((file) => resolve(ROOT, file));

type Json = unknown;
function differences(a: Json, b: Json, path = ''): string[] {
  if (JSON.stringify(a) === JSON.stringify(b)) return [];
  if (typeof a !== 'object' || typeof b !== 'object' || !a || !b)
    return [`${path || '.'}: ${JSON.stringify(a)} ≠ ${JSON.stringify(b)}`];
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].flatMap((key) =>
    differences(
      (a as Record<string, Json>)[key],
      (b as Record<string, Json>)[key],
      `${path}.${key}`,
    ),
  );
}
const strip = (report: Record<string, Json>) => {
  const { generatedAt: _g, durationMs: _d, ...rest } = report;
  return rest;
};

function cli(file: string): Record<string, Json> {
  const cache = mkdtempSync(join(tmpdir(), 'vulnpilot-live-'));
  const flag = file.endsWith('cyclonedx.json') ? '--sbom' : '--path';
  const result = spawnSync(
    process.execPath,
    [
      join(ROOT, 'dist/cli.js'),
      flag,
      basename(file),
      '--json',
      '--non-interactive',
    ],
    {
      cwd: dirname(file),
      encoding: 'utf8',
      env: {
        ...process.env,
        VULNPILOT_CACHE_DIR: cache,
        VULNPILOT_TELEMETRY: '0',
      },
    },
  );
  rmSync(cache, { recursive: true, force: true });
  return JSON.parse(result.stdout) as Record<string, Json>;
}

const browser = await chromium.launch();
const context = await browser.newContext({ acceptDownloads: true });
const page = await context.newPage();
const requests: string[] = [];
const consoleErrors: string[] = [];
page.on('request', (request) =>
  requests.push(`${request.method()} ${request.url()}`),
);
page.on('console', (message) => {
  if (message.type() === 'error') consoleErrors.push(message.text());
});
if (process.env.SHARE)
  await page.goto(`${BASE}/?_vercel_share=${process.env.SHARE}`);

let failures = 0;
for (const file of files) {
  const fromCli = cli(file);
  requests.length = 0;
  await page.goto(`${BASE}/scan`);
  await page.locator('#file-input').setInputFiles(file);
  await page.locator('#found-title').waitFor({ state: 'visible' });
  const before = requests.filter((line) => !line.includes(new URL(BASE).host));
  await page.locator('#scan-button').click();
  await page.locator('#report').waitFor({ state: 'visible', timeout: 60_000 });
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download JSON' }).click(),
  ]);
  const fromBrowser = JSON.parse(
    readFileSync((await download.path())!, 'utf8'),
  );
  const hosts = [
    ...new Set(
      requests
        .map((line) => new URL(line.split(' ')[1]!).host)
        .filter((host) => host !== new URL(BASE).host),
    ),
  ].sort();
  const diff = differences(strip(fromCli), strip(fromBrowser));
  const summary = (fromCli as { summary: Record<string, number> }).summary;
  console.log(
    `\n${file.replace(ROOT, '').replaceAll('\\', '/')}: ${summary.dependencies} packages, ${summary.issues} issues, ${summary.activelyExploited} KEV`,
  );
  console.log(
    `  external requests before Scan: ${before.length}; after: ${hosts.join(', ')}`,
  );
  console.log(
    diff.length === 0
      ? '  identical to the CLI report'
      : diff.map((line) => `  ${line}`).join('\n'),
  );
  if (diff.length > 0 || before.length > 0) failures += 1;
}
console.log(
  `\nConsole errors: ${consoleErrors.length === 0 ? 'none' : consoleErrors.join(' | ')}`,
);
await browser.close();
process.exitCode = failures > 0 ? 1 : 0;
