import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { type CliEnvironment, runCli } from '../src/main.js';

let cacheDir: string;
beforeEach(async () => {
  cacheDir = await mkdtemp(join(tmpdir(), 'vulnpilot-cli-test-'));
});
afterEach(async () => {
  await rm(cacheDir, { recursive: true, force: true });
});

async function run(args: string[], io: CliEnvironment = {}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const code = await runCli(['node', 'vulnpilot', ...args], {
    env: { VULNPILOT_MOCK: '1', VULNPILOT_CACHE_DIR: cacheDir },
    interactive: false,
    stdout: (text) => stdout.push(text),
    stderr: (text) => stderr.push(text),
    ...io,
  });
  return { code, stdout: stdout.join('\n'), stderr: stderr.join('\n') };
}

const CRA_FLAGS = [
  '--eu-distribution',
  'yes',
  '--commercial',
  'yes',
  '--product-type',
  'app',
];

it('scans a project with mock data and exits 1 when issues are found', async () => {
  const result = await run([
    '--path',
    'test/fixtures/projects/yarn-berry',
    ...CRA_FLAGS,
  ]);
  expect(result.code).toBe(1);
  expect(result.stdout).toContain('LIKELY APPLIES');
  expect(result.stdout).toContain('must be reported within 24 hours');
  expect(result.stdout).toContain('Not legal advice');
  expect(fetch).not.toHaveBeenCalled();
});

it('prints JSON only on stdout', async () => {
  const result = await run(['--path', 'test/fixtures/projects/pnpm', '--json']);
  const report = JSON.parse(result.stdout);
  expect(report).toMatchObject({
    schemaVersion: '1.0.0',
    mock: true,
    input: { format: 'pnpm-lock', dependencies: 7, skipped: 1 },
    cra: { verdict: 'unclear' },
    summary: { issues: 3, activelyExploited: 1 },
  });
  expect(result.stderr).toBe('');
});

it('reads a CycloneDX SBOM and honours --fail-on', async () => {
  const sbom = ['--sbom', 'test/fixtures/sbom/cyclonedx.json', '--json'];
  expect((await run([...sbom, '--fail-on', 'kev'])).code).toBe(1);
  expect((await run([...sbom, '--fail-on', 'critical'])).code).toBe(1);
});

it('exits 0 when nothing is found or nothing matches --fail-on', async () => {
  const lockfile = (packages: Record<string, string>) =>
    JSON.stringify({
      lockfileVersion: 3,
      packages: Object.fromEntries(
        Object.entries(packages).map(([name, version]) => [
          `node_modules/${name}`,
          { version },
        ]),
      ),
    });
  const clean = join(cacheDir, 'clean');
  await mkdir(clean);
  await writeFile(
    join(clean, 'package-lock.json'),
    lockfile({ picocolors: '1.1.1' }),
  );
  const result = await run(['--path', clean]);
  expect(result.code).toBe(0);
  expect(result.stdout).toContain('No known vulnerabilities found.');

  const lodashOnly = join(cacheDir, 'lodash');
  await mkdir(lodashOnly);
  await writeFile(
    join(lodashOnly, 'package-lock.json'),
    lockfile({ lodash: '4.17.20' }),
  );
  expect(
    (await run(['--path', lodashOnly, '--fail-on', 'critical'])).code,
  ).toBe(0);
  expect((await run(['--path', lodashOnly, '--fail-on', 'kev'])).code).toBe(0);
  expect((await run(['--path', lodashOnly, '--fail-on', 'high'])).code).toBe(1);
  expect((await run(['--path', lodashOnly])).code).toBe(1);
});

it('exits 2 with a clear message when no lockfile is found', async () => {
  const result = await run(['--path', cacheDir]);
  expect(result.code).toBe(2);
  expect(result.stderr).toMatch(/No lockfile found .*--sbom/);
  expect(result.stdout).toBe('');
});

it('exits 2 for invalid flags and 0 for --help/--version', async () => {
  expect((await run(['--fail-on', 'medium'])).code).toBe(2);
  expect((await run(['--version'])).code).toBe(0);
  const help = await run(['--help']);
  expect(help.code).toBe(0);
  expect(help.stdout).toContain('Exit codes: 0 no issues, 1 issues found');
});

it('exits 2 when OSV is unreachable and nothing is found', async () => {
  const result = await run(['--path', 'test/fixtures/projects/npm', '--json'], {
    env: { VULNPILOT_CACHE_DIR: cacheDir },
    fetch: vi
      .fn<typeof fetch>()
      .mockRejectedValue(new TypeError('fetch failed')),
  });
  expect(result.code).toBe(2);
  expect(JSON.parse(result.stdout).sources[0]).toMatchObject({
    name: 'osv',
    status: 'unavailable',
  });
  expect(result.stderr).toContain('osv unavailable');
});

it('works --offline from a warm cache without network access', async () => {
  // Warm the cache through an injected (non-mock) fetch backed by the fixtures.
  const { createMockFetch } = await import('../src/mock.js');
  const online = vi.fn(createMockFetch());
  const env = { VULNPILOT_CACHE_DIR: cacheDir };
  const first = await run(['--path', 'test/fixtures/projects/npm', '--json'], {
    env,
    fetch: online,
  });
  expect(online).toHaveBeenCalled();
  const offlineFetch = vi.fn<typeof fetch>();
  const second = await run(
    ['--path', 'test/fixtures/projects/npm', '--json', '--offline'],
    {
      env,
      fetch: offlineFetch,
    },
  );
  expect(offlineFetch).not.toHaveBeenCalled();
  expect(second.code).toBe(first.code);
  expect(JSON.parse(second.stdout).issues).toEqual(
    JSON.parse(first.stdout).issues,
  );

  const cold = await run(
    ['--path', 'test/fixtures/projects/npm', '--json', '--offline'],
    {
      env: { VULNPILOT_CACHE_DIR: join(cacheDir, 'empty') },
      fetch: offlineFetch,
    },
  );
  expect(cold.code).toBe(2);
  expect(
    JSON.parse(cold.stdout).sources.map((s: { status: string }) => s.status),
  ).toEqual(['unavailable', 'unavailable', 'ok']);
});
