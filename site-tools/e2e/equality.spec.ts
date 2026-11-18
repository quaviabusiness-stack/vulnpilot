// The bar for the browser scanner: for every fixture, the report it produces
// equals the CLI's --json report for the same file and the same mocked
// responses, except for generatedAt and durationMs.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import type { Page } from '@playwright/test';
import { runCli } from '../../src/main.js';
import { createMockFetch } from '../../src/mock.js';
import { ROOT } from '../build/paths.js';
import { expect, open, test } from './support.js';

test.describe.configure({ mode: 'serial' });

const FIXTURES: [string, '--path' | '--sbom'][] = [
  ['projects/npm/package-lock.json', '--path'],
  ['projects/pnpm/pnpm-lock.yaml', '--path'],
  ['projects/yarn-v1/yarn.lock', '--path'],
  ['projects/yarn-berry/yarn.lock', '--path'],
  ['sbom/cyclonedx.json', '--sbom'],
];

const ANSWER_SETS: { name: string; flags: string[]; labels: string[] }[] = [
  { name: 'no answers', flags: [], labels: [] },
  {
    name: 'EU, commercial, firmware',
    flags: [
      '--eu-distribution',
      'yes',
      '--commercial',
      'yes',
      '--product-type',
      'firmware',
    ],
    labels: ['Yes', 'Yes', 'Firmware or a connected hardware device'],
  },
];

type Json = Record<string, unknown>;
const comparable = (report: Json) => {
  const {
    generatedAt: _generatedAt,
    durationMs: _durationMs,
    ...rest
  } = report;
  return rest;
};

/** The CLI's own entry point, run from the fixture's directory so input.file is the bare name. */
async function cliReport(
  file: string,
  flag: string,
  answers: string[],
): Promise<Json> {
  const cache = mkdtempSync(join(tmpdir(), 'vulnpilot-equality-'));
  const cwd = process.cwd();
  let stdout = '';
  process.chdir(dirname(file));
  try {
    await runCli(
      [
        'node',
        'vulnpilot',
        flag,
        basename(file),
        '--json',
        '--non-interactive',
        ...answers,
      ],
      {
        env: { VULNPILOT_CACHE_DIR: cache, VULNPILOT_TELEMETRY: '0' },
        fetch: createMockFetch(),
        sleep: async () => {},
        stdout: (text) => {
          stdout += text;
        },
        stderr: () => {},
        interactive: false,
        telemetryFetch: async () => new Response(null, { status: 204 }),
      },
    );
  } finally {
    process.chdir(cwd);
    rmSync(cache, { recursive: true, force: true });
  }
  return JSON.parse(stdout) as Json;
}

async function browserReport(
  page: Page,
  file: string,
  labels: string[],
): Promise<Json> {
  await open(page, '/scan');
  const questions = page.locator('#cra-form fieldset');
  for (const [index, label] of labels.entries())
    await questions.nth(index).getByLabel(label, { exact: true }).check();
  await page.locator('#file-input').setInputFiles(file);
  await expect(page.locator('#found-title')).toBeFocused();
  await page.locator('#scan-button').click();
  await expect(page.locator('#report-title')).toBeFocused({ timeout: 15_000 });
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download JSON' }).click(),
  ]);
  return JSON.parse(readFileSync((await download.path())!, 'utf8')) as Json;
}

for (const [path, flag] of FIXTURES)
  for (const answers of ANSWER_SETS)
    test(`${path}, ${answers.name}: browser report equals CLI report @cross`, async ({
      page,
    }) => {
      const file = join(ROOT, 'test/fixtures', path);
      const cli = await cliReport(file, flag, answers.flags);
      const browser = await browserReport(page, file, answers.labels);
      expect((cli.summary as Json).dependencies).toBeGreaterThan(0);
      expect(comparable(browser)).toEqual(comparable(cli));
    });
