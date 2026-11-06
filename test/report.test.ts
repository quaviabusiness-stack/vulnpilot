import { Ajv } from 'ajv';
import { describe, expect, it } from 'vitest';
import schema from '../schema/report-v1.schema.json' with { type: 'json' };
import { Cache } from '../src/cache.js';
import { assessCra } from '../src/cra.js';
import { createHttpClient } from '../src/http.js';
import { readLockfile, readSbom } from '../src/lockfiles/index.js';
import { createMockFetch } from '../src/mock.js';
import {
  createReport,
  ctaUrl,
  formatEpss,
  exitCodeFor,
  formatText,
  REPORTING_WARNING,
  type Report,
  SCHEMA_VERSION,
} from '../src/report.js';
import { scan } from '../src/scan.js';
import type { Answers, Inventory } from '../src/types.js';

const applies: Answers = {
  euDistribution: 'yes',
  commercial: 'yes',
  productType: 'app',
};

async function build(
  inventory: Inventory,
  answers: Answers = applies,
  fetchMock: typeof fetch = createMockFetch(),
): Promise<Report> {
  const result = await scan(inventory.dependencies, {
    http: createHttpClient({ fetch: fetchMock, sleep: async () => {} }),
    cache: new Cache(null),
  });
  return createReport({
    inventory,
    scan: result,
    cra: assessCra(answers, new Date('2026-11-05T00:00:00Z')),
    mock: true,
    durationMs: 1234,
    now: new Date('2026-11-05T00:00:00Z'),
  });
}
const npmProject = () => readLockfile('test/fixtures/projects/npm');
const text = (report: Report, waitlistUrl = '') =>
  formatText(report, { color: false, waitlistUrl });

describe('JSON report', () => {
  const ajv = new Ajv({ allErrors: true, validateFormats: false });
  const validate = ajv.compile(schema);

  it.each([
    ['npm project', npmProject],
    ['CycloneDX SBOM', () => readSbom('test/fixtures/sbom/cyclonedx.json')],
  ])('matches the versioned JSON schema (%s)', async (_name, load) => {
    const report = JSON.parse(JSON.stringify(await build(await load())));
    expect(validate(report), JSON.stringify(validate.errors)).toBe(true);
    expect(report.schemaVersion).toBe(SCHEMA_VERSION);
  });

  it('matches the schema when sources fail', async () => {
    const report = await build(await npmProject(), applies, async () => {
      throw new TypeError('fetch failed');
    });
    expect(validate(JSON.parse(JSON.stringify(report)))).toBe(true);
  });

  it('summarises counts', async () => {
    const report = await build(
      await readSbom('test/fixtures/sbom/cyclonedx.json'),
    );
    expect(report.summary).toEqual({
      dependencies: 5,
      vulnerablePackages: 3,
      issues: 4,
      criticalOrHigh: 2,
      activelyExploited: 1,
      uncheckedDependencies: 0,
    });
    expect(report.input).toMatchObject({ format: 'cyclonedx', skipped: 2 });
  });
});

describe('exit codes', () => {
  it('returns 1 for any issue by default and 0 for a clean project', async () => {
    const report = await build(await npmProject());
    expect(exitCodeFor(report)).toBe(1);
    expect(exitCodeFor({ ...report, issues: [] })).toBe(0);
  });

  it('applies --fail-on thresholds', async () => {
    const report = await build(await npmProject());
    const withoutKev = report.issues.filter((issue) => !issue.kev);
    const mediumOnly = report.issues.filter(
      (issue) => issue.severity.level === 'medium',
    );
    expect(exitCodeFor(report, 'kev')).toBe(1);
    expect(exitCodeFor({ ...report, issues: withoutKev }, 'kev')).toBe(0);
    expect(exitCodeFor(report, 'critical')).toBe(1);
    expect(exitCodeFor({ ...report, issues: withoutKev }, 'critical')).toBe(0);
    expect(exitCodeFor({ ...report, issues: withoutKev }, 'high')).toBe(1);
    expect(exitCodeFor({ ...report, issues: mediumOnly }, 'high')).toBe(0);
  });

  it('returns 2 when missing data prevents a "no issues" answer', async () => {
    const report = await build(await npmProject());
    const sources = (status: 'ok' | 'unavailable', name = 'osv') =>
      report.sources.map((item) =>
        item.name === name ? { ...item, status } : item,
      );
    expect(
      exitCodeFor({ ...report, issues: [], sources: sources('unavailable') }),
    ).toBe(2);
    expect(
      exitCodeFor(
        { ...report, issues: [], sources: sources('unavailable', 'cisa-kev') },
        'kev',
      ),
    ).toBe(2);
    // Issues already found still exit 1; missing EPSS never blocks.
    expect(exitCodeFor({ ...report, sources: sources('unavailable') })).toBe(1);
    expect(
      exitCodeFor({
        ...report,
        issues: [],
        sources: sources('unavailable', 'first-epss'),
      }),
    ).toBe(0);
  });
});

describe('text output', () => {
  it('shows the verdict, counts, top issues with fix versions and the disclaimer', async () => {
    const output = text(await build(await npmProject()));
    expect(output).toContain('EU Cyber Resilience Act: LIKELY APPLIES');
    expect(output).toContain('11 September 2026 (in force)');
    expect(output).toContain('11 December 2027');
    expect(output).toContain('Not legal advice');
    expect(output).toMatch(/Dependencies\s+4/);
    expect(output).toMatch(/Vulnerable packages\s+2/);
    expect(output).toMatch(/Critical\/high issues\s+2/);
    expect(output).toMatch(/Actively exploited\s+1 \(CISA KEV\)/);
    expect(output).toContain(
      ' 1. minimist@1.2.5  CVE-2099-1003  CRITICAL 9.8 · EPSS 5.0% · KNOWN EXPLOITED',
    );
    expect(output).toContain('Fix: upgrade to 1.2.6');
    expect(output).toContain('MOCK DATA');
  });

  it('prints the 24-hour reporting line only for KEV issues when the CRA likely applies', async () => {
    const inventory = await npmProject();
    expect(text(await build(inventory))).toContain(REPORTING_WARNING);
    expect(
      text(await build(inventory, { ...applies, commercial: 'no' })),
    ).not.toContain(REPORTING_WARNING);
    const noKev = await build(inventory);
    noKev.issues = noKev.issues.filter((issue) => !issue.kev);
    noKev.summary.activelyExploited = 0;
    expect(text(noKev)).not.toContain(REPORTING_WARNING);
  });

  it('limits the list to the top 10 issues', async () => {
    const report = await build(await npmProject());
    report.issues = Array.from({ length: 12 }, () => report.issues[2]!);
    const output = text(report);
    expect(output).toContain('Top 10 of 12 issue(s)');
    expect(output).toContain('10. lodash@4.17.20');
    expect(output).not.toContain('11. ');
  });

  it('names unavailable sources', async () => {
    const report = await build(await npmProject(), applies, async () => {
      throw new TypeError('fetch failed');
    });
    const output = text(report);
    expect(output).toContain('OSV.dev unavailable: fetch failed');
    expect(output).toContain('CISA KEV unavailable');
    expect(output).toContain('results are incomplete');
    expect(output).not.toContain('No known vulnerabilities');
  });

  it('prints a one-line CTA only when a waitlist URL was built in', async () => {
    const report = await build(await npmProject());
    expect(text(report)).not.toContain('continuous monitoring');
    const output = text(report, 'https://vulnpilot.example/waitlist');
    expect(output.split('\n').at(-1)).toBe(
      'Get continuous monitoring and ready-to-send 24h report drafts: https://vulnpilot.example/waitlist?utm_source=cli',
    );
    expect(formatEpss(0.99999)).toBe('>99.9%');
    expect(formatEpss(0.0123)).toBe('1.2%');
    expect(ctaUrl('https://x.example/?a=1')).toBe(
      'https://x.example/?a=1&utm_source=cli',
    );
  });
});
