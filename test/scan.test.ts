import { describe, expect, it, vi } from 'vitest';
import { Cache } from '../src/cache.js';
import { createHttpClient } from '../src/http.js';
import { EPSS_API } from '../src/epss.js';
import { KEV_URL } from '../src/kev.js';
import { createMockFetch } from '../src/mock.js';
import { compareIssues, type Issue, scan } from '../src/scan.js';
import type { Dependency } from '../src/types.js';

const npm = (name: string, version: string): Dependency => ({
  ecosystem: 'npm',
  name,
  version,
});
const PROJECT = [
  npm('lodash', '4.17.20'),
  npm('minimist', '1.2.5'),
  npm('picocolors', '1.1.1'),
];

function context(fetchMock: typeof fetch = createMockFetch()) {
  return {
    http: createHttpClient({ fetch: fetchMock, sleep: async () => {} }),
    cache: new Cache(null),
  };
}

/** Mock fetch with selected upstreams failing. */
function failing(...prefixes: string[]): typeof fetch {
  const mock = createMockFetch();
  return async (input, init) => {
    if (prefixes.some((prefix) => String(input).startsWith(prefix)))
      return new Response('', { status: 503 });
    return mock(input, init);
  };
}

describe('scan', () => {
  it('combines OSV, KEV and EPSS and sorts KEV first, then EPSS, then CVSS', async () => {
    const result = await scan(PROJECT, context());
    expect(result.sources).toEqual([
      { name: 'osv', status: 'ok' },
      { name: 'cisa-kev', status: 'ok' },
      { name: 'first-epss', status: 'ok' },
    ]);
    expect(
      result.issues.map((issue) => [
        `${issue.package.name}@${issue.package.version}`,
        issue.cves[0],
        issue.kev !== null,
        issue.epss?.score,
        issue.severity.score,
        issue.recommendedFix,
      ]),
    ).toEqual([
      ['minimist@1.2.5', 'CVE-2099-1003', true, 0.05, 9.8, '1.2.6'],
      ['lodash@4.17.20', 'CVE-2099-1001', false, 0.21333, 7.2, '4.17.21'],
      ['lodash@4.17.20', 'CVE-2099-1002', false, 0.0123, 5.3, '4.17.21'],
    ]);
    expect(result.issues[0]!.kev).toMatchObject({
      cve: 'CVE-2099-1003',
      dateAdded: '2099-01-01',
      knownRansomwareCampaignUse: false,
    });
  });

  it('merges advisories that share an alias into one issue', async () => {
    const result = await scan(
      [{ ecosystem: 'PyPI', name: 'urllib3', version: '2.0.7' }],
      context(),
    );
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0]).toMatchObject({
      id: 'GHSA-mock-url1-0005',
      aliases: ['CVE-2099-1005', 'PYSEC-mock-0005'],
      cves: ['CVE-2099-1005'],
      severity: { level: 'medium' },
      recommendedFix: '2.0.8',
      epss: null,
    });
  });

  it('continues without KEV and says the source was unavailable', async () => {
    const result = await scan(PROJECT, context(failing(KEV_URL)));
    expect(result.sources[1]).toEqual({
      name: 'cisa-kev',
      status: 'unavailable',
      message: expect.stringContaining('HTTP 503'),
    });
    expect(result.issues).toHaveLength(3);
    expect(result.issues.every((issue) => issue.kev === null)).toBe(true);
    // Without KEV the order falls back to EPSS.
    expect(result.issues[0]!.cves[0]).toBe('CVE-2099-1001');
  });

  it('continues without EPSS', async () => {
    const result = await scan(PROJECT, context(failing(EPSS_API)));
    expect(result.sources[2]).toMatchObject({
      name: 'first-epss',
      status: 'unavailable',
    });
    expect(result.issues.map((issue) => issue.epss)).toEqual([
      null,
      null,
      null,
    ]);
    expect(result.issues[0]!.kev).not.toBeNull();
  });

  it('reports OSV as unavailable rather than claiming zero vulnerabilities', async () => {
    const result = await scan(
      PROJECT,
      context(failing('https://api.osv.dev/')),
    );
    expect(result.sources[0]).toMatchObject({
      name: 'osv',
      status: 'unavailable',
    });
    expect(result.issues).toEqual([]);
    expect(result.uncheckedDependencies).toBe(3);
    expect(result.sources[1]).toMatchObject({ status: 'ok' });
  });

  it('keeps an issue with its ID when advisory details are unavailable', async () => {
    const result = await scan(
      [npm('minimist', '1.2.5')],
      context(failing('https://api.osv.dev/v1/vulns/')),
    );
    expect(result.sources[0]).toMatchObject({ name: 'osv', status: 'partial' });
    expect(result.issues[0]).toMatchObject({
      id: 'GHSA-mock-min1-0003',
      detailsAvailable: false,
      severity: { level: 'unknown' },
    });
  });

  it('makes no requests beyond KEV for an empty inventory', async () => {
    const request = vi.fn(createMockFetch());
    const result = await scan([], context(request));
    expect(result.issues).toEqual([]);
    expect(request.mock.calls.map(([url]) => String(url))).toEqual([KEV_URL]);
  });
});

describe('compareIssues', () => {
  const issue = (overrides: Partial<Issue>): Issue => ({
    package: npm('pkg', '1.0.0'),
    id: 'X',
    aliases: [],
    cves: [],
    summary: '',
    severity: { level: 'unknown', score: null, vector: null },
    fixedVersions: [],
    recommendedFix: null,
    kev: null,
    epss: null,
    references: [],
    detailsAvailable: true,
    ...overrides,
  });
  const kev = {
    cve: 'C',
    dateAdded: '',
    dueDate: '',
    knownRansomwareCampaignUse: false,
    name: '',
  };
  const epss = (score: number) => ({
    cve: 'C',
    score,
    percentile: 0,
    date: '',
  });

  it('ranks KEV above any EPSS, EPSS above CVSS, and labels when scores are missing', () => {
    const items = [
      issue({
        id: 'cvss-10',
        severity: { level: 'critical', score: 10, vector: null },
      }),
      issue({ id: 'epss-low', epss: epss(0.01) }),
      issue({
        id: 'kev',
        kev,
        severity: { level: 'low', score: 2, vector: null },
      }),
      issue({ id: 'epss-high', epss: epss(0.9) }),
      issue({
        id: 'label-high',
        severity: { level: 'high', score: null, vector: null },
      }),
      issue({ id: 'unknown' }),
      issue({ id: 'kev-epss', kev, epss: epss(0.5) }),
    ];
    expect(items.sort(compareIssues).map((item) => item.id)).toEqual([
      'kev-epss',
      'kev',
      'epss-high',
      'epss-low',
      'cvss-10',
      'label-high',
      'unknown',
    ]);
  });
});
