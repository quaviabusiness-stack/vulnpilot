import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import vulns from './fixtures/mock/osv-vulns.json' with { type: 'json' };
import { Cache } from '../src/cache.js';
import { cvss3BaseScore } from '../src/cvss.js';
import { createHttpClient, getJson, mapLimit } from '../src/http.js';
import {
  compareVersions,
  fetchVulnerabilities,
  fixesFor,
  queryVulnerabilityIds,
  severityOf,
  trimRecord,
} from '../src/osv.js';
import type { Dependency } from '../src/types.js';

const dependencies: Dependency[] = [
  { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
  { name: 'picocolors', version: '1.1.1', ecosystem: 'npm' },
];
const noSleep = vi.fn(async (_ms: number) => {});
const context = (fetchMock: typeof fetch, cache = new Cache(null)) => ({
  http: createHttpClient({ fetch: fetchMock, sleep: noSleep }),
  cache,
});

let cacheDir: string;
beforeEach(async () => {
  cacheDir = await mkdtemp(join(tmpdir(), 'vulnpilot-osv-test-'));
});
afterEach(async () => {
  await rm(cacheDir, { recursive: true, force: true });
});

describe('OSV querybatch', () => {
  it('posts only package identifiers, ecosystems and versions', async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        Response.json({ results: [{ vulns: [{ id: 'GHSA-1' }] }, {}] }),
      );
    const result = await queryVulnerabilityIds(dependencies, context(request));
    expect([...result.ids.values()]).toEqual([['GHSA-1'], []]);
    const [url, init] = request.mock.calls[0]!;
    expect(url).toBe('https://api.osv.dev/v1/querybatch');
    expect(init?.method).toBe('POST');
    expect(init?.redirect).toBe('error');
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.parse(String(init?.body))).toEqual({
      queries: dependencies.map(({ name, version, ecosystem }) => ({
        package: { name, ecosystem },
        version,
      })),
    });
  });

  it('queries purl-only components by purl', async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json({ results: [{}] }));
    const purl = 'pkg:deb/debian/openssl@3.0.11-1?distro=debian-12';
    await queryVulnerabilityIds(
      [{ ecosystem: '', name: 'debian/openssl', version: '3.0.11-1', purl }],
      context(request),
    );
    expect(JSON.parse(String(request.mock.calls[0]![1]?.body))).toEqual({
      queries: [{ package: { purl } }],
    });
  });

  it('batches at 1000 queries', async () => {
    const items = Array.from({ length: 2001 }, (_, index) => ({
      ...dependencies[0]!,
      name: `dep-${index}`,
    }));
    const request = vi
      .fn<typeof fetch>()
      .mockImplementation(async (_url, init) => {
        const { queries } = JSON.parse(String(init?.body)) as {
          queries: unknown[];
        };
        return Response.json({ results: queries.map(() => ({})) });
      });
    const result = await queryVulnerabilityIds(items, context(request));
    expect(
      request.mock.calls.map(
        ([, init]) =>
          (JSON.parse(String(init?.body)) as { queries: unknown[] }).queries
            .length,
      ),
    ).toEqual([1000, 1000, 1]);
    expect(result.ids.size).toBe(2001);
  });

  it('follows per-query pagination and deduplicates IDs', async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({
          results: [{ vulns: [{ id: 'A' }], next_page_token: 'page2' }, {}],
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ results: [{ vulns: [{ id: 'A' }, { id: 'B' }] }] }),
      );
    const result = await queryVulnerabilityIds(dependencies, context(request));
    expect([...result.ids.values()][0]).toEqual(['A', 'B']);
    expect(
      JSON.parse(String(request.mock.calls[1]?.[1]?.body)).queries[0],
    ).toMatchObject({
      page_token: 'page2',
    });
  });

  it.each([
    { results: [] },
    { results: [{ error: 'bad query' }, {}] },
    { results: [{ vulns: [{ id: 123 }] }, {}] },
    { results: [{ next_page_token: 'same' }, {}] },
  ])(
    'reports invalid responses as an error, never as zero vulnerabilities: %j',
    async (body) => {
      const request = vi
        .fn<typeof fetch>()
        .mockImplementation(async () => Response.json(body));
      const result = await queryVulnerabilityIds(
        dependencies,
        context(request),
      );
      expect(result.error).toMatch(/OSV/);
      expect(result.unchecked).toBe(2);
      expect(result.ids.size).toBe(0);
    },
  );

  it('caches results for 24 hours and serves them offline', async () => {
    let now = 1_000_000;
    const cache = new Cache(cacheDir, false, () => now);
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        Response.json({ results: [{ vulns: [{ id: 'X' }] }, {}] }),
      );
    await queryVulnerabilityIds(dependencies, context(request, cache));
    await queryVulnerabilityIds(dependencies, context(request, cache));
    expect(request).toHaveBeenCalledTimes(1);

    now += 25 * 60 * 60 * 1000;
    const offline = new Cache(cacheDir, true, () => now);
    const failing = vi.fn<typeof fetch>();
    const result = await queryVulnerabilityIds(
      dependencies,
      context(failing, offline),
    );
    expect(failing).not.toHaveBeenCalled();
    expect([...result.ids.values()]).toEqual([['X'], []]);

    request.mockResolvedValue(Response.json({ results: [{}, {}] }));
    await queryVulnerabilityIds(dependencies, context(request, cache));
    expect(request).toHaveBeenCalledTimes(2); // stale entry refreshed online
  });

  it('reports uncached packages in offline mode', async () => {
    const result = await queryVulnerabilityIds(
      dependencies,
      context(vi.fn<typeof fetch>(), new Cache(cacheDir, true)),
    );
    expect(result).toMatchObject({
      unchecked: 2,
      error: expect.stringContaining('offline'),
    });
  });
});

describe('OSV vulnerability details', () => {
  it('fetches each ID with at most 10 requests in flight', async () => {
    let inFlight = 0;
    let peak = 0;
    const request = vi.fn<typeof fetch>().mockImplementation(async (url) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 2));
      inFlight -= 1;
      return Response.json({
        id: decodeURIComponent(String(url).split('/').pop()!),
      });
    });
    const ids = Array.from({ length: 35 }, (_, index) => `GHSA-${index}`);
    const result = await fetchVulnerabilities(ids, context(request));
    expect(result.records.size).toBe(35);
    expect(peak).toBe(10);
    expect(request.mock.calls[0]![0]).toBe(
      'https://api.osv.dev/v1/vulns/GHSA-0',
    );
  });

  it('retries transient failures with backoff and keeps going when one ID fails', async () => {
    noSleep.mockClear();
    const request = vi.fn<typeof fetch>().mockImplementation(async (url) => {
      const id = String(url).split('/').pop()!;
      if (id === 'BAD') return new Response('', { status: 404 });
      if (request.mock.calls.filter(([u]) => u === url).length < 3)
        return new Response('', { status: 503 });
      return Response.json({ id });
    });
    const result = await fetchVulnerabilities(
      ['GOOD', 'BAD'],
      context(request),
    );
    expect([...result.records.keys()]).toEqual(['GOOD']);
    expect(result.failed).toEqual(['BAD']);
    expect(result.error).toContain('HTTP 404');
    // GOOD: 2x 503 then success; BAD: 404 is not retried.
    expect(request).toHaveBeenCalledTimes(4);
    const delays = noSleep.mock.calls.map(([ms]) => ms as number);
    expect(delays).toHaveLength(2);
    expect(delays[0]).toBeGreaterThanOrEqual(400);
    expect(delays[0]).toBeLessThan(600);
    expect(delays[1]).toBeGreaterThanOrEqual(800);
    expect(delays[1]).toBeLessThan(1000);
  });

  it('gives up after the configured retries', async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockRejectedValue(new TypeError('fetch failed'));
    const result = await fetchVulnerabilities(['A'], context(request));
    expect(result.failed).toEqual(['A']);
    expect(request).toHaveBeenCalledTimes(3);
  });

  it('aborts slow requests after the timeout', async () => {
    const request = vi.fn<typeof fetch>().mockImplementation(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init!.signal!.addEventListener('abort', () =>
            reject(init!.signal!.reason),
          );
        }),
    );
    await expect(
      getJson(
        createHttpClient({
          fetch: request,
          sleep: noSleep,
          timeoutMs: 5,
          retries: 0,
        }),
        'https://api.osv.dev/v1/vulns/A',
      ),
    ).rejects.toMatchObject({ name: 'TimeoutError' });
  });
});

describe('normalisation', () => {
  const lodash = dependencies[0]!;
  const record = (id: keyof typeof vulns) => trimRecord(vulns[id]);

  it('computes CVSS v3 base scores, ignoring temporal metrics', () => {
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(
      9.8,
    );
    expect(
      cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H'),
    ).toBe(10);
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H')).toBe(
      7.2,
    );
    expect(cvss3BaseScore('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N')).toBe(
      2.5,
    );
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(
      0,
    );
    expect(cvss3BaseScore('CVSS:4.0/AV:N')).toBeUndefined();
    expect(cvss3BaseScore('CVSS:3.1/AV:X/AC:L')).toBeUndefined();
  });

  it('derives severity from CVSS v3, falling back to the advisory label for v4', () => {
    expect(severityOf(record('GHSA-mock-lod1-0001'), lodash)).toEqual({
      level: 'high',
      score: 7.2,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
    });
    expect(
      severityOf(record('GHSA-mock-url1-0005'), {
        ecosystem: 'PyPI',
        name: 'urllib3',
        version: '2.0.7',
      }),
    ).toMatchObject({
      level: 'medium',
      score: null,
      vector: expect.stringMatching(/^CVSS:4/),
    });
    expect(severityOf(record('PYSEC-mock-0005'), lodash).level).toBe('unknown');
  });

  it('uses details when an advisory has no summary', () => {
    expect(record('PYSEC-mock-0005').summary).toMatch(
      /^MOCK: Cookie header leak/,
    );
  });

  it('recommends the fix from the range containing the installed version', () => {
    const log4j = record('GHSA-mock-log1-0004');
    const dep = (version: string): Dependency => ({
      ecosystem: 'Maven',
      name: 'org.apache.logging.log4j:log4j-core',
      version,
    });
    expect(fixesFor(log4j, dep('2.14.1'))).toEqual({
      recommended: '2.15.0',
      all: ['2.12.2', '2.15.0'],
    });
    expect(fixesFor(log4j, dep('2.5')).recommended).toBe('2.12.2');
    const minimist = record('GHSA-mock-min1-0003');
    expect(
      fixesFor(minimist, {
        ecosystem: 'npm',
        name: 'minimist',
        version: '1.2.5',
      }).recommended,
    ).toBe('1.2.6');
    expect(fixesFor({ ...minimist, affected: [] }, lodash)).toEqual({
      recommended: null,
      all: [],
    });
  });

  it('orders versions numerically with pre-releases first', () => {
    const sorted = ['1.10.0', '1.2.0', '1.2.0-rc.1', 'v1.9.0', '1.2'].sort(
      compareVersions,
    );
    expect(sorted).toEqual(['1.2', '1.2.0-rc.1', '1.2.0', 'v1.9.0', '1.10.0']);
  });

  it('runs mapLimit tasks in order with bounded concurrency', async () => {
    expect(await mapLimit([3, 1, 2], 2, async (n) => n * 2)).toEqual([6, 2, 4]);
    expect(await mapLimit([], 10, async () => 1)).toEqual([]);
  });
});
