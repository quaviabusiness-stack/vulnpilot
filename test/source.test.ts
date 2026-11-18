import { describe, expect, it, vi } from 'vitest';
import kevFeed from './fixtures/mock/kev.json' with { type: 'json' };
import { createHttpClient } from '../src/http.js';
import { KEV_URL, loadKev } from '../src/kev.js';
import { createMockFetch } from '../src/mock.js';
import { OSV_API, osvQueryBodies } from '../src/osv.js';
import { scan } from '../src/scan.js';
import { NO_CACHE, type ScanProgress } from '../src/source.js';
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

function context(
  fetchMock: typeof fetch = createMockFetch(),
  extra: { kevUrl?: string; onProgress?: (event: ScanProgress) => void } = {},
) {
  return {
    http: createHttpClient({ fetch: fetchMock, sleep: async () => {} }),
    cache: NO_CACHE,
    ...extra,
  };
}

const last = (
  events: ScanProgress[],
  match: (event: ScanProgress) => boolean,
) => events.filter(match).at(-1);

describe('scan progress', () => {
  it('reports real counts for every source', async () => {
    const events: ScanProgress[] = [];
    await scan(
      PROJECT,
      context(undefined, { onProgress: (e) => events.push(e) }),
    );
    expect(
      last(events, (e) => e.source === 'osv' && e.step === 'packages'),
    ).toEqual({
      source: 'osv',
      step: 'packages',
      done: 3,
      failed: 0,
      total: 3,
    });
    expect(
      last(events, (e) => e.source === 'osv' && e.step === 'advisories'),
    ).toEqual({
      source: 'osv',
      step: 'advisories',
      done: 3,
      failed: 0,
      total: 3,
    });
    expect(last(events, (e) => e.source === 'first-epss')).toEqual({
      source: 'first-epss',
      done: 3,
      failed: 0,
      total: 3,
    });
    expect(last(events, (e) => e.source === 'cisa-kev')).toEqual({
      source: 'cisa-kev',
      catalogVersion: '2099.01.01',
      dateReleased: '2099-01-01T00:00:00.000Z',
      entries: 3,
    });
    // Counts only ever grow.
    const advisories = events.filter(
      (e) => e.source === 'osv' && e.step === 'advisories',
    );
    expect(advisories[0]).toMatchObject({ done: 0, total: 3 });
  });

  it('does not change the result, even when the listener throws', async () => {
    const plain = await scan(PROJECT, context());
    const observed = await scan(
      PROJECT,
      context(undefined, { onProgress: () => {} }),
    );
    const throwing = await scan(
      PROJECT,
      context(undefined, {
        onProgress: () => {
          throw new Error('listener bug');
        },
      }),
    );
    expect(observed).toEqual(plain);
    expect(throwing).toEqual(plain);
  });

  it('reports which source failed and why', async () => {
    const mock = createMockFetch();
    const events: ScanProgress[] = [];
    const failing: typeof fetch = async (input, init) =>
      String(input).startsWith(OSV_API)
        ? new Response('', { status: 503 })
        : mock(input, init);
    await scan(
      PROJECT,
      context(failing, { onProgress: (e) => events.push(e) }),
    );
    expect(
      last(events, (e) => e.source === 'osv' && e.step === 'packages'),
    ).toEqual({
      source: 'osv',
      step: 'packages',
      done: 0,
      failed: 3,
      total: 3,
      error: 'HTTP 503 from api.osv.dev',
    });
  });
});

describe('OSV request bodies', () => {
  it('are exactly the bodies the scan sends', async () => {
    const mock = createMockFetch();
    const sent: string[] = [];
    const spy = vi.fn<typeof fetch>(async (input, init) => {
      if (String(input) === `${OSV_API}/querybatch`)
        sent.push(String(init?.body));
      return mock(input, init);
    });
    await scan(PROJECT, context(spy));
    expect(sent).toEqual(osvQueryBodies(PROJECT));
  });

  it('split into batches of 1,000', () => {
    const many = Array.from({ length: 2500 }, (_, index) =>
      npm(`package-${index}`, '1.0.0'),
    );
    const bodies = osvQueryBodies(many).map(
      (body) => (JSON.parse(body) as { queries: unknown[] }).queries.length,
    );
    expect(bodies).toEqual([1000, 1000, 500]);
    expect(JSON.parse(osvQueryBodies(PROJECT)[0]!)).toEqual({
      queries: PROJECT.map(({ name, ecosystem, version }) => ({
        package: { name, ecosystem },
        version,
      })),
    });
  });
});

describe('KEV source', () => {
  it('reads a trimmed copy from another URL with the same result', async () => {
    const trimmed = {
      catalogVersion: kevFeed.catalogVersion,
      dateReleased: kevFeed.dateReleased,
      count: kevFeed.vulnerabilities.length,
      vulnerabilities: kevFeed.vulnerabilities.map((item) => ({
        cveID: item.cveID,
        vulnerabilityName: item.vulnerabilityName,
        dateAdded: item.dateAdded,
        dueDate: item.dueDate,
        knownRansomwareCampaignUse: item.knownRansomwareCampaignUse,
      })),
    };
    const urls: string[] = [];
    const local: typeof fetch = async (input) => {
      urls.push(String(input));
      return Response.json(trimmed);
    };
    const fromCopy = await loadKev(
      context(local, { kevUrl: 'https://example.test/api/kev' }),
    );
    const fromFeed = await loadKev(context());
    expect(urls).toEqual(['https://example.test/api/kev']);
    expect(fromCopy).toEqual(fromFeed);
    expect(fromCopy.dateReleased).toBe('2099-01-01T00:00:00.000Z');
  });

  it('defaults to the CISA feed', async () => {
    const urls: string[] = [];
    const mock = createMockFetch();
    await loadKev(
      context(async (input, init) => {
        urls.push(String(input));
        return mock(input, init);
      }),
    );
    expect(urls).toEqual([KEV_URL]);
  });
});

describe('NO_CACHE', () => {
  it('never returns or keeps anything', async () => {
    await NO_CACHE.set('ns', 'key', 1);
    expect(await NO_CACHE.get('ns', 'key')).toBeUndefined();
    expect(await NO_CACHE.getUsable('ns', 'key')).toBeUndefined();
    expect(NO_CACHE.offline).toBe(false);
  });
});
