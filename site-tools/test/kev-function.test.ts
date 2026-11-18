import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { KEV_URL, parseKev } from '../../src/kev.js';
import { handle, trimKev } from '../api/kev.js';
import { ROOT } from '../build/paths.js';

const feed = JSON.parse(
  readFileSync(join(ROOT, 'test/fixtures/mock/kev.json'), 'utf8'),
) as Record<string, unknown>;
const upstream = (body: unknown, init: ResponseInit = {}) =>
  vi.fn<typeof fetch>(async () =>
    typeof body === 'string'
      ? new Response(body, init)
      : Response.json(body, init),
  );
const get = (url = 'https://getvulnpilot.vercel.app/api/kev', method = 'GET') =>
  new Request(url, { method });

describe('trimKev', () => {
  it('keeps exactly what the CLI reads, so parseKev gives the same entries', () => {
    const trimmed = trimKev(feed);
    expect(parseKev(trimmed)).toEqual(parseKev(feed));
    expect(Object.keys(trimmed.vulnerabilities[0]!).sort()).toEqual([
      'cveID',
      'dateAdded',
      'dueDate',
      'knownRansomwareCampaignUse',
      'vulnerabilityName',
    ]);
    expect(trimmed).toMatchObject({
      catalogVersion: '2099.01.01',
      dateReleased: '2099-01-01T00:00:00.000Z',
      count: 3,
    });
  });

  it('rejects what the CLI rejects', () => {
    expect(() => trimKev({ vulnerabilities: [] })).toThrow();
    expect(() => trimKev({ nope: true })).toThrow();
  });
});

describe('GET /api/kev', () => {
  it('serves the trimmed catalog with CDN caching and security headers', async () => {
    const fetcher = upstream(feed);
    const response = await handle(get(), fetcher);
    expect(response.status).toBe(200);
    expect(fetcher).toHaveBeenCalledWith(
      KEV_URL,
      expect.objectContaining({ redirect: 'error' }),
    );
    expect(response.headers.get('cache-control')).toBe(
      'public, max-age=0, s-maxage=10800, stale-while-revalidate=86400',
    );
    expect(response.headers.get('content-security-policy')).toBe(
      "default-src 'none'; frame-ancestors 'none'",
    );
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect(await response.json()).toEqual(trimKev(feed));
  });

  it('answers HEAD without a body', async () => {
    const response = await handle(get(undefined, 'HEAD'), upstream(feed));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('');
  });

  it.each(['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])(
    'refuses %s without contacting CISA',
    async (method) => {
      const fetcher = upstream(feed);
      const response = await handle(get(undefined, method), fetcher);
      expect(response.status).toBe(405);
      expect(response.headers.get('allow')).toBe('GET, HEAD');
      expect(fetcher).not.toHaveBeenCalled();
    },
  );

  it('refuses any query string without contacting CISA', async () => {
    const fetcher = upstream(feed);
    const response = await handle(
      get('https://getvulnpilot.vercel.app/api/kev?bust=1'),
      fetcher,
    );
    expect(response.status).toBe(400);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    ['an upstream error', upstream('', { status: 503 })],
    ['invalid JSON', upstream('{ nope')],
    ['an unexpected format', upstream({ vulnerabilities: 'x' })],
    [
      'a feed over 10 MB',
      upstream('x', {
        headers: { 'content-length': String(11 * 1024 * 1024) },
      }),
    ],
    [
      'a redirect or network failure',
      vi.fn<typeof fetch>(async () => {
        throw new TypeError('fetch failed');
      }),
    ],
  ])('returns an uncached 502 for %s', async (_name, fetcher) => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const response = await handle(get(), fetcher);
    expect(response.status).toBe(502);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toEqual({
      error: 'The CISA KEV feed could not be fetched.',
    });
    errors.mockRestore();
  });

  it('stops reading a body that grows past 10 MB', async () => {
    const chunk = new Uint8Array(1024 * 1024);
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        sent += 1;
        if (sent > 20) controller.close();
        else controller.enqueue(chunk);
      },
    });
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const response = await handle(
      get(),
      vi.fn<typeof fetch>(async () => new Response(body)),
    );
    expect(response.status).toBe(502);
    expect(sent).toBeLessThanOrEqual(12);
    errors.mockRestore();
  });
});
