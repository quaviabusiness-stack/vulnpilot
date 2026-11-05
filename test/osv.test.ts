import { afterEach, expect, it, vi } from 'vitest';
import responseFixture from './fixtures/osv-response.json' with { type: 'json' };
import { queryOsv } from '../src/osv.js';
import type { Dependency } from '../src/types.js';

const dependencies: Dependency[] = [
  { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
  { name: 'picocolors', version: '1.1.1', ecosystem: 'npm' },
];
afterEach(() => vi.unstubAllEnvs());

it('uses bundled fixture data in OSV_MOCK mode without network access', async () => {
  vi.stubEnv('OSV_MOCK', '1');
  const result = await queryOsv(dependencies);
  expect(result[0]?.vulnerabilityIds).toEqual(['GHSA-mock-0001']);
  expect(result[1]?.vulnerabilityIds).toEqual([]);
  expect(fetch).not.toHaveBeenCalled();
  expect(
    (await queryOsv([...dependencies].reverse()))[1]?.vulnerabilityIds,
  ).toEqual(['GHSA-mock-0001']);
});

it('posts only package identifiers, ecosystems and versions', async () => {
  const request = vi
    .fn<typeof fetch>()
    .mockResolvedValue(Response.json(responseFixture));
  expect(
    (await queryOsv(dependencies, { fetch: request, mock: false }))[0]
      ?.vulnerabilityIds,
  ).toEqual(['GHSA-mock-0001']);
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

it('batches at 1000 queries and preserves ordering', async () => {
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
  const result = await queryOsv(items, { fetch: request, mock: false });
  expect(
    request.mock.calls.map(
      ([, init]) =>
        (JSON.parse(String(init?.body)) as { queries: unknown[] }).queries
          .length,
    ),
  ).toEqual([1000, 1000, 1]);
  expect(result.map((item) => item.dependency)).toEqual(items);
});

it('follows per-query pagination and deduplicates vulnerability IDs', async () => {
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
  const result = await queryOsv(dependencies, { fetch: request, mock: false });
  expect(result[0]?.vulnerabilityIds).toEqual(['A', 'B']);
  expect(JSON.parse(String(request.mock.calls[1]?.[1]?.body))).toEqual({
    queries: [
      {
        package: { name: 'lodash', ecosystem: 'npm' },
        version: '4.17.20',
        page_token: 'page2',
      },
    ],
  });
});

it('rejects repeated page tokens rather than looping', async () => {
  const request = vi
    .fn<typeof fetch>()
    .mockImplementation(async () =>
      Response.json({ results: [{ next_page_token: 'same' }] }),
    );
  await expect(
    queryOsv(dependencies.slice(0, 1), { fetch: request, mock: false }),
  ).rejects.toThrow('repeated a page token');
  expect(request).toHaveBeenCalledTimes(2);
});

it.each([
  { results: [] },
  { results: [{ error: 'bad query' }, {}] },
  { results: [{ vulns: [{ id: 123 }] }, {}] },
  { results: [{ vulns: 'bad' }, {}] },
])(
  'rejects invalid results instead of reporting zero vulnerabilities',
  async (response) => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json(response));
    await expect(
      queryOsv(dependencies, { fetch: request, mock: false }),
    ).rejects.toThrow('OSV returned');
  },
);

it('rejects HTTP errors and empty responses without retrying', async () => {
  const request = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response('', { status: 503 }));
  await expect(
    queryOsv(dependencies, { fetch: request, mock: false }),
  ).rejects.toThrow('HTTP 503');
  expect(request).toHaveBeenCalledTimes(1);
});

it('aborts requests after the configured timeout', async () => {
  const request = vi.fn<typeof fetch>().mockImplementation(
    (_url, init) =>
      new Promise((_resolve, reject) => {
        const signal = init!.signal!;
        signal.addEventListener('abort', () => reject(signal.reason), {
          once: true,
        });
      }),
  );
  await expect(
    queryOsv(dependencies, { fetch: request, timeoutMs: 5, mock: false }),
  ).rejects.toMatchObject({ name: 'TimeoutError' });
});

it('does not request anything for an empty lockfile', async () => {
  expect(await queryOsv([], { mock: false })).toEqual([]);
  expect(fetch).not.toHaveBeenCalled();
});
