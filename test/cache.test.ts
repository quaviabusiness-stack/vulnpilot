import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { Cache, defaultCacheDir } from '../src/cache.js';

let directory: string;
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'vulnpilot-cache-test-'));
});
afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

it('keeps entries fresh for 24 hours', async () => {
  let now = 0;
  const cache = new Cache(directory, false, () => now);
  await cache.set('ns', 'key', { a: 1 });
  now = 24 * 60 * 60 * 1000 - 1;
  expect(await cache.getUsable('ns', 'key')).toEqual({ a: 1 });
  now += 1;
  expect(await cache.getUsable('ns', 'key')).toBeUndefined();
  expect(await cache.get('ns', 'key')).toMatchObject({
    fresh: false,
    value: { a: 1 },
  });
  // Offline mode accepts stale data rather than nothing.
  expect(
    await new Cache(directory, true, () => now).getUsable('ns', 'key'),
  ).toEqual({ a: 1 });
});

it('stores null values distinctly from misses', async () => {
  const cache = new Cache(directory);
  await cache.set('epss', 'CVE-1', null);
  expect(await cache.getUsable('epss', 'CVE-1')).toBeNull();
  expect(await cache.getUsable('epss', 'CVE-2')).toBeUndefined();
});

it('is a no-op without a directory and never throws on unwritable paths', async () => {
  const disabled = new Cache(null);
  await disabled.set('ns', 'key', 1);
  expect(await disabled.getUsable('ns', 'key')).toBeUndefined();
  const broken = new Cache(join(directory, '\0invalid'));
  await expect(broken.set('ns', 'key', 1)).resolves.toBeUndefined();
});

it('uses the platform cache directory', () => {
  expect(defaultCacheDir({ VULNPILOT_CACHE_DIR: '/x' }, 'linux')).toBe('/x');
  expect(defaultCacheDir({ XDG_CACHE_HOME: '/xdg' }, 'linux')).toBe(
    join('/xdg', 'vulnpilot'),
  );
  expect(defaultCacheDir({ LOCALAPPDATA: 'C:\\Local' }, 'win32')).toBe(
    join('C:\\Local', 'vulnpilot', 'Cache'),
  );
  expect(defaultCacheDir({}, 'darwin')).toMatch(
    /Library[\\/]Caches[\\/]vulnpilot$/,
  );
});
