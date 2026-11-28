import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { defaultWarn, envSetting, type Warn } from './legacy.js';
import type { CacheHit, ResponseCache } from './source.js';

export type { CacheHit } from './source.js';

export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Platform cache directory: LOCALAPPDATA, ~/Library/Caches or XDG_CACHE_HOME.
 * RELVET_CACHE_DIR (or the deprecated VULNPILOT_CACHE_DIR) overrides it. The
 * cache from before the rename is not migrated; it refills within a day.
 */
export function defaultCacheDir(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  warn: Warn = defaultWarn,
): string {
  const override = envSetting(env, 'CACHE_DIR', warn);
  if (override) return override;
  if (platform === 'win32')
    return join(
      env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'),
      'relvet',
      'Cache',
    );
  if (platform === 'darwin')
    return join(homedir(), 'Library', 'Caches', 'relvet');
  return join(env.XDG_CACHE_HOME ?? join(homedir(), '.cache'), 'relvet');
}

interface Entry<T> {
  fetchedAt: number;
  value: T;
}

/**
 * File-per-key JSON cache. Entries are fresh for 24 hours; stale entries are
 * only returned when explicitly requested (e.g. as a fallback when offline).
 * A null directory disables caching entirely (mock mode, tests).
 */
export class Cache implements ResponseCache {
  constructor(
    readonly directory: string | null,
    readonly offline = false,
    private readonly now: () => number = Date.now,
    private readonly ttlMs = CACHE_TTL_MS,
  ) {}

  #path(namespace: string, key: string): string {
    const hash = createHash('sha256').update(key).digest('hex').slice(0, 40);
    return join(this.directory!, namespace, `${hash}.json`);
  }

  async get<T>(
    namespace: string,
    key: string,
  ): Promise<CacheHit<T> | undefined> {
    if (!this.directory) return undefined;
    try {
      const entry = JSON.parse(
        await readFile(this.#path(namespace, key), 'utf8'),
      ) as Entry<T>;
      if (typeof entry.fetchedAt !== 'number') return undefined;
      return {
        value: entry.value,
        fetchedAt: entry.fetchedAt,
        fresh: this.now() - entry.fetchedAt < this.ttlMs,
      };
    } catch {
      return undefined;
    }
  }

  /** Fresh entry, or in offline mode any entry regardless of age. */
  async getUsable<T>(namespace: string, key: string): Promise<T | undefined> {
    const hit = await this.get<T>(namespace, key);
    return hit && (hit.fresh || this.offline) ? hit.value : undefined;
  }

  async set(namespace: string, key: string, value: unknown): Promise<void> {
    if (!this.directory) return;
    const file = this.#path(namespace, key);
    const temporary = `${file}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
    try {
      await mkdir(join(this.directory, namespace), { recursive: true });
      await writeFile(
        temporary,
        JSON.stringify({
          fetchedAt: this.now(),
          value,
        } satisfies Entry<unknown>),
      );
      await rename(temporary, file);
    } catch {
      // Caching is an optimisation; an unwritable cache must not fail the scan.
    }
  }
}
