// What the data sources (OSV, EPSS, KEV) need from their caller. Pure: no
// Node APIs, so the browser scanner can bundle the same sources as the CLI.
import type { HttpClient } from './http.js';

export interface CacheHit<T> {
  value: T;
  fetchedAt: number;
  fresh: boolean;
}

/** Response cache used by the sources. The CLI's file cache implements it. */
export interface ResponseCache {
  readonly offline: boolean;
  get<T>(namespace: string, key: string): Promise<CacheHit<T> | undefined>;
  /** Fresh entry, or in offline mode any entry regardless of age. */
  getUsable<T>(namespace: string, key: string): Promise<T | undefined>;
  set(namespace: string, key: string, value: unknown): Promise<void>;
}

/** Never hits and never stores. The browser scanner keeps nothing. */
export const NO_CACHE: ResponseCache = {
  offline: false,
  get: async () => undefined,
  getUsable: async () => undefined,
  set: async () => {},
};

/**
 * Real counts reported while a scan runs. `done` counts completed lookups,
 * `failed` the ones that could not be completed; `error` is the first reason.
 */
export type ScanProgress =
  | {
      source: 'osv';
      step: 'packages' | 'advisories';
      done: number;
      failed: number;
      total: number;
      error?: string;
    }
  | {
      source: 'first-epss';
      done: number;
      failed: number;
      total: number;
      error?: string;
    }
  | {
      source: 'cisa-kev';
      catalogVersion?: string;
      dateReleased?: string;
      entries?: number;
      error?: string;
    };

export interface SourceContext {
  http: HttpClient;
  cache: ResponseCache;
  /** KEV catalog URL. Defaults to the CISA feed; the browser scanner uses /api/kev. */
  kevUrl?: string;
  /** Receives progress counts. The CLI does not use it. */
  onProgress?: (event: ScanProgress) => void;
}

/** A failing progress listener must never change the outcome of a scan. */
export function reportProgress(
  context: SourceContext,
  event: ScanProgress,
): void {
  try {
    context.onProgress?.(event);
  } catch {
    // Progress is informational only.
  }
}
