// The scanner core, loaded by /scan only after a file has been parsed. This
// is the CLI's code path: the same sources, scan, ranking and report, with
// the browser's fetch and no cache.
import { EPSS_BATCH_SIZE } from '../../src/epss.js';
import { createHttpClient } from '../../src/http.js';
import {
  OSV_BATCH_SIZE,
  OSV_DETAIL_CONCURRENCY,
  osvQueryBodies,
} from '../../src/osv.js';
import {
  createReport,
  exitCodeFor,
  formatEpss,
  formatText,
} from '../../src/report.js';
import { scan, type ScanResult } from '../../src/scan.js';
import { NO_CACHE, type ScanProgress } from '../../src/source.js';
import type { Dependency } from '../../src/types.js';

export {
  createReport,
  EPSS_BATCH_SIZE,
  exitCodeFor,
  formatEpss,
  formatText,
  OSV_BATCH_SIZE,
  OSV_DETAIL_CONCURRENCY,
  osvQueryBodies,
};
export type { Report } from '../../src/report.js';
export type { ScanResult } from '../../src/scan.js';

export interface ScanRun {
  scan: ScanResult;
  durationMs: number;
  finishedAt: Date;
}

/**
 * Runs the CLI's scan from the browser. Requests send no referrer and bypass
 * the HTTP cache, so nothing about the scan is kept, and no credentials go to
 * another origin: OSV.dev and FIRST get none. (The site sets no cookies; only
 * a protected preview deployment has an access cookie, for /api/kev.)
 */
export async function runScan(
  dependencies: Dependency[],
  options: {
    kevUrl: string;
    signal: AbortSignal;
    onProgress: (event: ScanProgress) => void;
  },
): Promise<ScanRun> {
  const { signal } = options;
  const http = createHttpClient({
    fetch: (input, init) =>
      globalThis.fetch(input, {
        ...init,
        credentials: 'same-origin',
        referrerPolicy: 'no-referrer',
        cache: 'no-store',
        signal: init?.signal ? AbortSignal.any([init.signal, signal]) : signal,
      }),
    // After Stop, retries give up at once instead of backing off.
    sleep: (ms) =>
      signal.aborted
        ? Promise.resolve()
        : new Promise((resolve) => {
            const timer = setTimeout(resolve, ms);
            signal.addEventListener(
              'abort',
              () => {
                clearTimeout(timer);
                resolve();
              },
              { once: true },
            );
          }),
  });
  const started = performance.now();
  const result = await scan(dependencies, {
    http,
    cache: NO_CACHE,
    kevUrl: options.kevUrl,
    onProgress: options.onProgress,
  });
  return {
    scan: result,
    durationMs: performance.now() - started,
    finishedAt: new Date(),
  };
}
