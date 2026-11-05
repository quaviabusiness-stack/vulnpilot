import { errorMessage, getJson, mapLimit } from './http.js';
import type { SourceContext } from './osv.js';
import { isRecord } from './types.js';

export const EPSS_API = 'https://api.first.org/data/v1/epss';
const BATCH_SIZE = 100;

export interface EpssScore {
  /** Probability of exploitation activity in the next 30 days (0-1). */
  score: number;
  percentile: number;
  date: string;
}

export interface EpssLookup {
  /** null = EPSS has no score for that CVE; absent = could not be checked. */
  scores: Map<string, EpssScore | null>;
  unchecked: number;
  error?: string;
}

export function parseEpss(value: unknown): Map<string, EpssScore> {
  if (!isRecord(value) || !Array.isArray(value.data))
    throw new Error('EPSS API returned an unexpected format.');
  const scores = new Map<string, EpssScore>();
  for (const item of value.data) {
    if (!isRecord(item) || typeof item.cve !== 'string') continue;
    const score = Number(item.epss);
    const percentile = Number(item.percentile);
    if (!Number.isFinite(score) || !Number.isFinite(percentile)) continue;
    scores.set(item.cve, { score, percentile, date: String(item.date ?? '') });
  }
  return scores;
}

export async function loadEpss(
  cves: string[],
  context: SourceContext,
): Promise<EpssLookup> {
  const scores = new Map<string, EpssScore | null>();
  const pending: string[] = [];
  for (const cve of new Set(cves)) {
    const cached = await context.cache.getUsable<EpssScore | null>('epss', cve);
    if (cached !== undefined) scores.set(cve, cached);
    else pending.push(cve);
  }
  if (pending.length === 0) return { scores, unchecked: 0 };
  if (context.cache.offline)
    return {
      scores,
      unchecked: pending.length,
      error: `offline and ${pending.length} CVE(s) are not in the cache`,
    };

  const batches: string[][] = [];
  for (let offset = 0; offset < pending.length; offset += BATCH_SIZE)
    batches.push(pending.slice(offset, offset + BATCH_SIZE));
  let unchecked = 0;
  let firstError: string | undefined;
  await mapLimit(batches, 3, async (batch) => {
    try {
      const url = `${EPSS_API}?cve=${batch.join(',')}&limit=${BATCH_SIZE}`;
      const found = parseEpss(await getJson(context.http, url));
      for (const cve of batch) {
        const score = found.get(cve) ?? null;
        scores.set(cve, score);
        await context.cache.set('epss', cve, score);
      }
    } catch (error) {
      unchecked += batch.length;
      firstError ??= errorMessage(error);
    }
  });
  return { scores, unchecked, ...(firstError ? { error: firstError } : {}) };
}
