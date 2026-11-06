import type { Cache } from './cache.js';
import { cvss3BaseScore, levelFromLabel, levelFromScore } from './cvss.js';
import { errorMessage, getJson, type HttpClient, mapLimit } from './http.js';
import {
  type Dependency,
  dependencyKey,
  isRecord,
  type SeverityLevel,
} from './types.js';

export const OSV_API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;
const DETAIL_CONCURRENCY = 10;

export interface SourceContext {
  http: HttpClient;
  cache: Cache;
}

// ---------------------------------------------------------------------------
// Step 1: POST /v1/querybatch -> vulnerability IDs per package.

interface Page {
  ids: string[];
  token: string | undefined;
}

function parseBatch(value: unknown, expected: number): Page[] {
  if (
    !isRecord(value) ||
    !Array.isArray(value.results) ||
    value.results.length !== expected
  )
    throw new Error('OSV returned an invalid number of results.');
  return value.results.map((result: unknown) => {
    if (!isRecord(result) || result.error !== undefined)
      throw new Error('OSV returned a failed query.');
    if (result.vulns !== undefined && !Array.isArray(result.vulns))
      throw new Error('OSV returned invalid vulnerabilities.');
    const ids = ((result.vulns ?? []) as unknown[]).map((vuln) => {
      if (!isRecord(vuln) || typeof vuln.id !== 'string' || !vuln.id)
        throw new Error('OSV returned an invalid vulnerability ID.');
      return vuln.id;
    });
    if (
      result.next_page_token !== undefined &&
      typeof result.next_page_token !== 'string'
    )
      throw new Error('OSV returned an invalid page token.');
    return { ids, token: result.next_page_token as string | undefined };
  });
}

function toQuery(dependency: Dependency, token: string | undefined) {
  return {
    ...(dependency.purl
      ? { package: { purl: dependency.purl } }
      : {
          package: { name: dependency.name, ecosystem: dependency.ecosystem },
          version: dependency.version,
        }),
    ...(token ? { page_token: token } : {}),
  };
}

export interface IdLookup {
  /** Vulnerability IDs per dependencyKey; absent keys could not be checked. */
  ids: Map<string, string[]>;
  unchecked: number;
  error?: string;
}

export async function queryVulnerabilityIds(
  dependencies: Dependency[],
  context: SourceContext,
): Promise<IdLookup> {
  const ids = new Map<string, string[]>();
  const pending: Dependency[] = [];
  for (const dependency of dependencies) {
    const cached = await context.cache.getUsable<string[]>(
      'osv-query',
      dependencyKey(dependency),
    );
    if (cached) ids.set(dependencyKey(dependency), cached);
    else pending.push(dependency);
  }
  if (pending.length === 0) return { ids, unchecked: 0 };
  if (context.cache.offline)
    return {
      ids,
      unchecked: pending.length,
      error: `offline and ${pending.length} package(s) are not in the cache`,
    };

  let unchecked = pending.length;
  try {
    for (let offset = 0; offset < pending.length; offset += BATCH_SIZE) {
      let queue = pending
        .slice(offset, offset + BATCH_SIZE)
        .map((dependency) => ({
          dependency,
          found: [] as string[],
          token: undefined as string | undefined,
          seenTokens: new Set<string>(),
        }));
      const batch = [...queue];
      while (queue.length > 0) {
        const response = await getJson(context.http, `${OSV_API}/querybatch`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            queries: queue.map(({ dependency, token }) =>
              toQuery(dependency, token),
            ),
          }),
        });
        const pages = parseBatch(response, queue.length);
        queue = queue.filter((item, index) => {
          const page = pages[index]!;
          item.found = [...new Set([...item.found, ...page.ids])];
          if (!page.token) return false;
          if (item.seenTokens.has(page.token))
            throw new Error('OSV repeated a page token.');
          item.seenTokens.add(page.token);
          item.token = page.token;
          return true;
        });
      }
      for (const { dependency, found } of batch) {
        ids.set(dependencyKey(dependency), found);
        await context.cache.set('osv-query', dependencyKey(dependency), found);
      }
      unchecked -= batch.length;
    }
  } catch (error) {
    return { ids, unchecked, error: errorMessage(error) };
  }
  return { ids, unchecked: 0 };
}

// ---------------------------------------------------------------------------
// Step 2: GET /v1/vulns/{id} -> details, trimmed to what the report needs.

export interface OsvRange {
  type: string;
  events: Record<string, string>[];
}

export interface OsvAffected {
  ecosystem: string;
  name: string;
  purl: string;
  ranges: OsvRange[];
  severity?: string;
}

export interface OsvRecord {
  id: string;
  summary: string;
  aliases: string[];
  severity: { type: string; score: string }[];
  databaseSeverity?: string;
  affected: OsvAffected[];
  references: string[];
}

const str = (value: unknown): string =>
  typeof value === 'string' ? value : '';

export function trimRecord(value: unknown): OsvRecord {
  if (!isRecord(value) || typeof value.id !== 'string')
    throw new Error('OSV returned an invalid vulnerability record.');
  const list = (item: unknown): unknown[] => (Array.isArray(item) ? item : []);
  const details = str(value.details).replace(/\s+/g, ' ').trim();
  const databaseSeverity = isRecord(value.database_specific)
    ? str(value.database_specific.severity)
    : '';
  return {
    id: value.id,
    summary: str(value.summary) || details.slice(0, 160),
    aliases: list(value.aliases).filter(
      (a): a is string => typeof a === 'string',
    ),
    severity: list(value.severity)
      .filter(isRecord)
      .map((item) => ({ type: str(item.type), score: str(item.score) })),
    ...(databaseSeverity ? { databaseSeverity } : {}),
    affected: list(value.affected)
      .filter(isRecord)
      .map((item) => {
        const pkg = isRecord(item.package) ? item.package : {};
        const ecosystemSeverity = isRecord(item.ecosystem_specific)
          ? str(item.ecosystem_specific.severity)
          : '';
        return {
          ecosystem: str(pkg.ecosystem),
          name: str(pkg.name),
          purl: str(pkg.purl),
          ranges: list(item.ranges)
            .filter(isRecord)
            .map((range) => ({
              type: str(range.type),
              events: list(range.events)
                .filter(isRecord)
                .map((event) =>
                  Object.fromEntries(
                    Object.entries(event).filter(
                      (entry): entry is [string, string] =>
                        typeof entry[1] === 'string',
                    ),
                  ),
                ),
            })),
          ...(ecosystemSeverity ? { severity: ecosystemSeverity } : {}),
        };
      }),
    references: list(value.references)
      .filter(isRecord)
      .map((item) => str(item.url))
      .filter(Boolean)
      .slice(0, 10),
  };
}

export interface DetailLookup {
  records: Map<string, OsvRecord>;
  failed: string[];
  error?: string;
}

export async function fetchVulnerabilities(
  ids: string[],
  context: SourceContext,
): Promise<DetailLookup> {
  const records = new Map<string, OsvRecord>();
  const failed: string[] = [];
  let firstError: string | undefined;
  await mapLimit(ids, DETAIL_CONCURRENCY, async (id) => {
    const cached = await context.cache.getUsable<OsvRecord>('osv-vuln', id);
    if (cached) {
      records.set(id, cached);
      return;
    }
    if (context.cache.offline) {
      failed.push(id);
      firstError ??= 'offline and some advisories are not in the cache';
      return;
    }
    try {
      const record = trimRecord(
        await getJson(
          context.http,
          `${OSV_API}/vulns/${encodeURIComponent(id)}`,
        ),
      );
      records.set(id, record);
      await context.cache.set('osv-vuln', id, record);
    } catch (error) {
      failed.push(id);
      firstError ??= errorMessage(error);
    }
  });
  return { records, failed, ...(firstError ? { error: firstError } : {}) };
}

// ---------------------------------------------------------------------------
// Normalisation helpers.

export function cveIds(record: Pick<OsvRecord, 'id' | 'aliases'>): string[] {
  return [record.id, ...record.aliases].filter((id) =>
    /^CVE-\d{4}-\d{4,}$/.test(id),
  );
}

export interface Severity {
  level: SeverityLevel;
  score: number | null;
  vector: string | null;
}

export function severityOf(
  record: OsvRecord,
  dependency: Dependency,
): Severity {
  const v3 = record.severity.find((item) => item.type === 'CVSS_V3');
  const score = v3 ? cvss3BaseScore(v3.score) : undefined;
  if (score !== undefined)
    return { level: levelFromScore(score), score, vector: v3!.score };
  // TODO: compute CVSS v4 base scores; until then the advisory's label is used.
  const vector =
    record.severity.find((item) => item.type.startsWith('CVSS'))?.score ?? null;
  const label =
    levelFromLabel(record.databaseSeverity) ??
    levelFromLabel(matchingAffected(record, dependency)[0]?.severity);
  return { level: label ?? 'unknown', score: null, vector };
}

const normalizeName = (ecosystem: string, name: string) =>
  ecosystem === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;

function matchingAffected(record: OsvRecord, dependency: Dependency) {
  const matches = record.affected.filter((item) =>
    dependency.purl
      ? dependency.purl.startsWith(item.purl || '\0')
      : item.ecosystem === dependency.ecosystem &&
        normalizeName(item.ecosystem, item.name) ===
          normalizeName(dependency.ecosystem, dependency.name),
  );
  return matches.length > 0 ? matches : record.affected;
}

/** Loose version ordering good enough to pick a fix: numeric segments, pre-releases sort first. */
export function compareVersions(a: string, b: string): number {
  const left = a.replace(/^v/, '').split(/[.+-]/);
  const right = b.replace(/^v/, '').split(/[.+-]/);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const x = left[index];
    const y = right[index];
    if (x === y) continue;
    if (x === undefined) return /^\d+$/.test(y!) ? -1 : 1;
    if (y === undefined) return /^\d+$/.test(x) ? 1 : -1;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) return Number(x) - Number(y);
    if (xn !== yn) return xn ? 1 : -1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/** Fixed versions for this dependency and the nearest one that resolves the installed version. */
export function fixesFor(
  record: OsvRecord,
  dependency: Dependency,
): { recommended: string | null; all: string[] } {
  const all: string[] = [];
  let containing: string | undefined;
  for (const affected of matchingAffected(record, dependency)) {
    for (const range of affected.ranges) {
      if (range.type === 'GIT') continue;
      let introduced = '0';
      for (const event of range.events) {
        if (event.introduced !== undefined) introduced = event.introduced;
        if (event.fixed === undefined) continue;
        all.push(event.fixed);
        if (
          containing === undefined &&
          (introduced === '0' ||
            compareVersions(dependency.version, introduced) >= 0) &&
          compareVersions(dependency.version, event.fixed) < 0
        )
          containing = event.fixed;
      }
    }
  }
  const unique = [...new Set(all)].sort(compareVersions);
  const recommended =
    containing ??
    unique.find((version) => compareVersions(version, dependency.version) > 0);
  return { recommended: recommended ?? null, all: unique };
}
