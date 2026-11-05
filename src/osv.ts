import mockLock from '../test/fixtures/package-lock.json' with { type: 'json' };
import mockResponse from '../test/fixtures/osv-response.json' with { type: 'json' };
import { isRecord, parsePackageLock } from './lockfiles/package-lock.js';
import type { Dependency, Finding } from './types.js';

const ENDPOINT = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 1000;

interface QueryOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
  mock?: boolean;
}

interface Page {
  ids: string[];
  token: string | undefined;
}

function parseResponse(value: unknown, expected: number): Page[] {
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

export async function queryOsv(
  dependencies: Dependency[],
  options: QueryOptions = {},
): Promise<Finding[]> {
  const findings = dependencies.map((dependency) => ({
    dependency,
    vulnerabilityIds: [] as string[],
  }));
  if (options.mock ?? process.env.OSV_MOCK === '1') {
    const fixtureDependencies = parsePackageLock(JSON.stringify(mockLock));
    const pages = parseResponse(mockResponse, fixtureDependencies.length);
    for (const finding of findings) {
      const index = fixtureDependencies.findIndex(
        (item) =>
          item.name === finding.dependency.name &&
          item.version === finding.dependency.version,
      );
      finding.vulnerabilityIds = pages[index]?.ids ?? [];
    }
    return findings;
  }

  const request = options.fetch ?? fetch;
  for (let offset = 0; offset < dependencies.length; offset += BATCH_SIZE) {
    let pending = findings
      .slice(offset, offset + BATCH_SIZE)
      .map((finding) => ({
        finding,
        token: undefined as string | undefined,
        seenTokens: new Set<string>(),
      }));
    while (pending.length > 0) {
      const response = await request(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
        body: JSON.stringify({
          queries: pending.map(({ finding: { dependency }, token }) => ({
            package: { name: dependency.name, ecosystem: dependency.ecosystem },
            version: dependency.version,
            ...(token ? { page_token: token } : {}),
          })),
        }),
      });
      if (!response.ok)
        throw new Error(`OSV request failed (HTTP ${response.status}).`);
      const pages = parseResponse(await response.json(), pending.length);
      pending = pending.filter((item, index) => {
        const page = pages[index]!;
        item.finding.vulnerabilityIds = [
          ...new Set([...item.finding.vulnerabilityIds, ...page.ids]),
        ];
        if (!page.token) return false;
        if (item.seenTokens.has(page.token))
          throw new Error('OSV repeated a page token.');
        item.seenTokens.add(page.token);
        item.token = page.token;
        return true;
      });
    }
  }
  return findings;
}
