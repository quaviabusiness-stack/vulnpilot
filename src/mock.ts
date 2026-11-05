// Offline stand-ins for OSV, CISA KEV and FIRST EPSS. Used by the test suite and
// by `VULNPILOT_MOCK=1` smoke tests. All IDs are synthetic (CVE-2099-*, GHSA-mock-*).
import epss from '../test/fixtures/mock/epss.json' with { type: 'json' };
import kev from '../test/fixtures/mock/kev.json' with { type: 'json' };
import index from '../test/fixtures/mock/osv-index.json' with { type: 'json' };
import vulns from '../test/fixtures/mock/osv-vulns.json' with { type: 'json' };
import { EPSS_API } from './epss.js';
import { KEV_URL } from './kev.js';
import { OSV_API } from './osv.js';
import { isRecord } from './types.js';

const osvIndex: Record<string, string[]> = index;
const osvVulns: Record<string, unknown> = vulns;
const epssScores: Record<string, { epss: string; percentile: string }> = epss;

function queryKey(query: unknown): string {
  if (!isRecord(query) || !isRecord(query.package)) return '';
  if (typeof query.package.purl === 'string') return query.package.purl;
  return `${String(query.package.ecosystem)}|${String(query.package.name)}|${String(query.version)}`;
}

export function createMockFetch(): typeof fetch {
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.href === `${OSV_API}/querybatch`) {
      const { queries } = JSON.parse(String(init?.body)) as {
        queries: unknown[];
      };
      return Response.json({
        results: queries.map((query) => {
          const ids = osvIndex[queryKey(query)] ?? [];
          return ids.length > 0
            ? {
                vulns: ids.map((id) => ({
                  id,
                  modified: '2099-01-01T00:00:00Z',
                })),
              }
            : {};
        }),
      });
    }
    if (url.href.startsWith(`${OSV_API}/vulns/`)) {
      const id = decodeURIComponent(url.pathname.split('/').pop() ?? '');
      const record = osvVulns[id];
      return record
        ? Response.json(record)
        : Response.json(
            { code: 5, message: 'Bug not found.' },
            { status: 404 },
          );
    }
    if (url.href === KEV_URL) return Response.json(kev);
    if (`${url.origin}${url.pathname}` === EPSS_API) {
      const cves = (url.searchParams.get('cve') ?? '').split(',');
      const data = cves
        .filter((cve) => Object.hasOwn(epssScores, cve))
        .map((cve) => ({ cve, ...epssScores[cve], date: '2099-01-01' }));
      return Response.json({ status: 'OK', total: data.length, data });
    }
    return new Response('Not found', { status: 404 });
  };
}
