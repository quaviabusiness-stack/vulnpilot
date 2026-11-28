// GET /api/kev: the CISA Known Exploited Vulnerabilities catalog, trimmed to
// the fields Relvet uses and served same-origin, because browsers cannot
// read the CISA feed cross-origin (it sends no CORS headers).
//
// It takes no input: the upstream URL is fixed, query strings are refused, and
// only GET and HEAD are allowed. The response is cached by Vercel's CDN for
// three hours and served stale for up to a day while it revalidates, so CISA
// sees at most a few requests a day and an upstream outage keeps the last good
// copy. Errors are never cached.
import { KEV_URL, parseKev } from '../../src/kev.js';
import { isRecord } from '../../src/types.js';

const MAX_BYTES = 10 * 1024 * 1024;
const TIMEOUT_MS = 20_000;
const CACHE = 'public, max-age=0, s-maxage=10800, stale-while-revalidate=86400';

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

export interface TrimmedKev {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: {
    cveID: string;
    vulnerabilityName: string;
    dateAdded: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
  }[];
}

/**
 * Keeps exactly what `parseKev` reads, converted the same way, so the CLI's
 * parser gives the same entries from this copy as from the full feed.
 */
export function trimKev(feed: unknown): TrimmedKev {
  parseKev(feed); // Throws on anything the CLI would reject.
  const value = feed as Record<string, unknown>;
  const vulnerabilities = (value.vulnerabilities as unknown[])
    .filter(
      (item): item is Record<string, unknown> =>
        isRecord(item) && typeof item.cveID === 'string',
    )
    .map((item) => ({
      cveID: item.cveID as string,
      vulnerabilityName: String(item.vulnerabilityName ?? ''),
      dateAdded: String(item.dateAdded ?? ''),
      dueDate: String(item.dueDate ?? ''),
      knownRansomwareCampaignUse: String(item.knownRansomwareCampaignUse),
    }));
  return {
    catalogVersion: String(value.catalogVersion ?? ''),
    dateReleased: String(value.dateReleased ?? ''),
    count: vulnerabilities.length,
    vulnerabilities,
  };
}

async function readCapped(response: Response): Promise<string> {
  const declared = Number(response.headers.get('content-length'));
  if (declared > MAX_BYTES) throw new Error('feed too large');
  if (!response.body) throw new Error('empty response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BYTES) {
      await reader.cancel();
      throw new Error('feed too large');
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

export async function fetchTrimmedKev(
  fetcher: typeof fetch = fetch,
): Promise<TrimmedKev> {
  const response = await fetcher(KEV_URL, {
    redirect: 'error',
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`HTTP ${response.status} from CISA`);
  return trimKev(JSON.parse(await readCapped(response)));
}

const json = (status: number, body: unknown, headers: Record<string, string>) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...SECURITY_HEADERS,
      ...headers,
    },
  });

/** The handler, with the upstream fetch injectable for tests. */
export async function handle(
  request: Request,
  fetcher: typeof fetch = fetch,
): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD')
    return json(
      405,
      { error: 'Method not allowed.' },
      {
        Allow: 'GET, HEAD',
        'Cache-Control': 'no-store',
      },
    );
  // Any query string would bypass the CDN cache and reach CISA through us.
  if (new URL(request.url).search !== '')
    return json(
      400,
      { error: 'This endpoint takes no parameters.' },
      {
        'Cache-Control': 'no-store',
      },
    );
  try {
    const catalog = await fetchTrimmedKev(fetcher);
    const response = json(200, catalog, { 'Cache-Control': CACHE });
    return request.method === 'HEAD'
      ? new Response(null, { status: 200, headers: response.headers })
      : response;
  } catch (error) {
    console.error(
      `CISA KEV feed unavailable: ${error instanceof Error ? error.message : String(error)}`,
    );
    return json(
      502,
      { error: 'The CISA KEV feed could not be fetched.' },
      {
        'Cache-Control': 'no-store',
      },
    );
  }
}

export const GET = (request: Request) => handle(request);
export const HEAD = (request: Request) => handle(request);
export const POST = (request: Request) => handle(request);
export const PUT = (request: Request) => handle(request);
export const PATCH = (request: Request) => handle(request);
export const DELETE = (request: Request) => handle(request);
export const OPTIONS = (request: Request) => handle(request);
