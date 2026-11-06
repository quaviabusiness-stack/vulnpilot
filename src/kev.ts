import { errorMessage, getJson } from './http.js';
import type { SourceContext } from './osv.js';
import { isRecord } from './types.js';

export const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export interface KevEntry {
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: boolean;
  name: string;
}

interface KevCatalog {
  catalogVersion: string;
  entries: Record<string, KevEntry>;
}

export interface KevLookup {
  entries: Map<string, KevEntry> | null;
  catalogVersion?: string;
  note?: string;
  error?: string;
}

export function parseKev(value: unknown): KevCatalog {
  if (!isRecord(value) || !Array.isArray(value.vulnerabilities))
    throw new Error('CISA KEV feed has an unexpected format.');
  const entries: Record<string, KevEntry> = {};
  for (const item of value.vulnerabilities) {
    if (!isRecord(item) || typeof item.cveID !== 'string') continue;
    entries[item.cveID] = {
      dateAdded: String(item.dateAdded ?? ''),
      dueDate: String(item.dueDate ?? ''),
      knownRansomwareCampaignUse:
        String(item.knownRansomwareCampaignUse).toLowerCase() === 'known',
      name: String(item.vulnerabilityName ?? ''),
    };
  }
  if (Object.keys(entries).length === 0)
    throw new Error('CISA KEV feed contained no vulnerabilities.');
  return { catalogVersion: String(value.catalogVersion ?? ''), entries };
}

function lookup(catalog: KevCatalog, note?: string): KevLookup {
  return {
    entries: new Map(Object.entries(catalog.entries)),
    catalogVersion: catalog.catalogVersion,
    ...(note ? { note } : {}),
  };
}

export async function loadKev(context: SourceContext): Promise<KevLookup> {
  const hit = await context.cache.get<KevCatalog>('kev', KEV_URL);
  if (hit && (hit.fresh || context.cache.offline)) return lookup(hit.value);
  if (context.cache.offline)
    return {
      entries: null,
      error: 'offline and the KEV catalog is not cached',
    };
  try {
    // The full feed is ~2 MB, so it gets a longer timeout than API calls.
    const catalog = parseKev(
      await getJson(
        context.http,
        KEV_URL,
        {},
        Math.max(context.http.timeoutMs, 20_000),
      ),
    );
    await context.cache.set('kev', KEV_URL, catalog);
    return lookup(catalog);
  } catch (error) {
    if (hit)
      return lookup(
        hit.value,
        `download failed (${errorMessage(error)}); using cached catalog from ${new Date(hit.fetchedAt).toISOString().slice(0, 10)}`,
      );
    return { entries: null, error: errorMessage(error) };
  }
}
