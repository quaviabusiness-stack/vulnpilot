import { errorMessage, getJson } from './http.js';
import { reportProgress, type SourceContext } from './source.js';
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
  /** Absent in catalogs cached before this field was read. */
  dateReleased?: string;
  entries: Record<string, KevEntry>;
}

export interface KevLookup {
  entries: Map<string, KevEntry> | null;
  catalogVersion?: string;
  dateReleased?: string;
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
  return {
    catalogVersion: String(value.catalogVersion ?? ''),
    dateReleased: String(value.dateReleased ?? ''),
    entries,
  };
}

function lookup(
  context: SourceContext,
  catalog: KevCatalog,
  note?: string,
): KevLookup {
  const entries = new Map(Object.entries(catalog.entries));
  reportProgress(context, {
    source: 'cisa-kev',
    catalogVersion: catalog.catalogVersion,
    dateReleased: catalog.dateReleased ?? '',
    entries: entries.size,
  });
  return {
    entries,
    catalogVersion: catalog.catalogVersion,
    ...(catalog.dateReleased ? { dateReleased: catalog.dateReleased } : {}),
    ...(note ? { note } : {}),
  };
}

function failure(context: SourceContext, error: string): KevLookup {
  reportProgress(context, { source: 'cisa-kev', error });
  return { entries: null, error };
}

export async function loadKev(context: SourceContext): Promise<KevLookup> {
  const url = context.kevUrl ?? KEV_URL;
  const hit = await context.cache.get<KevCatalog>('kev', url);
  if (hit && (hit.fresh || context.cache.offline))
    return lookup(context, hit.value);
  if (context.cache.offline)
    return failure(context, 'offline and the KEV catalog is not cached');
  try {
    // The full feed is ~2 MB, so it gets a longer timeout than API calls.
    const catalog = parseKev(
      await getJson(
        context.http,
        url,
        {},
        Math.max(context.http.timeoutMs, 20_000),
      ),
    );
    await context.cache.set('kev', url, catalog);
    return lookup(context, catalog);
  } catch (error) {
    if (hit)
      return lookup(
        context,
        hit.value,
        `download failed (${errorMessage(error)}); using cached catalog from ${new Date(hit.fetchedAt).toISOString().slice(0, 10)}`,
      );
    return failure(context, errorMessage(error));
  }
}
