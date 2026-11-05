import { type EpssScore, loadEpss } from './epss.js';
import { type KevEntry, loadKev } from './kev.js';
import {
  cveIds,
  fetchVulnerabilities,
  fixesFor,
  type OsvRecord,
  queryVulnerabilityIds,
  type Severity,
  severityOf,
  type SourceContext,
} from './osv.js';
import {
  type Dependency,
  dependencyKey,
  dependencyLabel,
  type SeverityLevel,
  type SourceReport,
} from './types.js';

export interface Issue {
  package: Dependency;
  id: string;
  aliases: string[];
  cves: string[];
  summary: string;
  severity: Severity;
  fixedVersions: string[];
  recommendedFix: string | null;
  kev: (KevEntry & { cve: string }) | null;
  epss: (EpssScore & { cve: string }) | null;
  references: string[];
  /** False when OSV returned the ID but its details could not be fetched. */
  detailsAvailable: boolean;
}

export interface ScanResult {
  issues: Issue[];
  sources: SourceReport[];
  /** Dependencies OSV could not be asked about (offline without cache, outage). */
  uncheckedDependencies: number;
}

const LEVEL_SCORE: Record<SeverityLevel, number> = {
  critical: 9,
  high: 7,
  medium: 4,
  low: 0.1,
  unknown: -1,
};

/** KEV first, then EPSS (highest first), then CVSS (highest first). */
export function compareIssues(a: Issue, b: Issue): number {
  const kev = Number(b.kev !== null) - Number(a.kev !== null);
  if (kev) return kev;
  const epss = (b.epss?.score ?? -1) - (a.epss?.score ?? -1);
  if (epss) return epss;
  const cvss =
    (b.severity.score ?? LEVEL_SCORE[b.severity.level]) -
    (a.severity.score ?? LEVEL_SCORE[a.severity.level]);
  if (cvss) return cvss;
  return (
    dependencyLabel(a.package).localeCompare(dependencyLabel(b.package)) ||
    a.id.localeCompare(b.id)
  );
}

function placeholder(id: string): OsvRecord {
  return {
    id,
    summary: '',
    aliases: [],
    severity: [],
    affected: [],
    references: [],
  };
}

/** Merges advisories for one package that describe the same issue (shared ID or alias). */
function groupRecords(records: { record: OsvRecord; available: boolean }[]) {
  const groups: { ids: Set<string>; members: typeof records }[] = [];
  for (const entry of records) {
    const identifiers = [entry.record.id, ...entry.record.aliases];
    const matching = groups.filter((group) =>
      identifiers.some((id) => group.ids.has(id)),
    );
    const target = matching[0] ?? { ids: new Set<string>(), members: [] };
    if (!matching[0]) groups.push(target);
    for (const other of matching.slice(1)) {
      other.ids.forEach((id) => target.ids.add(id));
      target.members.push(...other.members);
      groups.splice(groups.indexOf(other), 1);
    }
    identifiers.forEach((id) => target.ids.add(id));
    target.members.push(entry);
  }
  return groups.map((group) => {
    const rank = ({ record, available }: (typeof records)[number]) =>
      Number(available) * 4 +
      Number(record.severity.length > 0) * 2 +
      Number(record.id.startsWith('GHSA-'));
    const primary = [...group.members].sort((a, b) => rank(b) - rank(a))[0]!;
    return {
      ...primary,
      aliases: [...group.ids].filter((id) => id !== primary.record.id).sort(),
    };
  });
}

export async function scan(
  dependencies: Dependency[],
  context: SourceContext,
): Promise<ScanResult> {
  // The KEV feed is independent of OSV results, so download it in parallel.
  const kevPromise = loadKev(context);
  const idLookup = await queryVulnerabilityIds(dependencies, context);
  const allIds = [...new Set([...idLookup.ids.values()].flat())].sort();
  const details = await fetchVulnerabilities(allIds, context);

  const issues: Issue[] = [];
  for (const dependency of dependencies) {
    const ids = idLookup.ids.get(dependencyKey(dependency)) ?? [];
    const grouped = groupRecords(
      ids.map((id) => {
        const record = details.records.get(id);
        return {
          record: record ?? placeholder(id),
          available: Boolean(record),
        };
      }),
    );
    for (const { record, available, aliases } of grouped) {
      const fixes = fixesFor(record, dependency);
      issues.push({
        package: dependency,
        id: record.id,
        aliases,
        cves: cveIds({ id: record.id, aliases }),
        summary: record.summary,
        severity: severityOf(record, dependency),
        fixedVersions: fixes.all,
        recommendedFix: fixes.recommended,
        kev: null,
        epss: null,
        references: record.references,
        detailsAvailable: available,
      });
    }
  }

  const cves = [...new Set(issues.flatMap((issue) => issue.cves))];
  const [kev, epss] = await Promise.all([kevPromise, loadEpss(cves, context)]);
  for (const issue of issues) {
    const kevCve = issue.cves.find((cve) => kev.entries?.has(cve));
    if (kevCve) issue.kev = { cve: kevCve, ...kev.entries!.get(kevCve)! };
    for (const cve of issue.cves) {
      const score = epss.scores.get(cve);
      if (score && score.score > (issue.epss?.score ?? -1))
        issue.epss = { cve, ...score };
    }
  }
  issues.sort(compareIssues);

  const sources: SourceReport[] = [];
  if (idLookup.error && idLookup.ids.size === 0 && dependencies.length > 0)
    sources.push({
      name: 'osv',
      status: 'unavailable',
      message: idLookup.error,
    });
  else if (idLookup.error || details.failed.length > 0)
    sources.push({
      name: 'osv',
      status: 'partial',
      message: [
        idLookup.error &&
          `${idLookup.unchecked} package(s) not checked: ${idLookup.error}`,
        details.failed.length > 0 &&
          `${details.failed.length} advisory detail(s) unavailable: ${details.error}`,
      ]
        .filter(Boolean)
        .join('; '),
    });
  else sources.push({ name: 'osv', status: 'ok' });

  if (!kev.entries)
    sources.push({
      name: 'cisa-kev',
      status: 'unavailable',
      message: kev.error ?? '',
    });
  else
    sources.push({
      name: 'cisa-kev',
      status: 'ok',
      ...(kev.note ? { message: kev.note } : {}),
    });

  if (epss.error && epss.scores.size === 0)
    sources.push({
      name: 'first-epss',
      status: 'unavailable',
      message: epss.error,
    });
  else if (epss.error)
    sources.push({
      name: 'first-epss',
      status: 'partial',
      message: `${epss.unchecked} CVE(s) not scored: ${epss.error}`,
    });
  else sources.push({ name: 'first-epss', status: 'ok' });

  return { issues, sources, uncheckedDependencies: idLookup.unchecked };
}
