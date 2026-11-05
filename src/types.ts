/** A resolved package version to look up in OSV. */
export interface Dependency {
  /** OSV ecosystem name, e.g. `npm`, `PyPI`, `Maven`. Empty when only a purl is known. */
  ecosystem: string;
  name: string;
  version: string;
  /** Set for SBOM components whose purl type has no OSV ecosystem mapping; queried by purl. */
  purl?: string;
}

export type InputFormat =
  'package-lock' | 'pnpm-lock' | 'yarn-v1' | 'yarn-berry' | 'cyclonedx';

export interface Inventory {
  format: InputFormat;
  file: string;
  dependencies: Dependency[];
  /** Entries that could not be queried (no exact version, local links, unsupported purls). */
  skipped: number;
}

export type Answer = 'yes' | 'no' | 'unknown';
export type ProductType =
  'app' | 'library' | 'firmware' | 'saas' | 'saas-with-client' | 'unknown';

export interface Answers {
  euDistribution: Answer;
  commercial: Answer;
  productType: ProductType;
}

export type CraVerdict = 'likely_applies' | 'likely_out_of_scope' | 'unclear';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export type SourceName = 'osv' | 'cisa-kev' | 'first-epss';
export type SourceStatus = 'ok' | 'partial' | 'unavailable';

export interface SourceReport {
  name: SourceName;
  status: SourceStatus;
  message?: string;
}

export function dependencyKey(dependency: Dependency): string {
  return (
    dependency.purl ??
    `${dependency.ecosystem}\0${dependency.name}\0${dependency.version}`
  );
}

export function dependencyLabel(dependency: Dependency): string {
  return `${dependency.name}@${dependency.version}`;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
