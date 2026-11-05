import type { SeverityLevel } from './types.js';

// CVSS v3.0/v3.1 base-score calculation (FIRST specification, section 7).
const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

function roundUp(value: number): number {
  const scaled = Math.round(value * 100_000);
  return scaled % 10_000 === 0
    ? scaled / 100_000
    : (Math.floor(scaled / 10_000) + 1) / 10;
}

/** Returns the CVSS v3 base score for a vector, or undefined if it is not a valid v3 vector. */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const metrics = new Map(
    vector
      .split('/')
      .slice(1)
      .map((part) => part.split(':') as [string, string]),
  );
  const pick = <T extends Record<string, number>>(table: T, key: string) =>
    table[metrics.get(key) as keyof T] as number | undefined;
  const scope = metrics.get('S');
  const av = pick(WEIGHTS.AV, 'AV');
  const ac = pick(WEIGHTS.AC, 'AC');
  const ui = pick(WEIGHTS.UI, 'UI');
  const c = pick(WEIGHTS.CIA, 'C');
  const i = pick(WEIGHTS.CIA, 'I');
  const a = pick(WEIGHTS.CIA, 'A');
  const prValue = metrics.get('PR');
  const pr =
    prValue === 'N'
      ? 0.85
      : prValue === 'L'
        ? scope === 'C'
          ? 0.68
          : 0.62
        : prValue === 'H'
          ? scope === 'C'
            ? 0.5
            : 0.27
          : undefined;
  if (
    (scope !== 'U' && scope !== 'C') ||
    [av, ac, ui, c, i, a, pr].some((value) => value === undefined)
  )
    return undefined;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact =
    scope === 'U'
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  if (impact <= 0) return 0;
  return scope === 'U'
    ? roundUp(Math.min(impact + exploitability, 10))
    : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

export function levelFromScore(score: number): SeverityLevel {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

export function levelFromLabel(label: unknown): SeverityLevel | undefined {
  if (typeof label !== 'string') return undefined;
  switch (label.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return undefined;
  }
}
