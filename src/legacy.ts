// Compatibility with the tool's name before 0.2.0. The CLI reads RELVET_*
// first; the old VULNPILOT_* variables still work, with a warning, so nobody
// who opted out of telemetry under the old name is silently opted back in.

/** The environment variable prefix used before 0.2.0. */
export const LEGACY_ENV_PREFIX = 'VULNPILOT_';

/** The config directory name used before 0.2.0 (telemetry state only). */
export const LEGACY_CONFIG_NAME = 'vulnpilot';

export type Warn = (message: string) => void;

const warned = new Set<string>();

/** Warn once per process about a deprecated variable. */
export function warnLegacy(name: string, warn: Warn): void {
  if (warned.has(name)) return;
  warned.add(name);
  warn(
    `Relvet: ${LEGACY_ENV_PREFIX}${name} is deprecated; use RELVET_${name} instead.`,
  );
}

/** Test hook: forget which warnings were shown. */
export function resetLegacyWarnings(): void {
  warned.clear();
}

/**
 * RELVET_<name> when set and non-empty, else the legacy VULNPILOT_<name>
 * (warning on use), else undefined.
 */
export function envSetting(
  env: NodeJS.ProcessEnv,
  name: string,
  warn: Warn,
): string | undefined {
  const current = env[`RELVET_${name}`];
  if (current) return current;
  const legacy = env[`${LEGACY_ENV_PREFIX}${name}`];
  if (legacy) {
    warnLegacy(name, warn);
    return legacy;
  }
  return undefined;
}

/** Deprecation warnings go to stderr so they never mix with --json output. */
export const defaultWarn: Warn = (message) => console.error(message);
