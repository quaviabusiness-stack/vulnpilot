// Input selection without file-system access, shared by the CLI (which reads
// files from disk in ./index.ts) and the browser scanner (which gets a File or
// pasted text).
import type { InputFormat, Inventory } from '../types.js';
import type { ParseResult } from './common.js';
import { parseCycloneDx } from './cyclonedx.js';
import { parsePackageLock } from './package-lock.js';
import { parsePnpmLock } from './pnpm-lock.js';
import { parseYarnLock, yarnLockFormat } from './yarn-lock.js';

export class InputError extends Error {}

export interface LockfileParser {
  parse: (content: string) => ParseResult;
  format: (content: string) => InputFormat;
}

export const LOCKFILES: Readonly<Record<string, LockfileParser>> = {
  'package-lock.json': {
    parse: parsePackageLock,
    format: () => 'package-lock',
  },
  'pnpm-lock.yaml': { parse: parsePnpmLock, format: () => 'pnpm-lock' },
  'yarn.lock': { parse: parseYarnLock, format: yarnLockFormat },
};

export const LOCKFILE_NAMES = Object.keys(LOCKFILES);

/** The parser for a lockfile base name, exactly as the CLI selects it. */
export function lockfileParser(name: string): LockfileParser | undefined {
  return Object.hasOwn(LOCKFILES, name) ? LOCKFILES[name] : undefined;
}

export function parseWith(
  file: string,
  parse: () => ParseResult,
  format: InputFormat,
): Inventory {
  try {
    return { format, file, ...parse() };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new InputError(`Could not parse ${file}: ${reason}`);
  }
}

/** Parses lockfile content the way `--path <lockfile>` does. */
export function parseLockfile(
  file: string,
  parser: LockfileParser,
  content: string,
): Inventory {
  return parseWith(file, () => parser.parse(content), parser.format(content));
}

/** Parses SBOM content the way `--sbom <file>` does. */
export function parseSbom(file: string, content: string): Inventory {
  return parseWith(file, () => parseCycloneDx(content), 'cyclonedx');
}

/** A lockfile base name, or `cyclonedx` for an SBOM. */
export type DetectedInput = (typeof LOCKFILE_NAMES)[number] | 'cyclonedx';

function jsonKind(content: string): DetectedInput | undefined {
  let value: unknown;
  try {
    // A byte order mark only affects detection here; parsing keeps it, as the CLI does.
    value = JSON.parse(content.replace(/^\uFEFF/, ''));
  } catch {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    return undefined;
  if ('bomFormat' in value && value.bomFormat === 'CycloneDX')
    return 'cyclonedx';
  if ('lockfileVersion' in value) return 'package-lock.json';
  return undefined;
}

/**
 * Picks how to read input that did not come from a path on disk. A canonical
 * lockfile name wins, as in the CLI. Anything else (pasted text, a renamed
 * download such as `package-lock (1).json`, an SBOM under any name) is
 * recognised by its content. Returns undefined when nothing matches.
 */
export function detectInput(
  content: string,
  name?: string,
): DetectedInput | undefined {
  if (name && lockfileParser(name)) return name;
  const text = content.replace(/^\uFEFF/, '');
  if (/^\s*[{[]/.test(text)) return jsonKind(text);
  if (/^__metadata:/m.test(text) || text.includes('# yarn lockfile v1'))
    return 'yarn.lock';
  if (/^lockfileVersion:/m.test(text) && /^(?:packages|importers):/m.test(text))
    return 'pnpm-lock.yaml';
  if (/^ {2}version "/m.test(text)) return 'yarn.lock';
  return undefined;
}

/** Reads detected input with the CLI's parsers; `file` is the label shown in the report. */
export function parseDetected(
  file: string,
  detected: DetectedInput,
  content: string,
): Inventory {
  if (detected === 'cyclonedx') return parseSbom(file, content);
  const parser = lockfileParser(detected);
  if (!parser) throw new InputError(`Unsupported input ${detected}.`);
  return parseLockfile(file, parser, content);
}
