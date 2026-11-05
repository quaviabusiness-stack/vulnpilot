import { lstat, readFile } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';
import type { InputFormat, Inventory } from '../types.js';
import type { ParseResult } from './common.js';
import { parseCycloneDx } from './cyclonedx.js';
import { parsePackageLock } from './package-lock.js';
import { parsePnpmLock } from './pnpm-lock.js';
import { parseYarnLock, yarnLockFormat } from './yarn-lock.js';

interface LockfileParser {
  parse: (content: string) => ParseResult;
  format: (content: string) => InputFormat;
}

const LOCKFILES: Record<string, LockfileParser> = {
  'package-lock.json': {
    parse: parsePackageLock,
    format: () => 'package-lock',
  },
  'pnpm-lock.yaml': { parse: parsePnpmLock, format: () => 'pnpm-lock' },
  'yarn.lock': { parse: parseYarnLock, format: yarnLockFormat },
};
const SUPPORTED = Object.keys(LOCKFILES).join(', ');

export class InputError extends Error {}

async function regularFile(file: string): Promise<string> {
  let info;
  try {
    info = await lstat(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT')
      throw new InputError(`File not found: ${file}`);
    throw error;
  }
  if (info.isSymbolicLink())
    throw new InputError('Input files must not be symlinks.');
  if (!info.isFile()) throw new InputError(`Not a regular file: ${file}`);
  return readFile(file, 'utf8');
}

function parseWith(
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

export async function readSbom(file: string): Promise<Inventory> {
  const content = await regularFile(resolve(file));
  return parseWith(file, () => parseCycloneDx(content), 'cyclonedx');
}

/** Reads one supported lockfile from a project directory or an explicit lockfile path. */
export async function readLockfile(input: string): Promise<Inventory> {
  const target = resolve(input);
  let info;
  try {
    info = await lstat(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT')
      throw new InputError(`Path not found: ${input}`);
    throw error;
  }
  if (info.isSymbolicLink())
    throw new InputError('Lockfile paths must not be symlinks.');
  let file = target;
  if (info.isDirectory()) {
    const found: string[] = [];
    for (const name of Object.keys(LOCKFILES)) {
      try {
        await lstat(join(target, name));
        found.push(name);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    if (found.length === 0)
      throw new InputError(
        `No lockfile found in ${target}. Expected one of ${SUPPORTED}. ` +
          'Run your package manager install first, pass --path <dir|lockfile>, ' +
          'or use --sbom <cyclonedx.json> for non-npm projects.',
      );
    if (found.length > 1)
      throw new InputError(
        `Multiple lockfiles found in ${target} (${found.join(', ')}). ` +
          'Pass the one you ship with, e.g. --path ' +
          join(input, found[0]!),
      );
    file = join(target, found[0]!);
  }
  const name = basename(file);
  const parser = Object.hasOwn(LOCKFILES, name) ? LOCKFILES[name] : undefined;
  if (!parser)
    throw new InputError(
      `Unsupported file ${name}. Expected one of ${SUPPORTED}, or use --sbom for CycloneDX.`,
    );
  const content = await regularFile(file);
  return parseWith(
    relative(process.cwd(), file) || file,
    () => parser.parse(content),
    parser.format(content),
  );
}
