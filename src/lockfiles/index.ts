import { lstat, readFile } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';
import type { Inventory } from '../types.js';
import {
  InputError,
  LOCKFILE_NAMES,
  lockfileParser,
  parseLockfile,
  parseSbom,
} from './detect.js';

export { InputError } from './detect.js';

const SUPPORTED = LOCKFILE_NAMES.join(', ');

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

export async function readSbom(file: string): Promise<Inventory> {
  const content = await regularFile(resolve(file));
  return parseSbom(file, content);
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
    for (const name of LOCKFILE_NAMES) {
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
  const parser = lockfileParser(name);
  if (!parser)
    throw new InputError(
      `Unsupported file ${name}. Expected one of ${SUPPORTED}, or use --sbom for CycloneDX.`,
    );
  const content = await regularFile(file);
  return parseLockfile(relative(process.cwd(), file) || file, parser, content);
}
