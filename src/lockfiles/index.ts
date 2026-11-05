import { lstat, readFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import type { Dependency } from '../types.js';
import { parsePackageLock } from './package-lock.js';
import { parsePnpmLock } from './pnpm-lock.js';
import { parseYarnLock } from './yarn-lock.js';

const parsers: Record<string, (content: string) => Dependency[]> = {
  'package-lock.json': parsePackageLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'yarn.lock': parseYarnLock,
};

export async function readDependencies(input: string): Promise<Dependency[]> {
  const target = resolve(input);
  const info = await lstat(target);
  if (info.isSymbolicLink())
    throw new Error('Lockfile paths must not be symlinks.');
  let file = target;
  if (info.isDirectory()) {
    const found: string[] = [];
    for (const name of Object.keys(parsers)) {
      try {
        await lstat(join(target, name));
        found.push(name);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    if (found.length !== 1) {
      throw new Error(
        found.length === 0
          ? 'No supported lockfile found. Expected package-lock.json, pnpm-lock.yaml or yarn.lock.'
          : 'Multiple lockfiles found. Use --path with a specific lockfile.',
      );
    }
    file = join(target, found[0]!);
  }
  const parser = Object.hasOwn(parsers, basename(file))
    ? parsers[basename(file)]
    : undefined;
  if (!parser)
    throw new Error('Only supported dependency lockfiles may be read.');
  const fileInfo = await lstat(file);
  if (!fileInfo.isFile() || fileInfo.isSymbolicLink())
    throw new Error('Expected a regular dependency lockfile.');
  return parser(await readFile(file, 'utf8'));
}
