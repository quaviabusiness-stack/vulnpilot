import type { Dependency } from '../types.js';

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const exactVersion = /^\d+\.\d+\.\d+(?:-[\da-zA-Z.-]+)?(?:\+[\da-zA-Z.-]+)?$/;

export function parsePackageLock(content: string): Dependency[] {
  const lock: unknown = JSON.parse(content);
  if (!isRecord(lock) || ![1, 2, 3].includes(Number(lock.lockfileVersion))) {
    throw new Error(
      'Expected package-lock.json with lockfileVersion 1, 2 or 3.',
    );
  }

  const dependencies = new Map<string, Dependency>();
  function add(name: string, entry: Record<string, unknown>): void {
    const rawVersion = entry.version;
    if (entry.link === true || typeof rawVersion !== 'string') return;
    let version: string = rawVersion;
    // Local, workspace, URL and git dependencies have no exact npm version.
    if (
      typeof entry.resolved === 'string' &&
      entry.resolved.startsWith('file:')
    )
      return;
    if (version.startsWith('npm:')) {
      const separator = version.lastIndexOf('@');
      name = version.slice(4, separator);
      version = version.slice(separator + 1);
    }
    if (!name || !exactVersion.test(version)) return;
    dependencies.set(`${name}@${version}`, { name, version, ecosystem: 'npm' });
  }

  if (Number(lock.lockfileVersion) >= 2) {
    if (!isRecord(lock.packages)) throw new Error('Missing lockfile packages.');
    for (const [location, entry] of Object.entries(lock.packages)) {
      if (!isRecord(entry) || !location.includes('node_modules/')) continue;
      const inferredName = location.slice(
        location.lastIndexOf('node_modules/') + 13,
      );
      add(typeof entry.name === 'string' ? entry.name : inferredName, entry);
    }
  } else {
    if (!isRecord(lock.dependencies))
      throw new Error('Missing lockfile dependencies.');
    function visit(entries: Record<string, unknown>): void {
      for (const [name, entry] of Object.entries(entries)) {
        if (!isRecord(entry)) continue;
        add(name, entry);
        if (isRecord(entry.dependencies)) visit(entry.dependencies);
      }
    }
    visit(lock.dependencies);
  }
  return [...dependencies.values()];
}
