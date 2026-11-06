import { isRecord } from '../types.js';
import { DependencySet, type ParseResult } from './common.js';

export function parsePackageLock(content: string): ParseResult {
  const lock: unknown = JSON.parse(content);
  if (!isRecord(lock) || ![1, 2, 3].includes(Number(lock.lockfileVersion))) {
    throw new Error(
      'Expected package-lock.json with lockfileVersion 1, 2 or 3.',
    );
  }

  const set = new DependencySet();
  function add(name: string, entry: Record<string, unknown>): void {
    const rawVersion = entry.version;
    if (entry.link === true || typeof rawVersion !== 'string') return;
    let version: string = rawVersion;
    // Local, workspace, URL and git dependencies have no exact npm version.
    if (
      typeof entry.resolved === 'string' &&
      /^(?:file:|link:|git\+|git:|github:)/.test(entry.resolved)
    ) {
      set.skip();
      return;
    }
    if (version.startsWith('npm:')) {
      const separator = version.lastIndexOf('@');
      name = version.slice(4, separator);
      version = version.slice(separator + 1);
    }
    set.addNpm(name, version);
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
  return set.result();
}
