import type { Dependency } from '../types.js';

export function parseYarnLock(_content: string): Dependency[] {
  // TODO: Support Yarn Classic and Berry lockfile formats.
  throw new Error('yarn.lock support is not implemented yet.');
}
