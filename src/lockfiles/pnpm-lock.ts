import type { Dependency } from '../types.js';

export function parsePnpmLock(_content: string): Dependency[] {
  // TODO: Parse pnpm snapshots, aliases, workspace links and peer suffixes.
  throw new Error('pnpm-lock.yaml support is not implemented yet.');
}
