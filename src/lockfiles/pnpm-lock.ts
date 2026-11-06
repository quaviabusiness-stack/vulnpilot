import { DependencySet, type ParseResult, unquote } from './common.js';

// pnpm-lock.yaml is machine-generated with a stable layout, so a line-based
// reader of the top-level `packages:` section avoids a YAML runtime dependency.
// Supported key shapes:
//   v5.x  /name/1.2.3            /@scope/name/1.2.3_peer@1.0.0
//   v6.x  /name@1.2.3            /@scope/name@1.2.3(peer@1.0.0)
//   v9.x  name@1.2.3             '@scope/name@1.2.3'   (peers live in `snapshots:`)
const KEY_LINE =
  /^ {2}('(?:[^']|'')*'|"(?:[^"\\]|\\.)*"|[^\s'"#].*?):(?:\s.*)?$/;

function lockfileVersion(lines: string[]): number {
  const line = lines.find((item) => item.startsWith('lockfileVersion:'));
  const version = line
    ? Number.parseFloat(unquote(line.slice('lockfileVersion:'.length)))
    : Number.NaN;
  if (!Number.isFinite(version) || version < 5 || version >= 10)
    throw new Error(
      'Expected pnpm-lock.yaml with lockfileVersion 5.x, 6.x or 9.x.',
    );
  return version;
}

function parseKey(
  rawKey: string,
  version: number,
): { name: string; version: string } | undefined {
  let key = unquote(rawKey).replaceAll("''", "'");
  if (version < 9) {
    // Registry packages start with "/"; other keys are git, tarball or local sources.
    if (!key.startsWith('/')) return undefined;
    key = key.slice(1);
  }
  if (version < 6) {
    const match = /^((?:@[^/]+\/)?[^/]+)\/([^/_]+)(?:_.+)?$/.exec(key);
    return match ? { name: match[1]!, version: match[2]! } : undefined;
  }
  key = key.replace(/\(.*$/, '');
  const at = key.lastIndexOf('@');
  if (at <= 0) return undefined;
  return { name: key.slice(0, at), version: key.slice(at + 1) };
}

export function parsePnpmLock(content: string): ParseResult {
  const lines = content.split(/\r?\n/);
  const version = lockfileVersion(lines);
  const set = new DependencySet();
  let inPackages = false;
  for (const line of lines) {
    if (/^\S/.test(line)) {
      inPackages = line.trimEnd() === 'packages:';
      continue;
    }
    if (!inPackages) continue;
    const match = KEY_LINE.exec(line);
    if (!match) continue;
    const parsed = parseKey(match[1]!, version);
    if (parsed) set.addNpm(parsed.name, parsed.version);
    else set.skip();
  }
  return set.result();
}
