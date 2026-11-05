import {
  DependencySet,
  type ParseResult,
  splitSpecifier,
  unquote,
} from './common.js';

// Ranges that do not resolve from a package registry, so their version is not
// an npm release that OSV could match.
const NON_REGISTRY =
  /^(?:file:|link:|portal:|workspace:|patch:|exec:|git|github:|gitlab:|bitbucket:|https?:)/;

function isBerry(lines: string[]): boolean {
  return lines.some((line) => line.trimEnd() === '__metadata:');
}

function entryHeaders(line: string): string[] | undefined {
  if (!line || /^[\s#]/.test(line) || !line.trimEnd().endsWith(':'))
    return undefined;
  return line
    .trimEnd()
    .slice(0, -1)
    .split(/,\s*/)
    .map((item) => unquote(item));
}

/** Yarn Classic (v1): `name@range:` headers followed by `  version "x.y.z"`. */
function parseClassic(lines: string[]): ParseResult {
  const set = new DependencySet();
  let specifier: string | undefined;
  for (const line of lines) {
    const headers = entryHeaders(line);
    if (headers) {
      specifier = headers[0];
      continue;
    }
    const version = /^ {2}version:? +"?([^"\s]+)"?\s*$/.exec(line);
    if (!version || specifier === undefined) continue;
    const parts = splitSpecifier(specifier);
    specifier = undefined;
    if (!parts) {
      set.skip();
      continue;
    }
    const { range } = parts;
    let { name } = parts;
    if (range.startsWith('npm:')) {
      // Alias: `alias@npm:real-name@^1.0.0` resolves to the real package.
      const real = splitSpecifier(range.slice(4));
      if (real) name = real.name;
    } else if (NON_REGISTRY.test(range) || /^[^@\s]+\/[^@\s]+$/.test(range)) {
      set.skip();
      continue;
    }
    set.addNpm(name, version[1]!);
  }
  return set.result();
}

/** Yarn Berry (v2+): each entry has `  resolution: "name@npm:x.y.z"`. */
function parseBerry(lines: string[]): ParseResult {
  const set = new DependencySet();
  for (const line of lines) {
    const match = /^ {2}resolution: +(.+?)\s*$/.exec(line);
    if (!match) continue;
    const parts = splitSpecifier(unquote(match[1]!));
    if (!parts || !parts.range.startsWith('npm:')) {
      set.skip();
      continue;
    }
    set.addNpm(parts.name, parts.range.slice(4));
  }
  return set.result();
}

export function parseYarnLock(content: string): ParseResult {
  const lines = content.split(/\r?\n/);
  if (isBerry(lines)) return parseBerry(lines);
  if (
    content.includes('# yarn lockfile v1') ||
    lines.some((line) => /^ {2}version "/.test(line))
  )
    return parseClassic(lines);
  throw new Error('Expected a Yarn Classic (v1) or Berry (v2+) yarn.lock.');
}

export function yarnLockFormat(content: string): 'yarn-v1' | 'yarn-berry' {
  return isBerry(content.split(/\r?\n/)) ? 'yarn-berry' : 'yarn-v1';
}
