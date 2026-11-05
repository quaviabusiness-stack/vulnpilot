import { type Dependency, isRecord } from '../types.js';
import { DependencySet, type ParseResult } from './common.js';

export interface Purl {
  type: string;
  namespace: string;
  name: string;
  version: string | undefined;
  qualifiers: Record<string, string>;
}

function decode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Minimal package-url parser (https://github.com/package-url/purl-spec). */
export function parsePurl(purl: string): Purl | undefined {
  if (!purl.startsWith('pkg:')) return undefined;
  let rest = purl.slice(4).replace(/^\/+/, '');
  const hash = rest.indexOf('#');
  if (hash >= 0) rest = rest.slice(0, hash);
  const qualifiers: Record<string, string> = {};
  const question = rest.indexOf('?');
  if (question >= 0) {
    for (const pair of rest.slice(question + 1).split('&')) {
      const [key, value = ''] = pair.split('=');
      if (key) qualifiers[key.toLowerCase()] = decode(value);
    }
    rest = rest.slice(0, question);
  }
  let version: string | undefined;
  const at = rest.lastIndexOf('@');
  // An unencoded npm scope ("@scope/name") must not be mistaken for a version.
  if (at > rest.lastIndexOf('/')) {
    version = decode(rest.slice(at + 1));
    rest = rest.slice(0, at);
  }
  const segments = rest.split('/').filter(Boolean);
  const type = segments.shift()?.toLowerCase();
  const name = segments.pop();
  if (!type || !name) return undefined;
  return {
    type,
    namespace: segments.map(decode).join('/'),
    name: decode(name),
    version,
    qualifiers,
  };
}

// purl type -> OSV ecosystem and package-name convention.
const ECOSYSTEMS: Record<string, (purl: Purl) => [string, string]> = {
  npm: (p) => ['npm', p.namespace ? `${p.namespace}/${p.name}` : p.name],
  pypi: (p) => ['PyPI', p.name],
  maven: (p) => ['Maven', `${p.namespace}:${p.name}`],
  golang: (p) => ['Go', p.namespace ? `${p.namespace}/${p.name}` : p.name],
  cargo: (p) => ['crates.io', p.name],
  gem: (p) => ['RubyGems', p.name],
  nuget: (p) => ['NuGet', p.name],
  composer: (p) => ['Packagist', `${p.namespace}/${p.name}`],
  hex: (p) => ['Hex', p.name],
  pub: (p) => ['Pub', p.name],
  conan: (p) => ['ConanCenter', p.name],
};
// Distribution packages are passed to OSV as purls (OSV maps them by distro qualifier).
const PURL_PASSTHROUGH = new Set(['deb', 'apk']);

export function purlToDependency(purl: string): Dependency | undefined {
  const parsed = parsePurl(purl);
  if (!parsed?.version) return undefined;
  const mapper = ECOSYSTEMS[parsed.type];
  if (mapper) {
    const [ecosystem, name] = mapper(parsed);
    return { ecosystem, name, version: parsed.version };
  }
  if (PURL_PASSTHROUGH.has(parsed.type))
    return {
      ecosystem: '',
      name: parsed.namespace
        ? `${parsed.namespace}/${parsed.name}`
        : parsed.name,
      version: parsed.version,
      purl: purl.replace(/#.*$/, ''),
    };
  return undefined;
}

export function parseCycloneDx(content: string): ParseResult {
  const bom: unknown = JSON.parse(content);
  if (!isRecord(bom) || bom.bomFormat !== 'CycloneDX')
    throw new Error('Expected a CycloneDX JSON SBOM (bomFormat "CycloneDX").');
  if (bom.components !== undefined && !Array.isArray(bom.components))
    throw new Error('CycloneDX components must be an array.');

  const set = new DependencySet();
  function visit(components: unknown[]): void {
    for (const component of components) {
      if (!isRecord(component)) continue;
      // TODO: match components without a purl (e.g. CPE-only firmware parts).
      const dependency =
        typeof component.purl === 'string'
          ? purlToDependency(component.purl)
          : undefined;
      if (dependency) set.add(dependency);
      else set.skip();
      if (Array.isArray(component.components)) visit(component.components);
    }
  }
  visit((bom.components ?? []) as unknown[]);
  return set.result();
}
