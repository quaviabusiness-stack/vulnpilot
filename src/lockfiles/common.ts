import { dependencyKey, type Dependency } from '../types.js';

export interface ParseResult {
  dependencies: Dependency[];
  skipped: number;
}

/** Exact npm semver; ranges, tags, git refs and local paths are rejected. */
export const exactNpmVersion =
  /^\d+\.\d+\.\d+(?:-[\da-zA-Z.-]+)?(?:\+[\da-zA-Z.-]+)?$/;

/** Collects dependencies, deduplicated by ecosystem + name + version (or purl). */
export class DependencySet {
  readonly #items = new Map<string, Dependency>();
  #skipped = 0;

  add(dependency: Dependency): void {
    const key = dependencyKey(dependency);
    if (!this.#items.has(key)) this.#items.set(key, dependency);
  }

  addNpm(name: string, version: string): void {
    if (!name || !exactNpmVersion.test(version)) {
      this.#skipped += 1;
      return;
    }
    this.add({ ecosystem: 'npm', name, version });
  }

  skip(): void {
    this.#skipped += 1;
  }

  result(): ParseResult {
    return { dependencies: [...this.#items.values()], skipped: this.#skipped };
  }
}

/** Removes matching single or double quotes around a YAML scalar. */
export function unquote(value: string): string {
  const trimmed = value.trim();
  if (
    trimmed.length >= 2 &&
    (trimmed[0] === '"' || trimmed[0] === "'") &&
    trimmed.at(-1) === trimmed[0]
  )
    return trimmed.slice(1, -1);
  return trimmed;
}

/** Splits `name@range` where the name may be scoped (`@scope/name@range`). */
export function splitSpecifier(
  specifier: string,
): { name: string; range: string } | undefined {
  const at = specifier.indexOf('@', specifier.startsWith('@') ? 1 : 0);
  if (at <= 0) return undefined;
  return { name: specifier.slice(0, at), range: specifier.slice(at + 1) };
}
