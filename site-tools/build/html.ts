// Rewrites the generated parts of the hand-written pages in site/: hashed
// asset references, `<!-- generated:name -->` regions and `data-proof` values.
// Everything else in the HTML is left exactly as written.
import * as prettier from 'prettier';

export type Manifest = ReadonlyMap<string, string>;

const HASHED = /\/assets\/([a-z0-9/_-]+?)-[A-Za-z0-9]{8,10}\.(css|js|woff2)/g;

/** Points every `/assets/name-<hash>.ext` reference at the current build. */
export function rewriteAssets(
  html: string,
  manifest: Manifest,
  file: string,
): string {
  return html.replace(HASHED, (match, name: string, ext: string) => {
    const logical = `/assets/${name}.${ext}`;
    const current = manifest.get(logical);
    if (!current) throw new Error(`${file}: unknown asset ${match}`);
    return current;
  });
}

const REGION =
  /<!-- generated:([a-z0-9-]+) -->[\s\S]*?<!-- \/generated:\1 -->/g;

export function replaceRegions(
  html: string,
  regions: Readonly<Record<string, string>>,
  file: string,
  used: Set<string>,
): string {
  return html.replace(REGION, (_match, name: string) => {
    const content = regions[name];
    if (content === undefined)
      throw new Error(`${file}: unknown region ${name}`);
    used.add(name);
    return `<!-- generated:${name} -->\n${content}\n<!-- /generated:${name} -->`;
  });
}

export interface ProofValue {
  html: string;
  datetime?: string;
}

// Prettier may break attributes and closing tags across lines.
const VALUE =
  /<(span|time)((?:\s+[a-z-]+="[^"]*")*?)\s+data-proof="([a-z-]+)"((?:\s+[a-z-]+="[^"]*")*)\s*>[^<]*<\/\1\s*>/g;

export function replaceValues(
  html: string,
  values: Readonly<Record<string, ProofValue>>,
  file: string,
): string {
  return html.replace(
    VALUE,
    (_match, tag: string, before: string, key: string, after: string) => {
      const value = values[key];
      if (!value) throw new Error(`${file}: unknown data-proof value ${key}`);
      let attrs = `${before} data-proof="${key}"${after}`;
      if (tag === 'time') {
        if (!value.datetime) throw new Error(`${file}: ${key} has no datetime`);
        attrs =
          attrs.replace(/\sdatetime="[^"]*"/, '') +
          ` datetime="${value.datetime}"`;
      }
      return `<${tag}${attrs}>${value.html}</${tag}>`;
    },
  );
}

export async function formatHtml(
  html: string,
  filepath: string,
): Promise<string> {
  const options = (await prettier.resolveConfig(filepath)) ?? {};
  return prettier.format(html, { ...options, filepath });
}
