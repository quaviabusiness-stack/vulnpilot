// A tiny element tree that renders to DOM nodes in the browser and to HTML in
// the generator, so static first renders and live updates share one template.
// Text is always text: there is no way to pass markup through.

export interface VNode {
  tag: string;
  attrs: Readonly<Record<string, string>>;
  children: readonly Child[];
}
export type Child = VNode | string | null | false | undefined;

export function h(
  tag: string,
  attrs: Record<string, string | false | null | undefined> = {},
  ...children: Child[]
): VNode {
  const clean: Record<string, string> = {};
  for (const [name, value] of Object.entries(attrs))
    if (typeof value === 'string') clean[name] = value;
  return { tag, attrs: clean, children };
}

const ATTRIBUTE = /^[a-z][a-z0-9-]*$/;
const TAG = /^[a-z][a-z0-9]*$/;

function check(node: VNode): void {
  if (!TAG.test(node.tag) || node.tag === 'script' || node.tag === 'style')
    throw new Error(`Unsupported element ${node.tag}.`);
  for (const name of Object.keys(node.attrs))
    if (!ATTRIBUTE.test(name) || name.startsWith('on'))
      throw new Error(`Unsupported attribute ${name}.`);
}

export function toDom(node: Child, document: Document): Node | null {
  if (node === null || node === false || node === undefined) return null;
  if (typeof node === 'string') return document.createTextNode(node);
  check(node);
  const element = document.createElement(node.tag);
  for (const [name, value] of Object.entries(node.attrs))
    element.setAttribute(name, value);
  for (const child of node.children) {
    const rendered = toDom(child, document);
    if (rendered) element.append(rendered);
  }
  return element;
}

const escapeText = (text: string) =>
  text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const escapeAttribute = (text: string) =>
  escapeText(text).replaceAll('"', '&quot;');
const VOID = new Set(['br', 'hr', 'img', 'input', 'meta', 'link', 'col']);

export function toHtml(node: Child): string {
  if (node === null || node === false || node === undefined) return '';
  if (typeof node === 'string') return escapeText(node);
  check(node);
  const attrs = Object.entries(node.attrs)
    .map(([name, value]) =>
      value === '' ? ` ${name}` : ` ${name}="${escapeAttribute(value)}"`,
    )
    .join('');
  if (VOID.has(node.tag)) return `<${node.tag}${attrs} />`;
  return `<${node.tag}${attrs}>${node.children.map(toHtml).join('')}</${node.tag}>`;
}
