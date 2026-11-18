// Generated parts of /docs and the CRA screen on /scan: the JSON report field
// reference (from schema/report-v1.schema.json) and the CRA questions (from
// src/cra.ts and src/questions.ts).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { assessCra, PRODUCT_TYPES, QUESTIONS } from '../../src/cra.js';
import { YES_NO } from '../../src/questions.js';
import type { ProductType } from '../../src/types.js';
import { craResultView } from '../scanner/cra-view.js';
import { h, toHtml, type VNode } from '../scanner/view.js';
import { ROOT, TOOLS } from './paths.js';

interface SchemaNode {
  type?: string | string[];
  const?: unknown;
  enum?: unknown[];
  pattern?: string;
  format?: string;
  minimum?: number;
  maximum?: number;
  properties?: Record<string, SchemaNode>;
  required?: string[];
  items?: SchemaNode;
  oneOf?: SchemaNode[];
  $ref?: string;
  definitions?: Record<string, SchemaNode>;
}

interface Field {
  path: string;
  type: string;
  required: boolean;
  values: string;
}

function fields(schema: SchemaNode): Field[] {
  const resolve = (node: SchemaNode): SchemaNode =>
    node.$ref
      ? schema.definitions![node.$ref.replace('#/definitions/', '')]!
      : node;
  const out: Field[] = [];
  function describe(node: SchemaNode): { type: string; object?: SchemaNode } {
    node = resolve(node);
    if (node.oneOf) {
      const parts = node.oneOf.map(describe);
      const object = parts.find((part) => part.object)?.object;
      return {
        type: parts.map((part) => part.type).join(' or '),
        ...(object ? { object } : {}),
      };
    }
    if (node.const !== undefined) return { type: 'string' };
    if (node.enum) return { type: 'string' };
    const types = Array.isArray(node.type) ? node.type : [node.type ?? 'any'];
    if (types.includes('array')) {
      const items = describe(node.items ?? {});
      return {
        type: `array of ${items.type === 'object' ? 'objects' : `${items.type}s`}`,
        ...(items.object ? { object: items.object } : {}),
      };
    }
    if (types.includes('object')) return { type: 'object', object: node };
    return { type: types.join(' or ') };
  }
  function values(node: SchemaNode): string {
    node = resolve(node);
    const parts: string[] = [];
    if (node.const !== undefined) parts.push(String(node.const));
    if (node.enum) parts.push(node.enum.join(', '));
    if (node.pattern) parts.push(`pattern ${node.pattern}`);
    if (node.format) parts.push(node.format);
    if (node.minimum !== undefined && node.maximum !== undefined)
      parts.push(`${node.minimum} to ${node.maximum}`);
    else if (node.minimum !== undefined) parts.push(`≥ ${node.minimum}`);
    if (node.items) {
      const items = resolve(node.items);
      if (items.pattern) parts.push(`pattern ${items.pattern}`);
    }
    return parts.join('; ');
  }
  function walk(node: SchemaNode, prefix: string): void {
    const required = new Set(node.required ?? []);
    for (const [name, child] of Object.entries(node.properties ?? {})) {
      const path = prefix ? `${prefix}.${name}` : name;
      const { type, object } = describe(child);
      out.push({
        path,
        type,
        required: required.has(name),
        values: values(child),
      });
      if (object) walk(object, type.startsWith('array') ? `${path}[]` : path);
    }
  }
  walk(schema, '');
  return out;
}

/** The JSON field reference table for /docs. */
export function fieldReference(): string {
  const schema = JSON.parse(
    readFileSync(join(ROOT, 'schema/report-v1.schema.json'), 'utf8'),
  ) as SchemaNode;
  const descriptions = JSON.parse(
    readFileSync(join(TOOLS, 'docs/report-fields.json'), 'utf8'),
  ) as Record<string, string>;
  delete descriptions.$comment;
  const rows = fields(schema);
  const missing = rows.filter((row) => !descriptions[row.path]);
  const extra = Object.keys(descriptions).filter(
    (path) => !rows.some((row) => row.path === path),
  );
  if (missing.length > 0 || extra.length > 0)
    throw new Error(
      `site-tools/docs/report-fields.json is out of step with the schema. Missing: ${missing.map((row) => row.path).join(', ') || 'none'}. Unknown: ${extra.join(', ') || 'none'}.`,
    );
  const table = h(
    'table',
    { class: 'fields' },
    h(
      'caption',
      { class: 'visually-hidden' },
      'Fields of the JSON report, generated from schema/report-v1.schema.json',
    ),
    h(
      'thead',
      {},
      h(
        'tr',
        {},
        h('th', { scope: 'col' }, 'Field'),
        h('th', { scope: 'col' }, 'Type'),
        h('th', { scope: 'col' }, 'Meaning'),
      ),
    ),
    h(
      'tbody',
      {},
      ...rows.map((row) =>
        h(
          'tr',
          {},
          h('th', { scope: 'row' }, h('code', {}, row.path)),
          h(
            'td',
            {},
            row.type,
            row.required ? '' : ', optional',
            row.values ? h('span', { class: 'field-values' }, row.values) : '',
          ),
          h('td', {}, descriptions[row.path]!),
        ),
      ),
    ),
  );
  return `<div class="table-scroll" role="region" aria-label="JSON report fields" tabindex="0">${toHtml(table)}</div>`;
}

const ANSWER_LABELS: Record<string, string> = Object.fromEntries(
  YES_NO.map(({ value, label }) => [value, label]),
);

function options(id: (typeof QUESTIONS)[number]['id']): [string, string][] {
  return id === 'productType'
    ? (Object.keys(PRODUCT_TYPES) as ProductType[]).map((value) => [
        value,
        PRODUCT_TYPES[value],
      ])
    : Object.entries(ANSWER_LABELS);
}

/** The three questions as radio groups for /scan; "Not sure" is preselected, as with --non-interactive. */
export function craQuestionsForm(): string {
  const groups: VNode[] = QUESTIONS.map(({ id, question }) =>
    h(
      'fieldset',
      { class: 'cra-question' },
      h('legend', {}, question),
      h(
        'div',
        { class: 'choices' },
        ...options(id).map(([value, label]) =>
          h(
            'label',
            { class: 'choice' },
            h('input', {
              type: 'radio',
              name: id,
              value,
              checked: value === 'unknown' ? '' : null,
            }),
            ` ${label}`,
          ),
        ),
      ),
    ),
  );
  return groups.map(toHtml).join('\n');
}

/** The verdict for "not sure" to every question, as first painted. */
export function craInitialResult(asOf: Date): string {
  return toHtml(
    craResultView(
      assessCra(
        {
          euDistribution: 'unknown',
          commercial: 'unknown',
          productType: 'unknown',
        },
        asOf,
      ),
    ),
  );
}

/** The questions and their answers as a list for /docs. */
export function craQuestionsList(): string {
  return toHtml(
    h(
      'ol',
      { class: 'docs-questions' },
      ...QUESTIONS.map(({ id, question }) =>
        h(
          'li',
          {},
          h('p', {}, question),
          h(
            'p',
            { class: 'docs-answers' },
            options(id)
              .map(([value, label]) => `${label} (${value})`)
              .join(' · '),
          ),
        ),
      ),
    ),
  );
}
