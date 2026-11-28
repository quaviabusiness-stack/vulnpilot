import { describe, expect, it } from 'vitest';
import { formatText } from '../../src/report.js';
import { ansiSegments, segmentsToHtml, stripAnsi } from '../scanner/ansi.js';
import { h, toHtml } from '../scanner/view.js';

const ESC = String.fromCharCode(27);
const sgr = (code: string, text: string) => `${ESC}[${code}m${text}${ESC}[0m`;

describe('ansiSegments', () => {
  it('maps the CLI styles to the terminal classes', () => {
    const text = `${sgr('1', 'bold')} ${sgr('2', 'dim')} ${sgr('1;31', 'red')} ${sgr('33', 'yellow')} ${sgr('32', 'green')}`;
    expect(ansiSegments(text)).toEqual([
      { text: 'bold', className: 't-b' },
      { text: ' ', className: null },
      { text: 'dim', className: 't-d' },
      { text: ' ', className: null },
      { text: 'red', className: 't-r' },
      { text: ' ', className: null },
      { text: 'yellow', className: 't-y' },
      { text: ' ', className: null },
      { text: 'green', className: 't-g' },
    ]);
  });

  it('fails on codes the CLI does not print', () => {
    expect(() => ansiSegments(sgr('4', 'underline'))).toThrow(
      'Unsupported SGR code 4',
    );
    expect(() => ansiSegments(`${ESC}]8;;https://x${ESC}\\`)).toThrow();
  });

  it('never changes the text', () => {
    const text = `${sgr('1', 'a <b> & c')}\n${sgr('2', '>>>')}`;
    expect(stripAnsi(text)).toBe('a <b> & c\n>>>');
  });

  it('renders every SGR code formatText can emit', () => {
    const report = {
      schemaVersion: '1.0.0',
      tool: { name: 'relvet', version: '0.0.0' },
      generatedAt: '2026-01-01T00:00:00.000Z',
      durationMs: 1,
      mock: false,
      input: {
        format: 'package-lock',
        file: 'package-lock.json',
        dependencies: 1,
        skipped: 1,
      },
      cra: {
        verdict: 'unclear',
        rule: 'insufficient-information',
        reason: 'Reason.',
        answers: [
          { id: 'euDistribution', question: 'q', answer: 'unknown' },
          { id: 'commercial', question: 'q', answer: 'unknown' },
          { id: 'productType', question: 'q', answer: 'unknown' },
        ],
        keyDates: [],
        disclaimer: 'Not legal advice.',
      },
      summary: {
        dependencies: 1,
        vulnerablePackages: 0,
        issues: 0,
        criticalOrHigh: 0,
        activelyExploited: 0,
        uncheckedDependencies: 0,
      },
      sources: [
        { name: 'osv', status: 'ok' },
        { name: 'cisa-kev', status: 'unavailable', message: 'HTTP 502' },
        { name: 'first-epss', status: 'ok' },
      ],
      issues: [],
    } as const;
    const text = formatText(report as never, { color: true, waitlistUrl: '' });
    const classes = new Set(
      ansiSegments(text).map((segment) => segment.className),
    );
    expect(classes).toEqual(new Set([null, 't-b', 't-d', 't-y', 't-g']));
  });
});

describe('segmentsToHtml', () => {
  it('escapes like the v1 page and wraps styled text', () => {
    expect(
      segmentsToHtml([
        { text: 'EPSS >99.9% & <x>', className: null },
        { text: 'KNOWN EXPLOITED', className: 't-r' },
      ]),
    ).toBe(
      'EPSS &gt;99.9% &amp; &lt;x&gt;<span class="t-r">KNOWN EXPLOITED</span>',
    );
  });
});

describe('view', () => {
  it('renders text as text, never as markup', () => {
    expect(
      toHtml(h('p', { title: '"x"' }, '<img src=x onerror=alert(1)>')),
    ).toBe('<p title="&quot;x&quot;">&lt;img src=x onerror=alert(1)&gt;</p>');
  });

  it('refuses scripts, styles and event handler attributes', () => {
    expect(() => toHtml(h('script', {}, 'x'))).toThrow();
    expect(() => toHtml(h('style', {}, 'x'))).toThrow();
    expect(() => toHtml(h('p', { onclick: 'x' }))).toThrow();
  });
});
