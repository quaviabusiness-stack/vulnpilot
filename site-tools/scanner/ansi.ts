// Turns the CLI's ANSI-styled text into segments with the terminal classes
// used on the site. One implementation for both the browser scanner (which
// builds DOM nodes) and the proof generator (which writes HTML), so the page
// and the scanner render the CLI's output the same way.

const ESC = String.fromCharCode(27);
const SGR = new RegExp(`${ESC}\\[([0-9;]*)m`, 'g');

/** The SGR codes `formatText` emits, and the class each one becomes. */
const STYLES: Readonly<Record<string, string>> = {
  '1': 't-b', // bold
  '2': 't-d', // dim
  '1;31': 't-r', // bold red: actively exploited, LIKELY APPLIES, counts
  '33': 't-y', // yellow: UNCLEAR, source notes
  '32': 't-g', // green: LIKELY OUT OF SCOPE, no known vulnerabilities
};

export interface Segment {
  text: string;
  /** A `t-*` class, or null for unstyled text. */
  className: string | null;
}

export function ansiSegments(input: string): Segment[] {
  const segments: Segment[] = [];
  let className: string | null = null;
  let last = 0;
  const push = (text: string) => {
    if (!text) return;
    if (text.includes(ESC))
      throw new Error('Unsupported escape sequence in CLI output.');
    const previous = segments.at(-1);
    if (previous && previous.className === className) previous.text += text;
    else segments.push({ text, className });
  };
  for (const match of input.matchAll(SGR)) {
    push(input.slice(last, match.index));
    const code = match[1] ?? '';
    if (code === '0' || code === '') className = null;
    else {
      const style = STYLES[code];
      if (!style) throw new Error(`Unsupported SGR code ${code}.`);
      className = style;
    }
    last = match.index + match[0].length;
  }
  push(input.slice(last));
  return segments;
}

export function stripAnsi(input: string): string {
  return ansiSegments(input)
    .map((segment) => segment.text)
    .join('');
}

const escapeHtml = (text: string) =>
  text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

/** Static HTML for the proof capture; escaped exactly like the v1 page. */
export function segmentsToHtml(segments: readonly Segment[]): string {
  return segments
    .map(({ text, className }) =>
      className
        ? `<span class="${className}">${escapeHtml(text)}</span>`
        : escapeHtml(text),
    )
    .join('');
}

export { escapeHtml };
