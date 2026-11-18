// Formatting shared by the scanner page and the generator.

const MONTHS = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];

/** `2026-09-11` → `11 September 2026`, as the CLI prints dates. */
export function longDate(iso: string): string {
  const [year, month, day] = iso.slice(0, 10).split('-').map(Number);
  return `${day} ${MONTHS[(month ?? 1) - 1]} ${year}`;
}

const grouping = new Intl.NumberFormat('en-GB');

/** `1284` → `1,284`. */
export function count(value: number): string {
  return grouping.format(value);
}

/** `2516582` → `2.4 MB`; one decimal, 1 KB = 1,024 bytes. */
export function bytes(value: number): string {
  if (value < 1024) return `${value} bytes`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

/** `1234` ms → `1.2 s`. */
export function seconds(ms: number): string {
  return `${(ms / 1000).toFixed(1)} s`;
}

/** `n thing`/`n things`, with a thousands separator. */
export function plural(value: number, one: string, many = `${one}s`): string {
  return `${count(value)} ${value === 1 ? one : many}`;
}
