// The /scan page. Plain DOM code: every string from a file, OSV, EPSS or the
// KEV catalog reaches the page as a text node, never as markup, and the page
// enforces Trusted Types to prove it. Nothing is stored and nothing leaves the
// tab until the visitor presses Scan.
import { assessCra, type CraAssessment } from '../../src/cra.js';
import type { DetectedInput } from '../../src/lockfiles/detect.js';
import type { ScanProgress } from '../../src/source.js';
import type {
  Answer,
  Answers,
  Dependency,
  Inventory,
  ProductType,
} from '../../src/types.js';
import { ansiSegments } from './ansi.js';
import { craResultView, VERDICT_TEXT } from './cra-view.js';
import { bytes, count, longDate, plural, seconds } from './format.js';
import type { ParseRequest, ParseResponse, ParseSource } from './protocol.js';
import { h, toDom, type Child } from './view.js';

type Core = typeof import('./core.js');
type ScanRun = import('./core.js').ScanRun;
type Report = import('./core.js').Report;

const MAX_BYTES = 32 * 1024 * 1024;
const PARSE_TIMEOUT_MS = 20_000;
const SAMPLE_URL = '/samples/cyclonedx.json';
const SAMPLE_PATH = 'test/fixtures/sbom/cyclonedx.json';
const SUPPORTED =
  'package-lock.json, pnpm-lock.yaml, yarn.lock, or a CycloneDX JSON SBOM';
const PASTED = 'pasted text';
const LIVE_INTERVAL_MS = 2000;

// ---------------------------------------------------------------------------
// DOM helpers

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing #${id}`);
  return element as T;
}

function render(target: Element, ...children: Child[]): void {
  target.replaceChildren(
    ...children
      .map((child) => toDom(child, document))
      .filter((node): node is Node => node !== null),
  );
}

function show(element: HTMLElement, visible: boolean): void {
  element.hidden = !visible;
}

const ui = {
  dropzone: byId('dropzone'),
  chooseFile: byId<HTMLButtonElement>('choose-file'),
  fileInput: byId<HTMLInputElement>('file-input'),
  sample: byId<HTMLButtonElement>('sample'),
  pasteInput: byId<HTMLTextAreaElement>('paste-input'),
  pasteRead: byId<HTMLButtonElement>('paste-read'),
  inputStatus: byId('input-status'),
  inputError: byId('input-error'),
  fileLine: byId('file-line'),
  fileSummary: byId('file-summary'),
  chooseAnother: byId<HTMLButtonElement>('choose-another'),
  found: byId('found'),
  foundTitle: byId('found-title'),
  foundBody: byId('found-body'),
  sent: byId('sent'),
  sentList: byId('sent-list'),
  showRequest: byId<HTMLButtonElement>('show-request'),
  request: byId('request'),
  requestMeta: byId('request-meta'),
  requestBody: byId('request-body'),
  requestPrevious: byId<HTMLButtonElement>('request-previous'),
  requestNext: byId<HTMLButtonElement>('request-next'),
  requestCopy: byId<HTMLButtonElement>('request-copy'),
  scanButton: byId<HTMLButtonElement>('scan-button'),
  scanLabel: byId('scan-label'),
  resetFromSent: byId<HTMLButtonElement>('reset-from-sent'),
  progress: byId('progress'),
  progressOsv: byId('progress-osv'),
  progressAdvisories: byId('progress-advisories'),
  progressKev: byId('progress-kev'),
  progressEpss: byId('progress-epss'),
  progressNote: byId('progress-note'),
  stop: byId<HTMLButtonElement>('stop'),
  report: byId('report'),
  reportTitle: byId('report-title'),
  reportMeta: byId('report-meta'),
  banners: byId('report-banners'),
  reportText: byId('report-text'),
  download: byId<HTMLButtonElement>('download-json'),
  toggleTable: byId<HTMLButtonElement>('toggle-table'),
  toggleAll: byId<HTMLButtonElement>('toggle-all'),
  scanAnother: byId<HTMLButtonElement>('scan-another'),
  table: byId('report-table'),
  facts: byId('report-facts'),
  craForm: byId('cra-form'),
  craResult: byId('cra-result'),
  live: byId('scan-live'),
};

// ---------------------------------------------------------------------------
// Announcements: one polite live region, at most one update every two seconds
// while a scan runs, so screen readers hear progress without a flood.

let liveTimer: ReturnType<typeof setTimeout> | undefined;
let livePending = '';
let liveLast = 0;

function announce(message: string, now = false): void {
  livePending = message;
  const wait = LIVE_INTERVAL_MS - (Date.now() - liveLast);
  if (now || wait <= 0) {
    clearTimeout(liveTimer);
    liveTimer = undefined;
    flush();
  } else liveTimer ??= setTimeout(flush, wait);
}

function flush(): void {
  liveTimer = undefined;
  liveLast = Date.now();
  // Clear first so the same message is announced again when repeated.
  ui.live.textContent = '';
  const message = livePending;
  requestAnimationFrame(() => {
    ui.live.textContent = message;
  });
}

// ---------------------------------------------------------------------------
// Copy buttons: data-copy-from names the element whose text is copied.

function setupCopy(button: HTMLButtonElement, text: () => string): void {
  const label = button.querySelector('.copy-label') ?? button;
  let timer: ReturnType<typeof setTimeout> | undefined;
  button.addEventListener('click', async () => {
    let result = 'Copied';
    try {
      await navigator.clipboard.writeText(text());
      announce('Copied to the clipboard.', true);
    } catch {
      result = 'Select';
      announce('Copying failed. Select the text and copy it.', true);
    }
    label.textContent = result;
    clearTimeout(timer);
    timer = setTimeout(() => {
      label.textContent = 'Copy';
    }, 1800);
  });
}

// ---------------------------------------------------------------------------
// The parse worker. Its URL goes through the page's only Trusted Types
// policy, which accepts exactly that one URL.

let policy: TrustedScriptURLPolicy | undefined;
let worker: Worker | null = null;
let nextRequest = 1;

function workerUrl(): string {
  if (!window.trustedTypes) return __WORKER_URL__;
  policy ??= window.trustedTypes.createPolicy('relvet-worker', {
    createScriptURL: (input) => {
      if (input !== __WORKER_URL__)
        throw new TypeError('Unexpected worker URL.');
      return input;
    },
  });
  return policy.createScriptURL(__WORKER_URL__) as string;
}

class ParseTimeout extends Error {}

function parseInWorker(
  source: ParseSource,
  label: string,
): Promise<ParseResponse> {
  worker ??= new Worker(workerUrl(), {
    type: 'module',
    name: 'relvet-parse',
  });
  const current = worker;
  const id = nextRequest++;
  return new Promise((resolve, reject) => {
    const stop = () => {
      current.terminate();
      if (worker === current) worker = null;
    };
    const timer = setTimeout(() => {
      cleanup();
      stop();
      reject(new ParseTimeout());
    }, PARSE_TIMEOUT_MS);
    const onMessage = (event: MessageEvent<ParseResponse>) => {
      if (event.data.id !== id) return;
      cleanup();
      resolve(event.data);
    };
    const onError = (event: ErrorEvent) => {
      cleanup();
      stop();
      reject(new Error(event.message || 'the parser stopped unexpectedly'));
    };
    function cleanup() {
      clearTimeout(timer);
      current.removeEventListener('message', onMessage);
      current.removeEventListener('error', onError);
    }
    current.addEventListener('message', onMessage);
    current.addEventListener('error', onError);
    // File bytes are transferred, not copied.
    current.postMessage(
      { id, source, label } satisfies ParseRequest,
      source.kind === 'bytes' ? [source.buffer] : [],
    );
  });
}

// ---------------------------------------------------------------------------
// State

interface Parsed {
  inventory: Inventory;
  detected: DetectedInput;
  label: string;
  bytes: number;
  ms: number;
  origin: 'file' | 'pasted' | 'sample';
}

interface Progress {
  osv?: Extract<ScanProgress, { source: 'osv' }>;
  advisories?: Extract<ScanProgress, { source: 'osv' }>;
  kev?: Extract<ScanProgress, { source: 'cisa-kev' }>;
  epss?: Extract<ScanProgress, { source: 'first-epss' }>;
}

let core: Core | null = null;
let parsed: Parsed | null = null;
let progress: Progress = {};
let run: ScanRun | null = null;
let report: Report | null = null;
let showAll = false;
let controller: AbortController | null = null;
/** Increments whenever earlier async work must be ignored. */
let generation = 0;

// ---------------------------------------------------------------------------
// Input

function cliHint(label: string, detected?: DetectedInput): string {
  if (
    detected === 'cyclonedx' ||
    (!detected && /\.json$/i.test(label) && label !== 'package-lock.json')
  )
    return `npx relvet --sbom ${shellWord(label)}`;
  return `npx relvet --path ${shellWord(label)}`;
}

function shellWord(word: string): string {
  return /^[\w./@-]+$/.test(word) ? word : `'${word.replaceAll("'", `'\\''`)}'`;
}

function showInputError(message: string): void {
  ui.inputStatus.textContent = '';
  ui.inputError.textContent = message;
  show(ui.inputError, true);
  ui.inputError.focus();
}

function clearInputError(): void {
  ui.inputError.textContent = '';
  show(ui.inputError, false);
}

/** Forgets everything about the previous input and result. */
function resetResult(): void {
  generation += 1;
  controller?.abort();
  controller = null;
  parsed = null;
  run = null;
  report = null;
  progress = {};
  showAll = false;
  bodies = null;
  for (const section of [ui.found, ui.sent, ui.progress, ui.report])
    show(section, false);
  ui.reportText.replaceChildren();
  ui.table.replaceChildren();
  show(ui.table, false);
  show(ui.request, false);
  ui.showRequest.setAttribute('aria-expanded', 'false');
}

function resetAll(): void {
  resetResult();
  clearInputError();
  ui.inputStatus.textContent = '';
  ui.pasteInput.value = '';
  show(ui.fileLine, false);
  show(ui.dropzone, true);
  ui.chooseFile.focus();
}

async function readInput(
  source: ParseSource,
  label: string,
  size: number,
  origin: Parsed['origin'],
): Promise<void> {
  resetResult();
  clearInputError();
  const mine = generation;
  const what = origin === 'pasted' ? 'The pasted text' : label;
  if (size > MAX_BYTES) {
    showInputError(
      `${what} is ${bytes(size)}. The browser scanner reads files up to 32 MB. ${
        origin === 'pasted'
          ? 'Save it to a file and scan it with the CLI: npx relvet --path <file>'
          : `Scan it with the CLI: ${cliHint(label)}`
      }`,
    );
    return;
  }
  if (size === 0) {
    showInputError(`${what} is empty.`);
    return;
  }
  ui.inputStatus.textContent = `Reading ${origin === 'pasted' ? 'the pasted text' : label} (${bytes(size)})…`;
  let response: ParseResponse;
  try {
    response = await parseInWorker(source, label);
  } catch (error) {
    if (mine !== generation) return;
    if (error instanceof ParseTimeout)
      showInputError(
        `Reading ${origin === 'pasted' ? 'the pasted text' : label} took longer than 20 seconds and was stopped. ${
          origin === 'pasted'
            ? 'Save it to a file and scan it with the CLI: npx relvet --path <file>'
            : `Scan it with the CLI: ${cliHint(label)}`
        }`,
      );
    else
      showInputError(
        `The file could not be read: ${error instanceof Error ? error.message : String(error)}. Choose another file, or scan it with the CLI.`,
      );
    return;
  }
  if (mine !== generation) return;
  if (!response.ok) {
    if (response.reason === 'unsupported')
      showInputError(
        origin === 'pasted'
          ? 'The pasted text is not a supported lockfile or SBOM. Expected the contents of package-lock.json, pnpm-lock.yaml, yarn.lock, or a CycloneDX JSON SBOM.'
          : `Unsupported file ${label}. Expected one of ${SUPPORTED}.`,
      );
    else if (response.reason === 'empty') showInputError(`${what} is empty.`);
    else showInputError(response.message);
    return;
  }
  try {
    core ??= await import('./core.js');
  } catch {
    if (mine !== generation) return;
    showInputError(
      'The scanner could not be loaded. Reload the page and try again.',
    );
    return;
  }
  if (mine !== generation) return;
  parsed = {
    inventory: response.inventory,
    detected: response.detected,
    label,
    bytes: response.bytes,
    ms: response.ms,
    origin,
  };
  ui.inputStatus.textContent = '';
  renderFileLine(parsed);
  renderFound(parsed);
  renderSent(parsed, core);
  const packages = parsed.inventory.dependencies.length;
  announce(
    packages > 0
      ? `Read ${parsed.label}: ${plural(packages, 'package')} to check, ${count(parsed.inventory.skipped)} skipped. Review what will be sent, then press Scan.`
      : `Read ${parsed.label}: nothing to check.`,
    true,
  );
  ui.foundTitle.focus();
}

async function readFile(file: File): Promise<void> {
  // The size check comes first, so an oversize file is never read.
  if (file.size > MAX_BYTES || file.size === 0) {
    await readInput({ kind: 'text', text: '' }, file.name, file.size, 'file');
    return;
  }
  resetResult();
  clearInputError();
  const mine = generation;
  ui.inputStatus.textContent = `Reading ${file.name} (${bytes(file.size)})…`;
  let buffer: ArrayBuffer;
  try {
    // Asynchronous file I/O; the page stays responsive. Parsing happens in the worker.
    buffer = await file.arrayBuffer();
  } catch (error) {
    if (mine !== generation) return;
    showInputError(
      `The file could not be read: ${error instanceof Error ? error.message : String(error)}. Choose another file, or scan it with the CLI.`,
    );
    return;
  }
  if (mine !== generation) return;
  await readInput(
    { kind: 'bytes', buffer, name: file.name },
    file.name,
    file.size,
    'file',
  );
}

function readText(text: string): void {
  void readInput(
    { kind: 'text', text },
    PASTED,
    new Blob([text]).size,
    'pasted',
  );
}

async function readSample(): Promise<void> {
  resetResult();
  clearInputError();
  const mine = generation;
  ui.inputStatus.textContent = 'Loading the sample SBOM…';
  let text: string;
  try {
    const response = await fetch(SAMPLE_URL);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    text = await response.text();
  } catch {
    if (mine !== generation) return;
    showInputError(
      'The sample SBOM could not be loaded. Reload the page and try again.',
    );
    return;
  }
  if (mine !== generation) return;
  await readInput(
    { kind: 'text', text, name: 'cyclonedx.json' },
    'cyclonedx.json',
    new Blob([text]).size,
    'sample',
  );
}

function dropped(event: DragEvent): void {
  if (!event.dataTransfer?.types.includes('Files')) return;
  event.preventDefault();
  ui.dropzone.classList.remove('is-over');
  const items = [...event.dataTransfer.items].filter(
    (item) => item.kind === 'file',
  );
  if (items.length > 1) {
    resetResult();
    showInputError('Drop one file at a time.');
    return;
  }
  const entry = items[0]?.webkitGetAsEntry?.();
  if (entry?.isDirectory) {
    resetResult();
    showInputError('That is a folder. Drop the lockfile inside it.');
    return;
  }
  const file = event.dataTransfer.files[0];
  if (file) void readFile(file);
}

// ---------------------------------------------------------------------------
// Found and Sent

function renderFileLine(current: Parsed): void {
  const what =
    current.origin === 'sample'
      ? [
          'cyclonedx.json · the sample SBOM from the repository, ',
          h('code', {}, SAMPLE_PATH),
          ` · ${bytes(current.bytes)}`,
        ]
      : current.origin === 'pasted'
        ? [
            `Pasted text · ${bytes(current.bytes)} · read in ${seconds(current.ms)}`,
          ]
        : [
            `${current.label} · ${bytes(current.bytes)} · read in ${seconds(current.ms)}`,
          ];
  render(ui.fileSummary, ...what);
  show(ui.dropzone, false);
  show(ui.fileLine, true);
}

function ecosystems(dependencies: Dependency[]): string {
  const counts = new Map<string, number>();
  for (const dependency of dependencies) {
    const name =
      dependency.ecosystem ||
      (dependency.purl?.slice(4).split('/')[0] ?? 'other');
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return [...counts]
    .sort(([a], [b]) => a.localeCompare(b, 'en', { sensitivity: 'base' }))
    .map(([name, value]) => `${name} ${count(value)}`)
    .join(' · ');
}

function renderFound(current: Parsed): void {
  const { inventory } = current;
  const packages = inventory.dependencies.length;
  const row = (term: string, value: Child, note?: string) =>
    h(
      'div',
      {},
      h('dt', {}, term),
      h(
        'dd',
        {},
        value,
        note ? h('span', { class: 'found-note' }, note) : null,
      ),
    );
  render(
    ui.foundBody,
    h(
      'dl',
      { class: 'facts-list' },
      row('Format', h('code', {}, inventory.format)),
      row(
        'Packages to check',
        count(packages),
        'unique name and version pairs, including development and transitive dependencies',
      ),
      row(
        'Skipped',
        count(inventory.skipped),
        'local/git/workspace links or components without a supported purl',
      ),
      packages > 0
        ? row('Ecosystems', ecosystems(inventory.dependencies))
        : null,
    ),
    packages === 0
      ? h(
          'p',
          { class: 'found-empty' },
          'Nothing to check: no package in this file has an exact registry version.',
        )
      : null,
  );
  show(ui.found, true);
}

function renderSent(current: Parsed, scanner: Core): void {
  const packages = current.inventory.dependencies.length;
  if (packages === 0) {
    show(ui.sent, false);
    return;
  }
  const requests = Math.ceil(packages / scanner.OSV_BATCH_SIZE);
  render(
    ui.sentList,
    h(
      'li',
      {},
      h('strong', {}, 'OSV.dev'),
      ' (',
      h('code', {}, 'api.osv.dev'),
      `): the ${plural(packages, 'package name and version', 'package names and versions')}, in ${plural(requests, 'request')} of up to ${count(scanner.OSV_BATCH_SIZE)}.`,
    ),
    h(
      'li',
      {},
      h('strong', {}, 'OSV.dev'),
      ` again: the ID of each advisory it returns, to fetch the details, at most ${scanner.OSV_DETAIL_CONCURRENCY} at a time.`,
    ),
    h(
      'li',
      {},
      h('strong', {}, 'FIRST EPSS'),
      ' (',
      h('code', {}, 'api.first.org'),
      `): the CVE IDs from those advisories, up to ${scanner.EPSS_BATCH_SIZE} per request.`,
    ),
    h(
      'li',
      {},
      h('strong', {}, 'This site'),
      ' (',
      h('code', {}, '/api/kev'),
      '): a request for the CISA KEV catalog. It carries nothing from your file, and nothing is sent to CISA.',
    ),
    h(
      'li',
      {},
      'Nothing else. The file stays in this tab, and nothing is stored.',
    ),
  );
  ui.scanLabel.textContent = `Scan ${plural(packages, 'package')}`;
  ui.scanButton.disabled = false;
  show(ui.sent, true);
}

let bodies: string[] | null = null;
let bodyIndex = 0;

function renderRequest(): void {
  if (!bodies || !core || !parsed) return;
  const body = bodies[bodyIndex] ?? '';
  const queries = (JSON.parse(body) as { queries: unknown[] }).queries.length;
  ui.requestMeta.textContent = `Request ${bodyIndex + 1} of ${bodies.length} · ${plural(queries, 'package')} · ${bytes(new TextEncoder().encode(body).byteLength)}`;
  ui.requestBody.textContent = body;
  show(ui.requestPrevious, bodies.length > 1);
  show(ui.requestNext, bodies.length > 1);
  ui.requestPrevious.disabled = bodyIndex === 0;
  ui.requestNext.disabled = bodyIndex === bodies.length - 1;
}

function toggleRequest(): void {
  const open = ui.showRequest.getAttribute('aria-expanded') !== 'true';
  if (open && parsed && core) {
    bodies ??= core.osvQueryBodies(parsed.inventory.dependencies);
    bodyIndex = 0;
    renderRequest();
  }
  ui.showRequest.setAttribute('aria-expanded', String(open));
  ui.showRequest.textContent = open
    ? 'Hide the OSV request'
    : 'Show the OSV request';
  show(ui.request, open);
}

// ---------------------------------------------------------------------------
// Progress

function osvText(event: Progress['osv']): string {
  if (!event) return 'starting';
  if (event.failed > 0)
    return `failed for ${count(event.failed)} of ${plural(event.total, 'package')} (${event.error ?? 'unknown error'})`;
  return `${count(event.done)} of ${plural(event.total, 'package')}`;
}

function advisoriesText(event: Progress['advisories']): string {
  if (!event) return 'waiting for OSV';
  if (event.total === 0) return 'none to fetch';
  const failed =
    event.failed > 0
      ? `, ${count(event.failed)} failed (${event.error ?? 'unknown error'})`
      : '';
  return `${count(event.done)} of ${count(event.total)}${failed}`;
}

function kevText(event: Progress['kev']): string {
  if (!event) return 'requested';
  if (event.error) return `unavailable (${event.error})`;
  const released = event.dateReleased
    ? `, released ${longDate(event.dateReleased)}`
    : '';
  return `catalog ${event.catalogVersion ?? 'unknown'}${released}`;
}

function epssText(event: Progress['epss']): string {
  if (!event) return 'waiting for advisories';
  if (event.total === 0) return 'no CVEs to score';
  if (event.failed > 0)
    return `${plural(event.failed, 'CVE')} not scored (${event.error ?? 'unknown error'})`;
  return `${count(event.done)} of ${plural(event.total, 'CVE')}`;
}

function renderProgress(): void {
  ui.progressOsv.textContent = osvText(progress.osv);
  ui.progressAdvisories.textContent = advisoriesText(progress.advisories);
  ui.progressKev.textContent = kevText(progress.kev);
  ui.progressEpss.textContent = epssText(progress.epss);
}

function onProgress(event: ScanProgress, mine: number): void {
  if (mine !== generation) return;
  if (event.source === 'osv')
    progress[event.step === 'packages' ? 'osv' : 'advisories'] = event;
  else if (event.source === 'cisa-kev') progress.kev = event;
  else progress.epss = event;
  renderProgress();
  announce(
    `OSV ${osvText(progress.osv)}. Advisories ${advisoriesText(progress.advisories)}.`,
  );
}

async function startScan(): Promise<void> {
  if (!parsed || !core || controller) return;
  const current = parsed;
  const scanner = core;
  const mine = generation;
  controller = new AbortController();
  progress = {};
  run = null;
  report = null;
  show(ui.report, false);
  ui.scanButton.disabled = true;
  ui.scanLabel.textContent = 'Scanning…';
  ui.progressNote.textContent = '';
  renderProgress();
  show(ui.stop, true);
  show(ui.progress, true);
  ui.stop.focus();
  announce('Scan started.', true);
  try {
    const result = await scanner.runScan(current.inventory.dependencies, {
      kevUrl: new URL('/api/kev', window.location.origin).href,
      signal: controller.signal,
      onProgress: (event) => onProgress(event, mine),
    });
    if (mine !== generation) return;
    run = result;
  } catch (error) {
    if (mine !== generation) return;
    ui.progressNote.textContent = `The scan failed: ${error instanceof Error ? error.message : String(error)}. Nothing from this run was kept.`;
    announce(ui.progressNote.textContent, true);
    finishScan(current);
    return;
  }
  finishScan(current);
  renderReport();
  show(ui.report, true);
  ui.reportTitle.focus();
  const summary = report!.summary;
  announce(
    `Scan finished: ${plural(summary.issues, 'issue')}, ${count(summary.activelyExploited)} actively exploited.`,
    true,
  );
}

function finishScan(current: Parsed): void {
  controller = null;
  show(ui.stop, false);
  ui.scanButton.disabled = false;
  ui.scanLabel.textContent = `Scan ${plural(current.inventory.dependencies.length, 'package')}`;
}

function stopScan(): void {
  if (!controller || !parsed) return;
  const current = parsed;
  // The parsed file stays; only this run is discarded.
  generation += 1;
  controller.abort();
  finishScan(current);
  ui.progressNote.textContent =
    'Stopped. Nothing from this run was kept. Press Scan to start again.';
  announce(ui.progressNote.textContent, true);
  ui.scanButton.focus();
}

// ---------------------------------------------------------------------------
// Report

function answers(): Answers {
  const value = (name: string) =>
    ui.craForm.querySelector<HTMLInputElement>(`input[name="${name}"]:checked`)
      ?.value ?? 'unknown';
  return {
    euDistribution: value('euDistribution') as Answer,
    commercial: value('commercial') as Answer,
    productType: value('productType') as ProductType,
  };
}

const EXIT_LABELS = { 0: 'no issues', 1: 'issues found', 2: 'incomplete data' };

function terminalCommand(current: Parsed, assessment: CraAssessment): string {
  const input =
    current.origin === 'sample'
      ? `--sbom ${SAMPLE_PATH}`
      : current.detected === 'cyclonedx'
        ? `--sbom ${current.origin === 'pasted' ? '<file>' : shellWord(current.label)}`
        : `--path ${current.detected}`;
  const flags = assessment.answers
    .filter(({ answer }) => answer !== 'unknown')
    .map(
      ({ id, answer }) =>
        `--${id === 'euDistribution' ? 'eu-distribution' : id === 'productType' ? 'product-type' : 'commercial'} ${answer}`,
    );
  return ['npx relvet', input, '--non-interactive', ...flags].join(' ');
}

function banner(title: string, text: string): Child {
  return h(
    'div',
    { class: 'banner' },
    h('p', {}, h('strong', {}, title), ` ${text}`),
  );
}

function renderBanners(current: Report, exitCode: 0 | 1 | 2): void {
  const source = (name: string) =>
    current.sources.find((item) => item.name === name);
  const items: Child[] = [];
  const osv = source('osv');
  if (osv?.status === 'unavailable')
    items.push(
      banner(
        'Incomplete data.',
        'OSV.dev could not be reached, so no package was checked. This is not a clean result: the CLI would exit 2. Try again later.',
      ),
    );
  else if (osv?.status === 'partial') {
    const parts: string[] = [];
    const unchecked = current.summary.uncheckedDependencies;
    if (unchecked > 0)
      parts.push(
        `OSV.dev did not answer for ${count(unchecked)} of ${plural(current.summary.dependencies, 'package')}, so they may have known vulnerabilities that are not listed.`,
      );
    const missing = current.issues.filter(
      (issue) => !issue.detailsAvailable,
    ).length;
    if (missing > 0)
      parts.push(
        `OSV.dev did not return details for ${plural(missing, 'advisory', 'advisories')}; they are listed by ID only.`,
      );
    parts.push(`The CLI would exit ${exitCode}.`);
    items.push(banner('Incomplete data.', parts.join(' ')));
  }
  if (source('cisa-kev')?.status !== 'ok')
    items.push(
      banner(
        'No KEV data.',
        'The CISA KEV catalog could not be loaded, so no issue is marked as actively exploited and the ranking uses EPSS and CVSS only.',
      ),
    );
  if (source('first-epss')?.status !== 'ok') {
    const missing = progress.epss?.failed ?? 0;
    items.push(
      banner(
        'Some EPSS scores missing.',
        `FIRST EPSS did not score ${plural(missing, 'CVE')}. Those issues are still listed and rank by CVSS.`,
      ),
    );
  }
  render(ui.banners, ...items);
  show(ui.banners, items.length > 0);
}

function renderTerminal(text: string): void {
  const nodes = ansiSegments(text).map(({ text: part, className }) => {
    if (!className) return document.createTextNode(part);
    const span = document.createElement('span');
    span.className = className;
    span.textContent = part;
    return span;
  });
  ui.reportText.replaceChildren(...nodes);
}

function renderTable(current: Report, limit: number, scanner: Core): void {
  const rows = current.issues
    .slice(0, limit)
    .map((issue, index) =>
      h(
        'tr',
        {},
        h('td', {}, String(index + 1)),
        h(
          'td',
          {},
          h('code', {}, `${issue.package.name}@${issue.package.version}`),
        ),
        h('td', {}, h('code', {}, issue.cves[0] ?? issue.id)),
        h(
          'td',
          {},
          issue.severity.level === 'unknown'
            ? 'unknown'
            : `${issue.severity.level.toUpperCase()}${issue.severity.score === null ? '' : ` ${issue.severity.score.toFixed(1)}`}`,
        ),
        h('td', {}, issue.epss ? scanner.formatEpss(issue.epss.score) : ''),
        h('td', {}, issue.kev ? 'Known exploited' : ''),
        h('td', {}, issue.recommendedFix ?? 'no fixed version published'),
      ),
    );
  render(
    ui.table,
    h(
      'div',
      {
        class: 'table-scroll',
        role: 'region',
        'aria-label': 'Issues table',
        tabindex: '0',
      },
      h(
        'table',
        { class: 'issues' },
        h('caption', {}, 'Issues, ranked as in the report'),
        h(
          'thead',
          {},
          h(
            'tr',
            {},
            ...['#', 'Package', 'ID', 'Severity', 'EPSS', 'KEV', 'Fix'].map(
              (name) => h('th', { scope: 'col' }, name),
            ),
          ),
        ),
        h('tbody', {}, ...rows),
      ),
    ),
  );
}

function renderReport(): void {
  if (!parsed || !run || !core) return;
  const current = parsed;
  const assessment = assessCra(answers(), new Date());
  report = core.createReport({
    inventory: current.inventory,
    scan: run.scan,
    cra: assessment,
    mock: false,
    durationMs: run.durationMs,
    now: run.finishedAt,
  });
  const total = report.issues.length;
  const limit = showAll ? Math.max(total, 1) : 10;
  renderTerminal(
    core.formatText(report, { color: true, waitlistUrl: '', limit }),
  );
  const exitCode = core.exitCodeFor(report);
  renderBanners(report, exitCode);

  const when = run.finishedAt;
  render(
    ui.reportMeta,
    `Live run in this tab, ${longDate(when.toISOString())}, ${when.toISOString().slice(11, 16)} UTC.`,
    current.origin === 'sample'
      ? ' This is a live run on the sample SBOM, not the dated capture on the home page. EPSS scores change daily, so the numbers can differ.'
      : '',
  );

  const epssDates = report.issues
    .map((issue) => issue.epss?.date)
    .filter((date): date is string => Boolean(date))
    .sort();
  const command = terminalCommand(current, assessment);
  render(
    ui.facts,
    h(
      'p',
      {},
      `CLI exit code for this result: ${exitCode} (${EXIT_LABELS[exitCode]}).`,
    ),
    h(
      'p',
      {},
      progress.kev?.catalogVersion
        ? `KEV ${kevText(progress.kev)}`
        : 'KEV catalog unavailable',
      epssDates.length > 0 ? ` · EPSS scores dated ${epssDates.at(-1)}` : '',
    ),
    h(
      'p',
      { class: 'facts-command' },
      'Same scan in a terminal: ',
      h('code', { id: 'terminal-command' }, command),
      ' ',
      h(
        'button',
        { class: 'copy copy-quiet', type: 'button', id: 'copy-command' },
        h('span', { class: 'copy-label' }, 'Copy'),
        h('span', { class: 'visually-hidden' }, ' the command'),
      ),
    ),
  );
  setupCopy(byId<HTMLButtonElement>('copy-command'), () => command);

  show(ui.toggleAll, total > 10);
  ui.toggleAll.textContent = showAll
    ? 'Show the top 10'
    : `Show all ${count(total)} issues`;
  ui.toggleAll.setAttribute('aria-pressed', String(showAll));
  show(ui.toggleTable, total > 0);
  if (!ui.table.hidden) renderTable(report, limit, core);
}

function download(): void {
  if (!report) return;
  const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `relvet-report-${report.generatedAt.slice(0, 10)}.json`;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  announce('The JSON report was saved by your browser.', true);
}

// ---------------------------------------------------------------------------
// CRA screen

function renderCra(announceVerdict: boolean): void {
  const assessment = assessCra(answers(), new Date());
  render(ui.craResult, craResultView(assessment));
  if (announceVerdict)
    announce(
      `CRA verdict: ${VERDICT_TEXT[assessment.verdict]}, rule ${assessment.rule}.`,
      true,
    );
  if (report) renderReport();
}

// ---------------------------------------------------------------------------
// Wiring

ui.chooseFile.addEventListener('click', () => ui.fileInput.click());
ui.chooseAnother.addEventListener('click', resetAll);
ui.resetFromSent.addEventListener('click', resetAll);
ui.scanAnother.addEventListener('click', resetAll);
ui.fileInput.addEventListener('change', () => {
  const file = ui.fileInput.files?.[0];
  ui.fileInput.value = '';
  if (file) void readFile(file);
});
ui.sample.addEventListener('click', () => void readSample());
ui.pasteRead.addEventListener('click', () => {
  const text = ui.pasteInput.value;
  ui.pasteInput.value = '';
  readText(text);
});
// Pasting anywhere in the drop zone reads the clipboard directly, so a large
// lockfile is never rendered into the text area.
ui.dropzone.addEventListener('paste', (event) => {
  const data = event.clipboardData;
  if (!data) return;
  const file = data.files[0];
  if (file) {
    event.preventDefault();
    void readFile(file);
    return;
  }
  const text = data.getData('text/plain');
  if (text) {
    event.preventDefault();
    readText(text);
  }
});
ui.dropzone.addEventListener('dragover', (event) => {
  if (!event.dataTransfer?.types.includes('Files')) return;
  event.preventDefault();
  ui.dropzone.classList.add('is-over');
});
ui.dropzone.addEventListener('dragleave', () =>
  ui.dropzone.classList.remove('is-over'),
);
// A file dropped anywhere on the page is read rather than opened by the browser.
document.addEventListener('dragover', (event) => {
  if (event.dataTransfer?.types.includes('Files')) event.preventDefault();
});
document.addEventListener('drop', dropped);

ui.showRequest.addEventListener('click', toggleRequest);
ui.requestPrevious.addEventListener('click', () => {
  bodyIndex = Math.max(0, bodyIndex - 1);
  renderRequest();
});
ui.requestNext.addEventListener('click', () => {
  bodyIndex = Math.min((bodies?.length ?? 1) - 1, bodyIndex + 1);
  renderRequest();
});
setupCopy(ui.requestCopy, () => bodies?.[bodyIndex] ?? '');
ui.scanButton.addEventListener('click', () => void startScan());
ui.stop.addEventListener('click', stopScan);
ui.download.addEventListener('click', download);
ui.toggleTable.addEventListener('click', () => {
  const open = ui.table.hidden;
  ui.toggleTable.setAttribute('aria-expanded', String(open));
  ui.toggleTable.textContent = open ? 'Hide the table' : 'Show as table';
  show(ui.table, open);
  if (open && report && core)
    renderTable(report, showAll ? report.issues.length : 10, core);
});
ui.toggleAll.addEventListener('click', () => {
  showAll = !showAll;
  renderReport();
  announce(
    showAll ? 'Showing all issues.' : 'Showing the top 10 issues.',
    true,
  );
});
ui.craForm.addEventListener('change', () => renderCra(true));
const flagsButton = document.getElementById('copy-flags');
if (flagsButton instanceof HTMLButtonElement)
  setupCopy(
    flagsButton,
    () => ui.craResult.querySelector('[data-cra-flags]')?.textContent ?? '',
  );

// Today's date decides which key dates are in force.
renderCra(false);

const arrival = new URLSearchParams(window.location.search);
if (arrival.has('handoff') || arrival.has('sample')) {
  history.replaceState(
    null,
    '',
    window.location.pathname + window.location.hash,
  );
  if (arrival.has('sample')) void readSample();
}
