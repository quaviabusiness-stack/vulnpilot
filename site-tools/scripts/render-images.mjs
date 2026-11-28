#!/usr/bin/env node
// Renders the site's raster images with Playwright's Chromium:
//
//   pnpm --filter site-tools images
//
//   site/favicon.ico           16 and 32 px PNG entries, from site/favicon.svg
//   site/apple-touch-icon.png  180 px, full-bleed (iOS rounds the corners)
//   site/og.png                1200 x 630, from site-tools/images/og.html with
//                              the counts of the proof capture
//
// site/favicon.svg is the source of the icons. Run this after changing it,
// the template or the proof capture, then review the images and commit them.
import { Buffer } from 'node:buffer';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from '@playwright/test';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const site = join(root, 'site');

const svg = readFileSync(join(site, 'favicon.svg'), 'utf8');
const fullBleed = svg.replace(/(<rect width="32" height="32") rx="7"/, '$1');
if (fullBleed === svg)
  throw new Error('favicon.svg: expected a 32 x 32 background with rx="7"');

const browser = await chromium.launch();
try {
  /** One square PNG of an SVG at `size` px; transparent outside the shape. */
  async function icon(source, size) {
    const page = await browser.newPage({
      viewport: { width: size, height: size },
      deviceScaleFactor: 1,
    });
    await page.setContent(
      `<style>html,body{margin:0;background:transparent}img{display:block}</style><img width="${size}" height="${size}" src="data:image/svg+xml;base64,${Buffer.from(source).toString('base64')}">`,
    );
    const png = await page.screenshot({ omitBackground: true });
    await page.close();
    return png;
  }

  // favicon.ico: ICONDIR + one ICONDIRENTRY per image, then the PNG data.
  const sizes = [16, 32];
  const images = [];
  for (const size of sizes) images.push(await icon(svg, size));
  const header = Buffer.alloc(6 + 16 * images.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length;
  images.forEach((png, index) => {
    const entry = 6 + index * 16;
    header.writeUInt8(sizes[index] % 256, entry);
    header.writeUInt8(sizes[index] % 256, entry + 1);
    header.writeUInt8(0, entry + 2);
    header.writeUInt8(0, entry + 3);
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(png.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += png.length;
  });
  writeFileSync(join(site, 'favicon.ico'), Buffer.concat([header, ...images]));

  writeFileSync(join(site, 'apple-touch-icon.png'), await icon(fullBleed, 180));

  // og.png from the template, with the counts of the capture shown on the site.
  const summary = JSON.parse(
    readFileSync(join(root, 'site-tools/proof/run.json'), 'utf8'),
  ).summary;
  const values = {
    fonts: pathToFileURL(join(root, 'site-src/fonts')).href,
    criticalOrHigh: String(summary.criticalOrHigh),
    activelyExploited: String(summary.activelyExploited),
  };
  const html = readFileSync(
    join(root, 'site-tools/images/og.html'),
    'utf8',
  ).replace(/\{\{(\w+)\}\}/g, (_match, name) => {
    if (!(name in values)) throw new Error(`og.html: unknown {{${name}}}`);
    return values[name];
  });
  const page = await browser.newPage({
    viewport: { width: 1200, height: 630 },
    deviceScaleFactor: 1,
  });
  // A file URL so the template may load the local fonts.
  const scratch = join(root, 'site-tools/images/.og-render.html');
  writeFileSync(scratch, html);
  try {
    await page.goto(pathToFileURL(scratch).href);
    // Strings, because these run in the page, not in Node.
    await page.evaluate('document.fonts.ready.then(() => true)');
    const loaded = await page.evaluate(
      "[...document.fonts].every((font) => font.status === 'loaded')",
    );
    if (!loaded) throw new Error('og.html: web fonts did not load');
    writeFileSync(join(site, 'og.png'), await page.screenshot());
  } finally {
    rmSync(scratch, { force: true });
  }
} finally {
  await browser.close();
}
console.log(
  'Wrote site/favicon.ico (16, 32), site/apple-touch-icon.png (180) and site/og.png (1200 x 630).',
);
