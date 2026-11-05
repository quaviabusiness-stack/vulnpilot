import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  parseCycloneDx,
  parsePurl,
  purlToDependency,
} from '../src/lockfiles/cyclonedx.js';
import { readLockfile, readSbom } from '../src/lockfiles/index.js';
import { parsePackageLock } from '../src/lockfiles/package-lock.js';
import { parsePnpmLock } from '../src/lockfiles/pnpm-lock.js';
import { parseYarnLock } from '../src/lockfiles/yarn-lock.js';
import type { Dependency } from '../src/types.js';

const directories: string[] = [];
async function directory() {
  const path = await mkdtemp(join(tmpdir(), 'vulnpilot-lock-test-'));
  directories.push(path);
  return path;
}
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

const labels = (dependencies: Dependency[]) =>
  dependencies.map(({ ecosystem, name, version }) =>
    ecosystem === 'npm'
      ? `${name}@${version}`
      : `${ecosystem}:${name}@${version}`,
  );
const fixture = (path: string) => readFile(join('test/fixtures', path), 'utf8');

// The same five registry packages appear in every npm-style fixture.
const COMMON = [
  '@babel/helper-string-parser@7.25.9',
  'lodash@4.17.20',
  'minimist@1.2.5',
  'picocolors@1.1.1',
];

describe('package-lock.json', () => {
  it('reads the fixture without treating the root project as a dependency', async () => {
    const result = parsePackageLock(
      await fixture('projects/npm/package-lock.json'),
    );
    expect(labels(result.dependencies)).toEqual(COMMON);
    expect(result.skipped).toBe(0);
  });

  it.each([2, 3])(
    'handles nested versions, scoped names, aliases, links and git in v%i',
    (lockfileVersion) => {
      const result = parsePackageLock(
        JSON.stringify({
          lockfileVersion,
          packages: {
            '': { name: 'root', version: '1.0.0' },
            'node_modules/a': { version: '1.0.0' },
            'node_modules/b/node_modules/a': { version: '1.0.0' },
            'node_modules/c/node_modules/a': { version: '2.0.0' },
            'node_modules/@scope/name': { version: '3.0.0-beta.1+build.2' },
            'node_modules/alias': { name: 'actual', version: '1.2.3' },
            'node_modules/local': {
              version: '1.0.0',
              resolved: 'file:../local',
            },
            'node_modules/gitdep': {
              version: '1.0.0',
              resolved: 'git+ssh://git@github.com/example/gitdep.git#abc',
            },
            'node_modules/workspace': {
              link: true,
              resolved: 'packages/workspace',
            },
            'packages/workspace': { name: 'workspace', version: '1.0.0' },
          },
        }),
      );
      expect(labels(result.dependencies)).toEqual([
        'a@1.0.0',
        'a@2.0.0',
        '@scope/name@3.0.0-beta.1+build.2',
        'actual@1.2.3',
      ]);
      expect(result.skipped).toBe(2);
    },
  );

  it('supports v1 transitive dependencies and scoped npm aliases', () => {
    const result = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          outer: {
            version: '1.0.0',
            dependencies: { inner: { version: '2.0.0' } },
          },
          alias: { version: 'npm:@scope/actual@3.0.0' },
        },
      }),
    );
    expect(result.dependencies.map((item) => item.name)).toEqual([
      'outer',
      'inner',
      '@scope/actual',
    ]);
  });

  it.each([
    'null',
    '{}',
    '{',
    '{"lockfileVersion":4}',
    '{"lockfileVersion":3}',
  ])('rejects malformed or unsupported input: %s', (content) => {
    expect(() => parsePackageLock(content)).toThrow();
  });
});

describe('pnpm-lock.yaml', () => {
  it('reads v9 packages (not snapshots), resolves aliases and skips git/link entries', async () => {
    const result = parsePnpmLock(await fixture('projects/pnpm/pnpm-lock.yaml'));
    expect(labels(result.dependencies)).toEqual([
      '@babel/helper-string-parser@7.25.9',
      'lodash@4.17.20',
      'minimist@1.2.5',
      'picocolors@1.1.1',
      'react-dom@18.3.1',
      'react@18.3.1',
      'string-width@4.2.3',
    ]);
    expect(result.skipped).toBe(1);
  });

  it('reads v6 keys with peer suffixes', () => {
    const result = parsePnpmLock(
      [
        "lockfileVersion: '6.0'",
        '',
        'packages:',
        '',
        '  /@babel/core@7.22.5(supports-color@8.1.1):',
        '    resolution: {integrity: sha512-x}',
        '',
        '  /lodash@4.17.20:',
        '    resolution: {integrity: sha512-y}',
        '    dev: true',
        '',
        '  github.com/example/repo/abc123:',
        '    name: repo',
        '    version: 1.0.0',
        '',
      ].join('\n'),
    );
    expect(labels(result.dependencies)).toEqual([
      '@babel/core@7.22.5',
      'lodash@4.17.20',
    ]);
    expect(result.skipped).toBe(1);
  });

  it('reads v5 keys with underscore peer suffixes and underscores in names', () => {
    const result = parsePnpmLock(
      [
        'lockfileVersion: 5.4',
        '',
        'specifiers:',
        '  lodash: ^4.17.20',
        '',
        'packages:',
        '',
        '  /@babel/core/7.0.0_supports-color@5.5.0:',
        '    resolution: {integrity: sha512-x}',
        '',
        '  /string_decoder/1.3.0:',
        '    resolution: {integrity: sha512-y}',
        '',
        '  /react-dom/17.0.2_react@17.0.2:',
        '    resolution: {integrity: sha512-z}',
        '',
      ].join('\r\n'),
    );
    expect(labels(result.dependencies)).toEqual([
      '@babel/core@7.0.0',
      'string_decoder@1.3.0',
      'react-dom@17.0.2',
    ]);
  });

  it.each(['', 'packages:\n', "lockfileVersion: '4.0'\n"])(
    'rejects files without a supported lockfileVersion: %j',
    (content) => {
      expect(() => parsePnpmLock(content)).toThrow('lockfileVersion');
    },
  );
});

describe('yarn.lock', () => {
  it('reads Yarn Classic (v1), resolving aliases and skipping git/file entries', async () => {
    const result = parseYarnLock(await fixture('projects/yarn-v1/yarn.lock'));
    expect(labels(result.dependencies)).toEqual([
      ...COMMON,
      'string-width@4.2.3',
    ]);
    expect(result.skipped).toBe(2);
  });

  it('reads Yarn Berry, skipping workspace and patch resolutions', async () => {
    const result = parseYarnLock(
      await fixture('projects/yarn-berry/yarn.lock'),
    );
    expect(labels(result.dependencies)).toEqual([
      ...COMMON,
      'resolve@1.22.8',
      'string-width@4.2.3',
    ]);
    expect(result.skipped).toBe(2);
  });

  it('rejects content that is not a yarn lockfile', () => {
    expect(() => parseYarnLock('hello: world\n')).toThrow('yarn.lock');
  });
});

describe('CycloneDX SBOM', () => {
  it('maps purls to OSV ecosystems, walks nested components and deduplicates', async () => {
    const result = parseCycloneDx(await fixture('sbom/cyclonedx.json'));
    expect(labels(result.dependencies)).toEqual([
      'Maven:org.apache.logging.log4j:log4j-core@2.14.1',
      'lodash@4.17.20',
      '@babel/helper-string-parser@7.25.9',
      'PyPI:requests@2.31.0',
      'PyPI:urllib3@2.0.7',
    ]);
    // pkg:generic (no OSV ecosystem) and a CPE-only component.
    expect(result.skipped).toBe(2);
  });

  it('parses purl parts including encoded scopes, qualifiers and subpaths', () => {
    expect(
      parsePurl('pkg:npm/%40angular/core@16.0.0?arch=x64#src/index.js'),
    ).toEqual({
      type: 'npm',
      namespace: '@angular',
      name: 'core',
      version: '16.0.0',
      qualifiers: { arch: 'x64' },
    });
    expect(parsePurl('pkg:npm/@angular/core')?.version).toBeUndefined();
    expect(
      purlToDependency('pkg:golang/github.com/gin-gonic/gin@v1.9.0'),
    ).toEqual({
      ecosystem: 'Go',
      name: 'github.com/gin-gonic/gin',
      version: 'v1.9.0',
    });
    expect(
      purlToDependency('pkg:deb/debian/openssl@3.0.11-1?distro=debian-12'),
    ).toMatchObject({
      ecosystem: '',
      purl: 'pkg:deb/debian/openssl@3.0.11-1?distro=debian-12',
    });
    expect(purlToDependency('pkg:npm/lodash')).toBeUndefined();
    expect(purlToDependency('not-a-purl')).toBeUndefined();
  });

  it('rejects documents that are not CycloneDX', () => {
    expect(() => parseCycloneDx('{"spdxVersion":"SPDX-2.3"}')).toThrow(
      'CycloneDX',
    );
  });
});

describe('input selection', () => {
  it.each([
    ['projects/npm', 'package-lock'],
    ['projects/pnpm', 'pnpm-lock'],
    ['projects/yarn-v1', 'yarn-v1'],
    ['projects/yarn-berry', 'yarn-berry'],
  ])('auto-detects the lockfile in %s', async (path, format) => {
    const inventory = await readLockfile(join('test/fixtures', path));
    expect(inventory.format).toBe(format);
    expect(inventory.dependencies.length).toBeGreaterThan(3);
  });

  it('reads an explicit lockfile path and an SBOM', async () => {
    expect(
      (await readLockfile('test/fixtures/projects/npm/package-lock.json'))
        .dependencies,
    ).toHaveLength(4);
    const sbom = await readSbom('test/fixtures/sbom/cyclonedx.json');
    expect(sbom.format).toBe('cyclonedx');
    expect(sbom.dependencies).toHaveLength(5);
  });

  it('gives a clear error when no lockfile is found', async () => {
    const path = await directory();
    await expect(readLockfile(path)).rejects.toThrow(
      /No lockfile found .*package-lock\.json, pnpm-lock\.yaml, yarn\.lock.*--sbom/,
    );
    await expect(readLockfile(join(path, 'missing'))).rejects.toThrow(
      'Path not found',
    );
  });

  it('asks for an explicit path when several lockfiles exist', async () => {
    const path = await directory();
    await writeFile(join(path, 'package-lock.json'), '{}');
    await writeFile(join(path, 'yarn.lock'), '');
    await expect(readLockfile(path)).rejects.toThrow(
      /Multiple lockfiles .*package-lock\.json, yarn\.lock/,
    );
  });

  it('rejects unsupported filenames and reports parse errors with the file name', async () => {
    const path = await directory();
    const source = join(path, 'source.ts');
    await writeFile(source, 'not a lockfile');
    await expect(readLockfile(source)).rejects.toThrow('Unsupported file');
    await writeFile(join(path, 'pnpm-lock.yaml'), 'garbage');
    await expect(readLockfile(path)).rejects.toThrow(
      /Could not parse .*pnpm-lock\.yaml/,
    );
  });
});
