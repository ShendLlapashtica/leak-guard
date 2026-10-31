/*!
 * The CLI is what /leak-scan runs and what a CI job would run, so its exit
 * codes are part of the contract: 0 clean, 1 findings, 2 nothing to scan.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'lib', 'cli.mjs');
const AWS = 'AKIA' + 'Q7FJ4LMNOPQRSTUV';

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'leak-guard-cli-'));
  const git = (...a) => execFileSync('git', ['-C', dir, ...a], { stdio: 'ignore' });
  git('init', '-q');
  git('config', 'user.email', 'test@example.com');
  git('config', 'user.name', 'test');
  writeFileSync(join(dir, '.gitignore'), '.env\n');
  writeFileSync(join(dir, 'app.js'), 'export const a = 1;\n');
  git('add', '-A');
  git('commit', '-qm', 'init');
  return { dir, git };
}

const run = (dir, ...args) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8' });

test('exit 0 and one line when the repository is clean', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const r = run(dir);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /clean/);
});

test('exit 1, with the file, line and an elided value', (t) => {
  const { dir, git } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  writeFileSync(join(dir, 'config.js'), `\nexport const key = "${AWS}";\n`);
  git('add', '-A');

  const r = run(dir);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /config\.js:2/);
  assert.match(r.stdout, /aws-access-key-id/);
  assert.ok(!r.stdout.includes(AWS), 'the CLI must not print the credential');
});

test('an untracked file counts — it is one git add away', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  writeFileSync(join(dir, 'new.js'), `const k = "${AWS}";\n`);
  assert.equal(run(dir).status, 1);
  assert.equal(run(dir, '--tracked').status, 0, '--tracked looks only at what git carries');
});

test('a gitignored .env is not scanned', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  writeFileSync(join(dir, '.env'), `AWS_ACCESS_KEY_ID=${AWS}\n`);
  assert.equal(run(dir).status, 0);
});

test('--json is machine-readable', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  writeFileSync(join(dir, 'config.js'), `const k = "${AWS}";\n`);
  const r = run(dir, '--json');
  const report = JSON.parse(r.stdout);
  assert.equal(report.ok, false);
  assert.equal(report.count, 1);
  assert.equal(report.findings[0].id, 'aws-access-key-id');
  assert.equal(report.findings[0].severity, 'high');
});

test('--staged reads the index, and exits 2 when nothing is staged', (t) => {
  const { dir, git } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  assert.equal(run(dir, '--staged').status, 2);

  writeFileSync(join(dir, 'config.js'), `const k = "${AWS}";\n`);
  assert.equal(run(dir, '--staged').status, 2, 'unstaged changes are not staged changes');

  git('add', 'config.js');
  const r = run(dir, '--staged');
  assert.equal(r.status, 1);
  assert.match(r.stdout, /config\.js/);
});

test('.leakguard.json scopes it: skip, allow and no-creds', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  mkdirSync(join(dir, 'fixtures'), { recursive: true });
  writeFileSync(join(dir, 'fixtures', 'keys.js'), `const k = "${AWS}";\n`);
  assert.equal(run(dir).status, 1);

  writeFileSync(join(dir, '.leakguard.json'), JSON.stringify({ skip: ['fixtures/'] }));
  assert.equal(run(dir).status, 0, 'skip must filter paths, not just text');

  writeFileSync(join(dir, 'a.js'), 'const password = "Tr0ub4dor&3-horse";\n');
  assert.equal(run(dir).status, 1);
  assert.equal(run(dir, '--no-creds').status, 0, 'a flag beats the config file');
});
