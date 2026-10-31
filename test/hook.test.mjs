/*!
 * These tests drive the hook the way Claude Code drives it: a JSON payload on
 * stdin, a decision on stdout. They run against a real temporary git
 * repository, because the whole design turns on what git would track.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const GUARD = join(dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'guard.mjs');

const AWS = 'AKIA' + 'Q7FJ4LMNOPQRSTUV';
const GH  = 'ghp_' + 'c'.repeat(36);
const JWT = 'eyJhbGciOiJIUzI1NiJ9.' + 'e30'.repeat(5) + '.' + 'z'.repeat(22);

/** A git repo that ignores .env and secrets/, with one commit. */
function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'leak-guard-'));
  const git = (...a) => execFileSync('git', ['-C', dir, ...a], { stdio: 'ignore' });
  git('init', '-q');
  git('config', 'user.email', 'test@example.com');
  git('config', 'user.name', 'test');
  git('config', 'commit.gpgsign', 'false');
  writeFileSync(join(dir, '.gitignore'), '.env\n.env.local\nsecrets/\n');
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'src', 'app.js'), 'export const a = 1;\n');
  git('add', '-A');
  git('commit', '-qm', 'init');
  return { dir, git };
}

function run(payload, { cwd, env = {} } = {}) {
  const out = execFileSync(process.execPath, [GUARD], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', cwd, ...payload }),
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  if (!out.trim()) return { decision: 'allow', raw: '' };
  const json = JSON.parse(out);
  return {
    decision: json.hookSpecificOutput?.permissionDecision ?? 'allow',
    reason: json.hookSpecificOutput?.permissionDecisionReason ?? '',
    systemMessage: json.systemMessage,
    raw: out,
  };
}

const write = (file_path, content) => ({ tool_name: 'Write', tool_input: { file_path, content } });

test('denies a credential going into a tracked file', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const r = run(write(join(dir, 'src/config.js'), `export const key = "${AWS}";\n`), { cwd: dir });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /AWS access key id/);
  assert.match(r.reason, /process\.env/, 'the reason must say what to do instead');
  assert.match(r.reason, /rotate/i);
  assert.ok(!r.raw.includes(AWS), 'the hook must not echo the credential');
});

test('allows a credential going into .env — that is where it belongs', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  assert.equal(run(write(join(dir, '.env'), `AWS_ACCESS_KEY_ID=${AWS}\n`), { cwd: dir }).decision, 'allow');
  assert.equal(run(write(join(dir, 'secrets/aws.txt'), AWS), { cwd: dir }).decision, 'allow');
});

test('denies it in .env.example, which does get committed', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const r = run(write(join(dir, '.env.example'), `AWS_ACCESS_KEY_ID=${AWS}\n`), { cwd: dir });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /example/i);
});

test('a file that is tracked is not covered by .gitignore matching it', (t) => {
  const { dir, git } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  // Someone committed .env before adding it to .gitignore. git keeps tracking
  // it, so a write to it still ends up in the next commit.
  writeFileSync(join(dir, '.env'), 'EMPTY=1\n');
  git('add', '-f', '.env');
  git('commit', '-qm', 'oops');

  const r = run(write(join(dir, '.env'), `KEY=${AWS}\n`), { cwd: dir });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /git rm --cached/, 'and it must say how to untrack it');
});

test('denies a .env that .gitignore does not cover — one git add away', (t) => {
  const { dir } = repo();          // .gitignore lists .env, not .env.production
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const r = run(write(join(dir, '.env.production'), `KEY=${AWS}\n`), { cwd: dir });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /\.gitignore/);
});

test('allows an ordinary write', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const r = run(write(join(dir, 'src/util.js'), 'export const sum = (a, b) => a + b;\n'), { cwd: dir });
  assert.equal(r.decision, 'allow');
  assert.equal(r.raw, '', 'a clean write must be silent');
});

test('reads Edit and MultiEdit payloads', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file_path = join(dir, 'src/app.js');

  assert.equal(run({
    tool_name: 'Edit',
    tool_input: { file_path, old_string: 'const a = 1', new_string: `const t = "${GH}"` },
  }, { cwd: dir }).decision, 'deny');

  assert.equal(run({
    tool_name: 'MultiEdit',
    tool_input: { file_path, edits: [{ old_string: 'x', new_string: 'y' }, { old_string: 'z', new_string: `k="${GH}"` }] },
  }, { cwd: dir }).decision, 'deny');

  assert.equal(run({
    tool_name: 'Edit',
    tool_input: { file_path, old_string: `k="${GH}"`, new_string: 'k=process.env.GH' },
  }, { cwd: dir }).decision, 'allow', 'removing a credential is not leaking one');
});

test('denies a commit whose staged diff adds a credential, and names the file', (t) => {
  const { dir, git } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  writeFileSync(join(dir, 'src/config.js'), `export const key = "${AWS}";\n`);
  git('add', 'src/config.js');

  const r = run({ tool_name: 'Bash', tool_input: { command: 'git commit -m "add config"' } }, { cwd: dir });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /src\/config\.js:1/);
  assert.ok(!r.raw.includes(AWS));
});

test('allows a commit with a clean staged diff', (t) => {
  const { dir, git } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  writeFileSync(join(dir, 'src/ok.js'), 'export const ok = true;\n');
  git('add', 'src/ok.js');

  assert.equal(run({ tool_name: 'Bash', tool_input: { command: 'git commit -m ok' } }, { cwd: dir }).decision, 'allow');
});

test('a staged .env is caught, because staging beats .gitignore', (t) => {
  const { dir, git } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  writeFileSync(join(dir, '.env'), `KEY=${AWS}\n`);
  git('add', '-f', '.env');

  assert.equal(run({ tool_name: 'Bash', tool_input: { command: 'git commit -am wip' } }, { cwd: dir }).decision, 'deny');
});

test('asks — does not deny — about a credential in a shell command', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const r = run({
    tool_name: 'Bash',
    tool_input: { command: `curl -H "Authorization: Bearer ${JWT}" https://api.example.com/me` },
  }, { cwd: dir });
  assert.equal(r.decision, 'ask', 'it may be exactly what the user asked for');
  assert.match(r.reason, /JWT/);
});

test('leaves ordinary commands alone', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  for (const command of ['ls -la', 'npm test', 'git status', 'git commit --help', 'echo hello']) {
    assert.equal(run({ tool_name: 'Bash', tool_input: { command } }, { cwd: dir }).decision, 'allow', command);
  }
});

test('ignores tools it has no business in', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  assert.equal(run({ tool_name: 'Read', tool_input: { file_path: join(dir, '.env') } }, { cwd: dir }).raw, '');
});

test('warn mode reports without standing in the way', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const r = run(write(join(dir, 'src/config.js'), `const k="${AWS}";`), {
    cwd: dir,
    env: { LEAK_GUARD_MODE: 'warn' },
  });
  assert.equal(r.decision, 'allow');
  assert.match(r.systemMessage, /AWS access key id/);
});

test('off mode is off', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  assert.equal(run(write(join(dir, 'src/config.js'), `const k="${AWS}";`), {
    cwd: dir,
    env: { LEAK_GUARD_MODE: 'off' },
  }).raw, '');
});

test('.leakguard.json scopes the guard', (t) => {
  const { dir } = repo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  writeFileSync(join(dir, '.leakguard.json'), JSON.stringify({
    creds: false,
    allow: ['aws-access-key-id'],
    skip: ['test/fixtures/'],
    forbid: ['api.internal.acme'],
  }));

  assert.equal(run(write(join(dir, 'src/a.js'), 'const password = "Tr0ub4dor&3-horse";'), { cwd: dir }).decision,
    'allow', 'creds:false switches off the assignment rule');
  assert.equal(run(write(join(dir, 'src/b.js'), `const k="${AWS}";`), { cwd: dir }).decision,
    'allow', 'allow[] switches off one shape rule');
  assert.equal(run(write(join(dir, 'test/fixtures/x.js'), `const k="${GH}";`), { cwd: dir }).decision,
    'allow', 'skip[] excludes a path');
  assert.equal(run(write(join(dir, 'src/c.js'), 'fetch("https://api.internal.acme/v1")'), { cwd: dir }).decision,
    'deny', 'forbid[] adds a literal of your own');
});

test('fails open on junk, and on a directory that is not a repository', () => {
  const out = execFileSync(process.execPath, [GUARD], { input: 'not json at all', encoding: 'utf8' });
  assert.equal(out.trim(), '', 'junk in, silence out — never a blocked tool call');

  const plain = mkdtempSync(join(tmpdir(), 'leak-guard-norepo-'));
  try {
    // No git repository, so nothing is "ignored" — a secret store is still
    // recognised by its name, and anything else is treated as committable.
    assert.equal(run(write(join(plain, '.env'), `KEY=${AWS}`), { cwd: plain }).decision, 'allow');
    assert.equal(run(write(join(plain, 'config.js'), `const k="${AWS}";`), { cwd: plain }).decision, 'deny');
  } finally {
    rmSync(plain, { recursive: true, force: true });
  }
});
