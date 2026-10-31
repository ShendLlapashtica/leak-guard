#!/usr/bin/env node
/*!
 * leak-guard — PreToolUse hook.
 *
 * Three decisions, and the middle one is the point of the plugin:
 *
 *   deny   a credential is going into a file git would track, or into the
 *          staged diff of a commit. Denying hands Claude a reason, so it
 *          rewrites the code instead of retrying the same write.
 *   allow  a credential is going into a file git ignores. That is where a
 *          credential belongs; a guard that fights `.env` gets uninstalled.
 *   ask    a credential appears in a shell command. It may be exactly what
 *          you asked for, so this one is yours to approve.
 *
 * Fails open, always. If anything in here throws, the tool call proceeds — a
 * secret scanner that can break your session is worse than no scanner.
 */

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { basename, isAbsolute, resolve } from 'node:path';
import { scan, scanDiffAdditions } from '../lib/scan.mjs';

const MAX_TEXT = 2_000_000;        // past this, a "file" is a build artifact
const GIT_TIMEOUT = 5_000;

function main() {
  let input;
  try {
    input = JSON.parse(readFileSync(0, 'utf8') || '{}');
  } catch {
    return allow();                 // not our JSON, not our business
  }

  try {
    const cwd = input.cwd || process.cwd();
    const cfg = loadConfig(cwd);
    if (cfg.mode === 'off') return allow();

    const tool = input.tool_name || '';
    const ti = input.tool_input || {};

    if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool)) return onWrite(tool, ti, cwd, cfg);
    if (tool === 'Bash') return onBash(ti, cwd, cfg);
    return allow();
  } catch (err) {
    // Fail open, but say so under ctrl+o rather than vanishing.
    process.stderr.write(`leak-guard: skipped (${err && err.message})\n`);
    return allow();
  }
}

/* ── Write / Edit ─────────────────────────────────────────────────────────── */

function onWrite(tool, ti, cwd, cfg) {
  const path = ti.file_path || ti.notebook_path || '';
  if (path && isSkipped(path, cfg)) return allow();

  const text = addedText(tool, ti).slice(0, MAX_TEXT);
  const findings = scan(text, cfg);
  if (!findings.length) return allow();

  const here = abs(path, cwd);
  const name = basename(path) || 'this file';
  const store = isSecretStore(path);
  const example = isExampleFile(path);
  const cover = coverage(here, cwd);

  // The only question that matters: would git carry this file into a commit?
  // A gitignored file is the right home for a credential, and so is a .env in
  // a directory git knows nothing about. An *example* file is a committed
  // template whatever its name suggests, so it never gets the benefit.
  if (!example && (cover === 'ignored' || (cover === 'no-repo' && store))) return allow();

  let where;
  if (example) {
    where = `${name} is an example/template file — it gets committed, so it must only ever hold obviously fake values.`;
  } else if (cover === 'tracked' && store) {
    where = `${name} is already tracked by git, so .gitignore does not protect it. Untrack it first:\n    git rm --cached ${name}\n  and make sure .gitignore lists it.`;
  } else if (store) {
    where = `${name} is not in .gitignore, so one "git add ." commits it. Add it to .gitignore first — then this write is fine.`;
  } else {
    where = `git does not ignore ${name}, so this value would be committed.`;
  }

  return verdict(cfg, 'deny', [
    `leak-guard: this write contains ${findings.length === 1 ? 'a credential' : `${findings.length} credentials`}.`,
    '',
    where,
    '',
    ...findings.map(fmt),
    '',
    'Fix it instead of retrying:',
    '  1. Keep the literal out of the file. Read it at runtime from the environment',
    '     (process.env.NAME / os.environ["NAME"]) or from a secret manager.',
    '  2. Put the real value in a gitignored file (.env), and commit a .env.example',
    '     holding only placeholder values.',
    '  3. If this value is already live somewhere, rotate it — it has been in a',
    '     model context window, so treat it as disclosed.',
    '',
    'If this is a false positive: add the rule id to "allow" in .leakguard.json,',
    'or set {"creds": false} to turn off the hardcoded-credential rule.',
  ].join('\n'));
}

function addedText(tool, ti) {
  if (tool === 'Write') return str(ti.content);
  if (tool === 'NotebookEdit') return str(ti.new_source);
  if (tool === 'Edit') return str(ti.new_string);
  if (tool === 'MultiEdit') return (ti.edits || []).map((e) => str(e && e.new_string)).join('\n');
  return '';
}

/* ── Bash ─────────────────────────────────────────────────────────────────── */

function onBash(ti, cwd, cfg) {
  const cmd = str(ti.command);
  if (!cmd) return allow();

  if (isGitCommit(cmd)) {
    const findings = stagedFindings(cwd, cfg);
    if (findings.length) {
      return verdict(cfg, 'deny', [
        `leak-guard: the staged changes contain ${findings.length === 1 ? 'a credential' : `${findings.length} credentials`}.`,
        '',
        ...findings.map(fmt),
        '',
        'Unstage the file (git restore --staged <file>), take the value out of it,',
        'and add it to .gitignore if it is a secret file. Rotate the credential —',
        'and if it is already in an earlier commit, rotating is the only real fix,',
        'because rewriting history does not un-publish what was pushed.',
      ].join('\n'));
    }
    return allow();
  }

  if (isGitPush(cmd)) {
    const findings = unpushedFindings(cwd, cfg);
    if (findings.length) {
      return verdict(cfg, 'deny', [
        `leak-guard: ${findings.length === 1 ? 'a commit about to be pushed adds a credential' : `commits about to be pushed add ${findings.length} credentials`}.`,
        '',
        ...findings.map(fmt),
        '',
        'A push is the point of no return: assume anything pushed is public and',
        'already indexed. Rotate the credential first, then fix the branch.',
      ].join('\n'));
    }
    return allow();
  }

  // A credential in a command line may be deliberate — that is the user's call,
  // not ours. High-confidence shapes only; no assignment rule here.
  const findings = scan(cmd.slice(0, MAX_TEXT), { ...cfg, creds: false });
  if (!findings.length) return allow();

  return verdict(cfg, 'ask', [
    'leak-guard: this command contains a credential in plain text.',
    '',
    ...findings.map(fmt),
    '',
    'Shell commands are recorded in the transcript and in your shell history.',
    'Prefer an environment variable, or a file the command reads.',
  ].join('\n'), 'ask');
}

const isGitCommit = (c) => /(^|[\s;&|(])git\b(?![^\s;&|]*--help)[^;&|]*\bcommit\b/.test(c);
const isGitPush   = (c) => /(^|[\s;&|(])git\b(?![^\s;&|]*--help)[^;&|]*\bpush\b/.test(c);

function stagedFindings(cwd, cfg) {
  const diff = git(cwd, ['diff', '--cached', '--no-color', '--unified=0', '--diff-filter=ACMR']);
  return diff ? scanDiffAdditions(diff, cfg) : [];
}

function unpushedFindings(cwd, cfg) {
  const base = ['@{u}', 'origin/HEAD'].find((r) => git(cwd, ['rev-parse', '--verify', '--quiet', r]));
  if (!base) return [];             // nothing to compare against; do not guess
  const diff = git(cwd, ['diff', '--no-color', '--unified=0', `${base}..HEAD`]);
  return diff ? scanDiffAdditions(diff, cfg) : [];
}

/* ── git helpers (every one of them fails open) ───────────────────────────── */

function git(cwd, args) {
  try {
    return execFileSync('git', ['-C', cwd, ...args], {
      encoding: 'utf8',
      timeout: GIT_TIMEOUT,
      maxBuffer: 16 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    });
  } catch {
    return '';
  }
}

/**
 * What git would do with this path.
 *
 *   'tracked'    git already carries it; .gitignore is irrelevant to it
 *   'ignored'    git will not commit it — safe to hold a credential
 *   'untracked'  not ignored, so one `git add .` commits it
 *   'no-repo'    not a git repository (or git is missing)
 *
 * Order matters: `--no-index` is deliberately not used, because a .env that
 * someone committed before writing the .gitignore line keeps being tracked,
 * and check-ignore would happily call it ignored.
 */
function coverage(path, cwd) {
  if (!path) return 'untracked';
  if (!ok(cwd, ['rev-parse', '--git-dir'])) return 'no-repo';
  if (ok(cwd, ['ls-files', '--error-unmatch', '--', path])) return 'tracked';
  if (ok(cwd, ['check-ignore', '-q', '--', path])) return 'ignored';
  return 'untracked';
}

/** True when the git command exits 0. */
function ok(cwd, args) {
  try {
    execFileSync('git', ['-C', cwd, ...args], {
      timeout: GIT_TIMEOUT,
      stdio: 'ignore',
      windowsHide: true,
    });
    return true;
  } catch {
    return false;
  }
}

/* ── classification ───────────────────────────────────────────────────────── */

function isSecretStore(path) {
  const b = basename(path).toLowerCase();
  if (/^\.env(\.|$)/.test(b) && !isExampleFile(path)) return true;
  if (/\.(pem|key|p12|pfx|jks|keystore|ppk)$/.test(b)) return true;
  if (/(^|[\\/])\.(ssh|aws|gnupg|docker|kube)[\\/]/.test(path.replace(/\\/g, '/'))) return true;
  if (/^(id_rsa|id_ed25519|id_ecdsa|\.netrc|\.pgpass|credentials)$/.test(b)) return true;
  return false;
}

function isExampleFile(path) {
  const b = basename(path).toLowerCase();
  return /(^|[.\-_])(example|examples|sample|template|dist|tpl)(\.|$)/.test(b);
}

const DEFAULT_SKIP = [
  /(^|[\\/])node_modules[\\/]/,
  /(^|[\\/])\.git[\\/]/,
  /(^|[\\/])(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|Cargo\.lock|poetry\.lock|composer\.lock|go\.sum)$/,
];

function isSkipped(path, cfg) {
  if (DEFAULT_SKIP.some((re) => re.test(path))) return true;
  return (cfg.skip || []).some((frag) => path.replace(/\\/g, '/').includes(String(frag)));
}

/* ── config ───────────────────────────────────────────────────────────────── */

function loadConfig(cwd) {
  const base = {
    mode: process.env.LEAK_GUARD_MODE || 'block',   // block | warn | off
    allow: [],
    forbid: [],
    forbidPattern: [],
    creds: true,
    skip: [],
  };
  for (const name of ['.leakguard.json', '.claude/leakguard.json']) {
    try {
      const raw = readFileSync(resolve(cwd, name), 'utf8');
      const user = JSON.parse(raw);
      return {
        ...base,
        ...user,
        mode: process.env.LEAK_GUARD_MODE || user.mode || base.mode,
        allow: [...base.allow, ...(user.allow || [])],
        forbid: [...base.forbid, ...(user.forbid || [])],
        forbidPattern: [...base.forbidPattern, ...(user.forbidPattern || [])],
      };
    } catch { /* absent or unparseable: keep the defaults */ }
  }
  return base;
}

/* ── output ───────────────────────────────────────────────────────────────── */

function verdict(cfg, decision, reason, kind = 'deny') {
  // "warn" keeps the finding visible but never stands in the way.
  if (cfg.mode === 'warn') return say({ systemMessage: reason, suppressOutput: true });
  return say({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: kind === 'ask' ? 'ask' : 'deny',
      permissionDecisionReason: reason,
    },
  });
}

function allow() { process.exit(0); }

function say(obj) {
  process.stdout.write(JSON.stringify(obj));
  process.exit(0);
}

function fmt(f) {
  const at = f.file ? `${f.file}:${f.line}` : `line ${f.line}`;
  const flag = f.severity === 'low' ? ' (lower confidence)' : '';
  return `  • ${at}  ${f.hint}${flag}\n      ${f.match}\n      …${f.context}…`;
}

const str = (v) => (typeof v === 'string' ? v : '');
const abs = (p, cwd) => (!p ? '' : isAbsolute(p) ? p : resolve(cwd, p));

// Last line on purpose: `const` declarations above are not initialised until
// the module body has run, and main() reads several of them. Calling it from
// the top threw a temporal-dead-zone error on every invocation — which
// fail-open turned into a guard that silently allowed everything.
main();
