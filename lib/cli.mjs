#!/usr/bin/env node
/*!
 * leak-guard — on-demand scan, for the code that is already there.
 *
 * The hook only sees writes from now on. This sweeps what the repo already
 * contains, which is where the one that got away is sitting.
 */

import { readFileSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve, basename } from 'node:path';
import { scan, scanDiffAdditions } from './scan.mjs';

const argv = process.argv.slice(2);
const has = (f) => argv.includes(`--${f}`);
const cwd = process.cwd();

if (has('help')) {
  console.log(`leak-guard — scan for credentials that would be committed

  leak-scan                 every file git tracks, plus untracked files
  leak-scan --staged        only what is staged right now
  leak-scan --tracked       only files git already tracks
  leak-scan <path...>       only these files
  leak-scan --json          machine-readable
  leak-scan --no-creds      skip the lower-confidence assignment rule

Exit codes: 0 clean, 1 findings, 2 nothing to scan.`);
  process.exit(0);
}

// A flag on the command line beats the config file, not the other way round.
const opt = { ...loadConfig(), ...(has('no-creds') ? { creds: false } : {}) };
const SKIP = /(^|\/)(node_modules|\.git|dist|build|coverage|vendor|\.next|\.venv|__pycache__)\//;
const BINARY = /\.(png|jpe?g|gif|webp|avif|ico|pdf|zip|gz|tgz|bz2|xz|7z|rar|mp[34]|mov|avi|woff2?|ttf|eot|otf|wasm|so|dll|dylib|exe|class|jar|pyc|node|bin|lock|lockb)$/i;
const LOCKFILE = /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|composer\.lock|go\.sum)$/;
const MAX_BYTES = 2_000_000;

let findings = [];

// `skip` is a path filter, so the CLI has to apply it itself — scan() only
// ever sees text and has no idea which file it came from.
const skipped = (file) => (opt.skip || []).some((s) => file.replace(/\\/g, '/').includes(String(s)));

if (has('staged')) {
  const diff = git(['diff', '--cached', '--no-color', '--unified=0', '--diff-filter=ACMR']);
  if (!diff.trim()) exit2('nothing is staged');
  findings = scanDiffAdditions(diff, opt).filter((f) => !skipped(f.file));
} else {
  const explicit = argv.filter((a) => !a.startsWith('--'));
  const files = explicit.length ? explicit : gitFiles(has('tracked'));
  if (!files.length) exit2('no files to scan (not a git repository? pass paths)');
  for (const f of files) {
    if (SKIP.test(f.replace(/\\/g, '/')) || BINARY.test(f) || LOCKFILE.test(basename(f))) continue;
    if (skipped(f)) continue;
    let text;
    try {
      if (statSync(resolve(cwd, f)).size > MAX_BYTES) continue;
      text = readFileSync(resolve(cwd, f), 'utf8');
    } catch { continue; }
    if (text.includes('\u0000')) continue;                  // binary after all
    for (const x of scan(text, opt)) findings.push({ ...x, file: f });
  }
}

if (has('json')) {
  console.log(JSON.stringify({ ok: findings.length === 0, count: findings.length, findings }, null, 2));
} else if (!findings.length) {
  console.log('leak-guard: clean — no credentials found.');
} else {
  const high = findings.filter((f) => f.severity === 'high');
  console.log(`leak-guard: ${findings.length} finding(s), ${high.length} high confidence\n`);
  for (const f of findings) {
    console.log(`${f.file}:${f.line}  [${f.id}]${f.severity === 'low' ? ' (lower confidence)' : ''}`);
    console.log(`    ${f.hint}: ${f.match}`);
    console.log(`    …${f.context}…\n`);
  }
  console.log('Rotate anything real before you touch the code — a credential in a');
  console.log('repository is disclosed from the moment it was pushed, not from the');
  console.log('moment someone notices.');
}

process.exit(findings.length ? 1 : 0);

function gitFiles(trackedOnly) {
  const tracked = git(['ls-files', '-z']).split('\0').filter(Boolean);
  if (trackedOnly) return tracked;
  // Untracked-but-not-ignored files count: they are one `git add .` away.
  const untracked = git(['ls-files', '-z', '--others', '--exclude-standard']).split('\0').filter(Boolean);
  return [...new Set([...tracked, ...untracked])];
}

function git(args) {
  try {
    return execFileSync('git', ['-C', cwd, ...args], {
      encoding: 'utf8', timeout: 10_000, maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true,
    });
  } catch { return ''; }
}

function loadConfig() {
  for (const name of ['.leakguard.json', '.claude/leakguard.json']) {
    try { return JSON.parse(readFileSync(resolve(cwd, name), 'utf8')); } catch { /* keep defaults */ }
  }
  return {};
}

function exit2(msg) {
  console.error(`leak-guard: ${msg}`);
  process.exit(2);
}
