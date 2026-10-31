/*!
 * leak-guard — the scanner.
 *
 * Two kinds of rule, and the split is the whole design:
 *
 *   severity 'high'  a string that is a credential by its own shape. A token
 *                    that starts `ghp_` and runs 36 characters is not a
 *                    coincidence, so finding one is never a guess.
 *   severity 'low'   a credential-shaped *assignment* — `password = "…"`.
 *                    Real, common, and the only rule here that can be wrong,
 *                    so placeholders are filtered hard and it can be switched
 *                    off with `{"creds": false}`.
 *
 * A rule that cries wolf gets switched off, and a rule that is switched off
 * catches nothing. That is why there is no entropy heuristic in here.
 *
 * MIT licensed. Zero dependencies.
 */

export const RULES = [
  // ── shape-identifiable credentials ───────────────────────────────────────
  { id: 'aws-access-key-id',   severity: 'high', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,                      hint: 'AWS access key id' },
  { id: 'github-token',        severity: 'high', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,                      hint: 'GitHub token' },
  { id: 'github-pat',          severity: 'high', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,                    hint: 'GitHub fine-grained PAT' },
  { id: 'slack-token',         severity: 'high', re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/g,                    hint: 'Slack token' },
  { id: 'slack-webhook',       severity: 'high', re: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_/-]{10,}/g, hint: 'Slack webhook URL' },
  { id: 'stripe-secret-key',   severity: 'high', re: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g,            hint: 'Stripe secret key' },
  { id: 'google-api-key',      severity: 'high', re: /\bAIza[0-9A-Za-z_-]{35}\b/g,                           hint: 'Google API key' },
  { id: 'anthropic-key',       severity: 'high', re: /\bsk-ant-[A-Za-z0-9_-]{24,}\b/g,                       hint: 'Anthropic API key' },
  { id: 'openai-key',          severity: 'high', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g,                 hint: 'OpenAI-style secret key' },
  { id: 'npm-token',           severity: 'high', re: /\bnpm_[A-Za-z0-9]{36}\b/g,                             hint: 'npm publish token' },
  { id: 'huggingface-token',   severity: 'high', re: /\bhf_[A-Za-z0-9]{30,}\b/g,                             hint: 'Hugging Face token' },
  { id: 'sendgrid-key',        severity: 'high', re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,      hint: 'SendGrid API key' },
  { id: 'private-key-block',   severity: 'high', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, hint: 'private key block' },
  { id: 'jwt',                 severity: 'high', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, hint: 'signed JWT' },
  { id: 'db-uri-password',     severity: 'high', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|clickhouse):\/\/[^\s/:@'"]+:[^\s/:@'"]+@/g, hint: 'database URI with an inline password' },
  { id: 'basic-auth-url',      severity: 'high', re: /\bhttps?:\/\/[^\s/:@'"]+:[^\s/:@'"]+@/g,               hint: 'credentials embedded in a URL' },

  // ── the one judgement call ───────────────────────────────────────────────
  {
    id: 'hardcoded-credential',
    severity: 'low',
    group: 'creds',
    // name  …  =  …  "value"
    re: /\b(?:pass(?:word|wd)?|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|credentials?)\b\s*[:=]>?\s*(['"`])([^'"`\n]{12,200})\1/gi,
    hint: 'a credential assigned a literal value',
    value: 2,
  },
];

/** Strings that look like a secret but are a stand-in for one. */
const PLACEHOLDER = [
  /your[_-]?|example|sample|placeholder|change[_-]?me|redact|dummy|fake|todo|fixme|insert|replace|here\b|\.\.\./i,
  /^(?:x+|y+|z+|a+|0+|1+|\*+|\.+|-+|_+|#+)$/i,
  /\$\{|\$\(|%s\b|%\(|\{\{|<[a-z_]|process\.env|os\.environ|getenv|env\[|secrets?\./i,
  /^(?:test|testing|password|hunter2|letmein|admin|root|localhost|postgres|mysql|sqlite)$/i,
];

/** Published example values that exist precisely to be written down. */
const DEFAULT_IGNORE = [
  /\bAKIAIOSFODNN7EXAMPLE\b/,
  /\bsk_test_(?:4eC39HqLyjWDarjtT1zdp7dc|BQokikJOvBiI2HlWgH4olfQ2)\b/,
  /\bAIzaSyExample|\bAIzaSy[A-Za-z0-9_-]*EXAMPLE/i,
];

/**
 * @param {string} text
 * @param {object} [opt]
 * @param {string[]} [opt.allow]           rule ids, or forbidden literals, to skip
 * @param {string[]} [opt.forbid]          extra literals that must not appear
 * @param {string[]} [opt.forbidPattern]   extra regex sources that must not match
 * @param {boolean}  [opt.creds=true]      enable the low-severity rule
 * @param {number}   [opt.context=56]
 * @returns {{id,severity,hint,match,line,index,context}[]}
 */
export function scan(text, opt = {}) {
  const {
    allow = [],
    forbid = [],
    forbidPattern = [],
    creds = true,
    context = 56,
    ignore = [],
  } = opt;

  if (typeof text !== 'string' || text === '') return [];

  const allowed = new Set(allow);
  const ignores = [...DEFAULT_IGNORE, ...ignore.map(toRe)];

  const rules = [
    ...RULES.filter((r) => !allowed.has(r.id) && !(r.group === 'creds' && !creds)),
    ...forbid.filter((s) => s && !allowed.has(s)).map((s) => ({
      id: `forbid:${s}`,
      severity: 'high',
      re: new RegExp(escapeRe(s), 'g'),
      hint: `forbidden string "${s}"`,
    })),
    ...forbidPattern.map((p, i) => ({
      id: `pattern:${i}`,
      severity: 'high',
      re: toRe(p),
      hint: `forbidden pattern ${p}`,
    })),
  ];

  // Line starts once, so every finding can name a line without re-splitting
  // the text. A minified file is one line; that is still the honest answer.
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') lineStarts.push(i + 1);

  const findings = [];
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      if (m[0].length === 0) { rule.re.lastIndex += 1; continue; }
      const at = m.index;
      const snippet = text.slice(Math.max(0, at - context), at + m[0].length + context);
      if (ignores.some((re) => { re.lastIndex = 0; return re.test(snippet); })) continue;

      // For the assignment rule, judge the captured value, not the whole match.
      const subject = rule.value ? m[rule.value] : m[0];
      if (rule.value && isPlaceholder(subject)) continue;

      findings.push({
        id: rule.id,
        severity: rule.severity,
        hint: rule.hint,
        match: redact(subject),
        index: at,
        line: lineOf(lineStarts, at),
        context: redact(snippet).replace(/\s+/g, ' ').trim(),
      });
    }
  }

  // One line can trip two rules — `const apiKey = "AKIA…"` trips the shape
  // rule and the assignment rule on the same value. Keep the stronger rule, so
  // what the user reads is "AWS access key id", not a vague "credential
  // assigned a literal value". Dedupe by severity first, then order by index.
  const seen = new Set();
  return findings
    .sort((a, b) => weight(b) - weight(a) || a.index - b.index)
    .filter((f) => {
      const k = `${f.line}:${f.match}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .sort((a, b) => a.index - b.index);
}

/**
 * Only the lines a diff *adds* can leak something new. Line numbers come from
 * the hunk headers, so a finding points at the line in the file rather than at
 * a meaningless offset inside the patch.
 */
export function scanDiffAdditions(diff, opt = {}) {
  const out = [];
  let file = null;
  let line = 0;
  for (const raw of splitLines(diff)) {
    if (raw.startsWith('diff --git')) {
      const m = / b\/(.+)$/.exec(raw);
      if (m) file = m[1];
      continue;
    }
    if (raw.startsWith('+++ ')) { file = raw.slice(4).replace(/^b\//, '').trim(); continue; }
    if (raw.startsWith('--- ') || raw.startsWith('index ')) continue;
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) { line = Number(hunk[1]); continue; }
    if (raw.startsWith('+')) {
      for (const f of scan(raw.slice(1), opt)) out.push({ ...f, line, file: file || '(unknown file)' });
      line += 1;
      continue;
    }
    if (raw.startsWith('-') || raw.startsWith(NO_NEWLINE)) continue;
    line += 1;                      // a context line
  }
  return out;
}

const NO_NEWLINE = String.fromCharCode(92);   // the "\ No newline at end" marker
const splitLines = (s) => String(s).split(/\r?\n/);

export function isPlaceholder(value) {
  const v = String(value).trim();
  if (v.length < 12) return true;
  if (PLACEHOLDER.some((re) => re.test(v))) return true;
  // A single lowercase dictionary-ish word is a stand-in, not a credential.
  if (/^[a-z]+$/.test(v)) return true;
  return false;
}

/**
 * Never print a credential in full. Hook output lands in a transcript, and a
 * transcript gets pasted into issues.
 */
export function redact(s) {
  return String(s).replace(/[A-Za-z0-9_\-+/=.]{13,}/g, (w) => `${w.slice(0, 4)}…${w.slice(-2)}[${w.length} chars]`);
}

const weight = (f) => (f.severity === 'high' ? 2 : 1);
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function toRe(p) {
  if (p instanceof RegExp) return new RegExp(p.source, p.flags.includes('g') ? p.flags : `${p.flags}g`);
  return new RegExp(p, 'g');
}

function lineOf(starts, index) {
  let lo = 0, hi = starts.length - 1, ans = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (starts[mid] <= index) { ans = mid; lo = mid + 1; } else hi = mid - 1;
  }
  return ans + 1;
}

export default scan;
