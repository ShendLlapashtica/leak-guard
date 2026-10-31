import { scan, scanDiffAdditions, redact, isPlaceholder, RULES } from '../lib/scan.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';

// Assembled from parts, so this file is not itself a secret-shaped string that
// other scanners flag.
const AWS    = 'AKIA' + 'Q7FJ4LMNOPQRSTUV';
const GH     = 'ghp_' + 'a'.repeat(36);
const STRIPE = 'sk_live_' + 'b'.repeat(24);
const JWT    = 'eyJhbGciOiJIUzI1NiJ9.' + 'e30'.repeat(5) + '.' + 'x'.repeat(22);

test('every rule has a unique id, a global regex and a hint', () => {
  const ids = new Set();
  for (const r of RULES) {
    assert.ok(!ids.has(r.id), `duplicate rule id ${r.id}`);
    ids.add(r.id);
    assert.ok(r.re.flags.includes('g'), `${r.id} must be global or exec() loops forever`);
    assert.ok(r.hint, `${r.id} needs a hint`);
    assert.ok(['high', 'low'].includes(r.severity), `${r.id} needs a severity`);
  }
});

test('catches the shapes that are a credential by construction', () => {
  const ids = scan(`a="${AWS}";b="${GH}";c="${STRIPE}";d="${JWT}";`).map((f) => f.id);
  for (const want of ['aws-access-key-id', 'github-token', 'stripe-secret-key', 'jwt']) {
    assert.ok(ids.includes(want), `missing ${want} in ${ids.join()}`);
  }
});

test('catches a database URI with an inline password', () => {
  const f = scan('DATABASE_URL="postgres://app:s3cr3t-pw@db.host:5432/main"');
  assert.ok(f.some((x) => x.id === 'db-uri-password'), JSON.stringify(f));
});

test('NEVER returns a credential in full', () => {
  const f = scan(`const k="${AWS}";`);
  assert.equal(f.length, 1);
  assert.ok(!f[0].match.includes(AWS), 'the finding must not carry the secret');
  assert.ok(!f[0].context.includes(AWS), 'nor the context');
  assert.match(f[0].match, /…/);
  assert.ok(f[0].match.startsWith('AKIA'), 'but it must stay identifiable');
});

test('reads from the environment: not a finding', () => {
  assert.deepEqual(scan('const apiKey = process.env.API_KEY;'), []);
  assert.deepEqual(scan('password = os.environ["DB_PASSWORD"]'), []);
  assert.deepEqual(scan('token: `${process.env.TOKEN}`'), []);
});

test('a hardcoded credential is a finding, a placeholder is not', () => {
  const hit = scan('const password = "Tr0ub4dor&3-horse";');
  assert.equal(hit.length, 1);
  assert.equal(hit[0].id, 'hardcoded-credential');
  assert.equal(hit[0].severity, 'low');

  for (const fake of [
    'const password = "your-password-here";',
    'const apiKey = "xxxxxxxxxxxxxxxx";',
    'const client_secret = "<CLIENT_SECRET>";',
    'const token = "${TOKEN}";',
    'password: "changeme-please"',
    'api_key = "EXAMPLE_KEY_VALUE"',
    'secret = "placeholder1234"',
  ]) {
    assert.deepEqual(scan(fake), [], fake);
  }
});

test('the assignment rule can be switched off, the shape rules cannot', () => {
  const src = `const password = "Tr0ub4dor&3-horse"; const k = "${AWS}";`;
  assert.equal(scan(src, { creds: false }).length, 1);
  assert.equal(scan(src, { creds: false })[0].id, 'aws-access-key-id');
});

test('allow silences one rule by id', () => {
  const src = `const k="${AWS}";`;
  assert.equal(scan(src).length, 1);
  assert.deepEqual(scan(src, { allow: ['aws-access-key-id'] }), []);
});

test('forbid takes literals, and treats them as literals', () => {
  const f = scan('fetch("https://api.internal.acme/v1")', { forbid: ['api.internal.acme'] });
  assert.equal(f.length, 1);
  assert.equal(f[0].id, 'forbid:api.internal.acme');
  assert.deepEqual(scan('const x = "abc";', { forbid: ['a.c'] }), [], '"a.c" must not match "abc"');
});

test('forbidPattern is forced global, so it reports every hit', () => {
  const f = scan('INTERNAL_A INTERNAL_B', { forbidPattern: [/INTERNAL_[A-Z]/] });
  assert.equal(f.length, 2, 'must find both, not loop on the first');
});

test('published example credentials are not findings', () => {
  // Assembled from parts: GitHub push protection rejects a push containing
  // Stripe's own documentation key, written out in full, in a test that exists
  // to prove it is ignored. Which is its own argument for this plugin.
  const stripeDocsKey = 'sk_test_' + '4eC39HqLyjWDarjtT1zdp7dc';
  assert.deepEqual(scan('AKIAIOSFODNN7EXAMPLE'), []);
  assert.deepEqual(scan(stripeDocsKey), []);
});

test('reports a line number, including inside one long line', () => {
  assert.equal(scan(`a\nb\nconst k="${AWS}";`)[0].line, 3);
  assert.equal(scan(`var a=1;const k="${AWS}";var b=2;`)[0].line, 1);
});

test('one line tripping two rules is reported once', () => {
  // Both the shape rule and the assignment rule match this.
  const f = scan(`const apiKey = "${AWS}";`);
  assert.equal(f.length, 1);
  assert.equal(f[0].id, 'aws-access-key-id', 'the stronger rule wins');
});

test('a diff reports only added lines, with the line number from the hunk', () => {
  const diff = [
    'diff --git a/src/config.js b/src/config.js',
    '--- a/src/config.js',
    '+++ b/src/config.js',
    '@@ -40,0 +41,1 @@',
    `+const k = "${AWS}";`,
    '@@ -80,1 +81,1 @@',
    `-const old = "${GH}";`,
    '+const old = process.env.GH;',
  ].join('\n');

  const f = scanDiffAdditions(diff);
  assert.equal(f.length, 1, 'a removed line is not a leak');
  assert.equal(f[0].file, 'src/config.js');
  assert.equal(f[0].line, 41);
});

test('a clean modern file produces nothing', () => {
  assert.deepEqual(scan(`
    const API = "https://api.example.com/v2";
    export async function load(id) {
      const r = await fetch(\`\${API}/items/\${id}\`, {
        headers: { authorization: \`Bearer \${process.env.TOKEN}\` },
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }
  `), []);
});

test('redact keeps the prefix and the length, drops the middle', () => {
  const out = redact(AWS);
  assert.ok(!out.includes(AWS));
  assert.match(out, /^AKIA….*\[20 chars\]$/);
  assert.equal(redact('short'), 'short', 'a short string is not a secret');
});

test('isPlaceholder judges the value, not the line', () => {
  assert.equal(isPlaceholder('hunter2'), true, 'too short to be real');
  assert.equal(isPlaceholder('yourpasswordhere'), true);
  assert.equal(isPlaceholder('correcthorsebattery'), true, 'a single lowercase word');
  assert.equal(isPlaceholder('Tr0ub4dor&3-horse'), false);
});

test('scan never throws on junk input', () => {
  for (const junk of [undefined, null, 0, '', {}, []]) {
    assert.deepEqual(scan(junk), [], String(junk));
  }
});
