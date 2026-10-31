# leak-guard

[![tests](https://github.com/ShendLlapashtica/leak-guard/actions/workflows/test.yml/badge.svg)](https://github.com/ShendLlapashtica/leak-guard/actions/workflows/test.yml)

**A Claude Code plugin that stops your agent committing your API keys.**

An agent writes files fast, and it commits them. Somewhere in that speed is the
write where the key went into `src/config.js` instead of `.env`, and the commit
that pushed it. You find out later — or a scanner finds out first.

leak-guard sits in front of `Write`, `Edit` and `Bash` and answers one question:
**would git carry this credential into a commit?**

```
/plugin marketplace add ShendLlapashtica/leak-guard
/plugin install leak-guard@leak-guard-marketplace
```

No dependencies, no API calls, nothing to configure. Node 18+ and git.

---

## What it decides

| Situation | Decision |
|---|---|
| A credential written into a file git would commit | **deny**, with the fix |
| A credential written into `.env`, or anything git ignores | **allow**, silently |
| A credential in the staged diff of a `git commit` | **deny**, naming file and line |
| A credential in commits a `git push` would send | **deny** |
| A credential typed into a shell command | **ask** — it may be deliberate |
| Anything else | invisible |

The second row is the one that matters. Most secret scanners treat every
credential as an emergency, including the one you deliberately put in `.env`,
and a tool that argues with `.env` gets switched off inside a day. A credential
in a gitignored file is not a leak. It is the fix.

So the guard never stands between you and `.env` — which also means there is
never a reason to hardcode a key "just to get it working".

## What a block looks like

Claude asked to write a Stripe key into a tracked file gets this back instead:

```
leak-guard: this write contains a credential.

git does not ignore config.js, so this value would be committed.

  • line 1  Stripe secret key
      sk_l…wx[32 chars]
      …const stripe = "sk_l…wx[32 chars]";…

Fix it instead of retrying:
  1. Keep the literal out of the file. Read it at runtime from the environment
     (process.env.NAME / os.environ["NAME"]) or from a secret manager.
  2. Put the real value in a gitignored file (.env), and commit a .env.example
     holding only placeholder values.
  3. If this value is already live somewhere, rotate it — it has been in a
     model context window, so treat it as disclosed.
```

A deny is a message to the agent, not just to you: it says what to do instead,
so Claude rewrites the code rather than retrying the same write. The bundled
`secret-hygiene` skill carries the longer version — where the value belongs,
what `.env.example` is for, and the order to do things in when a key is already
committed (rotate first; history rewriting is not remediation).

**The credential is never printed.** Findings are elided to a prefix and a
length — enough to tell you which key it is, not enough to use. Hook output
lands in a transcript, and transcripts get pasted into issues.

## Scanning what is already there

The hook only sees writes from now on. For what the repo already contains:

```
/leak-scan              # everything git tracks, plus untracked files
/leak-scan --staged     # just what is about to be committed
```

Or without Claude:

```bash
node ~/.claude/plugins/.../leak-guard/lib/cli.mjs --json
```

Exit 0 clean, 1 findings, 2 nothing to scan — so it drops into CI or a
pre-commit hook unchanged.

## The rules

Sixteen rules match strings that are a credential **by their own shape** — AWS
access key ids, GitHub tokens and fine-grained PATs, Slack tokens and webhooks,
Stripe secret keys, Google API keys, OpenAI and Anthropic keys, npm, Hugging
Face and SendGrid tokens, private key blocks, signed JWTs, database URIs with an
inline password, and credentials embedded in a URL. A token that starts `ghp_`
and runs 36 characters is not a coincidence, so these never guess.

One rule is a judgement call: a **credential-shaped assignment**, like
`password = "…"`. It is the most common real leak and the only rule here that
can be wrong, so placeholders are filtered hard — `your-password-here`,
`xxxxxxxx`, `${TOKEN}`, `<CLIENT_SECRET>`, `changeme`, anything read from the
environment, any single lowercase word, anything under 12 characters. Turn it
off with `{"creds": false}` if it still annoys you.

There is **no entropy heuristic**, deliberately. Entropy flags hashes, UUIDs,
base64 fixtures and minified identifiers, and a rule that cries wolf gets
switched off — and a rule that is switched off catches nothing.

## Configuration

Optional, `.leakguard.json` at the project root:

```json
{
  "mode": "block",
  "creds": true,
  "allow": ["jwt"],
  "skip": ["test/fixtures/", "docs/examples/"],
  "forbid": ["api.internal.acme", "ACME_LEGACY_TOKEN"],
  "forbidPattern": ["INTERNAL_[A-Z]{4,}"]
}
```

- **mode** — `block` (default), `warn` (report, never stand in the way), `off`.
  `LEAK_GUARD_MODE` overrides it for one session.
- **creds** — the lower-confidence assignment rule.
- **allow** — rule ids to switch off. Every finding prints its id.
- **skip** — path fragments to ignore entirely.
- **forbid** / **forbidPattern** — **your** strings. This is the part no built-in
  rule can do for you: an internal hostname, a legacy header name, a global that
  must never ship. Nobody else can guess what your repo must not contain.

## It fails open

If anything inside the hook throws — git missing, a payload it has never seen, a
config file with a typo — the tool call proceeds. A guard that can break your
session is worse than no guard. (That is not a slogan: the first working build
threw a temporal-dead-zone error on every single invocation, failed open exactly
as designed, and silently allowed everything. It took a test suite to notice.
There is now a test that the hook denies, not just that it does not crash.)

## Tests

```bash
npm test     # node --test, 42 tests, no dependencies
```

The hook tests drive it the way Claude Code does — a JSON payload on stdin, a
decision on stdout — against real temporary git repositories, because the whole
design turns on what git would do. Covered: deny into a tracked file, allow into
`.env`, deny in `.env.example`, deny into a `.env` that was committed before
`.gitignore` learned about it, deny a `.env` that `.gitignore` does not cover,
`Edit`/`MultiEdit` payloads, removing a credential is not leaking one, deny a
commit and name the file and line, allow a clean commit, ask about a shell
command, leave ordinary commands alone, `warn` and `off` modes, every config
key, and failing open on junk input and outside a repository. The CLI tests pin the
exit codes — 0 clean, 1 findings, 2 nothing to scan — because a CI job depends
on them.

## What it is not

- **Not a replacement for provider-side scanning.** GitHub secret scanning and
  push protection see things this cannot. Run both.
- **Not retroactive.** It guards writes and commits from the moment you install
  it. `/leak-scan` is for history, and it only reads the working tree — not past
  commits. For those, use `git log -p` with a scanner, or `trufflehog`.
- **Not a judge of whether a key is live.** It never calls a provider. If a
  finding is real, assume it works, and rotate.
- **Not proof of anything.** A regex catches shapes. A credential with no shape —
  a 20-character password, an internal ticket id — is yours to put in `forbid`.

## Related

[bundle-leak-check](https://github.com/ShendLlapashtica/bundle-leak-check) — the
same idea at the other end of the pipeline: fail the build when the bundle you
are about to ship to browsers contains what it must not. leak-guard grew out of
it.

---

MIT © Shend Llapashtica
