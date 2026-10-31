---
name: secret-hygiene
description: How to handle an API key, token, password or connection string in a repository - where the value goes, what gets committed, and what to do when one has already been committed or pushed. Use when wiring up authentication or a third-party API, when adding config, when a write was denied for containing a credential, or when the user pastes a key into the conversation.
---

# Secret hygiene

## The one rule

**A credential never appears as a literal in a file git tracks.** Not in source,
not in a config file, not in a test, not in a comment, not in a README, not
"temporarily". Everything below follows from that.

## Where the value goes

| Kind | Home | Committed? |
|---|---|---|
| Local development | `.env` (gitignored) | no |
| The shape of config | `.env.example`, placeholders only | yes |
| CI | the runner's secret store (GitHub Actions secrets, etc.) | no |
| Production | the platform's env vars or a secret manager | no |
| A key file (`.pem`, `.p12`) | gitignored path, or the secret manager | no |

Before writing the first line of config, check that `.gitignore` actually
contains `.env`. A `.env` that is already tracked keeps being committed no matter
what you add to `.gitignore` later — `git rm --cached .env` is what untracks it.

## Reading it in code

```js
const key = process.env.STRIPE_SECRET_KEY;
if (!key) throw new Error('STRIPE_SECRET_KEY is not set');   // fail loudly at boot
```

```python
import os
key = os.environ["STRIPE_SECRET_KEY"]      # KeyError at boot beats None at 3am
```

Fail at startup, not at the call site. A missing credential discovered on the
first request is an outage; discovered at boot it is a deploy that did not
happen.

Never log it, never put it in a URL query string (it lands in access logs,
proxy logs and `Referer` headers), never ship it to the browser. Anything a
browser can read is public — `NEXT_PUBLIC_*`, `VITE_*` and friends are compiled
into the bundle, so only a publishable key goes there.

## When a write is denied for containing a credential

The guard denied it because the file would be committed. Do not retry the write,
and do not work around it by writing the value somewhere else.

1. Replace the literal with an environment read.
2. Put the real value in `.env`; confirm `.env` is gitignored.
3. Add the variable name — with a placeholder value — to `.env.example`.
4. Tell the user the variable they need to set, by name.
5. If the value was real, say that it needs rotating: it has been through a
   model's context window, which is disclosure.

A credential belongs in `.env` and the guard allows that, so there is never a
reason to hardcode one to "get it working first".

## When one has already been committed

Say this plainly, in this order, because the order is what people get wrong:

1. **Rotate it now.** This is the only step that actually fixes anything.
   Everything else is tidying. If the commit was pushed to a public remote,
   assume the credential was harvested within minutes — scanners watch the
   firehose, and GitHub keeps pushed objects reachable even after a force-push.
2. **Then** remove it from the working tree and commit that.
3. **Only then**, if it matters, rewrite history (`git filter-repo`, or BFG) and
   force-push. Warn the user this rewrites every commit hash, breaks open pull
   requests and requires every collaborator to re-clone or hard-reset.
4. Check for forks and caches you cannot rewrite: forks, mirrors, CI logs,
   issue and PR comments, the provider's own audit log.

Never present history rewriting as the fix. "I removed it from the repo" is not
remediation; the key still works until it is rotated.

## Checking

```
/leak-scan            # the whole repository
/leak-scan --staged   # just what is about to be committed
```

Scope false positives in `.leakguard.json` at the project root rather than
switching the guard off:

```json
{
  "allow": ["hardcoded-credential"],
  "skip": ["test/fixtures/"],
  "forbid": ["my-internal-hostname.example"]
}
```
