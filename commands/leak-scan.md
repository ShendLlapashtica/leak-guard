---
description: Scan the repository for credentials that would be committed
argument-hint: "[--staged] [--tracked] [--no-creds] [path...]"
allowed-tools: Bash(node:*), Read, Grep
---

The hook only sees writes from now on. This sweeps what the repository already
contains — which is where the one that got away is sitting.

Run the scan:

```
node "${CLAUDE_PLUGIN_ROOT}/lib/cli.mjs" --json $ARGUMENTS
```

Default scope is every file git tracks plus every untracked file git does not
ignore. `--staged` scans only the staged diff. Exit code 0 is clean, 1 means
findings, 2 means there was nothing to scan.

Then report to the user:

1. **High-confidence findings first** (`"severity": "high"`). These are strings
   that are a credential by their own shape — an `AKIA…` key, a `ghp_…` token, a
   signed JWT. Treat each as real.
2. **Lower-confidence findings after** (`"severity": "low"`, rule
   `hardcoded-credential`). These are credential-shaped assignments. Read the
   line before saying anything — a fixture, a test double or a public sample is
   not a leak.
3. For each real finding, say **rotate first**. A credential in a repository was
   disclosed the moment it was pushed, not the moment someone noticed. Removing
   it from the code and rewriting history does not un-publish it; only rotation
   does. Give the rotation URL if you know the provider.
4. Only then propose the code fix: read the value from the environment, put the
   real one in a gitignored file, commit a `.env.example` with placeholders.

Never print a credential in full, in chat or in a file — the scanner already
elides them, so quote its output rather than re-reading the source line. If the
user asks for the full value, point them at the file and line instead.

If the scan is clean, say so in one line and stop. Do not pad it.

**False positives** belong in `.leakguard.json` at the project root, not in a
one-off argument:

```json
{ "allow": ["hardcoded-credential"], "skip": ["test/fixtures/"] }
```
