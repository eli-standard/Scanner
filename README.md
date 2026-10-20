# Scanner

Secret scanner for COMP 5370. Finds high-confidence secret patterns (API keys, tokens, connection strings, and similar) in a repository tree.

## Local usage

```bash
python scanner.py [path]
```

Useful flags:

- `--list-files` — show which files would be scanned
- `--min-length N` — minimum length for generic candidates
- `--max-file-bytes N` — skip files larger than N bytes
- `--no-fail` — always exit 0 (useful for dry runs)
- `-q` / `--quiet` — suppress the summary on stderr

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Clean scan, or every finding was dismissed via allowlist |
| 1 | Unresolved secret candidates remain |
| 2 | Invalid path / usage error |

## GitHub Action (reusable)

The Action lives in **this** repository. Any other repo you want to scan (for example a dummy website) only needs a thin workflow that calls it. Put that workflow in the **scanned** repo — GitHub only runs `pull_request` workflows from the repository that received the PR.

### Consumer workflow

In the repo under test, add `.github/workflows/secret-scan.yml`:

```yaml
name: Secret scan

on:
  pull_request:
    branches: [main]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: YOUR_ORG/Scanner@main
        # Optional inputs:
        # with:
        #   path: "."
        #   max-file-bytes: "1048576"
        #   min-length: "12"
```

Replace `YOUR_ORG` with your GitHub org or username. Pin to a tag (for example `@v1`) once you cut releases.

If the scanned repo is private and the Action repo is private, grant the workflow access under **Settings → Actions → General → Access**.

### What the Action does

1. Checks out is already done by the consumer workflow.
2. Sets up Python and runs this scanner against the workspace.
3. Emits GitHub Actions `::warning::` annotations for each unresolved finding.
4. Fails the job (exit 1) when unresolved findings remain.

### Dismissing false positives

GitHub has no built-in “dismiss” button for custom Action checks. To mark a finding as a false positive so the check passes:

1. Copy the finding’s fingerprint: `path:kind:value` (line number omitted so edits do not re-break the allowlist).
   - Full log lines look like `path:line:kind:value`; you may paste either form into the allowlist.
2. Add that line to `.scanner-allowlist` at the root of the **scanned** repository.
3. Push; the dismissed hit is skipped and the job passes if nothing else remains.

Example `.scanner-allowlist`:

```
# False positives (one fingerprint per line)
# fingerprint form: path:kind:value
docs/examples.env:sensitive_assignment:REPLACE_WITH_THE_FLAGGED_VALUE
```

Lines starting with `#` are comments. Blank lines are ignored.
