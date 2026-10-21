# Scanner

Secret scanner for COMP 5370. 

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
        #   danger-level: "4"   # 1=low … 4=critical (default)
```

Unresolved findings show up as PR annotations with a risk title (`Low` / `Moderate` / `High` / `Critical`). Known-pattern hits are annotated as errors; Shannon entropy hits use warnings (or errors when scored high/critical).

Replace `YOUR_ORG` with your GitHub org or username. Pin to a tag (for example `@v1`) once you cut releases.

If the scanned repo is private and the Action repo is private, grant the workflow access under **Settings → Actions → General → Access**.

