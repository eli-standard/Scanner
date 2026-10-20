"""Load and apply `.scanner-allowlist` dismissals for false positives."""

from __future__ import annotations

import re
from pathlib import Path

from candidates import Candidate

ALLOWLIST_FILENAME = ".scanner-allowlist"

# Printed finding: path:line:kind
_FULL_FINDING = re.compile(r"^(.+):(\d+):([^:]+)$")
# Allowlist fingerprint: path:kind (line omitted so edits don't re-fail)
_FINGERPRINT = re.compile(r"^(.+):([^:]+)$")


def fingerprint(rel: Path | str, kind: str) -> str:
    """Stable allowlist key (no secret value; line numbers omitted)."""
    return f"{Path(rel).as_posix()}:{kind}"


def candidate_fingerprint(candidate: Candidate, root: Path) -> str:
    try:
        rel = candidate.path.resolve().relative_to(root.resolve())
    except ValueError:
        rel = candidate.path
    return fingerprint(rel, candidate.kind)


def normalize_allowlist_entry(line: str) -> str | None:
    """Turn an allowlist line into a fingerprint, or None if blank/comment."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None

    full = _FULL_FINDING.match(text)
    if full:
        path, _line, kind = full.groups()
        return fingerprint(path, kind)

    fp = _FINGERPRINT.match(text)
    if fp:
        path, kind = fp.groups()
        return fingerprint(path, kind)

    return text


def load_allowlist(root: Path) -> set[str]:
    """Load fingerprints from `.scanner-allowlist` under *root* (empty if missing)."""
    path = root / ALLOWLIST_FILENAME
    if not path.is_file():
        return set()

    entries: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()

    for line in text.splitlines():
        normalized = normalize_allowlist_entry(line)
        if normalized:
            entries.add(normalized)
    return entries


def partition_candidates(
    candidates: list[Candidate],
    root: Path,
    allowlist: set[str],
) -> tuple[list[Candidate], list[Candidate]]:
    """Split into (unresolved, dismissed) using the allowlist."""
    unresolved: list[Candidate] = []
    dismissed: list[Candidate] = []
    for candidate in candidates:
        if candidate_fingerprint(candidate, root) in allowlist:
            dismissed.append(candidate)
        else:
            unresolved.append(candidate)
    return unresolved, dismissed
