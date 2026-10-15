"""Extract candidate secret-like strings from text files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Long runs of URL-safe / base64-ish characters (API keys, tokens, etc.).
_ALNUM_RUN = re.compile(r"[A-Za-z0-9_\-+/=]{16,}")

# Assignment-style values: key = "value" or key: 'value'
_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,64})\s*[=:]\s*["'](?P<value>[^"']{8,})["']"""
)

# Double- or single-quoted strings that look non-trivial.
_QUOTED = re.compile(r"""["']([^"']{12,})["']""")

DEFAULT_MIN_CANDIDATE_LENGTH = 12


@dataclass(frozen=True)
class Candidate:
    path: Path
    line_number: int
    value: str
    kind: str  # "alnum_run" | "assignment" | "quoted"


def _dedupe_key(candidate: Candidate) -> tuple[Path, int, str]:
    return (candidate.path, candidate.line_number, candidate.value)


def extract_from_line(
    path: Path,
    line_number: int,
    line: str,
    min_length: int = DEFAULT_MIN_CANDIDATE_LENGTH,
) -> list[Candidate]:
    """Pull candidate strings from a single line of text."""
    results: list[Candidate] = []
    seen: set[str] = set()

    def add(value: str, kind: str) -> None:
        value = value.strip()
        if len(value) < min_length:
            return
        if value in seen:
            return
        seen.add(value)
        results.append(
            Candidate(path=path, line_number=line_number, value=value, kind=kind)
        )

    for match in _ASSIGNMENT.finditer(line):
        add(match.group("value"), "assignment")

    for match in _QUOTED.finditer(line):
        add(match.group(1), "quoted")

    for match in _ALNUM_RUN.finditer(line):
        add(match.group(0), "alnum_run")

    return results


def extract_from_file(
    path: Path,
    min_length: int = DEFAULT_MIN_CANDIDATE_LENGTH,
) -> list[Candidate]:
    """
    Read a text file and return candidate strings with line numbers.

    Uses UTF-8 with replacement so slightly dirty files still scan.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    candidates: list[Candidate] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        candidates.extend(
            extract_from_line(path, line_number, line, min_length=min_length)
        )
    return candidates


def extract_from_paths(
    paths: list[Path],
    min_length: int = DEFAULT_MIN_CANDIDATE_LENGTH,
) -> list[Candidate]:
    """Extract candidates from many files, de-duplicating identical hits."""
    all_candidates: list[Candidate] = []
    seen: set[tuple[Path, int, str]] = set()

    for path in paths:
        for candidate in extract_from_file(path, min_length=min_length):
            key = _dedupe_key(candidate)
            if key in seen:
                continue
            seen.add(key)
            all_candidates.append(candidate)

    return all_candidates
