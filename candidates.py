"""Extract and match secret-like strings from text files.

Two complementary paths live here:
- Regex rules (`SECRET_RULES`) for known secret shapes (AWS, Stripe, GitHub, etc.)
- Generic candidate extraction for a future Shannon-entropy pass

Regex hits are the primary output of `extract_from_*`. Generic helpers are kept
separate so another teammate can wire entropy scoring without fighting this
module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# High-confidence secret regex rules (name, pattern)
# Patterns are calibrated against the superdupersecurewebsite fixture repo.
# ---------------------------------------------------------------------------

SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    # Cloud / vendor API keys and tokens
    (
        "aws_access_key_id",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "aws_secret_access_key",
        # 40-char AWS secret, usually only safe to claim next to a known key name
        re.compile(
            r"(?i)(?:aws_secret_access_key|secretaccesskey|secret_access_key)"
            r"""\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"""
        ),
    ),
    (
        "stripe_secret_key",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9_]{16,}\b"),
    ),
    (
        "stripe_publishable_key",
        re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9_]{16,}\b"),
    ),
    (
        "stripe_webhook_secret",
        re.compile(r"\bwhsec_[A-Za-z0-9_]{16,}\b"),
    ),
    (
        "github_pat",
        # classic PATs (ghp_) plus other GitHub token prefixes
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    ),
    (
        "github_fine_grained_pat",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "sendgrid_api_key",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "slack_bot_token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ),
    (
        "slack_webhook_url",
        re.compile(
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+=-]{20,}"
        ),
    ),
    # Connection strings / auth material
    (
        "connection_uri",
        # Common DB / cache / broker URI schemes (with or without credentials).
        re.compile(
            r"\b(?:"
            r"postgres(?:ql)?|"
            r"mongodb(?:\+srv)?|"
            r"mysql|"
            r"mariadb|"
            r"mssql|"
            r"sqlserver|"
            r"oracle|"
            r"cockroach(?:db)?|"
            r"cassandra|"
            r"neo4j|"
            r"redis|rediss|"
            r"amqp|amqps|"
            r"jdbc:(?:postgres(?:ql)?|mysql|mariadb|sqlserver|oracle)"
            r")://[^\s\"'<>\\]{8,}",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_uri",
        # Any URI scheme that embeds user:password@host (ftp, http(s), custom, …).
        # Negative lookbehind avoids re-matching inside jdbc:<scheme>:// URIs.
        re.compile(
            r"(?<!jdbc:)\b[a-z][a-z0-9+.-]*://"
            r"[^\s\"'<>\\/@:]{0,64}"  # user (may be empty, e.g. redis://:pass@host)
            r":"
            r"[^\s\"'<>\\/@]{1,128}"  # password
            r"@"
            r"[^\s\"'<>\\]{3,}",  # host[/path…]
            re.IGNORECASE,
        ),
    ),
    (
        "jwt_token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+([A-Za-z0-9_\-+/=.]{12,})\b"),
    ),
]

# Assignment catch-all for env / Dockerfile / YAML / JS object fields whose
# names look secret-related (checked in Python so camelCase is reliable).
# Prefer quoted literals; allow unquoted env-style values without code tokens.
_ASSIGNMENT_QUOTED = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.]*)\s*[=:]\s*["'](?P<value>[^"']{6,})["']"""
)
_ASSIGNMENT_UNQUOTED = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.]*)\s*[=:]\s*(?P<value>[^\s"'#,;(){}`]{6,})"""
)
_SENSITIVE_KEY_NAME = re.compile(
    r"(?i)("
    r"secret|password|passwd|token|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|"
    r"write[_-]?key|publishable[_-]?key|database[_-]?url|"
    r"aws_access_key_id"
    r")"
)
_CODE_LIKE_VALUE = re.compile(
    r"(?i)^("
    r"true|false|null|undefined|none|"
    r"bearer|"
    r".*\b(process\.env|form\.get|localStorage|header\.slice|Boolean|String|Number)\b.*"
    r")$"
)

# Prefer vendor-specific rule names over the generic assignment rule when both
# fire on the same value.
_GENERIC_KINDS = frozenset({"sensitive_assignment"})

# Values that look intentionally redacted / placeholder (e.g. .env.example).
_PLACEHOLDER_VALUE = re.compile(
    r"(?i)^("
    r"\*+|"
    r".*\*{3,}.*|"
    r"<*(redacted|placeholder|your[_-]?|xxx+|todo|changeme|replace[_-]?me|"
    r"password|secret|example|dummy|changethis)>?|"
    r"sk_(?:live|test)_\*+|"
    r"pk_(?:live|test)_\*+|"
    r"whsec_\*+|"
    r"ghp_\*+|"
    r"SG\.\*+|"
    r"AKIA\*+"
    r")$"
)

# ---------------------------------------------------------------------------
# Generic candidate patterns (for a future Shannon-entropy pass)
# ---------------------------------------------------------------------------

_ALNUM_RUN = re.compile(r"[A-Za-z0-9_\-+/=]{16,}")
_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,64})\s*[=:]\s*["'](?P<value>[^"']{8,})["']"""
)
_QUOTED = re.compile(r"""["']([^"']{12,})["']""")

DEFAULT_MIN_CANDIDATE_LENGTH = 12


@dataclass(frozen=True)
class Candidate:
    """A finding location. The matched secret itself is never retained."""

    path: Path
    line_number: int
    kind: str  # rule name, or generic: alnum_run | assignment | quoted


@dataclass(frozen=True)
class _EphemeralMatch:
    """Line-local match used only while filtering; discarded before return."""

    kind: str
    value: str


def _dedupe_key(candidate: Candidate) -> tuple[Path, int, str]:
    return (candidate.path, candidate.line_number, candidate.kind)


def _to_candidate(path: Path, line_number: int, match: _EphemeralMatch) -> Candidate:
    return Candidate(path=path, line_number=line_number, kind=match.kind)


_PLACEHOLDER_URI_PASSWORD = re.compile(
    r"(?i)://[^/\s\"']+:(?:password|changeme|secret|xxx|replace[_-]?me|your[_-]?password)@"
)


def is_placeholder(value: str) -> bool:
    """Return True for redacted / example values that should not be reported."""
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return True
    if _PLACEHOLDER_VALUE.match(cleaned):
        return True
    # e.g. postgres://user:password@localhost in .env.example
    if _PLACEHOLDER_URI_PASSWORD.search(cleaned):
        return True
    return False


def _rule_capture(match: re.Match[str]) -> str:
    """Prefer a named/numbered capture group when the rule wraps the secret."""
    if match.lastindex:
        # Prefer explicit 'value' group when present (assignment-style rules).
        try:
            named = match.groupdict()
        except IndexError:
            named = {}
        if "value" in named and named["value"] is not None:
            return named["value"]
        return match.group(match.lastindex)
    return match.group(0)


def _looks_like_code_value(value: str) -> bool:
    """Filter out JS/TS expressions mistakenly parsed as secret literals."""
    if _CODE_LIKE_VALUE.match(value):
        return True
    if any(ch in value for ch in "()`{}") or value.startswith("${"):
        return True
    # Property access like header.slice — but allow JWTs and URLs.
    if "." in value and not value.startswith("eyJ") and "://" not in value:
        if re.search(r"[A-Za-z_]\.[A-Za-z_]", value):
            return True
    return False


def _sensitive_assignments_in_line(line: str) -> list[_EphemeralMatch]:
    """Flag assignment values when the left-hand name looks secret-related."""
    results: list[_EphemeralMatch] = []
    seen: set[str] = set()

    matches = list(_ASSIGNMENT_QUOTED.finditer(line)) + list(
        _ASSIGNMENT_UNQUOTED.finditer(line)
    )
    for match in matches:
        key_name = match.group("key")
        if not _SENSITIVE_KEY_NAME.search(key_name):
            continue
        value = match.group("value").strip().rstrip(",;")
        if (
            is_placeholder(value)
            or _looks_like_code_value(value)
            or value in seen
        ):
            continue
        seen.add(value)
        results.append(_EphemeralMatch(kind="sensitive_assignment", value=value))
    return results


def find_secrets_in_line(
    path: Path,
    line_number: int,
    line: str,
) -> list[Candidate]:
    """Match known secret patterns on a single line.

    Matched secret strings exist only as locals while this function runs; returned
    ``Candidate`` objects keep path, line, and rule kind only.
    """
    results: list[_EphemeralMatch] = []
    seen_kinds: set[tuple[str, str]] = set()

    for rule_name, pattern in SECRET_RULES:
        for match in pattern.finditer(line):
            value = _rule_capture(match).strip().rstrip(",;")
            if is_placeholder(value):
                continue
            key = (rule_name, value)
            if key in seen_kinds:
                continue
            seen_kinds.add(key)
            results.append(_EphemeralMatch(kind=rule_name, value=value))

    for ephemeral in _sensitive_assignments_in_line(line):
        key = (ephemeral.kind, ephemeral.value)
        if key in seen_kinds:
            continue
        seen_kinds.add(key)
        results.append(ephemeral)

    # Prefer vendor-specific rule names when the same value was also caught by
    # a generic assignment rule.
    specific_values = {
        m.value for m in results if m.kind not in _GENERIC_KINDS
    }
    # Also drop "Bearer <token>" assignments when bearer_token already reported
    # the token itself.
    bearer_values = {m.value for m in results if m.kind == "bearer_token"}
    specific_values.update(f"Bearer {token}" for token in bearer_values)

    filtered = [
        m
        for m in results
        if m.kind not in _GENERIC_KINDS or m.value not in specific_values
    ]

    # Prefer connection_uri over credential_uri when both match the same string
    # (e.g. postgres://user:pass@host).
    connection_values = {m.value for m in filtered if m.kind == "connection_uri"}
    final_matches = [
        m
        for m in filtered
        if not (m.kind == "credential_uri" and m.value in connection_values)
    ]

    return [_to_candidate(path, line_number, m) for m in final_matches]


def extract_generic_from_line(
    path: Path,
    line_number: int,
    line: str,
    min_length: int = DEFAULT_MIN_CANDIDATE_LENGTH,
) -> list[Candidate]:
    """
    Pull generic candidate strings for entropy scoring.

    Kept separate from regex rules so the Shannon pass can consume these without
    depending on vendor-specific patterns.
    """
    results: list[Candidate] = []
    seen: set[str] = set()

    def add(value: str, kind: str) -> None:
        value = value.strip()
        if len(value) < min_length or is_placeholder(value):
            return
        if value in seen:
            return
        seen.add(value)
        # value used only for dedupe/filter above; not stored on Candidate
        results.append(Candidate(path=path, line_number=line_number, kind=kind))

    for match in _ASSIGNMENT.finditer(line):
        add(match.group("value"), "assignment")

    for match in _QUOTED.finditer(line):
        add(match.group(1), "quoted")

    for match in _ALNUM_RUN.finditer(line):
        add(match.group(0), "alnum_run")

    return results


def extract_from_line(
    path: Path,
    line_number: int,
    line: str,
    min_length: int = DEFAULT_MIN_CANDIDATE_LENGTH,
    include_generic: bool = False,
) -> list[Candidate]:
    """
    Scan one line for secrets.

    By default returns regex rule hits only. Set include_generic=True to also
    emit entropy-oriented candidates.
    """
    results = find_secrets_in_line(path, line_number, line)
    if include_generic:
        results.extend(
            extract_generic_from_line(path, line_number, line, min_length=min_length)
        )
    return results


def extract_from_file(
    path: Path,
    min_length: int = DEFAULT_MIN_CANDIDATE_LENGTH,
    include_generic: bool = False,
) -> list[Candidate]:
    """Read a text file and return secret candidates with line numbers."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    candidates: list[Candidate] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        candidates.extend(
            extract_from_line(
                path,
                line_number,
                line,
                min_length=min_length,
                include_generic=include_generic,
            )
        )
    return candidates


def extract_from_paths(
    paths: list[Path],
    min_length: int = DEFAULT_MIN_CANDIDATE_LENGTH,
    include_generic: bool = False,
) -> list[Candidate]:
    """Extract candidates from many files, de-duplicating identical hits."""
    all_candidates: list[Candidate] = []
    seen: set[tuple[Path, int, str]] = set()

    for path in paths:
        for candidate in extract_from_file(
            path,
            min_length=min_length,
            include_generic=include_generic,
        ):
            key = _dedupe_key(candidate)
            if key in seen:
                continue
            seen.add(key)
            all_candidates.append(candidate)

    return all_candidates
