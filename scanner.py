#!/usr/bin/env python3
"""CLI entrypoint for the scanner."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
import time

from allowlist import (
    ALLOWLIST_FILENAME,
    candidate_fingerprint,
    load_allowlist,
    partition_candidates,
)
from candidates import Candidate, extract_from_paths
from walker import DEFAULT_MAX_FILE_BYTES, iter_files

_CRITICAL = 4

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="scan a repository for potential secret strings.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="root directory to scan if you just wanted to start from a specific directory. defaults to current directory",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help=f"skip files larger than this many bytes. most code files for a project aren't that big. bigger files tend to be stuff like logs that probably wouldn't have secrets. can change this as we want",
    )
    parser.add_argument(
        "--list-files",
        action="store_true",
        help="just list the files that would be scanned without actually scanning",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="only print the candidates without a summary",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="always exit 0 even when unresolved candidates are found",
    )
    parser.add_argument(
        "level",
        nargs="?",
        default=_CRITICAL,
        help="shows files with the danger level above the level provided. Defaults to the most dangerous. Level 1: Low, Level 2: Medium, Level 3: High, Level 4: Dangerous",
    )
    return parser


def _relative_path(candidate: Candidate, root: Path) -> Path:
    try:
        return candidate.path.resolve().relative_to(root.resolve())
    except ValueError:
        return candidate.path


def _format_finding(candidate: Candidate, root: Path) -> str:
    rel = _relative_path(candidate, root)
    return f"Path: {rel.as_posix()}\nLine: {candidate.line_number}\nCandidate Type: {candidate.kind}\nLevel of Risk: {candidate.risk}\n"


def _escape_gha(value: str) -> str:
    """Escape characters that break GitHub Actions workflow command syntax."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _emit_gha_annotation(candidate: Candidate, root: Path) -> None:
    """Emit a GitHub Actions annotation that includes kind and risk level."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    rel = _relative_path(candidate, root).as_posix()
    risk = (candidate.risk or "unknown").lower()
    # Surface critical/high as errors so the PR Checks UI ranks them above
    # moderate/low warnings from Shannon entropy hits.
    command = "error" if risk in ("critical", "high") else "warning"
    title = _escape_gha(f"{risk.capitalize()} risk")
    message = _escape_gha(f"{candidate.kind} ({risk} risk)")
    print(
        f"::{command} file={rel},line={candidate.line_number},title={title}::{message}",
        flush=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(args.path)
    try:
        files = iter_files(root, max_file_bytes=args.max_file_bytes)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.list_files:
        for path in files:
            print(path)
        if not args.quiet:
            print(f"\n{len(files)} file(s) would be scanned", file=sys.stderr)
        return 0

    try:
        danger = int(args.level)
        if danger < 1 or danger > 4:
            print("Invalid danger level. Defaulting to Critical")
            danger = _CRITICAL
    except (ValueError, TypeError) as exc:
        print("Invalid danger level input. Defaulting to Critical")
        danger = _CRITICAL
    
    print("Welcome to the Secret Scanner!")
    print("============================================================")
    time.sleep(1)
    print("Scanning for secrets...")
    time.sleep(2)
    candidates = extract_from_paths(files, danger)
    allowlist = load_allowlist(root)
    unresolved, dismissed = partition_candidates(candidates, root, allowlist)

    for candidate in dismissed:
        if not args.quiet:
            fp = candidate_fingerprint(candidate, root)
            print(f"dismissed: {fp}", file=sys.stderr)
    print("============================================================")
    print("Unresolved findings:")
    print("============================================================")
    for candidate in unresolved:
        time.sleep(0.15)
        print(_format_finding(candidate, root))
        _emit_gha_annotation(candidate, root)

    if not args.quiet:
        print(
            f"\nScanned {len(files)} file(s); "
            f"found {len(candidates)} candidate(s) "
            f"({len(unresolved)} unresolved, {len(dismissed)} dismissed)",
            file=sys.stderr,
        )
        if unresolved:
            print(
                f"To dismiss a false positive, add its fingerprint "
                f"(path:kind) to {ALLOWLIST_FILENAME}",
                file=sys.stderr,
            )

    if unresolved and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
