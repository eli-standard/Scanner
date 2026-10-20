#!/usr/bin/env python3
"""CLI entrypoint for the scanner."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from allowlist import (
    ALLOWLIST_FILENAME,
    candidate_fingerprint,
    load_allowlist,
    partition_candidates,
)
from candidates import Candidate, extract_from_paths
from walker import DEFAULT_MAX_FILE_BYTES, iter_files


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
        "--min-length",
        type=int,
        default=12,
        help="minimum length a string must be to be considered a potential secret. really more a debugging option cause there could be short strings that are still secrets",
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
    return parser


def _relative_path(candidate: Candidate, root: Path) -> Path:
    try:
        return candidate.path.resolve().relative_to(root.resolve())
    except ValueError:
        return candidate.path


def _format_finding(candidate: Candidate, root: Path) -> str:
    rel = _relative_path(candidate, root)
    return f"{rel.as_posix()}:{candidate.line_number}:{candidate.kind}:{candidate.value}"


def _emit_gha_warning(candidate: Candidate, root: Path) -> None:
    """Emit a GitHub Actions warning annotation for an unresolved finding."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    rel = _relative_path(candidate, root).as_posix()
    # Escape characters that break workflow command syntax
    message = f"{candidate.kind}: {candidate.value}"
    message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(
        f"::warning file={rel},line={candidate.line_number}::{message}",
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

    candidates = extract_from_paths(files, min_length=args.min_length)
    allowlist = load_allowlist(root)
    unresolved, dismissed = partition_candidates(candidates, root, allowlist)

    for candidate in dismissed:
        if not args.quiet:
            fp = candidate_fingerprint(candidate, root)
            print(f"dismissed: {fp}", file=sys.stderr)

    for candidate in unresolved:
        print(_format_finding(candidate, root))
        _emit_gha_warning(candidate, root)

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
                f"(path:kind:value) to {ALLOWLIST_FILENAME}",
                file=sys.stderr,
            )

    if unresolved and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
