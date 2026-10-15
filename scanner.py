#!/usr/bin/env python3
"""CLI entrypoint for the scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from candidates import extract_from_paths
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
    return parser


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
    root_resolved = root.resolve()

    for candidate in candidates:
        try:
            rel = candidate.path.resolve().relative_to(root_resolved)
        except ValueError:
            rel = candidate.path
        print(f"{rel}:{candidate.line_number}:{candidate.kind}:{candidate.value}")

    if not args.quiet:
        print(
            f"\nScanned {len(files)} file(s); found {len(candidates)} candidate(s)",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
