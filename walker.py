"""Discover readable text files in a repository tree."""

from __future__ import annotations

import os
from pathlib import Path

# Common directories to skip over as they wouldn't have secrets
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".eggs",
        "dist",
        "build",
        "target",
        "vendor",
        ".idea",
        ".vscode",
        "coverage",
        "htmlcov",
    }
)

# file types that we can't parse and should skip
SKIP_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".svg",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".7z",
        ".rar",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".o",
        ".a",
        ".class",
        ".jar",
        ".war",
        ".pyc",
        ".pyo",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".wav",
        ".avi",
        ".mov",
        ".sqlite",
        ".db",
        ".lock",
    }
)

DEFAULT_MAX_FILE_BYTES = 1_048_576  # 1 MiB

# Files that must not be scanned (scanner metadata, not source)
SKIP_FILES = frozenset(
    {
        ".scanner-allowlist",
        "readme",
        "readme.md",
        "readme.rst",
        "readme.txt",
    }
)

# .egg-info directories are created by python packages when they are installed, 
# but since they are named like "dirname.egg-info" we have to handle them directly
def should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.endswith(".egg-info")

def is_probably_binary(sample: bytes) -> bool:
    # null bytes in the first chunk usually mean binary data
    return b"\x00" in sample

def iter_files(
    root: Path,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> list[Path]:
    """
    recursively looks through the repository and returns a list of file paths that should be scanned
    doesn't actually read anything from the files except checking if it's binary
    skips directories and files that are too large, binary, empty, or can't be scanned
    """
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {root}")

    found: list[Path] = []

    for dirpath_str, dirnames, filenames in os.walk(root, topdown=True):
        # make dirnames the sorted list of directories inside the current directory that we should scan so later loops don't go into 
        # directories we want to skip
        dirnames[:] = sorted(name for name in dirnames if not should_skip_dir(name))
        dirpath = Path(dirpath_str)

        for name in sorted(filenames):
            path = dirpath / name
            if name.lower() in SKIP_FILES:
                continue
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue

            try:
                size = path.stat().st_size
            except OSError:
                continue

            if size == 0 or size > max_file_bytes:
                continue

            try:
                with path.open("rb") as handle:
                    sample = handle.read(8192)
            except OSError:
                continue

            if is_probably_binary(sample):
                continue

            found.append(path)

    return found
