#!/usr/bin/env python3
"""Fail when a Kordex runtime Dockerfile uses a tag-only base image."""

from __future__ import annotations

import re
import sys
from pathlib import Path

DOCKERFILES = (
    "control-plane/Dockerfile",
    "agent/Dockerfile",
    "operator/Dockerfile",
    "dashboard/Dockerfile",
    "integrations/Containerfile.agent-relay",
)
ARG_RE = re.compile(r"^ARG\s+(KORDEX_[A-Z0-9_]*_BASE)=([^\s#]+)\s*$")
FROM_RE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?\$\{(KORDEX_[A-Z0-9_]*_BASE)\}(?:\s+AS\s+\S+)?\s*$", re.IGNORECASE)
IMAGE_DIGEST_RE = re.compile(r"^[a-z0-9][a-z0-9._/:+-]*@sha256:[a-f0-9]{64}$")


class BaseImageError(ValueError):
    pass


def validate_dockerfile(path: Path, text: str) -> int:
    bases: dict[str, str] = {}
    uses: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        arg_match = ARG_RE.fullmatch(line.strip())
        if arg_match:
            name, reference = arg_match.groups()
            if name in bases:
                raise BaseImageError(f"{path}:{number}: duplicate base ARG {name}")
            if not IMAGE_DIGEST_RE.fullmatch(reference):
                raise BaseImageError(f"{path}:{number}: base image must be pinned by sha256 digest")
            bases[name] = reference
            continue

        if line.lstrip().upper().startswith("FROM "):
            from_match = FROM_RE.fullmatch(line.strip())
            if not from_match:
                raise BaseImageError(f"{path}:{number}: FROM must reference a digest-pinned KORDEX base ARG")
            uses.append(from_match.group(1))

    for name in uses:
        if name not in bases:
            raise BaseImageError(f"{path}: FROM references undeclared base ARG {name}")
    if not bases:
        raise BaseImageError(f"{path}: no pinned base image ARGs were declared")
    if not uses:
        raise BaseImageError(f"{path}: no FROM instruction references a pinned base image")
    for name in bases:
        if name not in uses:
            raise BaseImageError(f"{path}: base ARG {name} is not used")
    return len(uses)


def verify_repository(root: Path) -> dict[str, int]:
    results: dict[str, int] = {}
    for relative in DOCKERFILES:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise BaseImageError(f"runtime Dockerfile is missing or unsafe: {relative}")
        results[relative] = validate_dockerfile(path, path.read_text(encoding="utf-8"))
    return results


def main() -> int:
    try:
        results = verify_repository(Path(__file__).resolve().parent.parent)
    except (OSError, UnicodeError, BaseImageError) as exc:
        print(f"container base lock validation failed: {exc}", file=sys.stderr)
        return 1
    print("digest-pinned container bases verified: " + ", ".join(sorted(results)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
