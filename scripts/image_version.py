#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 idelephant contributors

"""Emit an image version derived from Git tags and commit metadata.

The versioning scheme is:

* If HEAD is exactly at the latest release tag, emit that release version.
* Otherwise, bump the patch level of the latest release and emit a prerelease
  version containing the commit distance and short git hash.

Examples:

* v0.2.2 at HEAD -> 0.2.2
* 3 commits after v0.2.2 on commit abc1234 -> 0.2.3-rc.3+gabc1234
"""

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


TAG_RE = re.compile(r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)$")


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def next_patch(self):
        return Version(self.major, self.minor, self.patch + 1)


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def iter_release_tags():
    output = git("tag", "--list")
    tags = []
    for raw_tag in output.splitlines():
        tag = raw_tag.strip()
        match = TAG_RE.fullmatch(tag)
        if not match:
            continue
        version = Version(
            int(match.group("major")),
            int(match.group("minor")),
            int(match.group("patch")),
        )
        tags.append((version, tag))
    if not tags:
        raise RuntimeError("No release tags matching vX.Y.Z were found")
    tags.sort()
    return tags


def latest_release() -> tuple[Version, str]:
    return iter_release_tags()[-1]


def commit_distance(tag: str) -> int:
    return int(git("rev-list", f"{tag}..HEAD", "--count"))


def short_head() -> str:
    return git("rev-parse", "--short", "HEAD")


def is_dirty() -> bool:
    return bool(git("status", "--porcelain"))


def ensure_repo_root() -> None:
    repo_root = Path(git("rev-parse", "--show-toplevel"))
    # Running from anywhere inside the repository is fine, but this check gives
    # a clearer error when the script is copied elsewhere.
    if not repo_root.exists():
        raise RuntimeError("Git repository root could not be determined")


def main() -> int:
    try:
        ensure_repo_root()
        latest_version, latest_tag = latest_release()
        distance = commit_distance(latest_tag)
        dirty_suffix = ".dirty" if is_dirty() else ""
        if distance == 0:
            print(f"{latest_version}{dirty_suffix}")
            return 0

        next_version = latest_version.next_patch()
        print(f"{next_version}-rc.{distance}+g{short_head()}{dirty_suffix}")
        return 0
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
