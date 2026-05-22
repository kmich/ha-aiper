#!/usr/bin/env python3
"""Check release version state for repository workflows."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = SEMVER_RE.fullmatch(value)
    if match is None:
        raise SystemExit(f"Invalid SemVer: {value}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def _git_lines(*args: str) -> list[str]:
    return subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()


def _read_pyproject_version() -> str:
    pyproject = Path("pyproject.toml").read_text()
    pyproject_match = re.search(r'(?m)^version = "([^"]+)"$', pyproject)
    if pyproject_match is None:
        raise SystemExit("pyproject.toml has no [project] version")
    return pyproject_match.group(1)


def _check_matching_versions() -> str:
    manifest = json.loads(Path("custom_components/aiper/manifest.json").read_text())
    manifest_version = str(manifest.get("version", ""))
    pyproject_version = _read_pyproject_version()

    if manifest_version != pyproject_version:
        raise SystemExit(
            f"Version mismatch: manifest.json has {manifest_version}, pyproject.toml has {pyproject_version}"
        )
    if SEMVER_RE.fullmatch(manifest_version) is None:
        raise SystemExit(f"Version is not SemVer MAJOR.MINOR.PATCH: {manifest_version}")

    lock = Path("uv.lock").read_text()
    lock_match = re.search(
        r'(?ms)\[\[package\]\]\nname = "ha-aiper"\nversion = "([^"]+)"',
        lock,
    )
    if lock_match and lock_match.group(1) != manifest_version:
        raise SystemExit(
            f"Version mismatch: uv.lock has {lock_match.group(1)}, manifest/pyproject have {manifest_version}"
        )

    return manifest_version


def _write_outputs(outputs: dict[str, str]) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    lines = [f"{name}={value}" for name, value in outputs.items()]

    if github_output:
        with Path(github_output).open("a") as output_file:
            for line in lines:
                print(line, file=output_file)

    for line in lines:
        print(line)


def main() -> None:
    version = _check_matching_versions()
    tag = f"v{version}"
    current_tag_exists = bool(_git_lines("tag", "--list", tag))

    semver_tags = sorted(
        _git_lines("tag", "--list", "v[0-9]*.[0-9]*.[0-9]*"),
        key=lambda value: _version_tuple(value[1:]),
    )
    latest_version = semver_tags[-1][1:] if semver_tags else ""

    release_candidate = not current_tag_exists
    if release_candidate and latest_version and _version_tuple(version) <= _version_tuple(latest_version):
        raise SystemExit(f"Current version {version} has no tag, but is not newer than latest tag v{latest_version}")

    _write_outputs(
        {
            "version": version,
            "tag": tag,
            "release_candidate": "true" if release_candidate else "false",
            "latest_tag": f"v{latest_version}" if latest_version else "",
        }
    )


if __name__ == "__main__":
    main()
