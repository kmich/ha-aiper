#!/usr/bin/env python3
"""Fail if any integration module is below the per-module coverage floor.

Home Assistant's Silver quality-scale rule asks for >95% test coverage in
every integration module, which coverage.py's total `fail_under` cannot
express. Run after `pytest --cov --cov-report=json`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MODULE_FLOOR = 95.0


def main() -> None:
    report = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json").read_text(encoding="utf-8"))
    failures = []
    for path, data in sorted(report["files"].items()):
        percent = float(data["summary"]["percent_covered"])
        if percent < MODULE_FLOOR:
            failures.append(f"{path}: {percent:.1f}% < {MODULE_FLOOR}%")
    if failures:
        raise SystemExit("Per-module coverage below floor:\n" + "\n".join(failures))
    print(f"OK: all {len(report['files'])} modules at or above {MODULE_FLOOR}% coverage")


if __name__ == "__main__":
    main()
