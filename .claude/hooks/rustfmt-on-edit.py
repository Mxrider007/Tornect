#!/usr/bin/env python3
"""PostToolUse hook: run rustfmt on any .rs file Claude Code just edited.

Reads the hook payload from stdin (JSON with tool_input.file_path) and formats
the file in place. Never blocks the edit: formatting failures (e.g. a file that
does not parse yet) are reported on stderr and exit 0.
"""
import json
import os
import subprocess
import sys


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001 - hook must never fail hard
        return 0
    tool_input = payload.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("path")
    if not path or not path.endswith(".rs") or not os.path.isfile(path):
        return 0
    try:
        subprocess.run(
            ["rustfmt", "--edition", "2024", "--quiet", path],
            check=False,
            timeout=30,
            capture_output=True,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"rustfmt hook: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
