#!/usr/bin/env python3

import argparse
import json
import re
from pathlib import Path


def update_mapping(lines: list[str], section: str, mapping: str, names: list[str], tag: str) -> None:
    section_start = next(index for index, line in enumerate(lines) if line == f"{section}:\n")
    mapping_start = next(
        index
        for index in range(section_start + 1, len(lines))
        if lines[index] == f"  {mapping}:\n"
    )

    pending = set(names)
    for index in range(mapping_start + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith("    "):
            break
        match = re.fullmatch(r"    ([a-z0-9-]+): .*\n", line)
        if match and match.group(1) in pending:
            lines[index] = f"    {match.group(1)}: {tag}\n"
            pending.remove(match.group(1))

    if pending:
        raise ValueError(f"missing {section}.{mapping} keys: {', '.join(sorted(pending))}")


def update_scalar(lines: list[str], section: str, key: str, value: str) -> None:
    section_start = next(index for index, line in enumerate(lines) if line == f"{section}:\n")
    for index in range(section_start + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith("  "):
            break
        if line.startswith(f"  {key}:"):
            lines[index] = f"  {key}: {value}\n"
            return
    raise ValueError(f"missing {section}.{key}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--applications", type=json.loads, default=[])
    parser.add_argument("--migrations", type=json.loads, default=[])
    parser.add_argument("--analytics-init", action="store_true")
    args = parser.parse_args()

    lines = args.file.read_text(encoding="utf-8").splitlines(keepends=True)
    update_mapping(lines, "globalImage", "tags", args.applications, args.tag)
    update_mapping(lines, "migrations", "tags", args.migrations, args.tag)
    if args.analytics_init:
        update_scalar(lines, "analyticsInit", "tag", args.tag)
    args.file.write_text("".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
