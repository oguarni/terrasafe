#!/usr/bin/env python3
"""Generate pip-compatible scan-action constraints from runtime requirements."""

from __future__ import annotations

import re
from pathlib import Path


ACTION_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = ACTION_DIRECTORY.parents[2]
SOURCE = REPOSITORY_ROOT / "requirements.txt"
DESTINATION = ACTION_DIRECTORY / "constraints.txt"

PINNED_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^]]+\])?"
    r"(?P<pin>\s*==\s*[^\s;]+.*)$"
)
SKIPPED_OPTIONS = (
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
)
HEADER = (
    "# Generated from requirements.txt; do not edit.\n"
    "# Regenerate: python .github/actions/terravault-scan/generate-constraints.py\n"
)


def project_requirements(source: Path) -> list[str]:
    """Return all pinned requirements with any extras removed."""
    projected: list[str] = []

    for line_number, raw_line in enumerate(source.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(SKIPPED_OPTIONS):
            continue

        match = PINNED_REQUIREMENT.fullmatch(line)
        if match is None:
            raise ValueError(
                f"{source}:{line_number}: expected a requirement pinned with ==: "
                f"{raw_line!r}"
            )
        projected.append(f"{match.group('name')}{match.group('pin')}")

    if not projected:
        raise ValueError(f"{source}: no pinned requirements found")

    return projected


def main() -> None:
    """Write the deterministic constraints projection."""
    requirements = project_requirements(SOURCE)
    DESTINATION.write_text(HEADER + "\n".join(requirements) + "\n")


if __name__ == "__main__":
    main()
