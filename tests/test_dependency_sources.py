"""Guard the composite action's dependency subset against silent version drift.

The action intentionally owns only the package names it needs and receives all
versions from the root ``requirements.txt`` through pip's constraints option.
Constraints affect only packages named in both files, so adding an action-only
dependency would silently restore an unconstrained install path unless this
boundary is checked explicitly.
"""
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_REQUIREMENTS = (
    REPO_ROOT / ".github" / "actions" / "terravault-scan" / "requirements.txt"
)
RUNTIME_REQUIREMENTS = REPO_ROOT / "requirements.txt"


def _package_names(path: Path) -> set[str]:
    """Return normalized names from the repository's requirements files."""
    names = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        requirement = raw_line.partition("#")[0].strip()
        if requirement:
            # PEP 503 normalization makes equivalent '-'/'_' spellings compare
            # equal instead of treating harmless spelling differences as drift.
            names.add(canonicalize_name(Requirement(requirement).name))
    return names


def test_action_dependencies_have_runtime_constraints():
    action_names = _package_names(ACTION_REQUIREMENTS)
    runtime_names = _package_names(RUNTIME_REQUIREMENTS)

    unconstrained = sorted(action_names - runtime_names)
    assert not unconstrained, (
        "composite action packages missing from root requirements.txt: "
        f"{', '.join(unconstrained)}"
    )
