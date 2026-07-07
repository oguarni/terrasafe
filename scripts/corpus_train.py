#!/usr/bin/env python3
"""Train the Isolation Forest on structural features from real Terraform modules.

This implements the "future work" noted in ``terravault/infrastructure/CLAUDE_ML.md``:
replace the purely synthetic secure baseline with structural features extracted
from a corpus of real, well-maintained Terraform modules pulled from the public
Terraform Registry.

Pipeline (each phase is a subcommand; ``all`` chains them):

  collect   Download the most-downloaded AWS modules from curated, reputable
            registry namespaces into ``corpus/`` (only ``*.tf`` files are kept).
  extract   Parse every collected ``.tf`` file with the production ``HCLParser``
            and run ``StructuralFeatureExtractor`` - the exact inference-time
            code path - keeping one 8-dim vector per file that declares at
            least one resource. Saves ``corpus/features.npy``.
  train     Stack the real vectors onto the persisted synthetic baseline via
            ``ModelManager.update_model_with_feedback()`` (the documented
            no-catastrophic-forgetting path) and save a new model version.

Run from the repository root (the parser's path-traversal guard only allows
files under the current working directory).

Examples:
    python scripts/corpus_train.py collect --max-modules 400
    python scripts/corpus_train.py extract
    python scripts/corpus_train.py train
    python scripts/corpus_train.py all --max-modules 400
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import numpy as np  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from terravault.application.feature_extraction import (  # noqa: E402
    FEATURE_BOUNDS,
    FEATURE_NAMES,
    StructuralFeatureExtractor,
)
from terravault.infrastructure.ml_model import MLPredictor, ModelManager  # noqa: E402
from terravault.infrastructure.parser import HCLParser, TerraformParseError  # noqa: E402

REGISTRY = "https://registry.terraform.io/v1/modules"

# Curated namespaces of widely used, actively maintained AWS modules. These are
# the "known-good structure" population the Isolation Forest should learn.
DEFAULT_NAMESPACES = ("terraform-aws-modules", "cloudposse", "aws-ia")

# Directories inside a module repo that are not part of the shipped module
# (examples are often intentionally minimal or insecure; tests are synthetic).
SKIP_DIR_PARTS = frozenset({"examples", "example", "test", "tests", ".terraform", ".github"})

MAX_TF_FILE_BYTES = 512 * 1024  # skip pathological single files
USER_AGENT = "terravault-corpus-builder (+https://github.com/oguarni/terravault)"

_GITHUB_GET_RE = re.compile(
    r"git::https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/?]+?)(?:\.git)?"
    r"(?://[^?]*)?\?ref=(?P<ref>[^&]+)"
)


def _http_get(url: str, timeout: int = 30, retries: int = 2) -> Any:
    """GET with a UA header and simple retry/backoff on transient failures."""
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            return urllib.request.urlopen(request, timeout=timeout)  # nosec B310 - https URLs only
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"GET {url} failed after {retries + 1} attempts: {last_error}")


def _list_namespace_modules(namespace: str, page_cap: int = 30) -> List[Dict[str, Any]]:
    """Return all AWS-provider modules listed under a registry namespace."""
    modules: List[Dict[str, Any]] = []
    offset = 0
    for _ in range(page_cap):
        url = f"{REGISTRY}/{urllib.parse.quote(namespace)}?limit=100&offset={offset}"
        with _http_get(url) as response:
            payload = json.load(response)
        page = payload.get("modules", [])
        modules.extend(m for m in page if m.get("provider") == "aws")
        next_offset = payload.get("meta", {}).get("next_offset")
        if not page or next_offset is None:
            break
        offset = next_offset
    return modules


def _resolve_github_tarball(module: Dict[str, Any]) -> Optional[str]:
    """Resolve a module's registry download pointer to a codeload tarball URL."""
    path = "/".join(
        urllib.parse.quote(str(module[key]))
        for key in ("namespace", "name", "provider", "version")
    )
    with _http_get(f"{REGISTRY}/{path}/download") as response:
        get_header = response.headers.get("X-Terraform-Get", "")
    match = _GITHUB_GET_RE.search(get_header)
    if not match:
        return None
    owner, repo, ref = match.group("owner"), match.group("repo"), match.group("ref")
    return f"https://codeload.github.com/{owner}/{repo}/tar.gz/{urllib.parse.quote(ref)}"


def _iter_module_tf_members(tar: tarfile.TarFile) -> Iterator[tarfile.TarInfo]:
    """Yield regular ``*.tf`` members that belong to the module proper."""
    for member in tar:
        if not member.isreg() or not member.name.endswith(".tf"):
            continue
        if member.size == 0 or member.size > MAX_TF_FILE_BYTES:
            continue
        parts = Path(member.name).parts
        if any(part in SKIP_DIR_PARTS for part in parts):
            continue
        if any(part.startswith("..") or ":" in part for part in parts):
            continue
        yield member


def _store_module_tf_files(tarball: bytes, dest_dir: Path) -> int:
    """Write the module's ``.tf`` files under ``dest_dir``; return files kept."""
    kept = 0
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        for member in _iter_module_tf_members(tar):
            handle = tar.extractfile(member)
            if handle is None:
                continue
            # Drop the "<repo>-<ref>/" archive prefix, keep the inner layout.
            relative = Path(*Path(member.name).parts[1:])
            target = dest_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(handle.read())
            kept += 1
    return kept


def cmd_collect(args: argparse.Namespace) -> int:
    """Download top registry modules into the corpus directory."""
    corpus_dir = Path(args.corpus_dir)
    modules_dir = corpus_dir / "modules"
    modules_dir.mkdir(parents=True, exist_ok=True)

    namespaces = [ns.strip() for ns in args.namespaces.split(",") if ns.strip()]
    print(f"Listing AWS modules from namespaces: {', '.join(namespaces)}")
    listed: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for namespace in namespaces:
        for module in _list_namespace_modules(namespace):
            listed[(module["namespace"], module["name"])] = module
    ranked = sorted(listed.values(), key=lambda m: m.get("downloads", 0), reverse=True)
    ranked = ranked[: args.max_modules]
    print(f"Found {len(listed)} modules; downloading top {len(ranked)} by downloads")

    manifest: List[Dict[str, Any]] = []
    failed = 0
    for index, module in enumerate(ranked, start=1):
        label = f"{module['namespace']}/{module['name']}@{module['version']}"
        dest = modules_dir / f"{module['namespace']}__{module['name']}"
        try:
            tarball_url = _resolve_github_tarball(module)
            if tarball_url is None:
                raise RuntimeError("no GitHub source resolved from registry")
            with _http_get(tarball_url, timeout=60) as response:
                kept = _store_module_tf_files(response.read(), dest)
            manifest.append({
                "namespace": module["namespace"],
                "name": module["name"],
                "version": module["version"],
                "downloads": module.get("downloads", 0),
                "tf_files": kept,
            })
            print(f"  [{index}/{len(ranked)}] {label}: {kept} .tf files")
        except (RuntimeError, tarfile.TarError, OSError) as exc:
            failed += 1
            print(f"  [{index}/{len(ranked)}] {label}: SKIPPED ({exc})")
        time.sleep(args.sleep)

    total_files = sum(entry["tf_files"] for entry in manifest)
    (corpus_dir / "manifest.json").write_text(
        json.dumps({"modules": manifest, "failed": failed, "tf_files": total_files}, indent=2),
        encoding="utf-8",
    )
    print(f"Collected {len(manifest)} modules ({total_files} .tf files, {failed} skipped) "
          f"-> {modules_dir}")
    if not manifest:
        print("ERROR: no modules collected", file=sys.stderr)
        return 1
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    """Extract the 8-dim structural feature vector from every corpus file."""
    corpus_dir = Path(args.corpus_dir)
    tf_files = sorted((corpus_dir / "modules").rglob("*.tf"))
    if not tf_files:
        print(f"ERROR: no .tf files under {corpus_dir / 'modules'} - run collect first",
              file=sys.stderr)
        return 1

    parser = HCLParser()
    extractor = StructuralFeatureExtractor()
    rows: List[np.ndarray] = []
    parse_failures = 0
    resource_free = 0
    for tf_file in tf_files:
        try:
            tf_content, raw_content = parser.parse(str(tf_file))
        except TerraformParseError:
            parse_failures += 1
            continue
        vector = extractor.extract(tf_content, raw_content)
        if vector[0, 0] < 1:  # resource_count: keep only files that declare resources
            resource_free += 1
            continue
        rows.append(vector)

    if not rows:
        print("ERROR: extracted zero feature vectors", file=sys.stderr)
        return 1

    features = np.vstack(rows)
    lower = np.array([bound[0] for bound in FEATURE_BOUNDS])
    upper = np.array([bound[1] for bound in FEATURE_BOUNDS])
    features = np.clip(features, lower, upper)

    features_path = corpus_dir / "features.npy"
    np.save(features_path, features)
    meta = {
        "tf_files_seen": len(tf_files),
        "vectors_kept": int(features.shape[0]),
        "resource_free_files": resource_free,
        "parse_failures": parse_failures,
        "feature_stats": {
            name: {
                "min": round(float(features[:, i].min()), 3),
                "mean": round(float(features[:, i].mean()), 3),
                "max": round(float(features[:, i].max()), 3),
            }
            for i, name in enumerate(FEATURE_NAMES)
        },
    }
    (corpus_dir / "features_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"Scanned {len(tf_files)} .tf files: kept {features.shape[0]} vectors "
          f"({resource_free} resource-free, {parse_failures} parse failures)")
    print(f"{'feature':<28}{'min':>10}{'mean':>10}{'max':>10}")
    for name, stats in meta["feature_stats"].items():
        print(f"{name:<28}{stats['min']:>10}{stats['mean']:>10}{stats['max']:>10}")
    print(f"Saved {features_path}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    """Refit the model on synthetic baseline + real corpus features."""
    features_path = Path(args.corpus_dir) / "features.npy"
    if not features_path.exists():
        print(f"ERROR: {features_path} not found - run extract first", file=sys.stderr)
        return 1
    corpus_features = np.load(features_path)
    print(f"Loaded {corpus_features.shape[0]} corpus vectors from {features_path}")

    manager = ModelManager(model_dir=args.model_dir)
    if not manager.model_exists():
        print("No existing model - training the synthetic secure baseline first")
        MLPredictor(manager)  # bootstraps and persists the 300-sample baseline
    baseline_size = 0
    if manager.training_data_path.exists():
        baseline_size = int(np.load(manager.training_data_path).shape[0])

    model = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_estimators=150,
        max_samples="auto",
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
    )
    metadata: Dict[str, Any] = {
        "training_source": "synthetic secure baseline + Terraform Registry corpus",
        "corpus_vectors": int(corpus_features.shape[0]),
        "feature_names": list(FEATURE_NAMES),
        "model_parameters": {"contamination": 0.1, "n_estimators": 150, "random_state": 42},
    }
    manifest_path = Path(args.corpus_dir) / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        metadata["corpus_modules"] = len(manifest.get("modules", []))

    manager.update_model_with_feedback(model, StandardScaler(), corpus_features, metadata)

    # update_model_with_feedback logs-and-continues on failure; verify the save.
    expected_total = baseline_size + corpus_features.shape[0]
    saved = json.loads(manager.metadata_path.read_text(encoding="utf-8"))
    if saved.get("total_samples") != expected_total:
        print(f"ERROR: model save not verified (expected total_samples={expected_total}, "
              f"metadata says {saved.get('total_samples')})", file=sys.stderr)
        return 1
    print(f"Model version {manager.get_current_version()} trained on "
          f"{expected_total} samples ({baseline_size} baseline + "
          f"{corpus_features.shape[0]} corpus) -> {manager.model_dir}")
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    """Run collect, extract, and train in sequence."""
    for step in (cmd_collect, cmd_extract, cmd_train):
        code = step(args)
        if code != 0:
            return code
    return 0


def main() -> int:
    """Parse arguments and dispatch to the selected pipeline phase."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("collect", "extract", "train", "all"))
    parser.add_argument("--corpus-dir", default="corpus",
                        help="corpus working directory (default: ./corpus)")
    parser.add_argument("--model-dir", default="models",
                        help="model output directory (default: ./models)")
    parser.add_argument("--namespaces", default=",".join(DEFAULT_NAMESPACES),
                        help="comma-separated registry namespaces to pull from")
    parser.add_argument("--max-modules", type=int, default=400,
                        help="maximum number of modules to download (default: 400)")
    parser.add_argument("--sleep", type=float, default=0.15,
                        help="pause between module downloads in seconds")
    args = parser.parse_args()
    dispatch = {"collect": cmd_collect, "extract": cmd_extract,
                "train": cmd_train, "all": cmd_all}
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
