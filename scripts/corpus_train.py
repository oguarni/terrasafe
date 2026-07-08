#!/usr/bin/env python3
"""Train the Isolation Forest on structural features from real Terraform modules.

This implements the "future work" noted in ``terravault/infrastructure/CLAUDE_ML.md``:
replace the purely synthetic secure baseline with structural features extracted
from a corpus of real, well-maintained Terraform modules pulled from the public
Terraform Registry.

Pipeline (each phase is a subcommand; ``all`` chains them):

  collect       Download registry AWS modules into ``corpus/`` (only ``*.tf``
                files are kept). Default: curated namespaces; with
                ``--registry-wide`` every AWS-provider module in the registry
                is listed and ranked by downloads.
  github-fetch  Materialise ``.tf`` blobs exported from the BigQuery public
                GitHub dataset (newline-delimited JSON shards, optionally
                gzipped) into ``corpus/modules/github/``.
  extract       Parse every collected ``.tf`` file with the production
                ``HCLParser`` and run ``StructuralFeatureExtractor`` - the
                exact inference-time code path - keeping one 8-dim vector per
                file that declares at least one resource. Deduplicates files
                by content hash first. Saves ``corpus/features.npy``.
  train         Stack the real vectors onto the persisted synthetic baseline
                via ``ModelManager.update_model_with_feedback()`` (the
                documented no-catastrophic-forgetting path) and save a new
                model version.

Run from the repository root (the parser's path-traversal guard only allows
files under the current working directory).

Examples:
    python scripts/corpus_train.py collect --max-modules 400
    python scripts/corpus_train.py collect --registry-wide --max-modules 12000 --workers 16
    python scripts/corpus_train.py github-fetch --shards-dir corpus/github_shards
    python scripts/corpus_train.py extract --workers 0
    python scripts/corpus_train.py train --source-label "baseline + registry-wide + GitHub"
    python scripts/corpus_train.py all --max-modules 400
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import signal
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
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

# Wild-corpus guard: real-world GitHub files exist whose HCL parse effectively
# never terminates (observed: 2 files pinning a core for an hour). Each file
# gets this many seconds before it is skipped as a parse failure.
PARSE_TIMEOUT_SECONDS = 15
_HAS_ALARM = hasattr(signal, "SIGALRM")  # SIGALRM is Unix-only

_GITHUB_GET_RE = re.compile(
    r"git::https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/?]+?)(?:\.git)?"
    r"(?://[^?]*)?\?ref=(?P<ref>[^&]+)"
)


def _http_get(url: str, timeout: int = 30, retries: int = 2) -> Any:
    """GET with a UA header and simple retry/backoff on transient failures.

    Client errors other than 429 (e.g. a module whose GitHub repo was deleted)
    fail immediately - retrying a 404 just slows large collections down.
    """
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            return urllib.request.urlopen(request, timeout=timeout)  # nosec B310 - https URLs only
        except urllib.error.HTTPError as exc:
            if exc.code != 429 and exc.code < 500:
                raise RuntimeError(f"GET {url} failed: HTTP {exc.code}") from exc
            last_error = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
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


def _list_all_aws_modules(page_cap: int = 400) -> List[Dict[str, Any]]:
    """Return every AWS-provider module in the registry (global listing)."""
    modules: List[Dict[str, Any]] = []
    offset = 0
    for _ in range(page_cap):
        url = f"{REGISTRY}?provider=aws&limit=100&offset={offset}"
        with _http_get(url) as response:
            payload = json.load(response)
        page = payload.get("modules", [])
        modules.extend(page)
        next_offset = payload.get("meta", {}).get("next_offset")
        if not page or next_offset is None:
            break
        offset = next_offset
        time.sleep(0.05)
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


def _collect_one(module: Dict[str, Any], modules_dir: Path) -> Dict[str, Any]:
    """Download one module's tarball and return its manifest entry."""
    dest = modules_dir / f"{module['namespace']}__{module['name']}"
    tarball_url = _resolve_github_tarball(module)
    if tarball_url is None:
        raise RuntimeError("no GitHub source resolved from registry")
    with _http_get(tarball_url, timeout=90, retries=3) as response:
        kept = _store_module_tf_files(response.read(), dest)
    return {
        "namespace": module["namespace"],
        "name": module["name"],
        "version": module["version"],
        "downloads": module.get("downloads", 0),
        "tf_files": kept,
    }


def cmd_collect(args: argparse.Namespace) -> int:
    """Download registry modules (curated or registry-wide) into the corpus."""
    corpus_dir = Path(args.corpus_dir)
    modules_dir = corpus_dir / "modules"
    modules_dir.mkdir(parents=True, exist_ok=True)

    listed: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if args.registry_wide:
        print("Listing every AWS-provider module in the Terraform Registry")
        for module in _list_all_aws_modules():
            listed[(module["namespace"], module["name"])] = module
    else:
        namespaces = [ns.strip() for ns in args.namespaces.split(",") if ns.strip()]
        print(f"Listing AWS modules from namespaces: {', '.join(namespaces)}")
        for namespace in namespaces:
            for module in _list_namespace_modules(namespace):
                listed[(module["namespace"], module["name"])] = module
    ranked = sorted(listed.values(), key=lambda m: m.get("downloads", 0), reverse=True)
    ranked = ranked[: args.max_modules]
    workers = args.workers if args.workers > 0 else min(16, (os.cpu_count() or 4) * 4)
    print(f"Found {len(listed)} modules; downloading top {len(ranked)} by downloads "
          f"({workers} workers)")

    manifest: List[Dict[str, Any]] = []
    failed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_collect_one, module, modules_dir): module for module in ranked}
        for index, future in enumerate(as_completed(futures), start=1):
            module = futures[future]
            label = f"{module['namespace']}/{module['name']}@{module['version']}"
            try:
                manifest.append(future.result())
                print(f"  [{index}/{len(ranked)}] {label}: {manifest[-1]['tf_files']} .tf files")
            except (RuntimeError, tarfile.TarError, OSError) as exc:
                failed += 1
                print(f"  [{index}/{len(ranked)}] {label}: SKIPPED ({exc})")

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


_BLOB_ID_RE = re.compile(r"[0-9a-f]{40}")


def cmd_github_fetch(args: argparse.Namespace) -> int:
    """Materialise BigQuery-exported GitHub ``.tf`` blobs into the corpus."""
    corpus_dir = Path(args.corpus_dir)
    shards_dir = Path(args.shards_dir)
    shards = sorted(
        path for path in shards_dir.rglob("*")
        if path.is_file() and path.name.endswith((".json", ".json.gz", ".jsonl", ".jsonl.gz"))
    )
    if not shards:
        print(f"ERROR: no JSONL shards under {shards_dir}", file=sys.stderr)
        return 1

    dest_dir = corpus_dir / "modules" / "github"
    dest_dir.mkdir(parents=True, exist_ok=True)
    kept = 0
    skipped = 0
    for shard in shards:
        opener = gzip.open if shard.name.endswith(".gz") else open
        with opener(shard, "rt", encoding="utf-8") as handle:  # type: ignore[operator]
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                blob_id = str(row.get("id", ""))
                content = row.get("content")
                if (not content or not _BLOB_ID_RE.fullmatch(blob_id)
                        or len(content.encode("utf-8")) > MAX_TF_FILE_BYTES):
                    skipped += 1
                    continue
                (dest_dir / f"{blob_id}.tf").write_text(content, encoding="utf-8")
                kept += 1
    (corpus_dir / "github_manifest.json").write_text(
        json.dumps({"shards": len(shards), "blobs_kept": kept, "blobs_skipped": skipped},
                   indent=2),
        encoding="utf-8",
    )
    print(f"Materialised {kept} GitHub blobs ({skipped} skipped) from {len(shards)} shards "
          f"-> {dest_dir}")
    if not kept:
        print("ERROR: no GitHub blobs materialised", file=sys.stderr)
        return 1
    return 0


# Per-process state for parallel extraction; built once per worker so every
# file goes through the exact production parser + extractor code path.
_EXTRACT_STATE: Dict[str, Any] = {}


class _ParseTimeout(Exception):
    """Raised via SIGALRM when one file's parse exceeds PARSE_TIMEOUT_SECONDS."""


def _alarm_handler(signum: int, frame: Any) -> None:  # pylint: disable=unused-argument
    """SIGALRM handler: abort the current file's parse."""
    _EXTRACT_STATE["timed_out"] = True
    raise _ParseTimeout()


def _extract_worker_init() -> None:
    """Initialise the production parser + extractor in a worker process."""
    _EXTRACT_STATE["parser"] = HCLParser()
    _EXTRACT_STATE["extractor"] = StructuralFeatureExtractor()
    if _HAS_ALARM:
        signal.signal(signal.SIGALRM, _alarm_handler)


def _extract_one(path_str: str) -> Tuple[str, Optional[List[float]]]:
    """Parse one file; return ``(status, vector-or-None)``.

    The parser's internal broad except can swallow ``_ParseTimeout`` and
    re-raise it as ``TerraformParseError``, so the timeout flag - not the
    exception type - decides how a failure is reported.
    """
    if _HAS_ALARM:
        _EXTRACT_STATE["timed_out"] = False
        signal.alarm(PARSE_TIMEOUT_SECONDS)
    try:
        tf_content, raw_content = _EXTRACT_STATE["parser"].parse(path_str)
        vector = _EXTRACT_STATE["extractor"].extract(tf_content, raw_content)
    except (TerraformParseError, _ParseTimeout):
        if _EXTRACT_STATE.get("timed_out"):
            print(f"  TIMEOUT >{PARSE_TIMEOUT_SECONDS}s: {path_str}", flush=True)
        return ("parse_failure", None)
    finally:
        if _HAS_ALARM:
            signal.alarm(0)
    if vector[0, 0] < 1:  # resource_count: keep only files that declare resources
        return ("resource_free", None)
    return ("kept", vector[0].tolist())


def _dedup_by_content(tf_files: List[Path]) -> Tuple[List[Path], int, int]:
    """Drop empty/oversize files and content-hash duplicates."""
    unique_files: List[Path] = []
    seen: set = set()
    duplicates = 0
    unreadable = 0
    for tf_file in tf_files:
        try:
            data = tf_file.read_bytes()
        except OSError:
            unreadable += 1
            continue
        if not data or len(data) > MAX_TF_FILE_BYTES:
            unreadable += 1
            continue
        digest = hashlib.sha256(data).digest()
        if digest in seen:
            duplicates += 1
            continue
        seen.add(digest)
        unique_files.append(tf_file)
    return unique_files, duplicates, unreadable


def cmd_extract(args: argparse.Namespace) -> int:
    """Extract the 8-dim structural feature vector from every corpus file."""
    corpus_dir = Path(args.corpus_dir)
    tf_files = sorted((corpus_dir / "modules").rglob("*.tf"))
    if not tf_files:
        print(f"ERROR: no .tf files under {corpus_dir / 'modules'} - run collect first",
              file=sys.stderr)
        return 1

    unique_files, duplicates, unreadable = _dedup_by_content(tf_files)
    workers = args.workers if args.workers > 0 else (os.cpu_count() or 1)
    print(f"Scanning {len(unique_files)} unique .tf files "
          f"({duplicates} duplicates, {unreadable} empty/oversize/unreadable skipped; "
          f"{workers} workers)")

    github_root = corpus_dir / "modules" / "github"
    rows: List[List[float]] = []
    stats: Dict[str, Dict[str, int]] = {
        "registry": {"kept": 0, "parse_failure": 0, "resource_free": 0},
        "github": {"kept": 0, "parse_failure": 0, "resource_free": 0},
    }
    path_strings = [str(path) for path in unique_files]
    if workers == 1:
        _extract_worker_init()
        results = map(_extract_one, path_strings)
    else:
        pool = ProcessPoolExecutor(max_workers=workers, initializer=_extract_worker_init)
        results = pool.map(_extract_one, path_strings,
                           chunksize=max(1, len(path_strings) // (workers * 8)))
    for index, (tf_file, (status, payload)) in enumerate(zip(unique_files, results), start=1):
        source = "github" if github_root in tf_file.parents else "registry"
        stats[source][status] += 1
        if payload is not None:
            rows.append(payload)
        if index % 5000 == 0:
            print(f"  ... {index}/{len(unique_files)} files ({len(rows)} vectors so far)",
                  flush=True)
    if workers != 1:
        pool.shutdown()

    if not rows:
        print("ERROR: extracted zero feature vectors", file=sys.stderr)
        return 1

    features = np.array(rows, dtype=np.float64)
    lower = np.array([bound[0] for bound in FEATURE_BOUNDS])
    upper = np.array([bound[1] for bound in FEATURE_BOUNDS])
    features = np.clip(features, lower, upper)

    parse_failures = sum(s["parse_failure"] for s in stats.values())
    resource_free = sum(s["resource_free"] for s in stats.values())
    features_path = corpus_dir / "features.npy"
    np.save(features_path, features)
    meta = {
        "tf_files_seen": len(tf_files),
        "unique_files": len(unique_files),
        "duplicates_skipped": duplicates,
        "empty_oversize_unreadable": unreadable,
        "vectors_kept": int(features.shape[0]),
        "resource_free_files": resource_free,
        "parse_failures": parse_failures,
        "by_source": stats,
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

    print(f"Scanned {len(tf_files)} .tf files ({len(unique_files)} unique): "
          f"kept {features.shape[0]} vectors "
          f"({resource_free} resource-free, {parse_failures} parse failures)")
    print(f"  registry: {stats['registry']}  github: {stats['github']}")
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
        "training_source": args.source_label,
        "corpus_vectors": int(corpus_features.shape[0]),
        "feature_names": list(FEATURE_NAMES),
        "model_parameters": {"contamination": 0.1, "n_estimators": 150, "random_state": 42},
    }
    manifest_path = Path(args.corpus_dir) / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        metadata["corpus_modules"] = len(manifest.get("modules", []))
    gh_manifest_path = Path(args.corpus_dir) / "github_manifest.json"
    if gh_manifest_path.exists():
        gh_manifest = json.loads(gh_manifest_path.read_text(encoding="utf-8"))
        metadata["github_blobs"] = gh_manifest.get("blobs_kept", 0)
    features_meta_path = Path(args.corpus_dir) / "features_meta.json"
    if features_meta_path.exists():
        features_meta = json.loads(features_meta_path.read_text(encoding="utf-8"))
        metadata["corpus_by_source"] = features_meta.get("by_source")

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
    parser.add_argument("command", choices=("collect", "github-fetch", "extract", "train", "all"))
    parser.add_argument("--corpus-dir", default="corpus",
                        help="corpus working directory (default: ./corpus)")
    parser.add_argument("--model-dir", default="models",
                        help="model output directory (default: ./models)")
    parser.add_argument("--namespaces", default=",".join(DEFAULT_NAMESPACES),
                        help="comma-separated registry namespaces to pull from")
    parser.add_argument("--registry-wide", action="store_true",
                        help="collect from every AWS-provider module in the registry")
    parser.add_argument("--max-modules", type=int, default=400,
                        help="maximum number of modules to download (default: 400)")
    parser.add_argument("--workers", type=int, default=0,
                        help="parallel workers for collect/extract (0 = auto)")
    parser.add_argument("--shards-dir", default="corpus/github_shards",
                        help="directory of BigQuery JSONL shards for github-fetch")
    parser.add_argument("--source-label",
                        default="synthetic secure baseline + Terraform Registry corpus",
                        help="training_source string recorded in model metadata")
    args = parser.parse_args()
    dispatch = {"collect": cmd_collect, "github-fetch": cmd_github_fetch,
                "extract": cmd_extract, "train": cmd_train, "all": cmd_all}
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
