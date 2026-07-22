#!/usr/bin/env bash
# Build exactly ONE benchmark target and record the outcome as JSON.
#
# One process per target, invoked in parallel by run_baseline.sh. A target that
# fails to fetch, configure or compile writes status="build-failed" and returns
# 0 — a single dead upstream URL or a modern-clang rejection must never abort
# the run, because partial coverage of the benchmark is still a usable baseline.
#
# Usage: build_target.sh <recipe.sh> <work-root> <bin-dir> <seed-root> <status-dir>
set -uo pipefail

RECIPE="$1"
WORK_ROOT="$2"
BIN_DIR="$3"
SEED_ROOT="$4"
STATUS_DIR="$5"

FUZZ_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_DIR="${FUZZ_HOME}/harnesses"
NPROC="${TV_BUILD_JOBS:-4}"
export HARNESS_DIR NPROC

# shellcheck source=fuzz_env.sh
. "${FUZZ_HOME}/fuzz_env.sh"
# shellcheck disable=SC1090
. "${RECIPE}"

WORKDIR="${WORK_ROOT}/${TARGET_ID}"
SEEDS_DIR="${SEED_ROOT}/${TARGET_ID}"
OUT_BIN="${BIN_DIR}/${TARGET_ID}"
BUILD_LOG="${STATUS_DIR}/${TARGET_ID}.build.log"
export WORKDIR SEEDS_DIR OUT_BIN

rm -rf "${WORKDIR}"
mkdir -p "${WORKDIR}" "${SEEDS_DIR}" "${BIN_DIR}" "${STATUS_DIR}"

# Configure scripts compile and RUN small test programs. Those test programs are
# ASan-instrumented here, and a LeakSanitizer report at their exit makes them
# exit non-zero, which silently makes ./configure misdetect features. Leak
# detection is re-enabled for the actual fuzzing (see fuzz_target.sh).
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:allocator_may_return_null=1"

started="$(date +%s)"
(
  set -e
  cd "${WORKDIR}"
  tv_build
) > "${BUILD_LOG}" 2>&1
build_rc=$?
elapsed=$(( $(date +%s) - started ))

if [ "${build_rc}" -eq 0 ] && [ -x "${OUT_BIN}" ]; then
  status="built"
  tv_seed >> "${BUILD_LOG}" 2>&1 || true
else
  status="build-failed"
fi

# Keep only the tail of a failed build log: enough to diagnose, small enough
# that the heartbeat can afford to ship it to GCS every few minutes.
tail -n 60 "${BUILD_LOG}" > "${BUILD_LOG}.tail" 2>/dev/null
mv -f "${BUILD_LOG}.tail" "${BUILD_LOG}" 2>/dev/null

python3 - "$STATUS_DIR/$TARGET_ID.build.json" <<PY
import json, sys
json.dump({
    "target": "${TARGET_ID}",
    "kind": "${TARGET_KIND}",
    "source_url": "${TARGET_SOURCE_URL}",
    "known_bug_reference": """${TARGET_KNOWN_BUG}""",
    "status": "${status}",
    "build_rc": ${build_rc},
    "build_seconds": ${elapsed},
    "binary": "${OUT_BIN}",
    "seeds_dir": "${SEEDS_DIR}",
}, open(sys.argv[1], "w"), indent=2)
PY

echo "build ${TARGET_ID}: ${status} in ${elapsed}s"
exit 0
