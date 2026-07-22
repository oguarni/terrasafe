#!/usr/bin/env bash
# Fuzz exactly ONE built target for a bounded wall-clock budget, then triage it
# and publish the per-target result immediately.
#
# Three properties this file exists to guarantee:
#
#  1. PER-TARGET BUDGET. `timeout` wraps libFuzzer's own -max_total_time, so a
#     target that ignores or outlives its budget still loses its slot. One
#     stubborn target cannot consume the run (the A.3 post-mortem failure mode).
#
#  2. KEEP FUZZING PAST THE FIRST CRASH. libFuzzer normally exits on crash #1,
#     which would cap every target's yield at one bug and make "bugs found" a
#     meaningless baseline. Fork mode with -ignore_crashes/-ignore_timeouts/
#     -ignore_ooms keeps the campaign alive and accumulates every artifact.
#     -fork=1 means exactly one concurrent child, i.e. one core per target, so
#     CPU-time stays attributable per target.
#
#  3. RESULTS ARE PUBLISHED PER TARGET, NOT AT THE END. The moment triage
#     finishes, the JSON goes to GCS. A run killed by the duration cap or by
#     credit expiry still leaves every completed target's baseline behind.
#
# Usage: fuzz_target.sh <build.json> <run-root> <budget-seconds>
set -uo pipefail

BUILD_JSON="$1"
RUN_ROOT="$2"
BUDGET="$3"

FUZZ_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=fuzz_env.sh
. "${FUZZ_HOME}/fuzz_env.sh"

read -r TARGET BIN SEEDS < <(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(d["target"], d["binary"], d["seeds_dir"])
' "${BUILD_JSON}")

ART="${RUN_ROOT}/artifacts/${TARGET}"
CORPUS="${RUN_ROOT}/corpus/${TARGET}"
LOG="${RUN_ROOT}/logs/${TARGET}.fuzz.log"
COV_LOG="${RUN_ROOT}/logs/${TARGET}.cov.log"
CPU_FILE="${RUN_ROOT}/logs/${TARGET}.cpu.txt"
RESULT="${RUN_ROOT}/results/${TARGET}.json"
mkdir -p "${ART}" "${CORPUS}" "${RUN_ROOT}/logs" "${RUN_ROOT}/results"

export ASAN_OPTIONS="${TV_ASAN_OPTIONS}"
export UBSAN_OPTIONS="${TV_UBSAN_OPTIONS}"

LIBFUZZER_COMMON=(
  -artifact_prefix="${ART}/"
  -max_total_time="${BUDGET}"
  -rss_limit_mb=2048
  -malloc_limit_mb=2048
  -timeout=25
  -max_len=65536
  -print_final_stats=1
)

START_EPOCH="$(date +%s)"
timeout -s TERM -k 30 "$((BUDGET + 120))" \
  /usr/bin/time -f '%U %S %e' -o "${CPU_FILE}" \
  "${BIN}" "${CORPUS}" "${SEEDS}" \
  -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
  "${LIBFUZZER_COMMON[@]}" > "${LOG}" 2>&1
END_EPOCH="$(date +%s)"

# Fork mode is the only part of libFuzzer this pipeline depends on that is not
# universally exercised. If it produced no iterations at all, fall back to the
# plain single-process loop rather than reporting a false zero-yield target.
if ! grep -qE '^#[0-9]+' "${LOG}" && [ "$((END_EPOCH - START_EPOCH))" -lt "$((BUDGET / 2))" ]; then
  tv_log "${TARGET}: fork mode produced no iterations, retrying single-process"
  mv -f "${LOG}" "${LOG}.forkfail" 2>/dev/null
  START_EPOCH="$(date +%s)"
  timeout -s TERM -k 30 "$((BUDGET + 120))" \
    /usr/bin/time -f '%U %S %e' -o "${CPU_FILE}" \
    "${BIN}" "${CORPUS}" "${SEEDS}" "${LIBFUZZER_COMMON[@]}" > "${LOG}" 2>&1
  END_EPOCH="$(date +%s)"
fi

# Edge coverage: replay the whole accumulated corpus with zero mutation. This
# reads the number straight out of libFuzzer's INITED line and is independent of
# whether the campaign ran in fork mode.
timeout -s TERM -k 15 180 "${BIN}" -runs=0 -print_final_stats=1 \
  "${CORPUS}" "${SEEDS}" > "${COV_LOG}" 2>&1 || true

python3 "${FUZZ_HOME}/triage_crashes.py" \
  --build-json "${BUILD_JSON}" \
  --binary "${BIN}" \
  --artifacts-dir "${ART}" \
  --corpus-dir "${CORPUS}" \
  --fuzz-log "${LOG}" \
  --coverage-log "${COV_LOG}" \
  --cpu-file "${CPU_FILE}" \
  --start-epoch "${START_EPOCH}" \
  --end-epoch "${END_EPOCH}" \
  --budget-seconds "${BUDGET}" \
  --out "${RESULT}"

# Publish this target the instant it is done — never wait for the run to end.
if [ -n "${TV_LIVE_DST:-}" ]; then
  gsutil -q cp "${RESULT}" "${TV_LIVE_DST}/results/" 2>/dev/null || true
  gsutil -q cp -r "${ART}" "${TV_LIVE_DST}/artifacts/" 2>/dev/null || true
fi

echo "fuzz ${TARGET}: done (${BUDGET}s budget)"
exit 0
