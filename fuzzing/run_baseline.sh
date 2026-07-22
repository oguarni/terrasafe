#!/usr/bin/env bash
# Track B Stage 0 orchestrator: build every benchmark target, fuzz them in
# parallel under a bounded budget, gate every crash, and keep the rolled-up
# baseline continuously fresh on disk.
#
# Runs on the VM (see scripts/gcp_fuzz_baseline.sh), but has no GCP dependency
# beyond the optional TV_LIVE_DST upload, so it is runnable locally for a
# smoke test.
#
# DEADLINE-DRIVEN, not schedule-driven. TV_BUDGET_MIN is the only hard number;
# everything else is derived from what is left after the previous phase. The
# per-target fuzz budget shrinks automatically if the builds ran long, so the
# triage reserve is never eaten and the run always reaches a written report.
#
# Usage: run_baseline.sh <run-root> <run-id>
set -uo pipefail

FUZZ_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_ROOT="${1:-/opt/fuzz-run}"
RUN_ID="${2:-local}"

BUDGET_MIN="${TV_BUDGET_MIN:-100}"          # whole orchestration, minutes
PER_BUILD_TIMEOUT="${TV_PER_BUILD_TIMEOUT:-420}"
BUILD_CONCURRENCY="${TV_BUILD_CONCURRENCY:-4}"
export TV_BUILD_JOBS="${TV_BUILD_JOBS:-4}"
TRIAGE_RESERVE_SEC="${TV_TRIAGE_RESERVE_SEC:-780}"
FUZZ_SECONDS_CAP="${TV_FUZZ_SECONDS:-1800}"
FUZZ_SLOTS="${TV_FUZZ_SLOTS:-$(nproc)}"
MIN_FUZZ_SECONDS=60

STATUS_FILE="${RUN_ROOT}/status.txt"
START_EPOCH="$(date +%s)"
DEADLINE_EPOCH=$(( START_EPOCH + BUDGET_MIN * 60 ))

mkdir -p "${RUN_ROOT}"/{bin,work,seeds,status,logs,results,artifacts,corpus}

mark() {
  printf '%s phase=%s %s\n' "$(date -u +%FT%TZ)" "$1" "${2:-}" >> "${STATUS_FILE}"
  echo ">> phase=$1 ${2:-}"
}

# Bounded job pool over an EXPLICIT pid list. The obvious `jobs -rp` + bare
# `wait` version deadlocks here: the background aggregator below is also a child,
# so a bare `wait` would block until a loop that never exits, exits.
POOL_PIDS=()

pool_reset() { POOL_PIDS=(); }

pool_alive() {
  local alive=() pid
  for pid in ${POOL_PIDS[@]+"${POOL_PIDS[@]}"}; do
    if kill -0 "${pid}" 2>/dev/null; then alive+=("${pid}"); fi
  done
  POOL_PIDS=(${alive[@]+"${alive[@]}"})
  echo "${#POOL_PIDS[@]}"
}

pool_wait_for_slot() {
  local limit="$1"
  while [ "$(pool_alive)" -ge "${limit}" ]; do sleep 2; done
}

pool_drain() {
  local pid
  for pid in ${POOL_PIDS[@]+"${POOL_PIDS[@]}"}; do wait "${pid}" 2>/dev/null; done
  pool_reset
}

aggregate_now() {
  python3 "${FUZZ_HOME}/aggregate_baseline.py" \
    --run-root "${RUN_ROOT}" --run-id "${RUN_ID}" >/dev/null 2>&1
}

mark start "budget_min=${BUDGET_MIN} slots=${FUZZ_SLOTS} deadline=$(date -u -d "@${DEADLINE_EPOCH}" +%FT%TZ)"

# Keep the rolled-up report current so the launcher's heartbeat always has a
# fresh, complete-so-far baseline to ship, whatever moment the VM dies at.
( while sleep 120; do aggregate_now; done ) &
AGGREGATOR_PID=$!

# --- phase 1: build --------------------------------------------------------
mark build
pool_reset
for recipe in "${FUZZ_HOME}"/targets/*.sh; do
  pool_wait_for_slot "${BUILD_CONCURRENCY}"
  timeout -s TERM -k 30 "${PER_BUILD_TIMEOUT}" \
    "${FUZZ_HOME}/build_target.sh" "${recipe}" \
    "${RUN_ROOT}/work" "${RUN_ROOT}/bin" "${RUN_ROOT}/seeds" "${RUN_ROOT}/status" &
  POOL_PIDS+=("$!")
done
pool_drain
aggregate_now
mark build-done "built=$(ls -1 "${RUN_ROOT}/bin" 2>/dev/null | wc -l)"

# Source trees are only needed for the build; drop them so a stopped VM's disk
# stays cheap and the artifact upload stays small.
rm -rf "${RUN_ROOT}/work" 2>/dev/null

# --- phase 2: derive the per-target budget from what is actually left -------
BUILT_JSONS=()
while IFS= read -r path; do BUILT_JSONS+=("${path}"); done < <(
  grep -l '"status": "built"' "${RUN_ROOT}/status"/*.build.json 2>/dev/null | sort
)
BUILT_COUNT="${#BUILT_JSONS[@]}"

if [ "${BUILT_COUNT}" -eq 0 ]; then
  mark abort "no target built"
  kill "${AGGREGATOR_PID}" 2>/dev/null
  aggregate_now
  exit 0
fi

WAVES=$(( (BUILT_COUNT + FUZZ_SLOTS - 1) / FUZZ_SLOTS ))
REMAINING=$(( DEADLINE_EPOCH - $(date +%s) - TRIAGE_RESERVE_SEC ))
PER_TARGET_BUDGET=$(( REMAINING / (WAVES > 0 ? WAVES : 1) ))
[ "${PER_TARGET_BUDGET}" -gt "${FUZZ_SECONDS_CAP}" ] && PER_TARGET_BUDGET="${FUZZ_SECONDS_CAP}"
[ "${PER_TARGET_BUDGET}" -lt "${MIN_FUZZ_SECONDS}" ] && PER_TARGET_BUDGET="${MIN_FUZZ_SECONDS}"

mark fuzz "targets=${BUILT_COUNT} waves=${WAVES} budget_s=${PER_TARGET_BUDGET}"

# --- phase 3: fuzz + gate, one process per target ---------------------------
pool_reset
for build_json in "${BUILT_JSONS[@]}"; do
  pool_wait_for_slot "${FUZZ_SLOTS}"
  "${FUZZ_HOME}/fuzz_target.sh" "${build_json}" "${RUN_ROOT}" "${PER_TARGET_BUDGET}" &
  POOL_PIDS+=("$!")
done
pool_drain

# --- phase 4: final roll-up -------------------------------------------------
kill "${AGGREGATOR_PID}" 2>/dev/null
mark aggregate
python3 "${FUZZ_HOME}/aggregate_baseline.py" --run-root "${RUN_ROOT}" --run-id "${RUN_ID}"
mark done "elapsed_s=$(( $(date +%s) - START_EPOCH ))"
