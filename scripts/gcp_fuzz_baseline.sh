#!/usr/bin/env bash
# Launch Track B "Stage 0" — the PLAIN-FUZZING BASELINE — on GCP.
#
# ---------------------------------------------------------------------------
# WHY THIS JOB EXISTS
# ---------------------------------------------------------------------------
# Track B's thesis question is: "does an LLM layer over fuzzing+sanitizers
# measurably improve bug yield, time-to-reproduce, triage quality and patch
# correctness versus plain fuzzing?" That question is unanswerable without the
# denominator. The Track B plan is explicit about it:
#
#   "Stage 0 — Benchmark & baseline. [...] Establish a plain-fuzzing baseline
#    (bugs found, time-to-repro). Without this you cannot claim the LLM added
#    anything — the same discipline as TerraVault's ablation."
#
# This is deliberately the UN-AUGMENTED ARM. There is no LLM anywhere in this
# job, by design: hand-written libFuzzer harnesses, hand-written minimal seeds,
# no dictionaries, no mined corpora, no LLM triage. Adding any of that here
# would contaminate the very comparison the run exists to enable. TerraVault
# already learned this the expensive way — the ablation is the honest core of
# the static half, and the dynamic half gets the same treatment from day one.
#
# ---------------------------------------------------------------------------
# WHY THIS BENCHMARK (and not fuzzer-test-suite or Magma)
# ---------------------------------------------------------------------------
# The plan lists three candidates. The choice here is the third — a small set of
# historical, pinned, known-bug OSS targets — and the reasoning is availability,
# not ambition:
#
#   * google/fuzzer-test-suite is the nominal first choice and is the closest
#     thing to a standard. It has bit-rotted: its per-target build.sh scripts
#     fetch from hosts that have since moved or died (ftp.pcre.org, the old
#     xmlsoft FTP, several SourceForge paths), and a dead download inside an
#     unattended VM is a silent zero, which is the worst possible outcome for a
#     baseline. Its *design* is adopted here (one tiny harness per pinned
#     upstream release with a documented bug); its fetch layer is not.
#
#   * Magma has the richest ground truth (injected canaries give per-bug
#     reached/triggered counters) but is Docker-based and its full build is
#     hours of work before a single input is fuzzed. With a run window measured
#     in ~2 hours and credits expiring, Magma would spend the entire budget
#     building and bank nothing. It is the right choice for Stage 0 on PAID
#     compute; it is the wrong choice today.
#
#   * Therefore: 9 pinned pre-fix upstream releases (cJSON 1.7.10, TinyXML-2
#     6.0.0, Expat 2.1.0, libyaml 0.1.7, libxml2 2.9.2, SQLite 3.13.0,
#     libarchive 3.2.1, RE2 2017-06-01, c-ares 1.11.0), each with the CVE or
#     OSS-Fuzz issue it is known to contain recorded in its recipe, fetched
#     from GitHub release/archive URLs and download.gnome.org — hosts that were
#     verified live at authoring time. Each target is independently skippable:
#     a dead URL or a modern-clang rejection costs exactly one row of the table.
#     Ordered cheapest-first so the schedule degrades gracefully.
#
# Two synthetic gate-validation targets ride along (excluded from every headline
# number). They plant a known heap-overflow and a known use-after-free so the
# run proves, on its own evidence, that the crash -> dedup -> minimise -> replay
# gate actually fires. Without them a zero-yield result is ambiguous.
#
# AFL++ is deliberately NOT installed. The plan permits it "only if it does not
# blow the setup budget"; a second engine doubles the build matrix and the
# per-target scheduling for a baseline whose job is to establish a floor, not to
# compare engines. libFuzzer + ASan is the floor. AFL++ belongs in Stage 1.
#
# ---------------------------------------------------------------------------
# WHAT IT MEASURES (the numbers a later LLM arm must beat)
# ---------------------------------------------------------------------------
# Per target: crashes found, TIME-TO-FIRST-CRASH, unique crashes deduplicated by
# sanitizer stack signature, edge coverage reached, executed units, and CPU
# seconds spent. Every crash passes a hard reproducibility gate before it counts
# (sanitizer-confirmed + minimised + deterministically replayable).
#
# ---------------------------------------------------------------------------
# OPERATIONAL GUARDS (paid for twice on this project — see the plan's post-mortem)
# ---------------------------------------------------------------------------
#   1. PARALLEL: one fuzzing process per vCPU, targets run concurrently.
#   2. PER-UNIT TIMEOUT: every build has a hard `timeout`, every target has a
#      wall-clock fuzz budget, every replay and minimisation is bounded. No
#      single pathological target or input can pin the run.
#   3. HEARTBEAT: log, phase status, per-target JSON and the rolled-up report
#      stream to ${DST}/live/ every ~3 min, and each target publishes its own
#      result the instant it is triaged. THE RUN IS EXPECTED TO BE KILLED by the
#      duration cap or by credit expiry — results are uploaded as they are
#      produced, never only at the end.
#   4. --instance-termination-action=STOP, never DELETE. A previous run on this
#      project was a total loss because DELETE vaporised the VM before upload.
#
# COST SAFETY: the free credits expire 2026-07-22 and the billing account is
# live, so --max-run-duration is set to stop the VM well before then. Override
# with TV_MAX_RUN_MIN, but never raise it past the expiry. The VM STOPS rather
# than deletes, so it still accrues (small) persistent-disk cost until deleted —
# delete it after collecting.
#
# ---------------------------------------------------------------------------
# RUN 1 POST-MORTEM (fuzz-baseline-20260721-213507)
# ---------------------------------------------------------------------------
# All 11 targets built in ~2 minutes and c-ares reproduced CVE-2016-5180 exactly
# as predicted (hundreds of crash artifacts). The library targets are sound:
# expat reached 3547 edges, libxml2 3217.
#
# The two SYNTHETIC gate-validation targets, however, reported cov=1 and found
# nothing across 634 million executions. The cause was in the gate harnesses
# themselves, not in the toolchain: their planted bug operated on a heap buffer
# that never escaped the function, so at -O1 LLVM deleted the whole
# allocate/overflow/free sequence as dead code. Measured on the run's own VM,
# the same harness yields 5 inline 8-bit counters at -O0 and 1 at -O1/-O2 --
# there was simply no bug left in the binary to find. Fixed by publishing the
# pointer through a volatile file-scope global (see the harness comments).
#
# Two things this cost, both worth recording. First, a synthetic gate target is
# only a gate if the compiler cannot optimise its bug away, and that has to be
# verified, not assumed. Second, the gate DID do its job in the negative sense:
# it was the one signal that separated "the campaign is blind" from "the targets
# are clean", and without it run 1 would have looked like a plausible low-yield
# baseline. Keep it, and keep checking it first.
#
# Also tightened in fuzz_env.sh while diagnosing: FUZZ_CFLAGS (libraries, with
# -fsanitize=fuzzer-no-link) and FUZZ_HARNESS_FLAGS (harness, with
# -fsanitize=fuzzer) are now mutually exclusive rather than both being passed to
# the same clang invocation. That was hygiene, not the bug -- it was measured to
# make no difference to the counter count -- but one -fsanitize group per
# invocation is the documented contract and worth holding to.
#
# Usage:  scripts/gcp_fuzz_baseline.sh
# Watch:    gsutil cat gs://terravault-ml-artifacts/runs/<RUN>/live/status.txt
#           gsutil cat gs://terravault-ml-artifacts/runs/<RUN>/live/baseline_report.md
# Collect (at any time — partial results are always valid):
#   gsutil -m cp -r gs://terravault-ml-artifacts/runs/<RUN>/ .
#   gcloud compute instances delete tv-<RUN> --zone=us-central1-a
set -euo pipefail

PROJECT="${TV_PROJECT:-terravault}"
ZONE="${TV_ZONE:-us-central1-a}"
BUCKET="${TV_BUCKET:-terravault-ml-artifacts}"
# ASan roughly triples RSS, and libxml2/SQLite corpora are memory-hungry, so the
# standard (4 GB/vCPU) shape is chosen over highcpu (1 GB/vCPU) despite costing
# more per hour: an OOM-killed worker produces no baseline at all.
#
# NOTE on the real binding quota: the regional E2 allowance is generous (128
# vCPUs in us-central1) but the project-wide CPUS_ALL_REGIONS limit is 32. Any
# other job already running on this project eats into it, so this launcher can
# be refused at creation time even with the region wide open. Drop to
# TV_MACHINE=e2-standard-8 in that case — the orchestrator is slot-driven and
# simply schedules the same targets in more waves, shortening each target's
# budget rather than dropping targets.
MACHINE="${TV_MACHINE:-e2-standard-16}"
REPO_URL="${TV_REPO_URL:-https://github.com/oguarni/terravault.git}"

# Hard cost ceiling. The VM self-stops at this age no matter what.
MAX_RUN_MIN="${TV_MAX_RUN_MIN:-120}"
# Orchestration budget, kept below MAX_RUN_MIN so the final upload always lands
# before GCP pulls the plug.
BUDGET_MIN="${TV_BUDGET_MIN:-100}"
# Per-target fuzzing ceiling; the orchestrator shrinks it further if the builds
# ran long, so the triage reserve is never eaten.
FUZZ_SECONDS="${TV_FUZZ_SECONDS:-1800}"

RUN="fuzz-baseline-$(date +%Y%m%d-%H%M%S)"
VM="tv-${RUN}"
REPO_ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

echo ">> staging Stage 0 fuzzing harness for run ${RUN}"
tar czf "${STAGE}/fuzz-src.tgz" -C "${REPO_ROOT}" fuzzing
gsutil cp "${STAGE}/fuzz-src.tgz" "gs://${BUCKET}/eval-src/${RUN}.tgz"

# Startup script in a file (not inline) so gcloud does not parse its commas as
# --metadata separators. Quoted heredoc keeps ${var} literal -> resolved on the
# VM via md().
STARTUP="${STAGE}/startup.sh"
cat > "${STARTUP}" <<'STARTUP_EOF'
#!/bin/bash
set -x; exec > >(tee /var/log/tv-fuzz.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/attributes/$1"; }
RUN=$(md run-id); BUCKET=$(md bucket); REPO_URL=$(md repo-url)
BUDGET_MIN=$(md budget-min); FUZZ_SECONDS=$(md fuzz-seconds)
DST="gs://${BUCKET}/runs/${RUN}"
RUN_ROOT=/opt/fuzz-run

mkdir -p "${RUN_ROOT}"
STATUS="${RUN_ROOT}/status.txt"
: > "${STATUS}"

# Heartbeat: every 3 min push the log, the phase trail, every per-target result
# and the rolled-up report to ${DST}/live/. The run is EXPECTED to die before it
# finishes, so a dead run must still leave a complete-so-far baseline in GCS.
( while sleep 180; do
    gsutil -q cp /var/log/tv-fuzz.log "${STATUS}" "${DST}/live/" 2>/dev/null
    gsutil -q cp "${RUN_ROOT}/baseline.json" "${RUN_ROOT}/baseline_report.md" \
      "${DST}/live/" 2>/dev/null
    gsutil -q -m rsync -r "${RUN_ROOT}/results" "${DST}/live/results" 2>/dev/null
    gsutil -q -m rsync -r "${RUN_ROOT}/status" "${DST}/live/status" 2>/dev/null
  done ) &
HEARTBEAT_PID=$!

echo "$(date -u +%FT%TZ) phase=boot" >> "${STATUS}"

# ASan's shadow mapping collides with the 32-bit mmap randomisation that Ubuntu
# 24.04 ships ("Shadow memory range interleaves with an existing memory
# mapping"). Every sanitised binary in this run would fail to start without this.
sysctl -w vm.mmap_rnd_bits=28 || true
ulimit -c 0

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  clang lld llvm cmake make git curl ca-certificates unzip xz-utils bzip2 \
  autoconf automake libtool pkg-config python3 time cpio binutils file
# The libFuzzer/ASan runtimes live in the versioned compiler-rt package on
# Ubuntu; install it explicitly rather than trusting the meta-package.
apt-get install -y libclang-rt-18-dev || apt-get install -y libclang-rt-dev || true
echo "$(date -u +%FT%TZ) phase=deps-done clang=$(clang --version | head -1)" >> "${STATUS}"

git clone --depth 1 "${REPO_URL}" /opt/tv

# Overlay the (uncommitted) Stage 0 harness staged for this run.
gsutil cp "gs://${BUCKET}/eval-src/${RUN}.tgz" /tmp/fuzz-src.tgz
tar xzf /tmp/fuzz-src.tgz -C /opt/tv
chmod +x /opt/tv/fuzzing/*.sh

# Per-target results publish themselves the moment they are triaged.
export TV_LIVE_DST="${DST}/live"
export TV_BUDGET_MIN="${BUDGET_MIN}"
export TV_FUZZ_SECONDS="${FUZZ_SECONDS}"
export TV_FUZZ_SLOTS="$(nproc)"

/opt/tv/fuzzing/run_baseline.sh "${RUN_ROOT}" "${RUN}"

echo "$(date -u +%FT%TZ) phase=upload" >> "${STATUS}"
kill "${HEARTBEAT_PID}" 2>/dev/null || true

# Final upload. Source trees were already dropped by the orchestrator; what
# remains is the evidence: results, reproducing inputs, corpora, logs.
gsutil -q cp "${RUN_ROOT}/baseline.json" "${RUN_ROOT}/baseline_report.md" "${DST}/" 2>/dev/null
gsutil -q -m rsync -r "${RUN_ROOT}/results" "${DST}/results" 2>/dev/null
gsutil -q -m rsync -r "${RUN_ROOT}/status" "${DST}/status" 2>/dev/null
gsutil -q -m rsync -r "${RUN_ROOT}/artifacts" "${DST}/artifacts" 2>/dev/null
gsutil -q -m rsync -r "${RUN_ROOT}/logs" "${DST}/logs" 2>/dev/null
gsutil -q -m rsync -r "${RUN_ROOT}/corpus" "${DST}/corpus" 2>/dev/null
gsutil -q cp /var/log/tv-fuzz.log "${STATUS}" "${DST}/" 2>/dev/null
echo "$(date -u +%FT%TZ) phase=done" >> "${STATUS}"
gsutil -q cp "${STATUS}" "${DST}/" 2>/dev/null
poweroff
STARTUP_EOF

STOP_UTC="$(date -u -d "+${MAX_RUN_MIN} minutes" +%FT%TZ)"
STOP_LOCAL="$(date -d "+${MAX_RUN_MIN} minutes" '+%Y-%m-%d %H:%M:%S %Z')"

echo ">> creating self-stopping VM ${VM} (zone ${ZONE}, ${MACHINE})"
echo ">> max-run-duration=${MAX_RUN_MIN}m -> expected self-STOP at ${STOP_UTC} (${STOP_LOCAL})"
gcloud config set project "${PROJECT}" >/dev/null 2>&1
gcloud compute instances create "${VM}" \
  --zone="${ZONE}" --machine-type="${MACHINE}" \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=100GB --boot-disk-type=pd-balanced --scopes=cloud-platform \
  --max-run-duration="${MAX_RUN_MIN}m" --instance-termination-action=STOP \
  --metadata=run-id="${RUN}",bucket="${BUCKET}",repo-url="${REPO_URL}",budget-min="${BUDGET_MIN}",fuzz-seconds="${FUZZ_SECONDS}" \
  --metadata-from-file=startup-script="${STARTUP}"

cat <<EOF

>> launched. run id: ${RUN}
>> VM:        ${VM}  (zone ${ZONE}, ${MACHINE})
>> self-STOP: ${STOP_UTC} / ${STOP_LOCAL}
>> status:    gsutil cat gs://${BUCKET}/runs/${RUN}/live/status.txt
>> report:    gsutil cat gs://${BUCKET}/runs/${RUN}/live/baseline_report.md
>> serial:    gcloud compute instances get-serial-port-output ${VM} --zone=${ZONE} | tail -40
>> collect:   gsutil -m cp -r gs://${BUCKET}/runs/${RUN}/ .
>> cleanup:   gcloud compute instances delete ${VM} --zone=${ZONE} --quiet
EOF
