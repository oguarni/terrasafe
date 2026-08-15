# Shared build environment for the Track B Stage 0 plain-fuzzing baseline.
#
# Sourced by build_target.sh and fuzz_target.sh. Defines the compiler flags every
# target is built with, so the baseline is measured under ONE detector
# configuration across all targets — a per-target flag drift would make the
# numbers incomparable, and comparability is the whole point of a baseline.
#
# Detector choice (deliberate, see PLANO_LONGO_futuro.md Track B scope):
#   * ASan is the primary detector — Track B's MVP scope is memory safety.
#   * UBSan is restricted to its memory-safety-adjacent checks. The arithmetic
#     and alignment checks (signed-integer-overflow, shift, alignment,
#     float-cast-overflow) are EXCLUDED on purpose: legacy C trips them
#     constantly on benign idioms and they would inflate the bug count with
#     findings the plan explicitly puts out of scope ("memory-safety + crashes
#     first; drop logic bugs"). An inflated baseline is worse than no baseline —
#     it is the number a later LLM arm has to beat.
#   * -fno-sanitize-recover=all makes every enabled check abort, so libFuzzer
#     sees it as a crash and writes an artifact we can gate on.
#
# Legacy-C relaxations: clang >= 15 promotes implicit-function-declaration and
# friends to hard errors. Every target here is pinned at a pre-fix release from
# 2014-2017, so without these the builds fail for reasons that have nothing to
# do with the experiment.

# shellcheck shell=bash

export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"

# `object-size` is deliberately absent: it needs optimisation to be meaningful
# and fires on the `char buf[1]` struct-hack that every one of these pinned
# 2014-2017 releases uses, which would flood the baseline with non-bugs.
TV_SAN_CHECKS="address,array-bounds,null,vla-bound,return,unreachable"

TV_LEGACY_C_FLAGS="-Wno-error=implicit-function-declaration -Wno-error=implicit-int"
TV_LEGACY_C_FLAGS="${TV_LEGACY_C_FLAGS} -Wno-error=int-conversion -Wno-error=incompatible-pointer-types"
TV_LEGACY_C_FLAGS="${TV_LEGACY_C_FLAGS} -Wno-error=return-type -Wno-error=deprecated-non-prototype"
TV_LEGACY_C_FLAGS="${TV_LEGACY_C_FLAGS} -Wno-deprecated-non-prototype -Wno-unused-command-line-argument"

TV_BASE_CFLAGS="-g -O1 -fno-omit-frame-pointer ${TV_LEGACY_C_FLAGS}"

# Exactly ONE -fsanitize= group per clang invocation. Run 1 passed both groups
# below to the same command; measurement on that run's VM showed it makes no
# difference to the instrumentation, but one group per invocation is the
# documented contract and the version that is obviously correct on inspection.
# Keep these two variables mutually exclusive at every call site.
#
# Library objects: instrument for coverage but do NOT link libFuzzer's main().
export FUZZ_CFLAGS="${TV_BASE_CFLAGS} -fsanitize=fuzzer-no-link,${TV_SAN_CHECKS} -fno-sanitize-recover=all"
export FUZZ_CXXFLAGS="${FUZZ_CFLAGS}"
# Harness compile+link step: instrumented AND carrying libFuzzer's main().
export FUZZ_HARNESS_FLAGS="${TV_BASE_CFLAGS} -fsanitize=fuzzer,${TV_SAN_CHECKS} -fno-sanitize-recover=all"

# Runtime options shared by fuzzing, minimisation and replay so that a crash
# reproduces under exactly the environment that produced it.
export TV_ASAN_OPTIONS="abort_on_error=0:detect_leaks=1:symbolize=1:print_stacktrace=1:handle_abort=1:allocator_may_return_null=1:detect_odr_violation=0"
export TV_UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

tv_log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }

# Fetch with retries. Pinned URLs only — every target is a specific historical
# release, never a moving branch, so the corpus of "known bugs" stays fixed.
tv_fetch() {
  local url="$1" out="$2"
  curl -fsSL --retry 4 --retry-delay 3 --retry-connrefused \
       --connect-timeout 20 --max-time 300 -o "${out}" "${url}"
}

# Locate a built static library without hard-coding libtool/CMake output paths,
# which differ between the autotools and CMake targets.
# `|| true` matters: recipes run under `set -e`, and a find that hits an
# unreadable directory would otherwise abort an otherwise successful build.
tv_find_lib() {
  local root="$1" name="$2"
  find "${root}" -name "${name}" -type f 2>/dev/null | head -n 1 || true
}
