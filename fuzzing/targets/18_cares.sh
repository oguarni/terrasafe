# shellcheck shell=bash
# c-ares 1.11.0 — the calibration target. CVE-2016-5180 is a seconds-to-find
# one-byte heap overflow under ASan, so it is the sanity check on the whole
# pipeline: if TIME-TO-FIRST-CRASH here is not on the order of seconds, the
# environment is broken rather than the targets being clean.
#
# Placed last because it is the only target that needs an autoreconf round-trip
# (the 1.11.0 git tag predates the pre-generated configure that later releases
# ship), which is the single most likely build failure in the set. Its failure
# must not cost any earlier target its slot.
TARGET_ID="cares_1_11_0"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://github.com/c-ares/c-ares/archive/refs/tags/cares-1_11_0.tar.gz"
TARGET_KNOWN_BUG="CVE-2016-5180: one-byte out-of-bounds write in ares_create_query() when encoding an escaped hostname; fixed in 1.12.0."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.tar.gz
  tar xzf src.tar.gz
  cd c-ares-cares-1_11_0
  ( ./buildconf >/dev/null 2>&1 || autoreconf -fi >/dev/null 2>&1 ) || return 1
  CFLAGS="${FUZZ_CFLAGS}" ./configure --disable-shared --enable-static >/dev/null
  make -j"${NPROC}" >/dev/null
  local lib
  lib="$(tv_find_lib . 'libcares.a')"
  [ -n "${lib}" ] || return 1
  ${CC} ${FUZZ_HARNESS_FLAGS} -I. \
    "${HARNESS_DIR}/cares_create_query_fuzzer.c" "${lib}" -o "${OUT_BIN}"
}

tv_seed() {
  printf 'www.example.com' > "${SEEDS_DIR}/hostname"
  printf 'a.b.c.d.e' > "${SEEDS_DIR}/labels"
  printf '.' > "${SEEDS_DIR}/root"
}
