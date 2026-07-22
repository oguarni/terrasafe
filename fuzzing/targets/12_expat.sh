# shellcheck shell=bash
# Expat 2.1.0 — release tarball ships a pre-generated ./configure, so no
# autoreconf round-trip is needed and the build cannot break on a modern
# autoconf refusing a 2012-era configure.ac.
TARGET_ID="expat_2_1_0"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://github.com/libexpat/libexpat/releases/download/R_2_1_0/expat-2.1.0.tar.gz"
TARGET_KNOWN_BUG="CVE-2016-0718: out-of-bounds read/write parsing malformed multi-byte input (fixed in 2.1.1); CVE-2015-1283 integer overflow in XML_GetBuffer."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.tar.gz
  tar xzf src.tar.gz
  cd expat-2.1.0
  CFLAGS="${FUZZ_CFLAGS}" ./configure --disable-shared --enable-static \
    --without-docbook >/dev/null
  make -j"${NPROC}" buildlib || make -j"${NPROC}"
  local lib
  lib="$(tv_find_lib . 'libexpat.a')"
  [ -n "${lib}" ] || return 1
  ${CC} ${FUZZ_HARNESS_FLAGS} -Ilib \
    "${HARNESS_DIR}/expat_parse_fuzzer.c" "${lib}" -o "${OUT_BIN}"
}

tv_seed() {
  printf '<a/>' > "${SEEDS_DIR}/minimal"
  printf '<?xml version="1.0" encoding="UTF-8"?><r a="v">t&amp;t</r>' > "${SEEDS_DIR}/typical"
  printf '<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>' > "${SEEDS_DIR}/entity"
}
