# shellcheck shell=bash
# libxml2 2.9.2 — the richest known-bug target in the set (a dozen documented
# heap overflows fixed between 2.9.2 and 2.9.4). Autotools, but the GNOME
# release tarball ships a pre-generated ./configure. Every optional dependency
# is switched off so the build cannot fail on a missing -dev package.
TARGET_ID="libxml2_2_9_2"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://download.gnome.org/sources/libxml2/2.9/libxml2-2.9.2.tar.xz"
TARGET_KNOWN_BUG="CVE-2015-8317, CVE-2016-1762, CVE-2016-1834, CVE-2016-1835, CVE-2016-1836, CVE-2016-1837, CVE-2016-1838, CVE-2016-1839, CVE-2016-1840: heap out-of-bounds reads/writes in the DTD, entity and encoding paths; fixed in 2.9.4."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.tar.xz
  tar xf src.tar.xz
  cd libxml2-2.9.2
  CFLAGS="${FUZZ_CFLAGS}" ./configure --disable-shared --enable-static \
    --without-python --without-lzma --without-zlib --without-iconv \
    --without-http --without-ftp --without-modules --without-debug >/dev/null
  make -j"${NPROC}" >/dev/null
  local lib
  lib="$(tv_find_lib . 'libxml2.a')"
  [ -n "${lib}" ] || return 1
  ${CC} ${FUZZ_HARNESS_FLAGS} -Iinclude -I. \
    "${HARNESS_DIR}/libxml2_read_memory_fuzzer.c" "${lib}" -o "${OUT_BIN}" -lm
}

tv_seed() {
  printf '<a/>' > "${SEEDS_DIR}/minimal"
  printf '<?xml version="1.0" encoding="UTF-8"?><r a="1"><c>t</c></r>' > "${SEEDS_DIR}/typical"
  printf '<!DOCTYPE r [<!ELEMENT r ANY><!ENTITY e "x">]><r>&e;</r>' > "${SEEDS_DIR}/dtd"
  printf '<?xml version="1.0" encoding="ISO-8859-1"?><r>\xe9\xff</r>' > "${SEEDS_DIR}/latin1"
}
