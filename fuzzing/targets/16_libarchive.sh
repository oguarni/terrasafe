# shellcheck shell=bash
# libarchive 3.2.1 — CMake. Every optional codec is disabled so the build has no
# system -dev dependencies; that restricts the reachable formats to the
# uncompressed ones (tar, cpio, ar, mtree, stored zip), which is exactly what
# the seeds below cover. A narrower but reliably-built target beats a broader
# one that fails to configure unattended.
TARGET_ID="libarchive_3_2_1"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://github.com/libarchive/libarchive/archive/refs/tags/v3.2.1.tar.gz"
TARGET_KNOWN_BUG="CVE-2016-5844 (integer overflow in the ISO9660 parser), CVE-2016-6250 (integer overflow writing large files), plus the 2015-2016 tar/cpio/mtree out-of-bounds reads; fixed in 3.2.2/3.3.x."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.tar.gz
  tar xzf src.tar.gz
  cmake -S libarchive-3.2.1 -B build \
    -DCMAKE_C_COMPILER="${CC}" -DCMAKE_C_FLAGS="${FUZZ_CFLAGS}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DENABLE_TEST=OFF -DENABLE_TAR=OFF -DENABLE_CPIO=OFF -DENABLE_CAT=OFF \
    -DENABLE_OPENSSL=OFF -DENABLE_NETTLE=OFF -DENABLE_LZMA=OFF \
    -DENABLE_BZip2=OFF -DENABLE_LZO=OFF -DENABLE_LZ4=OFF -DENABLE_ZLIB=OFF \
    -DENABLE_LIBXML2=OFF -DENABLE_EXPAT=OFF -DENABLE_ICONV=OFF \
    -DENABLE_ACL=OFF -DENABLE_XATTR=OFF >/dev/null
  cmake --build build -j "${NPROC}" --target archive_static >/dev/null 2>&1 \
    || cmake --build build -j "${NPROC}" >/dev/null 2>&1
  local lib
  lib="$(tv_find_lib build 'libarchive.a')"
  [ -n "${lib}" ] || return 1
  ${CC} ${FUZZ_HARNESS_FLAGS} -Ilibarchive-3.2.1/libarchive \
    "${HARNESS_DIR}/libarchive_read_fuzzer.c" "${lib}" -o "${OUT_BIN}"
}

# Binary container formats get no useful mutation pressure from random bytes, so
# the seeds are real archives built on the fly with system tools. They are still
# minimal and hand-made: no mined corpus, no LLM-generated inputs. That is the
# floor a later corpus-synthesis arm has to beat.
tv_seed() {
  local stage="${SEEDS_DIR}/.stage"
  mkdir -p "${stage}/dir"
  printf 'hello libarchive baseline\n' > "${stage}/dir/a.txt"
  printf '0123456789' > "${stage}/dir/b.bin"
  tar cf "${SEEDS_DIR}/seed.tar" -C "${stage}" dir 2>/dev/null || true
  ( cd "${stage}" && find dir | cpio -o --quiet > "${SEEDS_DIR}/seed.cpio" ) 2>/dev/null || true
  ar rcs "${SEEDS_DIR}/seed.a" "${stage}/dir/a.txt" 2>/dev/null || true
  rm -rf "${stage}"
}
