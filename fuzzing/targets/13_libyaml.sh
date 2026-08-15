# shellcheck shell=bash
# libyaml 0.1.7 — the checked-in CMakeLists avoids the autoreconf round-trip.
TARGET_ID="libyaml_0_1_7"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://github.com/yaml/libyaml/archive/refs/tags/0.1.7.tar.gz"
TARGET_KNOWN_BUG="OSS-Fuzz issues fixed between 0.1.7 and 0.2.1: out-of-bounds reads and invalid frees in the scanner/parser on malformed anchors, tags and block scalars."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.tar.gz
  tar xzf src.tar.gz
  cmake -S libyaml-0.1.7 -B build \
    -DCMAKE_C_COMPILER="${CC}" -DCMAKE_C_FLAGS="${FUZZ_CFLAGS}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/dev/null
  cmake --build build -j "${NPROC}" >/dev/null
  local lib
  lib="$(tv_find_lib build 'libyaml.a')"
  [ -n "${lib}" ] || return 1
  ${CC} ${FUZZ_HARNESS_FLAGS} -Ilibyaml-0.1.7/include \
    "${HARNESS_DIR}/libyaml_parse_fuzzer.c" "${lib}" -o "${OUT_BIN}"
}

tv_seed() {
  printf 'a: 1\n' > "${SEEDS_DIR}/scalar"
  printf -- '---\nlist:\n  - &a x\n  - *a\nmap: {k: v}\n' > "${SEEDS_DIR}/anchors"
  printf 'block: |\n  line one\n  line two\n' > "${SEEDS_DIR}/block"
}
