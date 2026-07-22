# shellcheck shell=bash
# RE2 2017-06-01 — CMake. Last in the order because it is the only C++ library
# build in the set and therefore the most likely to be rejected by a modern
# clang's default language mode; if it is dropped, everything above it has
# already produced data.
TARGET_ID="re2_2017_06_01"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://github.com/google/re2/archive/refs/tags/2017-06-01.tar.gz"
TARGET_KNOWN_BUG="2016-2017 OSS-Fuzz/fuzzer-test-suite findings against this era of RE2: out-of-bounds reads and CHECK failures compiling pathological patterns; fixed in later 2017-2018 releases."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.tar.gz
  tar xzf src.tar.gz
  cmake -S re2-2017-06-01 -B build \
    -DCMAKE_CXX_COMPILER="${CXX}" -DCMAKE_CXX_FLAGS="${FUZZ_CXXFLAGS} -std=c++11" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=OFF \
    -DRE2_BUILD_TESTING=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/dev/null
  cmake --build build -j "${NPROC}" --target re2 >/dev/null 2>&1 \
    || cmake --build build -j "${NPROC}" >/dev/null 2>&1
  local lib
  lib="$(tv_find_lib build 'libre2.a')"
  [ -n "${lib}" ] || return 1
  ${CXX} ${FUZZ_HARNESS_FLAGS} -std=c++11 -Ire2-2017-06-01 \
    "${HARNESS_DIR}/re2_compile_match_fuzzer.cc" "${lib}" -o "${OUT_BIN}" -lpthread
}

tv_seed() {
  printf 'a+b*' > "${SEEDS_DIR}/simple"
  printf '(?i)(foo|bar){2,4}[a-z0-9]+' > "${SEEDS_DIR}/groups"
  printf '\\b(\\w+)\\s+\\1\\b' > "${SEEDS_DIR}/classes"
  printf '(((((((((a)))))))))*' > "${SEEDS_DIR}/nested"
}
