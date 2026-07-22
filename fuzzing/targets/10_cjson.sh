# shellcheck shell=bash
# cJSON 1.7.10 — single translation unit, no build system needed. Ordered first
# among the real targets because it is the cheapest thing that can possibly
# produce baseline data, and the schedule is deadline-driven.
TARGET_ID="cjson_1_7_10"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.10.tar.gz"
TARGET_KNOWN_BUG="CVE-2019-11834 / CVE-2019-11835: out-of-bounds reads in cJSON parsing of multibyte and UTF-16 escape sequences; fixed in 1.7.11."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.tar.gz
  tar xzf src.tar.gz
  cd cJSON-1.7.10
  ${CC} ${FUZZ_CFLAGS} -c cJSON.c -o cJSON.o
  ${CC} ${FUZZ_HARNESS_FLAGS} -I. \
    "${HARNESS_DIR}/cjson_parse_fuzzer.c" cJSON.o -o "${OUT_BIN}" -lm
}

tv_seed() {
  printf '{}' > "${SEEDS_DIR}/empty_object"
  printf '{"a":1,"b":[true,null,"s"],"c":{"d":1.5e3}}' > "${SEEDS_DIR}/nested"
  printf '"\\u00e9\\ud83d\\ude00"' > "${SEEDS_DIR}/escapes"
}
