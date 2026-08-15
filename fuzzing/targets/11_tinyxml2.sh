# shellcheck shell=bash
# TinyXML-2 6.0.0 — one .cpp, one .h, no build system.
TARGET_ID="tinyxml2_6_0_0"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://github.com/leethomason/tinyxml2/archive/refs/tags/6.0.0.tar.gz"
TARGET_KNOWN_BUG="OSS-Fuzz issues against the 6.0.0 era: out-of-bounds reads in the entity/attribute scanner and printer paths, fixed across 6.x/7.x."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.tar.gz
  tar xzf src.tar.gz
  cd tinyxml2-6.0.0
  ${CXX} ${FUZZ_CXXFLAGS} -c tinyxml2.cpp -o tinyxml2.o
  ${CXX} ${FUZZ_HARNESS_FLAGS} -I. \
    "${HARNESS_DIR}/tinyxml2_parse_fuzzer.cc" tinyxml2.o -o "${OUT_BIN}"
}

tv_seed() {
  printf '<a/>' > "${SEEDS_DIR}/minimal"
  printf '<?xml version="1.0"?><r x="1"><c>&amp;&#65;</c><!--k--></r>' > "${SEEDS_DIR}/typical"
  printf '<r><![CDATA[<>&]]></r>' > "${SEEDS_DIR}/cdata"
}
