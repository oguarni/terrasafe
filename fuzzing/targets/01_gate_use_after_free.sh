# shellcheck shell=bash
TARGET_ID="gate_use_after_free"
TARGET_KIND="gate-validation"
TARGET_SOURCE_URL="(local harness)"
TARGET_KNOWN_BUG="Synthetic heap-use-after-free read behind a 4-byte magic. Second gate-validation bug class, used to prove stack-signature dedup separates distinct bugs. Excluded from baseline metrics."

tv_build() {
  ${CC} ${FUZZ_HARNESS_FLAGS} \
    "${HARNESS_DIR}/gate_use_after_free.c" -o "${OUT_BIN}"
}

tv_seed() {
  printf 'x' > "${SEEDS_DIR}/empty"
  printf 'TVA1z' > "${SEEDS_DIR}/near_magic"
}
