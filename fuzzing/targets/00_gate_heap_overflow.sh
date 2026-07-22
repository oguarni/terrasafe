# shellcheck shell=bash
TARGET_ID="gate_heap_overflow"
TARGET_KIND="gate-validation"
TARGET_SOURCE_URL="(local harness)"
TARGET_KNOWN_BUG="Synthetic 1-byte heap-buffer-overflow write behind a 4-byte magic. Validates the reproducibility gate; excluded from baseline metrics."

tv_build() {
  ${CC} ${FUZZ_HARNESS_FLAGS} \
    "${HARNESS_DIR}/gate_heap_overflow.c" -o "${OUT_BIN}"
}

tv_seed() {
  printf 'x' > "${SEEDS_DIR}/empty"
  printf 'TVA0z' > "${SEEDS_DIR}/near_magic"
}
