/* Reproducibility-gate validation target: a deliberate 1-byte heap overflow.
 *
 * This is NOT a benchmark target and is excluded from every baseline metric
 * (kind = gate-validation). Its only job is to prove, inside the same run, that
 * the crash -> sanitizer-report -> stack-signature dedup -> minimisation ->
 * deterministic-replay pipeline actually works end to end. If the real targets
 * yield nothing before the credits expire, this still proves the gate is sound;
 * if the gate ever stops firing here, the zero-crash result on real targets is
 * a harness bug, not a finding. Cheap insurance for a run that may be killed.
 *
 * WHY THE VOLATILE ESCAPE HATCH (run 1 post-mortem, fuzz-baseline-20260721-213507):
 * the first version of this file allocated, overflowed and freed a buffer that
 * never escaped the function. At -O1 that whole sequence is dead code and LLVM
 * deletes it -- the compiled harness had ONE basic block and ONE coverage
 * counter, and 634 million executions found nothing because there was nothing
 * left to find. Measured on the run's own VM: -O0 yields 5 inline 8-bit
 * counters, -O1 and -O2 yield 1. Publishing the pointer through a volatile
 * global defeats escape analysis and keeps the planted bug in the binary at the
 * same optimisation level every real target is built with. Do not "simplify"
 * these volatiles away. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Volatile file-scope state: the optimiser must assume both are observed. */
static char *volatile tv_escaped_buffer;
static volatile char tv_sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 5 || memcmp(data, "TVB0", 4) != 0) {
    return 0;
  }
  char *buf = (char *)malloc(8);
  if (buf == NULL) {
    return 0;
  }
  tv_escaped_buffer = buf; /* the allocation now escapes; nothing below is dead */
  memcpy(buf, "abcdefgh", 8);
  buf[8] = (char)data[4]; /* deliberate heap-buffer-overflow WRITE */
  tv_sink = buf[0];
  free(buf);
  return 0;
}
