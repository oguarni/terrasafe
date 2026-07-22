/* Reproducibility-gate validation target: a deliberate use-after-free.
 *
 * Second gate-validation target (see gate_heap_overflow.c). Two distinct bug
 * classes are used on purpose: they must produce two DIFFERENT stack
 * signatures, which is what validates the dedup half of the gate. A dedup that
 * collapses everything to one bucket and a dedup that works look identical on a
 * single-bug run.
 *
 * The volatile escape hatch is load-bearing for the same reason as in
 * gate_heap_overflow.c: without it the allocate/free/read sequence is dead code
 * at -O1 and the planted bug is compiled out of existence. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static char *volatile tv_escaped_buffer;
static volatile char tv_sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 5 || memcmp(data, "TVB1", 4) != 0) {
    return 0;
  }
  char *buf = (char *)malloc(16);
  if (buf == NULL) {
    return 0;
  }
  tv_escaped_buffer = buf;
  memset(buf, 0, 16);
  free(buf);
  tv_sink = buf[3]; /* deliberate heap-use-after-free READ */
  return 0;
}
