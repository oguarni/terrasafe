/* c-ares ares_create_query harness (hand-written baseline arm).
 *
 * Targets CVE-2016-5180: a one-byte out-of-bounds write when a hostname
 * containing escaped dot sequences is encoded into a DNS query. It is a
 * seconds-to-find bug under ASan, which makes it the calibration point of the
 * whole baseline: if TIME-TO-FIRST-CRASH here is not on the order of seconds,
 * something is wrong with the environment, not with the target.
 *
 * The class/type constants are spelled numerically (C_IN=1, T_A=1) to avoid
 * depending on <arpa/nameser.h>, which is not portable across the pinned
 * releases. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ares.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > 4096) {
    return 0;
  }
  char *name = (char *)malloc(size + 1);
  if (name == NULL) {
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  unsigned char *query = NULL;
  int query_len = 0;
  if (ares_create_query(name, 1 /* C_IN */, 1 /* T_A */, 0x1234, 0, &query,
                        &query_len, 0) == ARES_SUCCESS) {
    ares_free_string(query);
  }
  free(name);
  return 0;
}
