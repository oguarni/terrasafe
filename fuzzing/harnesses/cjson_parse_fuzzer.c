/* cJSON parse + re-serialise harness (hand-written baseline arm).
 *
 * Deliberately un-augmented: no LLM wrote this, no dictionary, no mined seed
 * corpus. Stage 1 of Track B synthesises harnesses with an LLM and must be
 * compared against exactly this kind of minimal, obvious, human-written entry
 * point — otherwise the comparison flatters the LLM.
 *
 * Printing the parsed tree back out is what reaches cJSON_Utils/print paths,
 * where the 1.7.10-era out-of-bounds reads live. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > (1 << 16)) {
    return 0;
  }
  char *text = (char *)malloc(size + 1);
  if (text == NULL) {
    return 0;
  }
  memcpy(text, data, size);
  text[size] = '\0';

  cJSON *item = cJSON_Parse(text);
  if (item != NULL) {
    char *printed = cJSON_PrintUnformatted(item);
    free(printed);
    cJSON_Delete(item);
  }
  free(text);
  return 0;
}
