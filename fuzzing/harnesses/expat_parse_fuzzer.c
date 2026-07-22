/* Expat XML_Parse harness (hand-written baseline arm).
 *
 * A single one-shot XML_Parse call with the default (auto-detected) encoding —
 * this is the path CVE-2016-0718 lives on, in the tokenizer's handling of
 * malformed multi-byte sequences. */
#include <stdint.h>
#include <stdlib.h>

#include "expat.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > (1 << 20)) {
    return 0;
  }
  XML_Parser parser = XML_ParserCreate(NULL);
  if (parser == NULL) {
    return 0;
  }
  XML_Parse(parser, (const char *)data, (int)size, 1);
  XML_ParserFree(parser);
  return 0;
}
