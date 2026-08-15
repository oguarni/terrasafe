// TinyXML-2 parse + print harness (hand-written baseline arm).
//
// Printing the document back out after parsing doubles the reachable surface
// for the cost of two lines, and the printer is where several of the OSS-Fuzz
// issues filed against the 6.0.0 era were found.
#include <cstddef>
#include <cstdint>

#include "tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > (1 << 20)) {
    return 0;
  }
  tinyxml2::XMLDocument doc;
  if (doc.Parse(reinterpret_cast<const char *>(data), size) ==
      tinyxml2::XML_SUCCESS) {
    tinyxml2::XMLPrinter printer;
    doc.Print(&printer);
  }
  return 0;
}
