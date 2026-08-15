/* libxml2 xmlReadMemory harness (hand-written baseline arm).
 *
 * DTD loading and entity substitution are enabled because the 2.9.2-era
 * heap-overflow CVEs (CVE-2016-1834/1835/1836/1839/1840 and friends) live in
 * the entity, DTD and encoding-conversion paths — a harness with them off would
 * report a deceptively clean baseline. Network access stays off (XML_PARSE_NONET)
 * so the run is hermetic and reproducible.
 *
 * Entity expansion can legitimately exhaust memory ("billion laughs"). Those are
 * recorded by the triage step as OOM artifacts, not as confirmed bugs — the
 * reproducibility gate only promotes sanitizer-confirmed, deterministically
 * replayable crashes. */
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

#include <libxml/parser.h>
#include <libxml/xmlerror.h>

static void tv_swallow_errors(void *ctx, const char *msg, ...) {
  (void)ctx;
  (void)msg;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  xmlInitParser();
  /* Parser diagnostics are pure noise here and slow the fuzz loop down. */
  xmlSetGenericErrorFunc(NULL, tv_swallow_errors);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > (1 << 20)) {
    return 0;
  }
  xmlDocPtr doc = xmlReadMemory((const char *)data, (int)size, "tv.xml", NULL,
                                XML_PARSE_NOENT | XML_PARSE_DTDLOAD |
                                    XML_PARSE_DTDATTR | XML_PARSE_NONET);
  if (doc != NULL) {
    xmlFreeDoc(doc);
  }
  return 0;
}
