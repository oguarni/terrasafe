/* libyaml event-stream parse harness (hand-written baseline arm).
 *
 * Drains the whole event stream rather than stopping at the first event, so the
 * scanner, parser and the token/anchor bookkeeping are all exercised — that is
 * where the OSS-Fuzz issues fixed between 0.1.7 and 0.2.1 were. */
#include <stddef.h>
#include <stdint.h>

#include <yaml.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  yaml_parser_t parser;
  if (!yaml_parser_initialize(&parser)) {
    return 0;
  }
  yaml_parser_set_input_string(&parser, data, size);

  int done = 0;
  while (!done) {
    yaml_event_t event;
    if (!yaml_parser_parse(&parser, &event)) {
      break;
    }
    done = (event.type == YAML_STREAM_END_EVENT);
    yaml_event_delete(&event);
  }
  yaml_parser_delete(&parser);
  return 0;
}
