// RE2 compile-and-match harness (hand-written baseline arm).
//
// The input is treated as a regular expression, compiled, and then run against
// a fixed subject string. Memory is capped (set_max_mem) and the pattern length
// is capped so that a pathological pattern costs a bounded amount of work
// instead of pinning a fuzzing slot — the same per-unit-of-work budget
// discipline the launcher applies at the target level.
#include <cstddef>
#include <cstdint>
#include <string>

#include "re2/re2.h"

namespace {
constexpr size_t kMaxPatternBytes = 512;
constexpr int64_t kMaxRe2Bytes = 1 << 20;
const char kSubject[] = "abcdefghijklmnopqrstuvwxyz0123456789 \t\n<>&\"'";
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > kMaxPatternBytes) {
    return 0;
  }
  const std::string pattern(reinterpret_cast<const char *>(data), size);

  RE2::Options options;
  options.set_log_errors(false);
  options.set_max_mem(kMaxRe2Bytes);

  RE2 re(pattern, options);
  if (!re.ok()) {
    return 0;
  }
  RE2::FullMatch(kSubject, re);
  RE2::PartialMatch(kSubject, re);
  return 0;
}
