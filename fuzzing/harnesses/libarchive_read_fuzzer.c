/* libarchive read-all-entries harness (hand-written baseline arm).
 *
 * Mirrors the shape of the upstream OSS-Fuzz harness: enable every format and
 * filter the pinned build was configured with, walk every header, and drain
 * every entry's data. Draining the data is what reaches the decoders where the
 * 3.2.1-era out-of-bounds reads (CVE-2016-5844, CVE-2016-6250 and the
 * 2015-2016 tar/cpio/mtree issues) actually live. */
#include <stdint.h>
#include <stdlib.h>

#include <archive.h>
#include <archive_entry.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct archive *handle = archive_read_new();
  if (handle == NULL) {
    return 0;
  }
  archive_read_support_filter_all(handle);
  archive_read_support_format_all(handle);

  if (archive_read_open_memory(handle, (void *)data, size) == ARCHIVE_OK) {
    struct archive_entry *entry = NULL;
    char sink[4096];
    while (archive_read_next_header(handle, &entry) == ARCHIVE_OK) {
      ssize_t read_bytes;
      do {
        read_bytes = archive_read_data(handle, sink, sizeof(sink));
      } while (read_bytes > 0);
      if (read_bytes < 0) {
        break;
      }
    }
  }
  archive_read_free(handle);
  return 0;
}
