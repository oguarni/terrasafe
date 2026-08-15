/* SQLite "run the input as SQL against :memory:" harness (baseline arm).
 *
 * A progress handler bounds runaway queries: without it a single pathological
 * input pins a worker for the whole campaign, which is exactly the failure mode
 * the A.3 run was killed by (see PLANO_LONGO_futuro.md, "Operational lesson").
 * The per-input libFuzzer -timeout is the outer guard; this is the inner one. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"

enum { TV_PROGRESS_OPS = 50000, TV_PROGRESS_LIMIT = 200 };

static int tv_progress_calls;

static int tv_progress_handler(void *unused) {
  (void)unused;
  return (++tv_progress_calls > TV_PROGRESS_LIMIT) ? 1 : 0;
}

static int tv_row_callback(void *unused, int argc, char **argv, char **names) {
  (void)unused;
  (void)argc;
  (void)argv;
  (void)names;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > (1 << 16)) {
    return 0;
  }
  char *sql = (char *)malloc(size + 1);
  if (sql == NULL) {
    return 0;
  }
  memcpy(sql, data, size);
  sql[size] = '\0';

  sqlite3 *db = NULL;
  if (sqlite3_open(":memory:", &db) == SQLITE_OK) {
    tv_progress_calls = 0;
    sqlite3_progress_handler(db, TV_PROGRESS_OPS, tv_progress_handler, NULL);
    char *error = NULL;
    sqlite3_exec(db, sql, tv_row_callback, NULL, &error);
    sqlite3_free(error);
  }
  sqlite3_close(db);
  free(sql);
  return 0;
}
