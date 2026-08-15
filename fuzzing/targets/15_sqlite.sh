# shellcheck shell=bash
# SQLite 3.13.0 amalgamation — one .c file, so the build cannot break on a
# build system, only on the compiler. Compiling it under ASan is the slowest
# single compile in the set (~1-2 min), which is why it sits after the cheap
# targets in the deadline-driven order.
TARGET_ID="sqlite_3_13_0"
TARGET_KIND="known-bug"
TARGET_SOURCE_URL="https://www.sqlite.org/2016/sqlite-amalgamation-3130000.zip"
TARGET_KNOWN_BUG="2016-2017 OSS-Fuzz campaign against the 3.13-3.16 series: out-of-bounds reads and assertion failures in the query planner, FTS and window/CTE handling, fixed across the 3.17-3.20 releases."

tv_build() {
  tv_fetch "${TARGET_SOURCE_URL}" src.zip
  unzip -q src.zip
  cd sqlite-amalgamation-3130000
  ${CC} ${FUZZ_CFLAGS} \
    -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION \
    -DSQLITE_MAX_LENGTH=128000 -DSQLITE_MAX_SQL_LENGTH=128000 \
    -DSQLITE_MAX_EXPR_DEPTH=64 -DSQLITE_ENABLE_FTS4 -DSQLITE_ENABLE_RTREE \
    -c sqlite3.c -o sqlite3.o
  ${CC} ${FUZZ_HARNESS_FLAGS} -I. \
    "${HARNESS_DIR}/sqlite_exec_fuzzer.c" sqlite3.o -o "${OUT_BIN}" -lpthread -lm -ldl
}

tv_seed() {
  printf 'CREATE TABLE t(a,b);INSERT INTO t VALUES(1,2);SELECT * FROM t;' > "${SEEDS_DIR}/basic"
  printf 'CREATE VIRTUAL TABLE f USING fts4(x);INSERT INTO f VALUES("a b");SELECT * FROM f WHERE x MATCH "a";' > "${SEEDS_DIR}/fts4"
  printf 'WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c LIMIT 5) SELECT * FROM c;' > "${SEEDS_DIR}/cte"
}
