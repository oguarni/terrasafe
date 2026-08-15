# Track B Stage 0 — plain-fuzzing baseline (fuzz-baseline-20260721-213507)

Generated 2026-07-22T01:32:37Z. **Partial by design** — this file is rewritten every couple of minutes while the campaign runs, so it is always readable even if the VM is stopped mid-run by the duration cap or by credit expiry.

## What this is

The **un-augmented arm** of Track B's thesis question. No LLM is involved anywhere in this run: hand-written libFuzzer harnesses, no synthesised seeds, no dictionaries, no LLM triage. Every number below is the floor a later LLM-augmented arm has to beat on bug yield, time-to-reproduce and triage quality.

A crash is counted only if a sanitizer confirms it, libFuzzer can minimise it, and the minimised input replays the same stack signature deterministically. Artifacts that fail any clause are kept and reported, but never counted.

## Headline

- `targets_total`: 9
- `targets_built`: 9
- `targets_build_failed`: 0
- `targets_fuzzed`: 9
- `targets_with_any_crash_artifact`: 2
- `targets_with_confirmed_bug`: 2
- `confirmed_unique_bugs`: 6
- `confirmed_memory_safety_bugs`: 6
- `unique_signatures`: 24
- `crash_artifacts`: 18983
- `median_time_to_first_crash_seconds`: 0
- `fastest_time_to_first_crash_seconds`: 0
- `total_edge_coverage`: 20355
- `total_executed_units`: 0
- `total_cpu_seconds`: 14713.5
- `total_fuzz_wall_seconds`: 16640
- `gate_validation_targets`: 2
- `gate_validation_confirmed_bugs`: 1

## Per-target

| target | kind | status | build s | budget s | CPU s | execs | edges | artifacts | unique sig | confirmed | TTFC s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `cares_1_11_0` | known-bug | fuzzed | 94 | 1500 | 845.05 | 0 | 32 | 12168 | 2 | 2 | 0 |
| `cjson_1_7_10` | known-bug | fuzzed | 2 | 1500 | 1478.58 | 0 | 257 | 0 | 0 | 0 | - |
| `expat_2_1_0` | known-bug | fuzzed | 11 | 1500 | 1486.36 | 0 | 3547 | 0 | 0 | 0 | - |
| `gate_heap_overflow` | gate-validation | fuzzed | 0 | 1500 | 1471.0 | 0 | 1 | 0 | 0 | 0 | - |
| `gate_use_after_free` | gate-validation | fuzzed | 0 | 1500 | 755.63 | 0 | 3 | 4943 | 1 | 1 | 1 |
| `libarchive_3_2_1` | known-bug | fuzzed | 78 | 1500 | 1103.07 | 0 | 1263 | 6815 | 22 | 4 | 0 |
| `libxml2_2_9_2` | known-bug | fuzzed | 57 | 1500 | 1477.93 | 0 | 3217 | 0 | 0 | 0 | - |
| `libyaml_0_1_7` | known-bug | fuzzed | 5 | 1500 | 1527.22 | 0 | 1573 | 0 | 0 | 0 | - |
| `re2_2017_06_01` | known-bug | fuzzed | 14 | 1500 | 1514.83 | 0 | 2838 | 0 | 0 | 0 | - |
| `sqlite_3_13_0` | known-bug | fuzzed | 73 | 1500 | 1503.24 | 0 | 7005 | 0 | 0 | 0 | - |
| `tinyxml2_6_0_0` | known-bug | fuzzed | 3 | 1500 | 1550.57 | 0 | 623 | 0 | 0 | 0 | - |

## Confirmed bugs (passed the reproducibility gate)

- `cares_1_11_0` `9a5c8bb8cfb3ab00` **memory leaks** (LeakSanitizer) at ares_create_query <- _start; first seen 0s, minimised to 2 B from 7 B, 11440 duplicate artifact(s).
- `cares_1_11_0` `b7964546c96b6fc5` **heap-buffer-overflow** (AddressSanitizer) at ares_create_query <- _start; first seen 5s, minimised to 2 B from 12 B, 726 duplicate artifact(s).
- `gate_use_after_free` `e2982dc368b52ad8` **heap-use-after-free** (AddressSanitizer) at _start; first seen 1s, minimised to 5 B from 7 B, 4942 duplicate artifact(s).
- `libarchive_3_2_1` `88551c036f09a562` **memory leaks** (LeakSanitizer) at archive_read_open_memory2 <- _start <- __archive_read_filter_ahead <- bzip2_reader_bid; first seen 15s, minimised to 6 B from 9 B, 74 duplicate artifact(s).
- `libarchive_3_2_1` `10c2dc4b7ff8d608` **memory leaks** (LeakSanitizer) at archive_string_ensure <- __archive_read_program <- lrzip_bidder_init <- choose_filters; first seen 22s, minimised to 6 B from 9 B, 1 duplicate artifact(s).
- `libarchive_3_2_1` `22aa507707ff1e48` **memory leaks** (LeakSanitizer) at archive_read_open_memory2 <- _start <- __archive_read_filter_ahead <- header_bin_be; first seen 42s, minimised to 6 B from 10 B, 3 duplicate artifact(s).
- `libarchive_3_2_1` `661e69c75b176ff7` **memory leaks** (LeakSanitizer) at archive_read_open_memory2 <- _start <- __archive_read_filter_ahead <- header_bin_le; first seen 179s, minimised to 6 B from 6 B, 4 duplicate artifact(s).

## Reading the gate-validation rows

`gate_heap_overflow` and `gate_use_after_free` are synthetic targets with a deliberate planted bug each. They are excluded from every headline figure. Their only job is to prove, inside this same run, that the crash -> dedup -> minimise -> replay pipeline fires at all. If they report zero confirmed bugs, a zero on the real targets means the pipeline is broken, not that the targets are clean.

