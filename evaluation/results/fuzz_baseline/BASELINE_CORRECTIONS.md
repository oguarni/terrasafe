# Corrections to `baseline.json` — read before quoting any number from this run

Run `fuzz-baseline-20260721-213507` (Track B Stage 0, the plain-fuzzing arm). The raw
`baseline.json` in this directory is the **uncorrected** output of the on-VM triage. Two of its
summary fields must not be quoted as-is. The per-bug records are correct and are the source of truth;
only the aggregate labels were wrong.

## 1. `confirmed_memory_safety_bugs` is inflated 6x — use 1, not 6

`triage_crashes.py` classified a finding as memory-safety by **sanitizer** (`AddressSanitizer`,
`LeakSanitizer`, `MemorySanitizer`) rather than by **bug class**. That swept every LeakSanitizer
finding into the memory-safety bucket. A memory leak is a resource-management defect — nothing
invalid is ever accessed — so it is neither a memory-safety violation nor a crash, and Stage 0's
declared scope is "memory-safety + crashes".

Recomputed from the same per-bug records, over the 9 real known-bug targets:

| Field | Reported | Corrected |
| --- | --- | --- |
| `confirmed_unique_bugs` | 6 | **6** (unchanged) |
| `confirmed_memory_safety_bugs` | 6 | **1** |
| `confirmed_resource_leak_bugs` | — | **5** |
| targets with a memory-safety bug | 2 of 9 | **1 of 9** |

Composition: **1 x AddressSanitizer heap-buffer-overflow** (c-ares 1.11.0, CVE-2016-5180) and
**5 x LeakSanitizer memory leaks** (c-ares 1, libarchive 4).

**The honest Stage 0 floor is therefore: 1 memory-safety bug across 9 known-bug targets in 4.09
CPU-hours of unseeded plain fuzzing.** This is the denominator any future LLM-augmented arm must be
measured against. Quoting 6 would inflate the baseline and make a later "the LLM improved yield"
claim unfalsifiable in the wrong direction — the same failure mode the project refuses elsewhere when
it declines to spin the rules-vs-ML ablation as a win.

Fixed for future runs in `fuzzing/triage_crashes.py` (`NON_MEMORY_SAFETY_CLASSES`) and surfaced as a
separate `confirmed_resource_leak_bugs` field in `fuzzing/aggregate_baseline.py`. The fix is offline
and re-derivable — it needs no GCP compute, because every bug record is already in `baseline.json`.

## 2. `executed_units` and `execs_per_second` read 0 — RESOLVED, see `exec_stats.json`

libFuzzer's fork mode calls `exit()` before `-print_final_stats`, so the execution counter never
reaches the summary. `triage_crashes.py` was patched to fall back to the parent's periodic
`#N: cov:` lines, but the fix missed this run's staged tarball, so both fields landed as 0. They were
**absent**, not genuinely zero.

Re-derived offline and banked in **`exec_stats.json`** (this directory), produced by
`fuzzing/rederive_exec_stats.py` reusing `triage_crashes._parse_executed_units`. All 9 known-bug
targets recovered, none missing:

| Field | `baseline.json` | Re-derived |
| --- | --- | --- |
| `total_executed_units` (9 known-bug targets) | 0 | **182,406,077** |
| mean throughput | 0.0 | **14,607.9 execs/CPU-second** |
| total fuzz CPU seconds | 14,713.5 (all 11 targets) | 12,486.85 (9 known-bug) |

Per-target throughput spans a 24x range — `libarchive_3_2_1` at 1,550 execs/CPU-s (slowest) to
`expat_2_1_0` at 37,163 (fastest). Quote the per-target row, not the mean, when comparing a single
target across arms.

**Two provenance errors in the previous version of this section, corrected here:**

1. `tv-fuzz.log` does **not** contain the counts. It is the VM orchestrator's `set -x` trace and holds
   zero `#N: cov:` lines. Force-tracking it therefore preserved nothing of this metric.
2. The counts live in `logs/<target>.fuzz.log`, which matches the global `logs/` rule at
   `.gitignore:195` and is **not** committed. `exec_stats.json` is now the only durable copy — do not
   expect to re-derive it again from a fresh clone.

**Do not quote 838,943,565 executed units.** That is the all-11-target sum, and the synthetic
`gate_heap_overflow` target contributes 634.7M of it — 76% — because it is a trivial harness built to
crash instantly, not a real library. Folding the gates in inflates Stage 0 throughput 4.6x. The two
gate targets are reported separately under `gate_validation` in `exec_stats.json`, matching the
known-bug-only convention `aggregate_baseline._summarise` already uses for every other headline
field.

## 3. Time-to-first-crash for the CVE is 5s, not 0s

The target-level `time_to_first_crash_seconds: 0` for `cares_1_11_0` belongs to the LeakSanitizer
finding. The CVE-2016-5180 heap-buffer-overflow has `first_seen_seconds: 5`. Quote 5s for the CVE.

## What is NOT in question

The reproducibility gate did its job: 18,983 raw artifacts collapsed to 24 unique stack signatures
and 6 confirmed findings, with 18 rejected as non-deterministic. Every confirmed finding is backed by
a minimised artifact on disk (25 `min-*` files, 2-6 bytes each), and all carry
`sanitizer_confirmed`, `minimized` and `deterministic` set to true. CVE-2016-5180 reproduces from a
**2-byte** input. The seven targets that found nothing found nothing honestly.
