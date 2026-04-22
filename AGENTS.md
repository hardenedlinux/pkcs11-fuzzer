# Agent Instructions: pkcs11-fuzzer

This repository manages a continuous fuzzing stack for the PKCS#11 ecosystem (OpenSSL, libp11, SoftHSM2, OpenSC).

## Core Architecture
- **Multi-Tree Builds:** Sources are cloned into `src/` and built into three parallel instrumented trees in `builds/`: `libfuzzer` (ASan+UBSan), `tsan` (ThreadSanitizer), and `coverage` (Source coverage).
- **Harnesses:** Found in `harnesses/`. Most use a shared `pkcs11_init()` from `common.h` which restores a SoftHSM2 token snapshot to `/tmp/fuzz-token-$PID`.
- **Orchestration:** `build-scripts/` handles the complex dance of building the four libraries with the correct cross-references and sanitizer flags.

## Essential Commands

### Build & Setup
- **Full Build:** `./build-scripts/build-all.sh` (Add `--coverage-tree` if you need coverage reports).
- **Upstream Testing:** Add flags like `--upstream-softhsm2 --upstream-libp11 --upstream-opensc` to build against latest GitHub heads instead of pinned tags.
- **Typical build:** `--upstream-softhsm2 --upstream-libp11 --upstream-opensc --coverage-tree`
- **Build Harnesses:** `make -C harnesses` (Requires `builds/libfuzzer` to exist).
- **Generate Seeds:** `make -C harnesses seeds` (Crucial for opcode-driven harnesses).

### Verification & Fuzzing
- **Smoke Test:** `make -C harnesses smoke-test` (Runs every harness for 10s; best way to verify a build).
- **Run Fuzzers:** `bash fuzzing/run-libfuzzer.sh` (Launches all harnesses in parallel).
- **Generate Coverage:** `make -C harnesses coverage` followed by `bash tools/show-coverage`.

### Crash Analysis
- **Basic Replay:** `./tools/analyze.sh crashes/raw/<filename>`
- **Full Workflow:** `python3 tools/patch_workflow.py crashes/raw/<filename>` (Attempts minimization, classification, and candidate patch generation).

## Critical Quirks & Gotchas
- **OpenSSL Version:** Avoid `--upstream-openssl`. Upstream 4.x/master often breaks the other components. Stick to the pinned version in `common.sh` unless specifically requested.
- **Token Model:** If harnesses fail with "fuzz-token not found", ensure `token-template/` exists (run `./build-scripts/build-all.sh`).
- **Sanitizer Flags:** The project explicitly disables `vptr` and `function` sanitizers (`-fno-sanitize=vptr,function`) to avoid false positives in the PKCS#11 C ABI and OpenSSL engine logic.
- **ODR Violations:** Always run with `ASAN_OPTIONS=detect_odr_violation=0` when running `tls_pkcs11_fuzz` or `libp11_evp_fuzz` to avoid noise from static vs dynamic OpenSSL links.
- **Incremental Builds:** If a component build fails, wipe its tree-specific build dir (e.g., `src/softhsm2/build-libfuzzer`) before retrying.
- **LeakSanitizer:** Benign leaks in OpenSSL/ENGINE are suppressed via `fuzzing/lsan.suppressions`. If you see new leaks, check if they are iterative (growing per-call) or one-off (init-time).
- **Cleanup:** Use `bash tools/cleanup.sh --artifacts` to clear large corpus/crash/log files without wiping the expensive library builds.
- **Project Exploration:** If the exploration process requires building the project, use the typical build command: `./build-scripts/build-all.sh --upstream-softhsm2 --upstream-libp11 --upstream-opensc --coverage-tree`. (Note: always exclude `--upstream-openssl` unless explicitly requested).
- **Source Modifications:** You may modify the `src/` trees directly for study, exploration, or debugging. However, any permanent improvements to target libraries must be implemented as clean `.patch` files (compatible with `patch -p1`) and placed in `build-scripts/patches/` or managed via `tools/patch_workflow.py`.
- **OpenSC Mock Driver:** Set `OPENSC_MOCK_PCSC=1` in the environment to enable the fuzzer-friendly mock PC/SC driver. This is required for `opensc_pkcs11_fuzz` to find a virtual smart card.
