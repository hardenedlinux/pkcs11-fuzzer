# pkcs11-fuzzer

A self-contained, continuous fuzzing suite for the PKCS#11 stack:
**OpenSSL · libp11 · SoftHSM2 · OpenSC (pkcs11-tool)**.

Everything — compiler, sanitizer runtimes, target libraries — is built from
source with pinned versions. Clone the repo, install a handful of system
packages, run one script, and the fuzzer is running.

---

## What it does

| Layer | What is tested |
|---|---|
| **PKCS#11 C API** | `C_Sign`, `C_Decrypt`, `C_FindObjects`, `C_WrapKey`, `C_Digest`, `C_GenerateKeyPair`, multi-part streaming — via eight libFuzzer harnesses that call SoftHSM2 directly |
| **libp11 EVP bridge** | OpenSSL `EVP_DigestSign`/`EVP_DigestVerify`/`EVP_PKEY_decrypt` routed through the libp11 ENGINE translation layer into SoftHSM2 |
| **OpenSC PKCS#11** | OpenSC's own `opensc-pkcs11.so` module: initialization, slot enumeration, mechanism listing, and attribute-template parsing (no smart card required) |
| **TLS + PKCS#11** | Full TLS 1.2/1.3 handshake with a PKCS#11-backed private key loaded through the libp11 OpenSSL ENGINE |

When a crash is found the pipeline:
1. Notifies you (desktop, Slack, Discord, or email)
2. Deduplicates and triages the crash
3. Verifies reproducibility, minimizes the input, classifies false positives
4. Generates a maintainer-ready bug report with a `patch -p1`-ready diff

---

## Architecture

```
pkcs11-fuzzer/
├── build-scripts/          # One script per component; build-all.sh drives everything
│   ├── common.sh           # Pinned versions, per-tree CC/CFLAGS/LDFLAGS tables
│   ├── 02-build-openssl.sh
│   ├── 03-build-softhsm2.sh
│   ├── 04-build-libp11.sh
│   ├── 05-build-opensc.sh
│   ├── build-all.sh        # Master: runs components for both sanitizer trees + optional coverage tree
│   ├── init-token.sh       # Creates SoftHSM2 token with RSA/EC/AES keys; snapshots it
│   └── patches/            # Source patches applied after cloning (e.g. SoftHSM2 ↔ OpenSSL 3.4 compat)
│
├── builds/                 # Install roots (populated by build-all.sh)
│   ├── libfuzzer/          # ASan + UBSan + fuzzer-no-link  ← harness tree
│   ├── tsan/               # TSan                            ← race detection
│   └── coverage/           # -fprofile-instr-generate        ← source coverage (optional)
│
├── harnesses/              # libFuzzer fuzz targets (C)
│   ├── common.h            # Shared PKCS#11 session setup, token snapshot restore
│   ├── pkcs11_sign_fuzz.c  # C_Sign: RSA-PKCS1, RSA-PSS, ECDSA mechanisms
│   ├── pkcs11_decrypt_fuzz.c  # C_Decrypt: RSA-OAEP, AES-ECB/CBC/GCM
│   ├── pkcs11_findobj_fuzz.c  # C_FindObjects with arbitrary attribute templates
│   ├── pkcs11_wrap_fuzz.c     # C_WrapKey, C_UnwrapKey, C_DeriveKey (ECDH)
│   ├── pkcs11_attrs_fuzz.c    # C_GetAttributeValue, C_SetAttributeValue, C_CopyObject
│   ├── pkcs11_digest_fuzz.c   # C_Digest + multi-part C_DigestUpdate/Final (SHA/MD5)
│   ├── pkcs11_multipart_fuzz.c # C_SignUpdate/Final, C_VerifyUpdate/Final, C_Encrypt/DecryptUpdate/Final
│   ├── pkcs11_keygen_fuzz.c   # C_GenerateKeyPair (RSA/EC) and C_GenerateKey (AES)
│   ├── libp11_evp_fuzz.c      # EVP_DigestSign/Verify/decrypt via libp11 ENGINE → SoftHSM2
│   ├── opensc_pkcs11_fuzz.c   # opensc-pkcs11.so: slot enum, mechanism info, attribute templates
│   ├── tls_pkcs11_fuzz.c      # Full TLS handshake via libp11 ENGINE + PKCS#11 key
│   └── Makefile
│
├── fuzzing/                # Runtime scripts
│   ├── run-libfuzzer.sh    # Launch all libFuzzer harnesses in parallel
│   ├── minimize-corpus.sh  # Deduplicate corpus (libFuzzer -merge=1)
│   ├── triage-crashes.sh   # Deduplicate crashes by stack key
│   ├── gen-coverage.sh     # llvm-cov HTML report; FULL mode when coverage tree present
│   ├── lsan.suppressions   # LeakSanitizer rules for known-benign OpenSSL ENGINE leaks
│   ├── continuous.sh       # Orchestrator: monitor, restart, minimize, notify
│   ├── notify.sh           # Multi-channel crash notification
│   └── notify.conf         # Notification configuration (edit before use)
│
├── tools/
│   ├── analyze.py          # Crash analysis engine (Python 3, stdlib only)
│   ├── analyze.sh          # Shell wrapper: single crash or --all / --apply-patches
│   ├── patch_workflow.py   # End-to-end lifecycle: analyze→patch→rebuild→verify→revert
│   ├── patch_workflow.sh   # Shell wrapper: --batch, --status, --revert
│   ├── show-coverage       # Print coverage trend table from coverage/coverage.log
│   ├── summarize.py        # Session summary: bug counts, disk usage, findings JSON
│   └── cleanup.sh          # Tiered teardown: archive findings then clean up
│
├── corpus/                 # Seed + evolved corpus per harness
├── crashes/
│   ├── raw/                # Crash artifacts from fuzzers
│   ├── deduplicated/       # After triage-crashes.sh
│   └── analysis/           # Per-crash: report.md, patch.diff, reproducer.*
└── token-template/         # Read-only SoftHSM2 token snapshot (RSA-2048, EC P-256, AES-256)
```

### Build trees

| Tree | Compiler | Flags | Purpose |
|---|---|---|---|
| `libfuzzer` | system `clang` | ASan + UBSan + `fuzzer-no-link` | libFuzzer harnesses |
| `tsan` | system `clang` | TSan | Race condition detection |
| `coverage` | system `clang` | `-fprofile-instr-generate -fcoverage-mapping` | Source-level coverage of target libraries |

The `coverage` tree is optional. Build it with `--coverage-tree` when you want
per-source-line coverage across OpenSSL, SoftHSM2, libp11, and OpenSC.

All components are built in both sanitizer trees so the sanitizer instruments
the full call stack, including the PKCS#11 module loaded via `dlopen`.

---

## Prerequisites

System Clang/LLVM packages plus a handful of development libraries. No
custom compiler build required.

```bash
# Ubuntu 22.04 / 24.04 — system packages
sudo apt-get install -y \
    git make autoconf automake libtool \
    pkg-config gettext xsltproc \
    build-essential \
    clang lld \
    libsqlite3-dev libpcsclite-dev \
    libboost-filesystem-dev \
    zlib1g-dev

# For a specific LLVM version (https://apt.llvm.org):
#   sudo apt-get install clang-18 lld-18
# The build scripts auto-detect whichever version is in PATH.
```

No system OpenSSL or SoftHSM2 needed — we build them from source with
sanitizer flags so the full call stack is instrumented.

**Disk space:** ~4 GB  
**RAM:** 4 GB minimum  
**CPU:** Any; build time ~15 min on 8 cores

---

## Quick Start

```bash
git clone <this-repo> pkcs11-fuzzer
cd pkcs11-fuzzer

# 1. Build everything from source (~15 min on 8 cores)
bash build-scripts/build-all.sh

# 1a. Build specific components from upstream HEAD (use when a component
#     hasn't cut a release with a fix you need)
bash build-scripts/build-all.sh --upstream-softhsm2 --upstream-libp11

# 1b. Also build the coverage tree for source-level library coverage reports
bash build-scripts/build-all.sh --coverage-tree

# 2. Compile fuzzing harnesses (~30 seconds)
make -C harnesses/

# 3. (Optional) quick sanity check — runs each harness 10 s on seed corpus
make -C harnesses/ smoke-test

# 4. (Optional) configure notifications
cp fuzzing/notify.conf fuzzing/notify.conf.local
$EDITOR fuzzing/notify.conf   # add Slack webhook, email, etc.

# 5. Start continuous fuzzing (run in screen or tmux)
screen -dmS fuzz bash fuzzing/continuous.sh
screen -r fuzz
```

Crashes appear in `crashes/raw/` within minutes.

### Code Coverage

Generate a seed corpus first, then run coverage after fuzzing for meaningful numbers:

```bash
make -C harnesses/ seeds              # generate seed corpus
make -C harnesses/ coverage            # FULL mode: OpenSSL+SoftHSM2+libp11+OpenSC
bash tools/show-coverage               # print coverage trend table
tail -f coverage/<harness>.log | grep -E 'NEW|PULSE'  # real-time cov growth
```

---

## PKCS#11 Component Roles

The "p11" prefix appears on several distinct projects. This table clarifies
what each one does and why it is (or is not) part of this fuzzer.

| Component | What it is | Role in this project |
|---|---|---|
| **libp11** (`github.com/OpenSC/libp11`) | An OpenSSL ENGINE/PROVIDER adapter that bridges OpenSSL's crypto API to any PKCS#11 module | **Built locally.** Used by `tls_pkcs11_fuzz` to route TLS handshake signing through SoftHSM2. Lives at `builds/*/lib/engines-3/pkcs11.so`. |
| **SoftHSM2** (`libsofthsm2.so`) | A software PKCS#11 token — implements the full PKCS#11 C API backed by OpenSSL crypto | **Built locally.** The actual HSM backend. All harnesses `dlopen` it directly. |
| **OpenSC** (`pkcs11-tool`) | A toolkit for smart cards; includes `pkcs11-tool`, a CLI that exercises any PKCS#11 module | **Built locally.** `pkcs11-tool` binary is part of the project scope. |
| **p11-kit** (system package) | A system-wide PKCS#11 module **registry and proxy** — lets apps find modules without knowing their path. Reads `/usr/share/p11-kit/modules/*.module` config files | **Not used.** Disabled in the SoftHSM2 build with `--without-p11-kit`. See below. |

### Why p11-kit is excluded

When SoftHSM2 is built with p11-kit support enabled (the default), `make
install` tries to write `softhsm2.module` to `/usr/share/p11-kit/modules/`
— a system directory that requires root. Since the entire project is designed
to run without elevated privileges, and our harnesses load `libsofthsm2.so`
by its absolute path anyway, p11-kit integration provides no value here.

```
# What we DON'T want (p11-kit path — requires system access):
Some app  →  p11-kit proxy  →  reads /usr/share/p11-kit/modules/softhsm2.module
                             →  loads libsofthsm2.so

# What we DO (direct path — fully self-contained):
Harness / libp11  →  dlopen("builds/libfuzzer/lib/softhsm/libsofthsm2.so")
```

`--without-p11-kit` is set in `build-scripts/03-build-softhsm2.sh` for both
sanitizer trees.

---

## Component Versions

All versions are pinned in `build-scripts/common.sh` — change them there
to upgrade any component.

| Component | Pinned version | Source |
|---|---|---|
| OpenSSL | 3.6.2 | github.com/openssl/openssl |
| SoftHSM2 | 2.6.1 | github.com/softhsm/SoftHSMv2 |
| libp11 | 0.4.18 | github.com/OpenSC/libp11 |
| OpenSC | 0.27.1 | github.com/OpenSC/OpenSC |

Use `--upstream-<component>` to build a specific component from its upstream HEAD
instead of the pinned tag. See [Upstream build mode](#upstream-build-mode).

---

## Build Details

### Clone strategy

All component repos (OpenSSL, SoftHSM2, libp11, OpenSC) are cloned with full
history. This lets you run `git log`, `git bisect`, and `git diff` against
any commit in the tree.

### Upstream build mode

Some components release infrequently. Use per-component flags to build only
the components you need from upstream, keeping the rest at their pinned versions:

```bash
# Only SoftHSM2 and libp11 from upstream; OpenSSL and OpenSC stay pinned
bash build-scripts/build-all.sh --upstream-softhsm2 --upstream-libp11

# All components from upstream HEAD (use with caution — see caveat below)
bash build-scripts/build-all.sh --upstream

# Only rebuild a single component from upstream
rm -rf src/opensc
bash build-scripts/build-all.sh --upstream-opensc
```

**Caveat — upstream incompatibility**: component heads can be mutually
incompatible. For example, OpenSSL 4.x made `asn1_string_st` fully opaque
before SoftHSM2 adapted to the new accessor API. The build scripts include a
compatibility patch (`build-scripts/patches/softhsm2-asn1-opaque.patch`)
that is applied automatically after cloning, but other incompatibilities may
surface when mixing upstream components. Always test with `make -C harnesses/
smoke-test` after an upstream build.

When `clone_if_needed` detects that the current upstream flag or pinned tag
differs from the previously cloned version it automatically wipes and re-clones,
keeping the source tree in sync with what was requested. Local modifications
(e.g. patches applied by `patch_workflow.py`) are protected — a source
directory with uncommitted changes is never wiped.

### Incremental rebuilds

`build-all.sh` skips already-installed components. To force a full rebuild
of one tree, delete its install root and re-run:

```bash
rm -rf builds/libfuzzer
bash build-scripts/build-all.sh   # rebuild the libfuzzer tree
```

To rebuild a single component:

```bash
rm -rf src/softhsm2/build-libfuzzer
bash build-scripts/03-build-softhsm2.sh libfuzzer
```

### Build scripts

Each script is self-contained, idempotent, and sources `common.sh` for
shared configuration. Run any of them standalone:

```bash
bash build-scripts/02-build-openssl.sh tsan     # rebuild OpenSSL for TSan tree
bash build-scripts/05-build-opensc.sh tsan     # rebuild OpenSC for TSan tree
bash build-scripts/init-token.sh               # re-create token snapshot
```

### Sanitizer notes

- **`-fsanitize=vptr` is disabled** across all trees. PKCS#11 shared
  libraries use C-style `void*` function pointers that UBSan's vptr check
  would flag as false positives across `dlopen` boundaries.
- **`-fsanitize=function` is disabled** across all trees. OpenSSL and
  SoftHSM2 use intentional C-style function pointer casts (ENGINE API,
  factory pattern) that trigger this Clang-specific check benignly.
- **`-fno-sanitize-recover=undefined`** is set so UBSan aborts on the first
  finding rather than continuing (makes crash artifacts deterministic).
- **`detect_leaks=0`** is set during `./configure` runs only. Autoconf
  feature-probe binaries allocate objects without freeing them (intentional),
  and ASan's LeakSanitizer would otherwise cause configure checks to report
  false failures (e.g. SoftHSM2's EC key support test).
- **libFuzzer** is provided by the system Clang package. Target libraries
  are compiled with `-fsanitize=fuzzer-no-link` so the engine is not
  embedded in them; Clang resolves `libclang_rt.fuzzer_no_main` automatically
  from its resource directory. Harness executables link with `-fsanitize=fuzzer`
  to bring in the engine and its `main()`.

### Build isolation notes

- **`--without-p11-kit`** is passed to SoftHSM2's configure. Without it,
  `make install` attempts to write a module registration file to the
  system-wide `/usr/share/p11-kit/modules/` directory, which requires root
  and is outside the project tree. See the [PKCS#11 Component Roles](#pkcs11-component-roles) section for context.
- **`no-shared`** is used for OpenSSL so libraries are static `.a` files.
  `-fPIC` is added so downstream shared libraries (SoftHSM2, libp11, OpenSC)
  can link the static archives in.
- **`no-fuzz-libfuzzer`** is passed to OpenSSL's
  Configure to prevent it from building its own internal fuzz targets.

---

## Harnesses

### Input format

Each harness splits the fuzz input at the first byte:

```
byte 0:       mechanism / operation selector
byte 1..end:  parameters and payload
```

This gives libFuzzer semantic coverage — it can learn which mechanisms are
valid and what parameter structures look like — rather than spending budget
on rejected calls.

### Harness details

There are **11 harnesses** covering four distinct code paths into the PKCS#11 stack:

| Harness | Operations fuzzed | Code paths reached |
|---|---|---|
| `pkcs11_sign_fuzz` | `C_SignInit + C_Sign` | RSA-PKCS1, RSA-PSS (fuzzed params), ECDSA |
| `pkcs11_decrypt_fuzz` | `C_DecryptInit + C_Decrypt` | RSA-PKCS1, RSA-OAEP (fuzzed params), AES-ECB/CBC/GCM |
| `pkcs11_findobj_fuzz` | `C_FindObjectsInit + C_FindObjects + C_GetAttributeValue` | Object search and attribute retrieval |
| `pkcs11_wrap_fuzz` | `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey` | Key export/import, ECDH derivation |
| `pkcs11_attrs_fuzz` | `C_GetAttributeValue`, `C_SetAttributeValue`, `C_CopyObject` | Attribute read/write/copy |
| `pkcs11_digest_fuzz` | `C_Digest` (single-part) + `C_DigestUpdate/Final` (multi-part) | SHA-1/256/384/512, MD5 hash paths |
| `pkcs11_multipart_fuzz` | `C_SignUpdate/Final`, `C_VerifyUpdate/Final`, `C_Encrypt/DecryptUpdate/Final` | State machine: Init→Update×N→Final for all operations |
| `pkcs11_keygen_fuzz` | `C_GenerateKeyPair` (RSA 512–1024 bit, EC P-256/384/521), `C_GenerateKey` (AES) | Key generation, prime generation, boundary validation |
| `libp11_evp_fuzz` | `EVP_DigestSign`, `EVP_DigestVerify`, `EVP_PKEY_decrypt` (multi-part variants) | **libp11 ENGINE bridge**: OpenSSL EVP → libp11 callbacks → PKCS#11 → SoftHSM2. Distinct from all other harnesses which bypass libp11 entirely. |
| `opensc_pkcs11_fuzz` | `C_GetSlotInfo`, `C_GetMechanismList`, `C_FindObjectsInit` with arbitrary attribute templates, `C_Initialize`/`C_Finalize` cycle | **OpenSC's PKCS#11 module** (`opensc-pkcs11.so`): exercises OpenSC's context creation, reader enumeration, slot management, and attribute template parsing. No smart card required. |
| `tls_pkcs11_fuzz` | Full TLS 1.2/1.3 handshake with PKCS#11-backed private key via libp11 ENGINE | TLS parsing, ENGINE API, PKCS#11 key delegation |

### Token state

`LLVMFuzzerInitialize()` (called once per process) restores the read-only
token snapshot from `token-template/` into a fresh per-process tmpfs path
and opens a PKCS#11 session. The session is reused across all
`LLVMFuzzerTestOneInput()` calls for throughput.

Keys in the token:
- `id=01` RSA-2048 key pair (`rsa-fuzz-key`)
- `id=02` EC P-256 key pair (`ec-fuzz-key`)
- `id=03` AES-256 secret key (`aes-fuzz-key`)

---

## Running the Fuzzers

### libFuzzer (PKCS#11 API harnesses)

```bash
export ASAN_OPTIONS="halt_on_error=1:detect_leaks=1:symbolize=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

bash fuzzing/run-libfuzzer.sh            # run forever
bash fuzzing/run-libfuzzer.sh --time 3600  # run for 1 hour
```

`run-libfuzzer.sh` automatically sets `LSAN_OPTIONS=suppressions=fuzzing/lsan.suppressions`
which filters known-benign OpenSSL ENGINE exit-time leaks so they do not
generate false crash artifacts.

### Continuous orchestrator

```bash
# Run in a detached screen session
screen -dmS fuzz bash fuzzing/continuous.sh

# Environment overrides
FUZZ_DURATION_H=48      bash fuzzing/continuous.sh   # stop after 48 h
FUZZ_MIN_INTERVAL=3600  bash fuzzing/continuous.sh   # minimize corpus every 1 h
FUZZ_COV_INTERVAL=43200 bash fuzzing/continuous.sh   # coverage report every 12 h
```

The orchestrator:
- Restarts dead fuzzer processes automatically
- Calls `triage-crashes.sh` and `notify.sh` within 60 s of a new crash
- Minimizes corpus every 6 hours (configurable via `FUZZ_MIN_INTERVAL`)
- Generates a coverage report every 24 hours (configurable via `FUZZ_COV_INTERVAL`)

### TSan (race detection)

The `tsan` tree is intended for running functional tests and workloads
concurrently against SoftHSM2 / pkcs11-tool, not for libFuzzer
(those use ASan). Example:

```bash
export SOFTHSM2_CONF=builds/tsan/etc/softhsm2.conf
# Run your concurrent PKCS#11 workload against builds/tsan/lib/softhsm/libsofthsm2.so
```

---

## Code Coverage

Coverage monitoring works at three levels.

### 1. Real-time during fuzzing (always available)

```bash
tail -f coverage/pkcs11_sign_fuzz.log | grep -E 'NEW|PULSE'
# #1423 NEW  cov: 3842 ft: 9102 corp: 87/4Kb  exec/s: 412
```

| Field | Meaning |
|---|---|
| `cov` | Basic blocks covered across the full instrumented stack (harness + SoftHSM2 + OpenSSL + libp11) |
| `ft` | Feature count — edges + value profiles (more sensitive than `cov`) |
| `corp` | Corpus size (entries / bytes) |

When `cov` and `ft` stop growing, the corpus has saturated reachable code — that is the signal to improve harness input variety or add new harnesses.

### 2. Per-component source coverage (coverage tree required)

Build the coverage tree once, then regenerate after each fuzzing session:

```bash
# Build once (~15 min, ~4 GB extra disk)
bash build-scripts/build-all.sh --coverage-tree

# After fuzzing — replay evolved corpus through coverage-instrumented binaries
make -C harnesses/ coverage

# View per-component breakdown (default)
bash tools/show-coverage
```

Sample output:
```
Component     Lines                         Functions                     Regions
────────────────────────────────────────────────────────────────────────────────────
softhsm2      ███░░░░░░░░░░░░░░░░░  17.61%  ███████░░░░░░░░░░░░░  36.24%  …  pkcs11_keygen_fuzz
openssl       █░░░░░░░░░░░░░░░░░░░   6.10%  ██░░░░░░░░░░░░░░░░░░  11.43%  …  pkcs11_sign_fuzz
libp11        ░░░░░░░░░░░░░░░░░░░░   0.00%  …   (exercised by libp11_evp_fuzz)
opensc        ░░░░░░░░░░░░░░░░░░░░   0.00%  …   (exercised by opensc_pkcs11_fuzz)
```

**Why libp11 and OpenSC show 0 % by default**: the eight PKCS#11 harnesses route directly to SoftHSM2, bypassing libp11 and `libopensc.so`. `libp11_evp_fuzz` and `opensc_pkcs11_fuzz` exercise those libraries; once their corpus evolves, the percentages will grow.

`show-coverage` flags:
```bash
bash tools/show-coverage                         # per-component (default)
bash tools/show-coverage --totals                # per-harness TOTAL view
bash tools/show-coverage --harness <name>        # component trend for one harness
bash tools/show-coverage --all                   # full raw log
```

**How the profiling works**: Clang's `-fprofile-instr-generate` runtime is process-global. When `libsofthsm2.so` (built with coverage flags, embedding a coverage-instrumented OpenSSL) is `dlopen`'d, all of SoftHSM2's and OpenSSL's counters are written to the same `.profraw` file. `llvm-cov show -object=libsofthsm2.so` then attributes those counters to their original source lines. The same mechanism applies to `pkcs11.so` (libp11) and `libopensc.so`.

### 3. Harness-only coverage (no coverage tree needed)

Without `builds/coverage/`, `gen-coverage.sh` falls back to harness-only mode — it only shows coverage of the harness `.c` files themselves (~100–300 lines). Useful as a quick sanity check that all harness branches are reachable.

---

## Corpus Management

```bash
# Generate initial seed corpus
make -C harnesses/ seeds

# Minimize after a fuzzing run
bash fuzzing/minimize-corpus.sh

# Generate HTML coverage report
bash fuzzing/gen-coverage.sh
# → coverage/<harness>/index.html
```

---

## Patch Workflow Tool

`tools/patch_workflow.py` is the end-to-end crash lifecycle tool. It chains
analysis, reproduction, patching, rebuild, and verification into a single
command, and keeps the state needed to revert at any time.

### Five stages

```
1. ANALYZE    → Run analyze.py; confirm crash is real (not a FP); generate patch
2. REPRODUCE  → Replay crash under harness to establish baseline
3. PATCH      → Apply patch.diff (dry-run first); back up original source files
4. REBUILD    → Clean + rebuild only the affected component (auto-detected from patch)
5. VERIFY     → Re-run harness with same input; confirm no sanitizer report
```

If verification fails the patch is automatically reverted. Original source
files are restored and the component is rebuilt. A JSON state file is always
written so you can revert later, even after the tool has exited.

### Usage

```bash
# Full pipeline on one crash
python3 tools/patch_workflow.py crashes/raw/pkcs11_findobj_fuzz-crash-abc123

# Interactive mode — prompt before patching and before rebuilding
python3 tools/patch_workflow.py --interactive crashes/raw/pkcs11_findobj_fuzz-crash-abc123

# Re-use a previous analysis (skip re-analysis)
python3 tools/patch_workflow.py \
    --analysis crashes/analysis/pkcs11_findobj_fuzz-crash-abc123 \
    crashes/raw/pkcs11_findobj_fuzz-crash-abc123

# Shell wrapper: process all raw crashes in batch
bash tools/patch_workflow.sh --batch

# Show status table of all previous runs
bash tools/patch_workflow.sh --status

# Revert a patch (source restored + component rebuilt to pre-patch state)
python3 tools/patch_workflow.py \
    --revert crashes/analysis/pkcs11_findobj_fuzz-crash-abc123/workflow_state.json
```

### Outcome codes

| Outcome | Meaning |
|---|---|
| `FIXED` | Patch applied, rebuild succeeded, crash no longer reproduces |
| `STILL_VULNERABLE` | Patch applied but crash still triggers — auto-reverted |
| `REVERTED` | User or tool reverted the patch; source is back to pre-patch state |
| `NOT_REPRODUCIBLE` | Crash did not trigger — possibly already fixed or fluke |
| `FALSE_POSITIVE` | Crash matched a known-benign pattern; no patch needed |
| `NO_PATCH` | Bug confirmed real but no automated patch template matches |
| `ANALYSIS_FAILED` | analyze.py could not parse the crash |
| `PATCH_FAILED` | Generated diff did not apply cleanly |
| `BUILD_FAILED` | Component rebuild failed after patching; patch auto-reverted |

### State file

Every run writes `crashes/analysis/<crash>/workflow_state.json`:

```json
{
  "crash_file":       "...",
  "harness":          "pkcs11_findobj_fuzz",
  "patch_file":       "...",
  "reproducible":     true,
  "patch_applied":    true,
  "rebuilt":          true,
  "verified_fixed":   true,
  "backed_up_files":  { "/abs/path/SoftHSM.cpp": "/abs/backup/SoftHSM.cpp" },
  "component_script": "03-build-softhsm2.sh",
  "rebuild_tree":     "libfuzzer",
  "stage":            "verified",
  "outcome":          "FIXED"
}
```

The `backed_up_files` map lets `--revert` restore the exact pre-patch content
even if `patch --reverse` fails (e.g. the file was modified after patching).

---

## Crash Analysis

The recommended entry point for handling a new crash is the **patch workflow
tool**, which automates the full cycle. Use `analyze.py` directly when you
want only the analysis step without applying a patch.

### Automated pipeline (patch_workflow — recommended)

```bash
# One command: analyze → reproduce → patch → rebuild → verify
python3 tools/patch_workflow.py crashes/raw/<crash_file>

# Interactive: pause and prompt before applying the patch
python3 tools/patch_workflow.py --interactive crashes/raw/<crash_file>

# Process every crash in crashes/raw/ in one pass
bash tools/patch_workflow.sh --batch

# See outcomes of all previous runs
bash tools/patch_workflow.sh --status

# Undo a patch at any time
python3 tools/patch_workflow.py --revert crashes/analysis/<crash>/workflow_state.json
```

### Analysis only (analyze.py)

```bash
# Analyze one crash: verify, minimize, FP-check, patch
python3 tools/analyze.py crashes/raw/pkcs11_findobj_fuzz-crash-abc123

# Analyze all crashes and print a summary
bash tools/analyze.sh --all

# Apply all generated patches (dry-run first is recommended)
patch -p1 --dry-run < crashes/analysis/<crash>/patch.diff
bash tools/analyze.sh --apply-patches
```

### What the analyzer produces

```
crashes/analysis/<crash_name>/
├── report.md       # Severity, summary, reproduction steps, source context, patch
├── patch.diff      # patch -p1 ready (apply from project root)
├── reproducer.bin  # Minimized crash input
├── reproducer.sh   # Standalone script — no build knowledge needed
└── analysis.json   # Machine-readable (CI integration)
```

### Analysis steps

| Step | What happens |
|---|---|
| 1. Verify | Replays crash under harness; confirms reproducibility |
| 2. Parse | Extracts sanitizer type, bug subtype, full C++ stack frames |
| 3. False-positive check | Matches against known-benign patterns (OpenSSL threading, factory patterns) |
| 4. Source context | Reads ±8 lines around crash site; highlights the crash line |
| 5. Minimize | Runs `libFuzzer -minimize_crash=1` to find smallest reproducer |
| 6. Patch | Pattern-based diff for known bug types; flags others for manual review |

### Automated patch patterns

| Bug subtype | Pattern detected | Patch generated |
|---|---|---|
| `misaligned-access` | `*(CK_ULONG_PTR)pValue` | Replace with `memcpy(&val, pValue, sizeof(val))` |
| `null-deref` (empty vector) | `memcpy(&vec[0], ptr, 0)` | Wrap with `if (len > 0)` guard |

Other bug types (heap-overflow, integer-overflow, etc.) receive a full report
and source context but require a manual fix.

---

## Notifications

Edit `fuzzing/notify.conf` to enable one or more channels:

```bash
# Desktop popup (Linux X11/Wayland)
NOTIFY_DESKTOP=1

# Slack
NOTIFY_SLACK_WEBHOOK="https://hooks.slack.com/services/T.../B.../xxx"

# Discord
NOTIFY_DISCORD_WEBHOOK="https://discord.com/api/webhooks/123/abc"

# Generic HTTP webhook  (POST {"level":..., "text":...})
NOTIFY_WEBHOOK_URL="https://your-endpoint/hook"

# Email (requires local `mail` command)
NOTIFY_EMAIL="team@example.com"
```

Notifications fire for:
- New crash detected (with deduplication, crash type, reproducer path)
- Fuzzer process restarted after unexpected exit
- Fuzzing session started / stopped

Send a test notification manually:

```bash
bash fuzzing/notify.sh crash "Test" "This is a test notification"
```

---

## Extending the Fuzzer

### Adding a new harness

1. Create `harnesses/my_fuzz.c` — implement `LLVMFuzzerInitialize` (call
   `pkcs11_init()`) and `LLVMFuzzerTestOneInput`.
2. Add it to `PKCS11_HARNESSES` in `harnesses/Makefile`.
3. Add seed files in `corpus/my/`.
4. Add it to the `HARNESSES` array in `fuzzing/run-libfuzzer.sh` and
   `fuzzing/gen-coverage.sh`.
5. Add seed generation in the `seeds` Makefile target.

### Adding a new patch pattern

Extend the `generate_patch()` function in `tools/analyze.py` with a new
`if ci.bug_subtype == "..."` block that matches the UBSan/ASan error string
and produces a replacement line list.

### Upgrading a component

Edit the `*_TAG` variables in `build-scripts/common.sh`, delete the
corresponding `src/<component>` directory, and re-run `build-all.sh`.

---

## Wrapping Up a Session

When a fuzzing task is complete and you are moving on, use the cleanup tool
to summarise findings, optionally hand them off, and free disk space.

### 1. Review what was found

```bash
python3 tools/summarize.py
```

Prints a session summary (crash counts, confirmed bugs, disk usage) and
writes `crashes/findings_summary.json`.

### 2. Archive findings for handoff (optional)

Creates a self-contained directory with reports, patches, reproducers, and
a README that anyone can use without knowing the project internals.

```bash
bash tools/cleanup.sh --archive=/path/to/handoff/dir --summary
```

The archive contains:

```
handoff/
├── ARCHIVE_README.md              # How to reproduce and apply patches
├── findings_summary.json          # Machine-readable bug list
├── notifications.log              # Timestamped crash events
├── analysis/
│   └── <crash>/
│       ├── report.md              # Human-readable bug report
│       ├── patch.diff             # Ready to apply with patch -p1
│       ├── reproducer.bin         # Minimized crash input
│       ├── reproducer.sh          # Standalone reproduction script
│       └── workflow_state.json    # Full patch lifecycle record
└── deduplicated/                  # Unique crash inputs (one per bug)
```

### 3. Clean up

Choose how much to remove. Each tier is independent — combine freely.

```bash
# Preview without deleting anything
bash tools/cleanup.sh --dry-run --all

# Artifacts only: crashes, corpus, coverage, harness binaries
bash tools/cleanup.sh --soft

# Artifacts + sanitized target builds (builds/{libfuzzer,tsan})
# Rebuild time: ~15 min.
bash tools/cleanup.sh --hard

# Full teardown — everything that can be regenerated (~4 GB)
# Rebuild time: ~15 min.
bash tools/cleanup.sh --all
```

Interactive mode (no flags) presents a menu, shows sizes, and asks for
confirmation — including an offer to archive findings before deleting:

```bash
bash tools/cleanup.sh
```

### Cleanup tiers

| Flag | What is removed | How to rebuild |
|---|---|---|
| `--artifacts` | Crash artifacts, **corpus files** (empty dirs kept for quick restart), `coverage/`, harness binaries, `token-template/` | `make -C harnesses/` + `init-token.sh` |
| `--targets` | Above + `builds/{libfuzzer,tsan}/`, `src/*/build-<tree>/`, **entire `corpus/` tree** | `build-all.sh` (~15 min) |
| `--sources` | All `src/` git clones | `build-all.sh` (re-clones + builds) |
| `--all` | All four tiers | `build-all.sh` (~45 min) |

**Note on corpus directories:** `--soft` (`--artifacts` alone) deletes all corpus
files but leaves the empty subdirectories (e.g. `corpus/pkcs11-sign/`). This is
intentional — libFuzzer can restart immediately without recreating them. On
`--hard` and `--all`, the entire `corpus/` tree is removed.

What is **never** deleted regardless of flags: `build-scripts/`, `harnesses/*.c`,
`harnesses/*.h`, `harnesses/Makefile`, `fuzzing/`, `tools/`, `README.md`.

---

## Troubleshooting

### Build fails with `Permission denied: /usr/share/p11-kit/modules/softhsm2.module`

SoftHSM2 was configured with p11-kit support enabled. `build-scripts/03-build-softhsm2.sh`
already passes `--without-p11-kit` to prevent this. If you see this error
on a clean checkout, verify the script contains that flag:

```bash
grep "without-p11-kit" build-scripts/03-build-softhsm2.sh
```

### SoftHSM2 builds without ECC support (`WITH_ECC` is `#undef`)

ASan's LeakSanitizer fires during autoconf's EC key feature probe, causing
configure to think EC is unavailable. The build script suppresses leaks
during `./configure` with `ASAN_OPTIONS=detect_leaks=0`, then re-enables
them for the actual build. If you see `WITH_ECC` undefined in
`src/softhsm2/build-<tree>/config.h`, delete the build dir and rebuild:

```bash
rm -rf src/softhsm2/build-libfuzzer
bash build-scripts/03-build-softhsm2.sh libfuzzer
```

### OpenSC build fails with `Only one of --enable-pcsc ... can be specified`

OpenSC 0.25.x requires exactly one smartcard reader driver to be enabled.
With `--disable-pcsc` and all other drivers at their default-off state, zero
drivers are enabled and configure errors out. The build script uses
`--enable-pcsc` (pcsc-lite headers are available as a build dependency), which
gives OpenSC a valid reader driver while not affecting PKCS#11 module
(`libsofthsm2.so`) access — our harnesses bypass the reader layer entirely.

### Duplicate `-fsanitize=...` flags in build output

When `capture=False` is used for the build log, libtool verbose output shows
the sanitizer flags appearing twice in the link command — once from `CFLAGS`
(set at configure time) and once from `LDFLAGS`. This is normal; the compiler
deduplicates them and it has no effect on the output binary.

---

## File Reference

| Path | Description |
|---|---|
| `build-scripts/common.sh` | Single source of truth: versions, paths, per-tree compiler flags; `clone_if_needed` protects locally-modified sources from accidental re-clone |
| `build-scripts/build-all.sh` | One-command full build; `--coverage-tree` adds profiling tree; `--upstream-<comp>` for per-component upstream; idempotent skip logic via built-stamps |
| `build-scripts/init-token.sh` | SoftHSM2 token init; re-run after rebuilding SoftHSM2 |
| `build-scripts/patches/` | Source patches applied after cloning (e.g. SoftHSM2 ↔ OpenSSL 3.4 ASN1 compatibility) |
| `harnesses/common.h` | Shared PKCS#11 session setup (`pkcs11_init`, token snapshot restore) |
| `harnesses/Makefile` | Builds all 11 harnesses; `make seeds`, `make smoke-test`, `make coverage`; `OPENSC_PKCS11_PATH` DEFS |
| `fuzzing/run-libfuzzer.sh` | Launches all 11 harnesses; sets `ASAN_OPTIONS`, `LSAN_OPTIONS`, `ASAN_SYMBOLIZER_PATH` |
| `fuzzing/lsan.suppressions` | LeakSanitizer rules suppressing known-benign OpenSSL ENGINE global leaks |
| `fuzzing/gen-coverage.sh` | FULL mode (coverage tree present): per-source-line + per-component report for all target libs; harness-only fallback otherwise |
| `fuzzing/continuous.sh` | Main entry point for production fuzzing |
| `fuzzing/notify.conf` | Notification channel configuration |
| `tools/analyze.py` | Crash verification, FP classification, minimization, patch generation |
| `tools/analyze.sh` | Shell wrapper: `-h`/`--help`, single crash, `--all`, `--apply-patches`, `--harness`, `--minimize-timeout` |
| `tools/patch_workflow.py` | End-to-end lifecycle: analyze → reproduce → patch → rebuild → verify → revert. Reads `.clone-stamp` to preserve upstream flags during rebuild so `clone_if_needed` does not wipe patched source. |
| `tools/patch_workflow.sh` | Shell wrapper: `--batch`, `--status`, `--revert` |
| `tools/show-coverage` | Per-component coverage bar chart (default); `--totals`, `--harness <name>`, `--all` views |
| `tools/summarize.py` | Session summary: crash counts, confirmed bugs, disk usage, findings JSON |
| `tools/cleanup.sh` | Tiered teardown: archive findings, clean artifacts/builds/sources |
| `token-template/` | Read-only SoftHSM2 token snapshot; restored per fuzzing process |
| `corpus/` | Seed + evolved corpus; committed seeds, evolved entries gitignored |
| `crashes/raw/` | Crash artifacts from libFuzzer |
| `crashes/analysis/` | Per-crash reports, patches, reproducers |
| `coverage/` | HTML coverage reports + `coverage.log` trending data (per-harness totals + per-component breakdown) + fuzzer logs |
