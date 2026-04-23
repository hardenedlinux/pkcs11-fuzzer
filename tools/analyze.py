#!/usr/bin/env python3
"""
tools/analyze.py — Bug verification, false-positive classification,
                   reproducible-steps generation, and patch creation.

Usage:
    python3 tools/analyze.py <crash_file> [--harness <name>] [--output <dir>]

For each confirmed bug it produces:
    <output_dir>/
        report.md          — Maintainer-ready bug report with repro steps
        reproducer.bin     — Minimized crash input
        reproducer.sh      — Shell script that reproduces the bug standalone
        patch.diff         — Unified diff ready for `patch -p1`
        analysis.json      — Machine-readable analysis for CI/tooling
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Project layout (resolved relative to this script's location)
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
BUILDS = PROJECT_ROOT / "builds"
HARNESSES = PROJECT_ROOT / "harnesses"
LIBFUZZER = BUILDS / "libfuzzer"

ASAN_ENV = {
    "ASAN_OPTIONS": "halt_on_error=0:detect_leaks=0:symbolize=1",
    "UBSAN_OPTIONS": "halt_on_error=0:print_stacktrace=1:symbolize=1",
    "SOFTHSM2_CONF": str(LIBFUZZER / "etc" / "softhsm2.conf"),
}


# ---------------------------------------------------------------------------
# Runtime version detection
# ---------------------------------------------------------------------------
def _run_version(cmd: list, pattern: str, fallback: str = "unknown") -> str:
    """Run a command and extract a version string via regex.

    Combines stdout and stderr so tools that print version info on either
    stream (e.g. softhsm2-util --version writes to stderr) are handled
    uniformly.
    """
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5
        )
        out = result.stdout.strip()
        m = re.search(pattern, out)
        return m.group(1) if m else (out.splitlines()[0] if out else fallback)
    except Exception:
        return fallback


def detect_component_versions() -> dict:
    """Query actual installed versions from built binaries and system GCC.

    Returns a dict suitable for embedding in generated reports.  When a
    component has not been built yet its entry reads 'not built'.
    """
    v: dict = {}

    openssl_bin = LIBFUZZER / "bin" / "openssl"
    v["OpenSSL"] = (
        _run_version([str(openssl_bin), "version"], r"OpenSSL\s+(\S+)")
        if openssl_bin.exists()
        else "not built"
    )

    softhsm_bin = LIBFUZZER / "bin" / "softhsm2-util"
    v["SoftHSM2"] = (
        _run_version([str(softhsm_bin), "--version"], r"(\d+\.\d+[\.\d]*)")
        if softhsm_bin.exists()
        else "not built"
    )

    pkcs11_tool = LIBFUZZER / "bin" / "pkcs11-tool"
    v["OpenSC"] = (
        _run_version([str(pkcs11_tool), "--version"], r"(\d+\.\d+[\.\d]*)")
        if pkcs11_tool.exists()
        else "not built"
    )

    v["Compiler"] = _run_version(
        ["gcc", "--version"], r"(gcc.*)", fallback="GCC (system)"
    )

    return v


# ---------------------------------------------------------------------------
# Known false-positive patterns (regex matched against sanitizer output)
# ---------------------------------------------------------------------------
FALSE_POSITIVE_PATTERNS = [
    # OpenSSL threading init — race in static init, harmless
    (
        r"threads_pthread\.c:\d+",
        "OpenSSL threading init (known benign race in static init)",
    ),
    # OpenSSL stack.c function pointer cast — benign UBSan vptr finding
    (
        r"crypto/stack/stack\.c:\d+",
        "OpenSSL OPENSSL_sk_pop_free function pointer (benign UBSan vptr finding, -fno-sanitize=vptr suppresses it)",
    ),
    # SoftHSM2 factory pattern — C-style void* factory, not exploitable
    (
        r"ObjectStoreToken\.cpp:77",
        "SoftHSM2 factory pattern (C-style void* function pointer, not exploitable)",
    ),
    # libstdc++ internals triggered by legit C++ usage
    (r"stl_algo\b.*stl_algo", "libstdc++ algorithm internal"),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class StackFrame:
    index: int
    address: str
    function: str
    file: str
    line: int
    column: int = 0


@dataclass
class CrashInfo:
    crash_file: str
    harness: str
    harness_binary: str
    sanitizer_type: str  # "ASan" | "UBSan" | "Unknown"
    bug_subtype: str  # "misaligned-access" | "null-deref" | "heap-overflow" | ...
    summary_line: str
    runtime_error: str
    stack: List[StackFrame] = field(default_factory=list)
    crash_location: Optional[StackFrame] = None
    is_false_positive: bool = False
    fp_reason: str = ""
    reproducible: bool = False
    source_context: str = ""
    repro_attempts: int = 1
    reproduced_on_attempt: int = 0


@dataclass
class BugReport:
    crash_info: CrashInfo
    minimal_input: bytes
    minimal_input_hex: str
    repro_command: str
    patch: str
    patch_description: str
    report_markdown: str
    analysis_json: dict


# ---------------------------------------------------------------------------
# Step 1: Detect harness from crash filename
# ---------------------------------------------------------------------------
def discover_harnesses() -> List[str]:
    """Return all harness names inferred from harness source files.

    Keeping this dynamic avoids stale hard-coded lists when new fuzz targets are
    added but the analysis tooling is not updated in lockstep.
    """

    return sorted(
        p.stem
        for p in HARNESSES.glob("*_fuzz.c")
        if p.name != "common.h"
    )


KNOWN_HARNESSES = discover_harnesses()


def detect_harness(crash_file: Path) -> Optional[str]:
    name = crash_file.name
    for h in KNOWN_HARNESSES:
        if name.startswith(h + "-") or name.startswith(h + "_"):
            return h
    return None


# ---------------------------------------------------------------------------
# Step 2: Run harness, capture sanitizer output
# ---------------------------------------------------------------------------
def run_harness(binary: Path, crash_file: Path) -> Tuple[str, int]:
    env = {**os.environ, **ASAN_ENV}
    result = subprocess.run(
        [str(binary), str(crash_file)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    return result.stderr + result.stdout, result.returncode


def verify_reproducibility(
    binary: Path, crash_file: Path, attempts: int
) -> Tuple[bool, str, int, int, List[str]]:
    logs: List[str] = []
    last_output = ""
    last_exit_code = 0
    attempts = max(attempts, 1)

    for attempt in range(1, attempts + 1):
        output, exit_code = run_harness(binary, crash_file)
        last_output = output
        last_exit_code = exit_code
        logs.append(f"=== Attempt {attempt} / {attempts} (exit={exit_code}) ===\n{output}")
        if "SUMMARY:" in output or "runtime error:" in output:
            return True, output, exit_code, attempt, logs

    return False, last_output, last_exit_code, 0, logs


# ---------------------------------------------------------------------------
# Step 3: Parse sanitizer output
# ---------------------------------------------------------------------------
UBSAN_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*(UndefinedBehaviorSanitizer|AddressSanitizer):\s*([\w-]+)\s+(.+?):(\d+):(\d+)"
)
UBSAN_RUNTIME_RE = re.compile(r"(.+?):(\d+):(\d+):\s+runtime error:\s+(.+)")
ASAN_SUMMARY_RE = re.compile(r"==\d+==ERROR: AddressSanitizer:\s+([\w-]+)")
FRAME_RE = re.compile(
    # C++ template names may contain spaces, so capture "in <func> <path>:line".
    # Linux file paths don't contain colons, so we use [^\s:]* to stop the
    # file group before the :line[:col] suffix.
    r"#(\d+)\s+(0x[0-9a-f]+)\s+in\s+(.+?)\s+(/[^\s:]+):(\d+)(?::(\d+))?"
)


def _parse_ubsan_output(output: str) -> CrashInfo:
    ci = CrashInfo(
        crash_file="",
        harness="",
        harness_binary="",
        sanitizer_type="UBSan",
        bug_subtype="ubsan-other",
        summary_line="",
        runtime_error="",
    )

    frames = []
    for m in FRAME_RE.finditer(output):
        frames.append(
            StackFrame(
                index=int(m.group(1)),
                address=m.group(2),
                function=m.group(3).strip(),
                file=m.group(4),
                line=int(m.group(5)),
                column=int(m.group(6)) if m.group(6) else 0,
            )
        )
    ci.stack = frames

    project_src = str(PROJECT_ROOT / "src")
    project_frame = None
    any_user_frame = None
    skip_funcs = (
        [
            "fuzzer::",
            "libFuzzer",
            "LLVMFuzzer",
            "__sanitizer",
            "asan_",
            "ubsan_",
            "__interceptor",
            "libc_start",
        ]
        + [h + "(" for h in KNOWN_HARNESSES]
        + KNOWN_HARNESSES
    )
    for f in frames:
        in_project = project_src in f.file or "softhsm2" in f.file.lower()
        is_runtime = any(p in f.function for p in skip_funcs)
        if in_project and project_frame is None:
            project_frame = f
        if not is_runtime and any_user_frame is None:
            any_user_frame = f
    ci.crash_location = project_frame or any_user_frame or (frames[0] if frames else None)

    m = UBSAN_RUNTIME_RE.search(output)
    if m:
        ci.runtime_error = m.group(4).strip()
        ci.summary_line = f"{m.group(1)}:{m.group(2)}:{m.group(3)}: runtime error: {ci.runtime_error}"
    m2 = UBSAN_SUMMARY_RE.search(output)
    if m2:
        ci.summary_line = output[m2.start() : m2.end()].strip()

    err = ci.runtime_error.lower()
    if "misaligned" in err:
        ci.bug_subtype = "misaligned-access"
    elif "null pointer" in err or "null" in err:
        ci.bug_subtype = "null-deref"
    elif "signed integer overflow" in err or "integer overflow" in err:
        ci.bug_subtype = "integer-overflow"
    elif "out of bounds" in err:
        ci.bug_subtype = "out-of-bounds"

    return ci


def _parse_asan_output(output: str) -> CrashInfo:
    ci = CrashInfo(
        crash_file="",
        harness="",
        harness_binary="",
        sanitizer_type="ASan",
        bug_subtype="unknown",
        summary_line="",
        runtime_error="",
    )

    frames = []
    for m in FRAME_RE.finditer(output):
        frames.append(
            StackFrame(
                index=int(m.group(1)),
                address=m.group(2),
                function=m.group(3).strip(),
                file=m.group(4),
                line=int(m.group(5)),
                column=int(m.group(6)) if m.group(6) else 0,
            )
        )
    ci.stack = frames

    project_src = str(PROJECT_ROOT / "src")
    project_frame = None
    any_user_frame = None
    skip_funcs = (
        [
            "fuzzer::",
            "libFuzzer",
            "LLVMFuzzer",
            "__sanitizer",
            "asan_",
            "ubsan_",
            "__interceptor",
            "libc_start",
        ]
        + [h + "(" for h in KNOWN_HARNESSES]
        + KNOWN_HARNESSES
    )
    for f in frames:
        in_project = project_src in f.file or "softhsm2" in f.file.lower()
        is_runtime = any(p in f.function for p in skip_funcs)
        if in_project and project_frame is None:
            project_frame = f
        if not is_runtime and any_user_frame is None:
            any_user_frame = f
    ci.crash_location = project_frame or any_user_frame or (frames[0] if frames else None)

    m = ASAN_SUMMARY_RE.search(output)
    if m:
        ci.bug_subtype = m.group(1).lower()
        ci.summary_line = f"ASan: {ci.bug_subtype}"

    return ci


def parse_sanitizer_output(output: str) -> CrashInfo:
    if "LeakSanitizer: detected memory leaks" in output:
        ci = _parse_asan_output(output)
        ci.sanitizer_type = "ASan"
        ci.bug_subtype = "memory-leak"
        ci.summary_line = "LeakSanitizer: detected memory leaks"
        return ci

    asan_pos = output.find("ERROR: AddressSanitizer:")
    ubsan_runtime_pos = output.find("runtime error:")
    ubsan_summary_pos = output.find("SUMMARY: UndefinedBehaviorSanitizer:")
    ubsan_pos_candidates = [p for p in (ubsan_runtime_pos, ubsan_summary_pos) if p != -1]
    ubsan_pos = min(ubsan_pos_candidates) if ubsan_pos_candidates else -1

    if asan_pos != -1 and (ubsan_pos == -1 or asan_pos <= ubsan_pos):
        return _parse_asan_output(output)
    if ubsan_pos != -1:
        return _parse_ubsan_output(output)

    return CrashInfo(
        crash_file="",
        harness="",
        harness_binary="",
        sanitizer_type="Unknown",
        bug_subtype="unknown",
        summary_line="",
        runtime_error="",
    )


def sanitizer_output_score(output: str) -> int:
    ci = parse_sanitizer_output(output)
    score = 0

    if ci.sanitizer_type != "Unknown":
        score += 20
    if ci.bug_subtype not in {"unknown", "segv", "attempting"}:
        score += 25
    if ci.runtime_error:
        score += 10
    if ci.summary_line:
        score += 5

    score += min(
        10,
        sum(
            1
            for frame in ci.stack
            if str(PROJECT_ROOT / "src") in frame.file or "softhsm2" in frame.file.lower()
        ),
    )

    for marker in (
        "heap-use-after-free",
        "stack-use-after-return",
        "use-after-poison",
        "double-free",
        "attempting double-free",
        "buffer-overflow",
    ):
        if marker in output:
            score += 30
            break

    return score


def choose_best_sanitizer_output(primary_output: str, out_dir: Path) -> str:
    best_output = primary_output
    best_score = sanitizer_output_score(primary_output)

    for extra in sorted(out_dir.glob("asan-report-*.log")):
        candidate = extra.read_text(errors="replace")
        score = sanitizer_output_score(candidate)
        if score > best_score:
            best_output = candidate
            best_score = score

    return best_output


# ---------------------------------------------------------------------------
# Step 4: False positive classification
# ---------------------------------------------------------------------------
def classify_false_positive(ci: CrashInfo, output: str) -> Tuple[bool, str]:
    if ci.harness == "pkcs11_concurrency_fuzz":
        common_h = PROJECT_ROOT / "harnesses" / "common.h"
        common_text = common_h.read_text(errors="replace") if common_h.exists() else ""
        concurrency_without_locking = (
            "C_Initialize(NULL_PTR)" in common_text
            and "CKF_OS_LOCKING_OK" not in common_text
        )
        race_signatures = (
            "SessionManager::openSession" in output
            or "SessionManager::closeSession" in output
            or "Session::setFindOp" in output
            or "SecureMemoryRegistry::add" in output
            or "SecureMemoryRegistry::remove" in output
        )
        if concurrency_without_locking and race_signatures:
            return (
                True,
                "Concurrency harness initialized PKCS#11 with NULL_PTR, which disables "
                "SoftHSM internal locking. The resulting session/registry races are harness-"
                "induced rather than valid library bugs; use CKF_OS_LOCKING_OK for threaded "
                "replay.",
            )

    for pattern, reason in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, output):
            return True, reason

    # Crashes in system includes (stl, libc) but NOT triggered by our code
    # Check: is the first non-skip frame in our source?
    if ci.crash_location:
        f = ci.crash_location.file
        if "/usr/lib" in f or "/usr/include" in f:
            # Could be a FP — check if called from SoftHSM2 code
            softhsm_in_stack = any("softhsm2" in fr.file.lower() for fr in ci.stack)
            if not softhsm_in_stack:
                return (
                    True,
                    f"Crash in system library ({f}) with no SoftHSM2 frames in stack",
                )

    return False, ""


# ---------------------------------------------------------------------------
# Step 5: Minimise crash input using libFuzzer -minimize_crash
# ---------------------------------------------------------------------------
def minimize_crash(binary: Path, crash_file: Path, timeout: int = 30) -> bytes:
    original = crash_file.read_bytes()
    with tempfile.TemporaryDirectory() as tmpdir:
        env = {**os.environ, **ASAN_ENV}
        try:
            result = subprocess.run(
                [
                    str(binary),
                    f"-minimize_crash=1",
                    f"-max_total_time={timeout}",
                    f"-artifact_prefix={tmpdir}/min-",
                    str(crash_file),
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout + 10,
            )
            # Find the minimised artifact
            artifacts = list(Path(tmpdir).glob("min-*"))
            if artifacts:
                smallest = min(artifacts, key=lambda p: p.stat().st_size)
                minimized = smallest.read_bytes()
                if 0 < len(minimized) <= len(original):
                    return minimized
        except (subprocess.TimeoutExpired, Exception):
            pass
    return original


# ---------------------------------------------------------------------------
# Step 6: Read source context around crash location
# ---------------------------------------------------------------------------
def read_source_context(frame: StackFrame, context: int = 8) -> str:
    path = Path(frame.file)
    if not path.exists():
        # Try relative to project root
        for root in [PROJECT_ROOT, PROJECT_ROOT / "src"]:
            for candidate in root.rglob(path.name):
                if candidate.exists():
                    path = candidate
                    break
    if not path.exists():
        return f"[source not found: {frame.file}]"

    lines = path.read_text(errors="replace").splitlines()
    start = max(0, frame.line - context - 1)
    end = min(len(lines), frame.line + context)
    numbered = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == frame.line else "   "
        numbered.append(f"{marker} {i:4d} | {line}")
    return "\n".join(numbered)


# ---------------------------------------------------------------------------
# Step 7: Patch generation
# ---------------------------------------------------------------------------
def generate_patch(ci: CrashInfo) -> Tuple[str, str]:
    """
    Returns (unified_diff, description).
    Pattern-based patching for the bug subtypes we see.
    """
    if not ci.crash_location:
        return "", "Could not determine crash location for patch."

    frame = ci.crash_location

    # For null-deref via ByteString::operator[], the fix must go into the
    # SoftHSM caller (SymDecryptInit / SymEncryptInit), not ByteString itself.
    # Walk the stack to find the first SoftHSM.cpp frame.
    if ci.bug_subtype == "null-deref":
        for f in ci.stack:
            if "SoftHSM.cpp" in f.file and "SoftHSM" in f.function:
                frame = f
                break

    path = Path(frame.file)

    # Resolve source path
    if not path.exists():
        for root in [PROJECT_ROOT, PROJECT_ROOT / "src"]:
            for candidate in root.rglob(path.name):
                path = candidate
                break

    if not path.exists():
        return "", f"Source file not found: {frame.file}"

    # Read source WITHOUT keepends so difflib handles newlines cleanly
    raw_text = path.read_text(errors="replace")
    lines = raw_text.splitlines()  # no trailing \n on each line
    crash_line = lines[frame.line - 1] if frame.line <= len(lines) else ""

    def misaligned_manual_fix_desc(reported_type: Optional[str]) -> str:
        if "member call on misaligned address" in ci.runtime_error:
            vector_frame = next(
                (f for f in ci.stack if "std::vector" in f.function), None
            )
            vector_hint = ""
            if vector_frame:
                vector_hint = (
                    f"\n\nThe stack passes through `{vector_frame.function}`, so the"
                    f" observed misalignment may be surfacing while a container is"
                    f" relocating or iterating over a previously corrupted pointer."
                )
            return (
                f"Likely corrupted or stale `{reported_type or 'object'}` pointer, not a"
                f" simple unaligned scalar read.\n\n"
                f"UBSan reported a member call on a misaligned address, which usually"
                f" means the object pointer was already invalid before this frame."
                f" Common causes are lifetime bugs, concurrent mutation of shared"
                f" containers, or leaving stale pointers behind after close/reset"
                f" operations.{vector_hint}\n\n"
                f"Recommended manual investigation:\n"
                f"- audit ownership/lifetime of the affected object near"
                f" `{frame.file}:{frame.line}`\n"
                f"- verify all reads and writes to the container/object use the same"
                f" synchronization\n"
                f"- check close/reset/destructor paths for dangling pointers left in"
                f" containers\n"
                f"- if any field ultimately comes from caller-controlled bytes, copy it"
                f" into an aligned local with memcpy() before typed access"
            )

        return (
            f"Replace direct typed-pointer dereference of {reported_type or 'pValue'}\n"
            f"with memcpy() to safely read possibly unaligned caller-provided data."
        )

    # -------------------------------------------------------------------------
    # Pattern A: misaligned scalar read from an unaligned PKCS#11 pValue
    #   T v = *(T_PTR)ptr;  ->  T v; memcpy(&v, ptr, sizeof(v));
    #   v = *(T*)ptr;       ->  memcpy(&v, ptr, sizeof(v));
    # -------------------------------------------------------------------------
    if ci.bug_subtype == "misaligned-access":
        reported_type = None
        m = re.search(r"type '([^']+)'", ci.runtime_error)
        if m:
            reported_type = m.group(1)

        def normalize_cast_type(cast_type: str) -> str:
            normalized = re.sub(r"\s+", "", cast_type)
            normalized = normalized.removesuffix("_PTR")
            while normalized.endswith("*"):
                normalized = normalized[:-1]
            return normalized

        def type_matches(cast_type: str) -> bool:
            return reported_type is None or normalize_cast_type(cast_type) == reported_type

        decl_pattern = re.compile(
            r"^(\s*)([A-Za-z_][\w:\s<>]*)\s+([A-Za-z_]\w*)\s*=\s*\*\(([^)]+)\)\s*([^;]+);$"
        )
        assign_pattern = re.compile(
            r"^(\s*)([A-Za-z_]\w*)\s*=\s*\*\(([^)]+)\)\s*([^;]+);$"
        )

        start = max(frame.line - 3, 1)
        end = min(frame.line + 3, len(lines))
        for lineno in range(start, end + 1):
            line = lines[lineno - 1]

            m = decl_pattern.match(line)
            if m and type_matches(m.group(4)):
                indent, decl_type, var_name, _, ptr_expr = m.groups()
                new_lines = [
                    f"{indent}{decl_type} {var_name};",
                    f"{indent}memcpy(&{var_name}, {ptr_expr}, sizeof({var_name}));",
                ]
            else:
                m = assign_pattern.match(line)
                if not (m and type_matches(m.group(3))):
                    continue
                indent, lhs, _, ptr_expr = m.groups()
                new_lines = [
                    f"{indent}memcpy(&{lhs}, {ptr_expr}, sizeof({lhs}));",
                ]

            desc = (
                f"Fix misaligned read of {reported_type or 'scalar value'} via PKCS#11 pValue.\n\n"
                f"The PKCS#11 spec exposes attribute values through pValue, which\n"
                f"does not guarantee natural alignment for typed loads. Casting the\n"
                f"buffer to a typed pointer and dereferencing it triggers undefined\n"
                f"behaviour when the input is misaligned.\n\n"
                f"Replace the direct dereference with memcpy(), which safely copies\n"
                f"the value from possibly unaligned storage."
            )
            patch = _make_unified_diff(path, lines, lineno, line, new_lines, desc)
            return patch, desc

        return "", misaligned_manual_fix_desc(reported_type)

    # -------------------------------------------------------------------------
    # Pattern B: null-deref via &vec[0] on empty ByteString
    #   memcpy(&vec[0], ptr, len)  when len may be 0
    # -------------------------------------------------------------------------
    if ci.bug_subtype == "null-deref" and (
        "stl_vector" in ci.runtime_error
        or any("ByteString" in f.function for f in ci.stack)
    ):
        # Find ALL occurrences of the pattern in the function, not just crash line
        # Pattern: aad.resize(expr); \n memcpy(&aad[0], ptr, expr);
        # Or:      iv.resize(expr);  \n memcpy(&iv[0], ptr, expr);
        def guard_memcpy_pattern(lines: list, file_path: Path) -> Tuple[str, list]:
            """Wrap memcpy(&vec[0], ..., len) with if (len > 0) guard.
            Works on lines WITHOUT trailing newlines (splitlines() without keepends)."""
            MEMCPY_EMPTY_VEC_RE = re.compile(
                r"(\s*)memcpy\(&(\w+)\[0\],\s*(.+?),\s*"
                r"(.+?(?:ulAADLen|ulIvLen|ulValueLen)[^;]*)\);"
            )
            patched = list(lines)
            changes = []
            offset = 0
            for i, line in enumerate(lines):
                m = MEMCPY_EMPTY_VEC_RE.match(line)
                if m:
                    indent, vec, src, length_expr = (
                        m.group(1),
                        m.group(2),
                        m.group(3),
                        m.group(4),
                    )
                    new_lines = [
                        f"{indent}if ({length_expr.strip()} > 0)",
                        f"{indent}\tmemcpy(&{vec}[0], {src}, {length_expr});",
                    ]
                    patched[i + offset : i + offset + 1] = new_lines
                    offset += len(new_lines) - 1
                    changes.append((i + 1, line, new_lines))
            return patched, changes

        patched_lines, changes = guard_memcpy_pattern(lines, path)
        if changes:
            desc = (
                "Guard memcpy(&vec[0], ..., len) with len > 0 check.\n\n"
                "When ulAADLen or ulIvLen is 0, ByteString::resize(0) creates\n"
                "an empty vector. Calling operator[] on an empty std::vector\n"
                "produces a reference to the null internal pointer — undefined\n"
                "behaviour caught by UBSan ('reference binding to null pointer').\n\n"
                "The fix wraps the memcpy in an explicit length check, which is\n"
                "also consistent with how other GCM implementations guard this path.\n"
                "Note: the same pattern appears in both SymEncryptInit (line ~2288)\n"
                "and SymDecryptInit (line ~3008) — both are fixed by this patch."
            )
            patch = _make_unified_diff_multi(path, lines, patched_lines, desc)
            return patch, desc

        desc = (
            "Guard memcpy(&vec[0], ..., 0) calls with an explicit length > 0\n"
            "check before accessing the first element of a potentially empty vector."
        )
        return "", desc

    if ci.bug_subtype in {"heap-use-after-free", "segv"}:
        stack_functions = {f.function for f in ci.stack}
        if (
            "SessionManager::closeSession(unsigned long)" in stack_functions
            and any("Session::setFindOp" in f.function for f in ci.stack)
        ) or (
            "SessionManager::getSession(unsigned long)" in stack_functions
            and any("Session::setFindOp" in f.function for f in ci.stack)
        ):
            desc = (
                "Likely session lifetime race in the session manager, not a standalone null/SEGV fix.\n\n"
                "The ASan stack shows one thread closing and deleting a Session while another"
                " thread still uses the raw Session* returned by SessionManager. The current"
                " getSession() API returns an unlocked raw pointer, so closeSession() can free"
                " the object before callers like C_FindObjectsInit finish updating it.\n\n"
                "Recommended manual fix direction:\n"
                "- audit all SessionManager accessors for raw-pointer escape after releasing"
                " sessionsMutex\n"
                "- either hold the same lock across lookup and use, or move session ownership"
                " to a reference-counted/borrowed lifetime model\n"
                "- review openSession() as well, since it mutates the sessions vector without"
                " taking sessionsMutex"
            )
            return "", desc

    # -------------------------------------------------------------------------
    # Pattern C: Missing free after OpenSSL d2i allocation (LeakSanitizer)
    # -------------------------------------------------------------------------
    if ci.bug_subtype == "memory-leak":
        d2i_re = re.compile(r"(\s*)(\w+)\s*=\s*(d2i_(\w+))\(.*?\);")
        m = d2i_re.search(crash_line)
        if m:
            indent, var, func, type_name = m.groups()
            free_func = f"{type_name}_free"
            if "PRINTABLESTRING" in type_name:
                free_func = "ASN1_STRING_free"

            # Check next non-empty line for common SoftHSM return pattern
            next_lineno = frame.line + 1
            while next_lineno <= len(lines) and not lines[next_lineno-1].strip():
                next_lineno += 1

            if next_lineno <= len(lines):
                next_line = lines[next_lineno-1]
                ret_re = re.compile(r"^(\s*)return\s+([^;]+);$")
                m2 = ret_re.match(next_line)
                if m2:
                    ret_indent, ret_expr = m2.groups()
                    if var in ret_expr:
                        # e.g. return OBJ_obj2nid(oid);
                        new_lines = [
                            f"{ret_indent}int nid = {ret_expr};",
                            f"{ret_indent}{free_func}({var});",
                            f"{ret_indent}return nid;"
                        ]
                        if "NID" not in ret_expr.upper():
                            # fallback for non-NID returns
                            new_lines = [
                                f"{ret_indent}auto _ret = {ret_expr};",
                                f"{ret_indent}{free_func}({var});",
                                f"{ret_indent}return _ret;"
                            ]
                        
                        desc = (
                            f"Fix memory leak of {type_name} allocated by {func}.\n\n"
                            f"The object is allocated by d2i but never freed before the\n"
                            f"function returns. Added a call to {free_func}() to release it."
                        )
                        patch = _make_unified_diff(path, lines, next_lineno, next_line, new_lines, desc)
                        return patch, desc

            return "", f"Memory leak of {var} (type {type_name}) allocated by {func}. Needs {free_func}()."

    return "", f"No automated patch template for bug subtype: {ci.bug_subtype}"


def _make_unified_diff(
    path: Path, original: list, lineno: int, old_line: str, new_lines: list, desc: str
) -> str:
    """
    Build a minimal unified diff.
    original   — file lines WITHOUT trailing newlines (splitlines() without keepends)
    lineno     — 1-based line number being replaced
    old_line   — original line text (no trailing \n)  [unused, kept for API compat]
    new_lines  — list of replacement line strings (no trailing \n)
    """
    import difflib

    rel = _rel_path(path)
    idx = lineno - 1  # 0-based

    patched = list(original)
    patched[idx : idx + 1] = new_lines

    # Diff the full files so line numbers in the hunk header are correct
    diff = list(
        difflib.unified_diff(
            [l + "\n" for l in original],
            [l + "\n" for l in patched],
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
            n=3,
        )
    )
    return "".join(diff)


def _make_unified_diff_multi(
    path: Path, original: list, patched: list, desc: str
) -> str:
    """Build a unified diff for multiple-line changes.
    original and patched are lists of lines WITHOUT trailing newlines."""
    import difflib

    rel = _rel_path(path)
    diff = list(
        difflib.unified_diff(
            [l + "\n" for l in original],
            [l + "\n" for l in patched],
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
            n=3,
        )
    )
    return "".join(diff)


def _rel_path(path: Path) -> str:
    """Return path relative to PROJECT_ROOT so 'patch -p1' works from PROJECT_ROOT."""
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        try:
            return "src/" + str(path.relative_to(PROJECT_ROOT / "src"))
        except ValueError:
            return str(path)


# ---------------------------------------------------------------------------
# Step 8: Generate maintainer report (Markdown)
# ---------------------------------------------------------------------------
def generate_report(
    ci: CrashInfo,
    minimal_input: bytes,
    repro_cmd: str,
    patch: str,
    patch_desc: str,
    crash_output: str,
) -> str:

    severity = {
        "misaligned-access": "Medium",
        "null-deref": "High",
        "heap-overflow": "Critical",
        "use-after-free": "Critical",
        "integer-overflow": "Medium",
    }.get(ci.bug_subtype, "Medium")

    versions = detect_component_versions()

    loc = ci.crash_location
    location_str = f"`{loc.file}:{loc.line}` in `{loc.function}`" if loc else "unknown"

    stack_str = "\n".join(
        f"    #{f.index} {f.address} in {f.function}  {f.file}:{f.line}"
        for f in ci.stack[:10]
    )

    patch_section = ""
    if patch:
        patch_section = f"""
## Suggested Patch

{patch_desc}

```diff
{patch}
```
"""
    else:
        patch_section = f"""
## Suggested Fix

{patch_desc}
"""

    hex_dump = " ".join(f"{b:02x}" for b in minimal_input[:64])
    if len(minimal_input) > 64:
        hex_dump += " ..."

    return textwrap.dedent(f"""\
    # Bug Report: {ci.bug_subtype.replace("-", " ").title()} in {ci.harness}

    **Severity:** {severity}
    **Sanitizer:** {ci.sanitizer_type}
    **Bug type:** `{ci.bug_subtype}`
    **Crash location:** {location_str}
    **Found by:** pkcs11-fuzzer / libFuzzer harness `{ci.harness}`

    ## Summary

    {ci.runtime_error or ci.summary_line}

    ## Reproduction Steps

    ### Prerequisites
    ```bash
    # Build the fuzzer project (one-time)
    cd /path/to/pkcs11-fuzzer
    bash build-scripts/build-all.sh
    make -C harnesses/
    ```

    ### Reproduce

    ```bash
    {repro_cmd}
    ```

    ### Minimal crash input ({len(minimal_input)} bytes)

    ```
    {hex_dump}
    ```

    Save as `reproducer.bin` and run the command above.

    ## Full Stack Trace

    ```
    {ci.summary_line}

    {stack_str}
    ```

    ## Source Context

    ```cpp
    {ci.source_context}
    ```
    {patch_section}
    ## Environment

    | Item | Value |
    |---|---|
    | Harness | `{ci.harness}` |
    | Sanitizers | ASan + UBSan (`-fsanitize=address,undefined`) |
    | Compiler | {versions["Compiler"]} |
    | OpenSSL | {versions["OpenSSL"]} |
    | SoftHSM2 | {versions["SoftHSM2"]} |
    | OpenSC | {versions["OpenSC"]} |

    ## Notes

    This bug was found automatically by a libFuzzer harness exercising the
    PKCS#11 C API. The crash reproduces deterministically with the input above.
    """)


# ---------------------------------------------------------------------------
# Step 9: Generate standalone reproducer shell script
# ---------------------------------------------------------------------------
def generate_repro_script(ci: CrashInfo, minimal_input: bytes) -> str:
    hex_input = "\\x" + "\\x".join(f"{b:02x}" for b in minimal_input)
    harness_path = HARNESSES / ci.harness
    return textwrap.dedent(f"""\
    #!/usr/bin/env bash
    # Standalone reproducer for: {ci.bug_subtype} in {ci.harness}
    # Generated by tools/analyze.py
    set -euo pipefail

    HARNESS="{harness_path}"
    INPUT=$(mktemp)

    # Write crash input
    printf '{hex_input}' > "$INPUT"

    export ASAN_OPTIONS="halt_on_error=1:detect_leaks=0:symbolize=1"
    export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:symbolize=1"
    export SOFTHSM2_CONF="{LIBFUZZER / "etc" / "softhsm2.conf"}"

    echo "Reproducing: {ci.bug_subtype} in {ci.harness}"
    echo "Input: $INPUT ({len(minimal_input)} bytes)"
    echo ""

    "$HARNESS" "$INPUT"
    EXIT=$?

    rm -f "$INPUT"

    if [[ $EXIT -ne 0 ]]; then
        echo ""
        echo "Bug reproduced (exit $EXIT)."
    else
        echo "No crash — bug may have been fixed."
    fi
    """)


def generate_nonrepro_report(
    harness_name: str,
    crash_path: Path,
    minimal_input: bytes,
    repro_cmd: str,
    exit_code: int,
    output: str,
    attempts: int,
) -> str:
    versions = detect_component_versions()
    hex_dump = " ".join(f"{b:02x}" for b in minimal_input[:64]) or "(empty input)"
    if len(minimal_input) > 64:
        hex_dump += " ..."

    captured = output.strip() or "No sanitizer output or crash summary was produced."

    return textwrap.dedent(f"""\
    # Non-Reproducible Crash Report: {harness_name}

    **Status:** Not reproducible on current build
    **Harness:** `{harness_name}`
    **Crash file:** `{crash_path}`
    **Replay attempts:** `{attempts}`
    **Observed exit code on rerun:** `{exit_code}`

    ## Summary

    This crash artifact did not reproduce when rerun on the current source tree and
    build after `{attempts}` replay attempt(s). It may have been a flaky input,
    depended on transient state, or already been fixed by unrelated changes.

    ## Reproduction Attempt

    ```bash
    {repro_cmd}
    ```

    ## Input ({len(minimal_input)} bytes)

    ```
    {hex_dump}
    ```

    ## Captured Output

    ```text
    {captured}
    ```

    ## Follow-Up Ideas

    - rerun with the exact build and environment that originally produced the crash
    - compare the current harness and SoftHSM sources against the revision where the
      crash was first observed
    - if the harness depends on token or filesystem state, preserve the original
      temporary artifacts and environment variables for replay
    - keep the reproducer input around in case the bug becomes reproducible again
    - inspect `repro_attempts.log` and any `fuzzing-session.*` files for the
      closest replay context captured from continuous fuzzing

    ## Environment

    | Item | Value |
    |---|---|
    | Harness | `{harness_name}` |
    | Sanitizers | ASan + UBSan (`-fsanitize=address,undefined`) |
    | Compiler | {versions["Compiler"]} |
    | OpenSSL | {versions["OpenSSL"]} |
    | SoftHSM2 | {versions["SoftHSM2"]} |
    | OpenSC | {versions["OpenSC"]} |
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Verify fuzzer crash, classify, minimize, generate patch and report."
    )
    ap.add_argument(
        "crash_file", help="Path to crash artifact from fuzzing/crashes/raw/"
    )
    ap.add_argument("--harness", help="Override harness name (e.g. pkcs11_sign_fuzz)")
    ap.add_argument(
        "--output",
        default=None,
        help="Output directory (default: crashes/analysis/<crash_basename>)",
    )
    ap.add_argument(
        "--minimize-timeout",
        type=int,
        default=30,
        help="Seconds to spend minimizing input (0 to skip)",
    )
    ap.add_argument(
        "--repro-attempts",
        type=int,
        default=3,
        help="How many times to replay the crash before declaring it non-reproducible",
    )
    args = ap.parse_args()

    crash_path = Path(args.crash_file).resolve()
    if not crash_path.exists():
        print(f"ERROR: crash file not found: {crash_path}", file=sys.stderr)
        sys.exit(1)

    # Detect harness
    harness_name = args.harness or detect_harness(crash_path)
    if not harness_name:
        print("ERROR: cannot determine harness. Use --harness <name>.", file=sys.stderr)
        print("Known harnesses:", ", ".join(KNOWN_HARNESSES), file=sys.stderr)
        sys.exit(1)

    harness_binary = HARNESSES / harness_name
    if not harness_binary.exists():
        print(f"ERROR: harness binary not found: {harness_binary}", file=sys.stderr)
        print("Run 'make -C harnesses/' first.", file=sys.stderr)
        sys.exit(1)

    out_dir = (
        Path(args.output)
        if args.output
        else PROJECT_ROOT / "crashes" / "analysis" / crash_path.name
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Analyzing: {crash_path.name}")
    print(f"    Harness:  {harness_name}")
    print(f"    Output:   {out_dir}")
    print()

    # --- Step 1: Run and capture output ---
    print("[1/6] Verifying crash reproducibility...")
    try:
        reproducible, output, exit_code, reproduced_on_attempt, replay_logs = (
            verify_reproducibility(harness_binary, crash_path, args.repro_attempts)
        )
    except subprocess.TimeoutExpired:
        print("  TIMEOUT running harness — treating as non-reproducible")
        sys.exit(1)

    if reproducible:
        print(
            f"  Reproducible: YES (attempt={reproduced_on_attempt}/{args.repro_attempts}, exit={exit_code})"
        )
    else:
        print(f"  Reproducible: NO (attempts={args.repro_attempts}, exit={exit_code})")

    repro_cmd = (
        f"cd {PROJECT_ROOT}\n"
        f"export ASAN_OPTIONS='halt_on_error=1:detect_leaks=0:symbolize=1'\n"
        f"export UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'\n"
        f"export SOFTHSM2_CONF='{LIBFUZZER}/etc/softhsm2.conf'\n"
        f"harnesses/{harness_name} reproducer.bin"
    )

    if not reproducible:
        print(
            "  This crash does not reproduce. It may have been a fluke or already fixed."
        )
        minimal = crash_path.read_bytes()
        ci = CrashInfo(
            crash_file=str(crash_path),
            harness=harness_name,
            harness_binary=str(harness_binary),
            sanitizer_type="Unknown",
            bug_subtype="not-reproducible",
            summary_line="",
            runtime_error="Crash did not reproduce on the current build.",
            reproducible=False,
            repro_attempts=args.repro_attempts,
        )
        report_md = generate_nonrepro_report(
            harness_name,
            crash_path,
            minimal,
            repro_cmd,
            exit_code,
            output,
            args.repro_attempts,
        )
        repro_sh = generate_repro_script(ci, minimal)
        analysis = {
            "crash_file": str(crash_path),
            "harness": harness_name,
            "sanitizer_type": "Unknown",
            "bug_subtype": "not-reproducible",
            "runtime_error": ci.runtime_error,
            "summary": "",
            "reproducible": False,
            "repro_attempts": args.repro_attempts,
            "reproduced_on_attempt": 0,
            "is_false_positive": False,
            "fp_reason": "",
            "crash_location": None,
            "stack": [],
            "minimal_input_hex": minimal.hex(),
            "has_patch": False,
        }
        (out_dir / "report.md").write_text(report_md)
        (out_dir / "reproducer.bin").write_bytes(minimal)
        (out_dir / "reproducer.sh").write_text(repro_sh)
        (out_dir / "reproducer.sh").chmod(0o755)
        (out_dir / "analysis.json").write_text(json.dumps(analysis, indent=2))
        (out_dir / "repro_attempts.log").write_text("\n\n".join(replay_logs))
        sys.exit(0)

    # --- Step 2: Parse ---
    print("[2/6] Parsing sanitizer output...")
    analysis_output = choose_best_sanitizer_output(output, out_dir)
    if analysis_output != output:
        print("  Using richer sanitizer details from captured ASan sidecar log.")
    ci = parse_sanitizer_output(analysis_output)
    ci.crash_file = str(crash_path)
    ci.harness = harness_name
    ci.harness_binary = str(harness_binary)
    ci.reproducible = reproducible
    ci.repro_attempts = args.repro_attempts
    ci.reproduced_on_attempt = reproduced_on_attempt
    print(f"  Sanitizer:  {ci.sanitizer_type}")
    print(f"  Bug type:   {ci.bug_subtype}")
    print(
        f"  Location:   {ci.crash_location.file}:{ci.crash_location.line}"
        if ci.crash_location
        else "  Location: unknown"
    )

    # --- Step 3: False positive check ---
    print("[3/6] Checking for false positives...")
    is_fp, fp_reason = classify_false_positive(ci, analysis_output)
    ci.is_false_positive = is_fp
    ci.fp_reason = fp_reason
    if is_fp:
        print(f"  FALSE POSITIVE: {fp_reason}")
        print("  Writing FP report and exiting.")
        fp_report = f"# False Positive\n\n**Reason:** {fp_reason}\n\n**Crash:** {crash_path.name}\n"
        (out_dir / "false_positive.md").write_text(fp_report)
        sys.exit(0)
    else:
        print("  Not a known false positive — treating as real bug.")

    # --- Step 4: Source context ---
    print("[4/6] Reading source context...")
    if ci.crash_location:
        ci.source_context = read_source_context(ci.crash_location)
        print(
            f"  Read context around {ci.crash_location.file}:{ci.crash_location.line}"
        )

    # --- Step 5: Minimize ---
    if args.minimize_timeout > 0:
        print(f"[5/6] Minimizing crash input (up to {args.minimize_timeout}s)...")
        original_size = crash_path.stat().st_size
        minimal = minimize_crash(harness_binary, crash_path, args.minimize_timeout)
        print(f"  {original_size} → {len(minimal)} bytes")
    else:
        print("[5/6] Skipping minimization (--minimize-timeout 0).")
        minimal = crash_path.read_bytes()

    # --- Step 6: Generate patch ---
    print("[6/6] Generating patch...")
    patch, patch_desc = generate_patch(ci)
    if patch:
        print(f"  Patch generated ({patch.count(chr(10))} lines diff)")
    else:
        print(f"  No automated patch: {patch_desc[:60]}")

    # --- Assemble report ---
    report_md = generate_report(ci, minimal, repro_cmd, patch, patch_desc, analysis_output)
    repro_sh = generate_repro_script(ci, minimal)

    analysis = {
        "crash_file": str(crash_path),
        "harness": harness_name,
        "sanitizer_type": ci.sanitizer_type,
        "bug_subtype": ci.bug_subtype,
        "runtime_error": ci.runtime_error,
        "summary": ci.summary_line,
        "reproducible": ci.reproducible,
        "repro_attempts": ci.repro_attempts,
        "reproduced_on_attempt": ci.reproduced_on_attempt,
        "is_false_positive": ci.is_false_positive,
        "fp_reason": ci.fp_reason,
        "crash_location": asdict(ci.crash_location) if ci.crash_location else None,
        "stack": [asdict(f) for f in ci.stack[:10]],
        "minimal_input_hex": minimal.hex(),
        "has_patch": bool(patch),
    }

    # --- Write outputs ---
    (out_dir / "report.md").write_text(report_md)
    (out_dir / "reproducer.bin").write_bytes(minimal)
    (out_dir / "reproducer.sh").write_text(repro_sh)
    (out_dir / "reproducer.sh").chmod(0o755)
    (out_dir / "analysis.json").write_text(json.dumps(analysis, indent=2))
    (out_dir / "repro_attempts.log").write_text("\n\n".join(replay_logs))
    if patch:
        (out_dir / "patch.diff").write_text(patch)

    # --- Print summary ---
    print()
    print("=" * 60)
    print(f"RESULT: {'REAL BUG' if not ci.is_false_positive else 'FALSE POSITIVE'}")
    print(f"  Type:     {ci.sanitizer_type}: {ci.bug_subtype}")
    print(
        f"  Location: {ci.crash_location.file}:{ci.crash_location.line}"
        if ci.crash_location
        else ""
    )
    print(f"  Input:    {len(minimal)} bytes")
    print(
        f"  Patch:    {'YES — apply with: patch -p1 < ' + str(out_dir / 'patch.diff') if patch else 'manual fix needed'}"
    )
    print()
    print("Output files:")
    for f in sorted(out_dir.iterdir()):
        print(f"  {f.name}")
    print("=" * 60)


if __name__ == "__main__":
    main()
