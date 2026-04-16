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


def parse_sanitizer_output(output: str) -> CrashInfo:
    ci = CrashInfo(
        crash_file="",
        harness="",
        harness_binary="",
        sanitizer_type="Unknown",
        bug_subtype="unknown",
        summary_line="",
        runtime_error="",
    )

    # Extract stack frames
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

    # Locate the crash site.
    # Priority order:
    #   1. First frame in our project source (softhsm2, openssl, libp11, opensc)
    #   2. First frame not in a fuzzer/sanitizer runtime
    #   3. Fall back to first frame
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

    project_src = str(PROJECT_ROOT / "src")
    project_frame = None
    any_user_frame = None
    for f in frames:
        in_project = project_src in f.file or "softhsm2" in f.file.lower()
        is_runtime = any(p in f.function for p in skip_funcs)
        is_system = f.file.startswith("/usr/lib") or f.file.startswith("/usr/include")
        if in_project and project_frame is None:
            project_frame = f
        if not is_runtime and any_user_frame is None:
            any_user_frame = f

    ci.crash_location = (
        project_frame or any_user_frame or (frames[0] if frames else None)
    )

    # Determine sanitizer type and bug subtype
    if "UndefinedBehaviorSanitizer" in output:
        ci.sanitizer_type = "UBSan"
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
        else:
            ci.bug_subtype = "ubsan-other"

    elif "AddressSanitizer" in output:
        ci.sanitizer_type = "ASan"
        m = ASAN_SUMMARY_RE.search(output)
        if m:
            ci.bug_subtype = m.group(1).lower()
            ci.summary_line = f"ASan: {ci.bug_subtype}"

    return ci


# ---------------------------------------------------------------------------
# Step 4: False positive classification
# ---------------------------------------------------------------------------
def classify_false_positive(ci: CrashInfo, output: str) -> Tuple[bool, str]:
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

    # -------------------------------------------------------------------------
    # Pattern A: misaligned CK_ULONG read
    #   *(CK_ULONG_PTR)ptr  →  memcpy(&val, ptr, sizeof(val))
    # -------------------------------------------------------------------------
    if ci.bug_subtype == "misaligned-access" and "CK_ULONG" in ci.runtime_error:
        pattern = re.compile(
            r"(\s*)(CK_ULONG\s+\w+)\s*=\s*\*\(CK_ULONG_PTR\)(\w+(?:\[\w+\])?\.pValue);"
        )
        m = pattern.search(crash_line)
        if m:
            indent, decl, ptr_expr = m.group(1), m.group(2), m.group(3)
            var_name = decl.split()[-1]
            old_line = crash_line
            new_line = [
                f"{indent}{decl};",
                f"{indent}memcpy(&{var_name}, {ptr_expr}, sizeof({var_name}));",
            ]
            desc = (
                f"Fix misaligned read of CK_ULONG via void pointer.\n\n"
                f"The PKCS#11 spec defines pValue as CK_VOID_PTR, which carries\n"
                f"no alignment guarantee. Casting directly to CK_ULONG_PTR and\n"
                f"dereferencing invokes undefined behaviour when the pointer is\n"
                f"not 8-byte aligned (UBSAN: load of misaligned address).\n\n"
                f"Replace the direct cast with memcpy(), which is the correct\n"
                f"way to read an unaligned value in C/C++."
            )
            patch = _make_unified_diff(
                path, lines, frame.line, old_line, new_line, desc
            )
            return patch, desc

        # Generic fallback for misaligned CK_ULONG
        desc = (
            "Replace direct CK_ULONG_PTR cast with memcpy() to handle\n"
            "potentially unaligned pValue pointer from caller."
        )
        return "", desc

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
        output, exit_code = run_harness(harness_binary, crash_path)
    except subprocess.TimeoutExpired:
        print("  TIMEOUT running harness — treating as non-reproducible")
        sys.exit(1)

    reproducible = "SUMMARY:" in output or "runtime error:" in output
    print(f"  Reproducible: {'YES' if reproducible else 'NO'} (exit={exit_code})")

    if not reproducible:
        print(
            "  This crash does not reproduce. It may have been a fluke or already fixed."
        )
        sys.exit(0)

    # --- Step 2: Parse ---
    print("[2/6] Parsing sanitizer output...")
    ci = parse_sanitizer_output(output)
    ci.crash_file = str(crash_path)
    ci.harness = harness_name
    ci.harness_binary = str(harness_binary)
    ci.reproducible = reproducible
    print(f"  Sanitizer:  {ci.sanitizer_type}")
    print(f"  Bug type:   {ci.bug_subtype}")
    print(
        f"  Location:   {ci.crash_location.file}:{ci.crash_location.line}"
        if ci.crash_location
        else "  Location: unknown"
    )

    # --- Step 3: False positive check ---
    print("[3/6] Checking for false positives...")
    is_fp, fp_reason = classify_false_positive(ci, output)
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

    # --- Build repro command ---
    repro_cmd = (
        f"cd {PROJECT_ROOT}\n"
        f"export ASAN_OPTIONS='halt_on_error=1:detect_leaks=0:symbolize=1'\n"
        f"export UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'\n"
        f"export SOFTHSM2_CONF='{LIBFUZZER}/etc/softhsm2.conf'\n"
        f"harnesses/{harness_name} reproducer.bin"
    )

    # --- Assemble report ---
    report_md = generate_report(ci, minimal, repro_cmd, patch, patch_desc, output)
    repro_sh = generate_repro_script(ci, minimal)

    analysis = {
        "crash_file": str(crash_path),
        "harness": harness_name,
        "sanitizer_type": ci.sanitizer_type,
        "bug_subtype": ci.bug_subtype,
        "runtime_error": ci.runtime_error,
        "summary": ci.summary_line,
        "reproducible": ci.reproducible,
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
