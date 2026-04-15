#!/usr/bin/env python3
"""
tools/patch_workflow.py — End-to-end crash verification and patch lifecycle.

Stages
------
1. ANALYZE    Run tools/analyze.py (or load existing analysis) to confirm the
              crash is reproducible and generate a patch.
2. REPRODUCE  Replay the crash under the harness binary to establish a baseline.
3. PATCH      Apply the generated patch.diff to the source tree; save original
              file state so revert is always possible.
4. REBUILD    Detect which component was patched and rebuild only that component
              for the affected sanitizer tree.
5. VERIFY     Re-run the harness with the same crash input.  Confirm it no
              longer triggers the sanitizer.
6. REPORT     Print a human-readable summary and write a JSON state file.

Revert
------
At any point after PATCH, running with --revert <state-file> reverses all
patches, rebuilds, and restores the binaries to their pre-patch state.

Usage
-----
  # Full pipeline on one crash
  python3 tools/patch_workflow.py crashes/raw/pkcs11_findobj_fuzz-crash-abc123

  # Full pipeline, skip analysis if already done
  python3 tools/patch_workflow.py --analysis crashes/analysis/<dir> crashes/raw/...

  # Revert a previously applied patch
  python3 tools/patch_workflow.py --revert crashes/analysis/<dir>/workflow_state.json

  # Interactive mode (prompt before each stage)
  python3 tools/patch_workflow.py --interactive crashes/raw/...
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Project layout
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
BUILD_SCRIPTS = PROJECT_ROOT / "build-scripts"
BUILDS = PROJECT_ROOT / "builds"
HARNESSES_DIR = PROJECT_ROOT / "harnesses"

ASAN_ENV_BASE = {
    "ASAN_OPTIONS": "halt_on_error=1:detect_leaks=0:symbolize=1",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1:symbolize=1",
    "SOFTHSM2_CONF": str(BUILDS / "libfuzzer" / "etc" / "softhsm2.conf"),
}

# Loose env for verify-no-crash (we want the process to exit cleanly)
ASAN_ENV_NOHALT = {
    **ASAN_ENV_BASE,
    "ASAN_OPTIONS": "halt_on_error=0:detect_leaks=0:symbolize=0",
    "UBSAN_OPTIONS": "halt_on_error=0:print_stacktrace=0",
}

# ---------------------------------------------------------------------------
# Source path → build script mapping
# ---------------------------------------------------------------------------
SOURCE_TO_SCRIPT: List[Tuple[str, str, str]] = [
    # (path fragment in diff, build script name, tree)
    ("softhsm2", "03-build-softhsm2.sh", "libfuzzer"),
    ("openssl", "02-build-openssl.sh", "libfuzzer"),
    ("libp11", "04-build-libp11.sh", "libfuzzer"),
    ("opensc", "05-build-opensc.sh", "libfuzzer"),
]


# ---------------------------------------------------------------------------
# State dataclass — persisted as JSON for revert support
# ---------------------------------------------------------------------------
@dataclass
class WorkflowState:
    crash_file: str = ""
    harness: str = ""
    analysis_dir: str = ""
    patch_file: str = ""

    # Stage results
    reproducible: bool = False
    patch_applied: bool = False
    rebuilt: bool = False
    verified_fixed: bool = False

    # Revert support
    backed_up_files: Dict[str, str] = field(default_factory=dict)
    # {original_path: backup_path}
    component_script: str = ""
    rebuild_tree: str = ""

    stage: str = "init"  # init|analyzed|reproduced|patched|rebuilt|verified
    outcome: str = ""  # FIXED|STILL_VULNERABLE|ANALYSIS_FAILED|NO_PATCH


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def banner(msg: str, width: int = 62) -> None:
    line = "─" * width
    print(f"\n{line}")
    print(f"  {msg}")
    print(line)


def run(
    cmd: List[str],
    env_extra: dict = None,
    timeout: int = 300,
    capture: bool = True,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    env = {**os.environ, **(env_extra or {})}
    return subprocess.run(
        cmd,
        env=env,
        timeout=timeout,
        capture_output=capture,
        text=True,
        cwd=str(cwd) if cwd else None,
    )


def crash_is_real(output: str) -> bool:
    """Return True if output contains a sanitizer report."""
    return bool(
        re.search(
            r"SUMMARY:\s*(AddressSanitizer|UndefinedBehaviorSanitizer)|"
            r"runtime error:|"
            r"==\d+==ERROR: AddressSanitizer",
            output,
        )
    )


def detect_component(patch_text: str) -> Tuple[str, str]:
    """Return (build_script_name, tree) for the first matching source path."""
    for fragment, script, tree in SOURCE_TO_SCRIPT:
        if fragment in patch_text:
            return script, tree
    return "", ""


def prompt_continue(msg: str, default_yes: bool = True) -> bool:
    default = "Y/n" if default_yes else "y/N"
    ans = input(f"\n  {msg} [{default}]: ").strip().lower()
    if not ans:
        return default_yes
    return ans.startswith("y")


# ---------------------------------------------------------------------------
# Stage 1: Analyze
# ---------------------------------------------------------------------------
def stage_analyze(
    crash_file: Path,
    state: WorkflowState,
    existing_analysis: Optional[Path],
    minimize_timeout: int,
) -> Optional[Path]:
    banner("Stage 1/5 — Analyze")

    if existing_analysis and (existing_analysis / "analysis.json").exists():
        print(f"  Using existing analysis: {existing_analysis}")
        return existing_analysis

    analysis_base = PROJECT_ROOT / "crashes" / "analysis" / crash_file.name
    analysis_base.mkdir(parents=True, exist_ok=True)

    print(f"  Running analyze.py on {crash_file.name} …")
    result = run(
        [
            sys.executable,
            str(SCRIPT_DIR / "analyze.py"),
            str(crash_file),
            "--minimize-timeout",
            str(minimize_timeout),
            "--output",
            str(analysis_base),
        ],
        timeout=minimize_timeout + 120,
        capture=False,
    )

    if result.returncode not in (0, 1):  # 0 = real bug found, 1 = not repro or FP
        print("  ERROR: analyze.py exited unexpectedly.")
        return None

    return analysis_base


# ---------------------------------------------------------------------------
# Stage 2: Reproduce baseline
# ---------------------------------------------------------------------------
def stage_reproduce(state: WorkflowState, analysis: dict, reproducer: Path) -> bool:
    banner("Stage 2/5 — Reproduce baseline (confirm crash)")

    harness_bin = HARNESSES_DIR / state.harness
    if not harness_bin.exists():
        print(f"  ERROR: harness not found: {harness_bin}")
        return False

    print(f"  Running:  {harness_bin.name} {reproducer.name}")
    try:
        result = run(
            [str(harness_bin), str(reproducer)], env_extra=ASAN_ENV_BASE, timeout=30
        )
        output = result.stderr + result.stdout
        if crash_is_real(output):
            summary = re.search(r"SUMMARY:\s*\w+:\s*[\w-]+\s*(.+?):(\d+)", output)
            loc = f" at {summary.group(1)}:{summary.group(2)}" if summary else ""
            print(f"  CRASH CONFIRMED{loc}")
            print(f"  Exit code: {result.returncode}")
            return True
        else:
            print("  No sanitizer report — crash did not reproduce.")
            print(f"  Exit code: {result.returncode}")
            return False
    except subprocess.TimeoutExpired:
        print("  TIMEOUT — treating as non-reproducible.")
        return False


# ---------------------------------------------------------------------------
# Stage 3: Apply patch
# ---------------------------------------------------------------------------
def stage_patch(state: WorkflowState, patch_file: Path, analysis_dir: Path) -> bool:
    banner("Stage 3/5 — Apply patch")

    patch_text = patch_file.read_text()
    print(f"  Patch file: {patch_file}")
    print()

    # Show the diff to the user
    for line in patch_text.splitlines()[:60]:
        prefix = line[:1]
        if prefix == "+":
            print(f"  \033[32m{line}\033[0m")
        elif prefix == "-":
            print(f"  \033[31m{line}\033[0m")
        elif prefix == "@":
            print(f"  \033[36m{line}\033[0m")
        else:
            print(f"  {line}")
    if len(patch_text.splitlines()) > 60:
        print(f"  … ({len(patch_text.splitlines()) - 60} more lines)")

    # Detect component
    script, tree = detect_component(patch_text)
    if not script:
        print("\n  ERROR: Cannot determine which component this patch modifies.")
        return False
    state.component_script = script
    state.rebuild_tree = tree
    print(f"\n  Component: {script} ({tree} tree)")

    # Backup original files before patching
    changed_files = [
        line.split("b/", 1)[1].strip()
        for line in patch_text.splitlines()
        if line.startswith("+++ b/")
    ]
    backup_dir = analysis_dir / "originals"
    backup_dir.mkdir(exist_ok=True)
    state.backed_up_files.clear()

    for rel in changed_files:
        src = PROJECT_ROOT / rel
        if src.exists():
            backup = backup_dir / Path(rel).name
            shutil.copy2(src, backup)
            state.backed_up_files[str(src)] = str(backup)
            print(f"  Backed up: {rel}")

    # Dry-run first — always run from PROJECT_ROOT so -p1 resolves correctly
    print("\n  Dry-run …")
    dry = run(
        ["patch", "-p1", "--batch", "--dry-run", "--input", str(patch_file)],
        timeout=30,
        cwd=PROJECT_ROOT,
    )
    if dry.returncode != 0:
        print("  DRY-RUN FAILED:")
        print((dry.stdout + dry.stderr).strip())
        return False
    print("  Dry-run OK")

    # Apply
    apply = run(
        ["patch", "-p1", "--batch", "--input", str(patch_file)],
        timeout=30,
        cwd=PROJECT_ROOT,
    )
    if apply.returncode != 0:
        print("  PATCH FAILED:")
        print((apply.stdout + apply.stderr).strip())
        # Restore backups
        _restore_backups(state)
        return False

    print(apply.stdout.strip() or "  Patch applied.")
    state.patch_applied = True
    return True


# ---------------------------------------------------------------------------
# Stage 4: Rebuild component
# ---------------------------------------------------------------------------
def stage_rebuild(state: WorkflowState) -> bool:
    banner("Stage 4/5 — Rebuild patched component")

    script = BUILD_SCRIPTS / state.component_script
    tree = state.rebuild_tree

    # For softhsm2/libp11/opensc we need to clean the per-tree build dir
    # so the patched source is picked up
    component_name = re.sub(r"^\d+-build-", "", state.component_script).replace(
        ".sh", ""
    )
    build_dir = PROJECT_ROOT / "src" / component_name / f"build-{tree}"

    if build_dir.exists():
        print(f"  Cleaning build dir: {build_dir.name}")
        shutil.rmtree(build_dir)

    # Read the original clone mode from the source's .clone-stamp so that
    # clone_if_needed() in the build script sees the same mode|tag and does
    # NOT wipe the source directory (which would destroy the applied patch).
    #
    # The stamp contains "<upstream_flag>|<tag>", e.g. "1|2.6.1" when built
    # with --upstream-softhsm2, or "0|2.6.1" for the pinned version.
    src_dir = PROJECT_ROOT / "src" / component_name
    clone_stamp = src_dir / ".clone-stamp"
    upstream_flag = "0"
    if clone_stamp.exists():
        stamp_content = clone_stamp.read_text().strip()
        upstream_flag = stamp_content.split("|")[0]  # "0" or "1"

    # Map component name → the per-component env var that the build script reads.
    upstream_var = f"USE_UPSTREAM_{component_name.upper().replace('-', '_')}"
    print(f"  {upstream_var}={upstream_flag}  (from {clone_stamp.name})")

    print(f"  Running: {script.name} {tree}")
    print("  (This may take several minutes …)\n")

    result = run(
        ["bash", str(script), tree],
        env_extra={upstream_var: upstream_flag},
        timeout=900,
        capture=False,
        cwd=PROJECT_ROOT,
    )

    if result.returncode != 0:
        print(f"\n  BUILD FAILED (exit {result.returncode})")
        return False

    state.rebuilt = True
    print(f"\n  Build complete.")
    return True


# ---------------------------------------------------------------------------
# Stage 5: Verify fix
# ---------------------------------------------------------------------------
def stage_verify(state: WorkflowState, reproducer: Path) -> bool:
    banner("Stage 5/5 — Verify fix (crash should NOT reproduce)")

    harness_bin = HARNESSES_DIR / state.harness
    print(f"  Running:  {harness_bin.name} {reproducer.name}")

    # Re-init token since SoftHSM2 was rebuilt
    if "softhsm2" in state.component_script:
        print("  (Re-initializing token after SoftHSM2 rebuild …)")
        run(["bash", str(BUILD_SCRIPTS / "init-token.sh")], timeout=60, capture=True)

    try:
        result = run(
            [str(harness_bin), str(reproducer)],
            env_extra=ASAN_ENV_NOHALT,
            timeout=30,
        )
        output = result.stderr + result.stdout

        if crash_is_real(output):
            print("  STILL VULNERABLE — sanitizer report present after patch.")
            print(f"  Exit code: {result.returncode}")
            return False
        else:
            print("  FIXED — no sanitizer report.")
            print(f"  Exit code: {result.returncode}")
            return True
    except subprocess.TimeoutExpired:
        print("  TIMEOUT — treating as inconclusive.")
        return False


# ---------------------------------------------------------------------------
# Revert
# ---------------------------------------------------------------------------
def _restore_backups(state: WorkflowState) -> None:
    for orig, backup in state.backed_up_files.items():
        src, dst = Path(backup), Path(orig)
        if src.exists():
            shutil.copy2(src, dst)
            print(f"  Restored: {dst.relative_to(PROJECT_ROOT)}")


def stage_revert(state: WorkflowState) -> bool:
    banner("Reverting patch")

    if not state.patch_applied:
        print("  No patch was applied — nothing to revert.")
        return True

    patch_file = Path(state.patch_file)
    if patch_file.exists():
        print(f"  Applying reverse patch: {patch_file.name}")
        result = run(
            ["patch", "-p1", "--batch", "--reverse", "--input", str(patch_file)],
            timeout=30,
            cwd=PROJECT_ROOT,
        )
        if result.returncode != 0:
            print("  Reverse patch failed — restoring from backups instead.")
            _restore_backups(state)
        else:
            print(result.stdout.strip() or "  Reverse patch applied.")
    else:
        print("  Patch file not found — restoring from backups.")
        _restore_backups(state)

    state.patch_applied = False

    if state.rebuilt and state.component_script:
        print(f"\n  Rebuilding {state.component_script} to restore original binaries …")
        # Clean patched build
        component_name = re.sub(r"^\d+-build-", "", state.component_script).replace(
            ".sh", ""
        )
        build_dir = (
            PROJECT_ROOT / "src" / component_name / f"build-{state.rebuild_tree}"
        )
        if build_dir.exists():
            shutil.rmtree(build_dir)

        # Forward the original clone mode so clone_if_needed does not wipe source.
        src_dir = PROJECT_ROOT / "src" / component_name
        clone_stamp = src_dir / ".clone-stamp"
        upstream_flag = "0"
        if clone_stamp.exists():
            upstream_flag = clone_stamp.read_text().strip().split("|")[0]
        upstream_var = f"USE_UPSTREAM_{component_name.upper().replace('-', '_')}"

        result = run(
            ["bash", str(BUILD_SCRIPTS / state.component_script), state.rebuild_tree],
            env_extra={upstream_var: upstream_flag},
            timeout=900,
            capture=False,
        )
        if result.returncode != 0:
            print(
                "  WARNING: Rebuild after revert failed. Binaries may be inconsistent."
            )
            return False

        if "softhsm2" in state.component_script:
            run(
                ["bash", str(BUILD_SCRIPTS / "init-token.sh")], timeout=60, capture=True
            )

    state.rebuilt = False
    print("\n  Revert complete. Source and binaries are back to pre-patch state.")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify, patch, rebuild, and validate a fuzzer crash fix.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "crash_file",
        nargs="?",
        help="Crash artifact from crashes/raw/ or crashes/deduplicated/",
    )
    ap.add_argument(
        "--analysis",
        metavar="DIR",
        help="Re-use existing analysis directory (skip re-analysis)",
    )
    ap.add_argument("--harness", metavar="NAME", help="Override harness detection")
    ap.add_argument(
        "--minimize-timeout",
        type=int,
        default=30,
        metavar="SEC",
        help="Seconds to spend minimizing crash input (default: 30)",
    )
    ap.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt before applying patch and before rebuild",
    )
    ap.add_argument(
        "--no-revert-on-failure",
        action="store_true",
        help="Keep the patch even if verification fails",
    )
    ap.add_argument(
        "--revert",
        metavar="STATE_JSON",
        help="Revert a previously applied patch (load state from JSON)",
    )
    args = ap.parse_args()

    # ── Revert mode ──────────────────────────────────────────────────────────
    if args.revert:
        state_file = Path(args.revert)
        if not state_file.exists():
            print(f"ERROR: state file not found: {state_file}", file=sys.stderr)
            return 1
        state = WorkflowState(**json.loads(state_file.read_text()))
        ok = stage_revert(state)
        state.stage = "reverted"
        state.outcome = "REVERTED"
        state_file.write_text(json.dumps(asdict(state), indent=2))
        return 0 if ok else 1

    # ── Forward mode ─────────────────────────────────────────────────────────
    if not args.crash_file:
        ap.print_help()
        return 1

    crash_file = Path(args.crash_file).resolve()
    if not crash_file.exists():
        print(f"ERROR: crash file not found: {crash_file}", file=sys.stderr)
        return 1

    state = WorkflowState(crash_file=str(crash_file))

    print(f"\n{'═' * 62}")
    print(f"  pkcs11-fuzzer patch workflow")
    print(f"  Crash: {crash_file.name}")
    print(f"{'═' * 62}")

    # ── Stage 1: Analyze ─────────────────────────────────────────────────────
    existing = Path(args.analysis) if args.analysis else None
    analysis_dir = stage_analyze(crash_file, state, existing, args.minimize_timeout)
    state.stage = "analyzed"

    if not analysis_dir:
        state.outcome = "ANALYSIS_FAILED"
        _save_state(state, crash_file)
        _print_summary(state)
        return 1

    state.analysis_dir = str(analysis_dir)

    # Load analysis JSON
    analysis_json = analysis_dir / "analysis.json"
    if not analysis_json.exists():
        print("  ERROR: analysis.json not found.")
        state.outcome = "ANALYSIS_FAILED"
        _save_state(state, crash_file)
        _print_summary(state)
        return 1

    analysis = json.loads(analysis_json.read_text())

    if analysis.get("is_false_positive"):
        print(f"\n  FALSE POSITIVE: {analysis.get('fp_reason', '')}")
        print("  Nothing to patch.")
        state.outcome = "FALSE_POSITIVE"
        _save_state(state, crash_file)
        _print_summary(state)
        return 0

    if not analysis.get("reproducible"):
        print("\n  Crash is NOT reproducible. No action taken.")
        state.outcome = "NOT_REPRODUCIBLE"
        _save_state(state, crash_file)
        _print_summary(state)
        return 0

    state.harness = args.harness or analysis.get("harness", "")
    if not state.harness:
        print("  ERROR: cannot determine harness.")
        return 1

    # Locate reproducer (minimized preferred, original as fallback)
    reproducer = analysis_dir / "reproducer.bin"
    if not reproducer.exists():
        reproducer = crash_file
    print(f"\n  Harness:    {state.harness}")
    print(f"  Bug type:   {analysis.get('bug_subtype', 'unknown')}")
    print(f"  Reproducer: {reproducer.name} ({reproducer.stat().st_size} bytes)")

    # Patch file
    patch_file = analysis_dir / "patch.diff"
    if not patch_file.exists() or not patch_file.read_text().strip():
        print("\n  No automated patch available for this bug type.")
        print("  The bug report is in:", analysis_dir / "report.md")
        print("  Fix the bug manually, then run:")
        print(f"    python3 tools/analyze.py {crash_file}")
        state.outcome = "NO_PATCH"
        _save_state(state, crash_file)
        _print_summary(state)
        return 0

    state.patch_file = str(patch_file)

    # ── Stage 2: Reproduce ────────────────────────────────────────────────────
    ok = stage_reproduce(state, analysis, reproducer)
    if not ok:
        state.outcome = "NOT_REPRODUCIBLE"
        _save_state(state, crash_file)
        _print_summary(state)
        return 0
    state.reproducible = True
    state.stage = "reproduced"

    # ── Stage 3: Patch ───────────────────────────────────────────────────────
    if args.interactive:
        if not prompt_continue("Apply the patch above?"):
            print("  Skipping patch at user request.")
            state.outcome = "SKIPPED"
            _save_state(state, crash_file)
            return 0

    ok = stage_patch(state, patch_file, analysis_dir)
    if not ok:
        state.outcome = "PATCH_FAILED"
        _save_state(state, crash_file)
        _print_summary(state)
        return 1
    state.stage = "patched"
    _save_state(state, crash_file)

    # ── Stage 4: Rebuild ─────────────────────────────────────────────────────
    if args.interactive:
        if not prompt_continue(
            f"Rebuild {state.component_script} ({state.rebuild_tree} tree)?"
        ):
            print("  Skipping rebuild at user request.")
            state.outcome = "SKIPPED"
            _save_state(state, crash_file)
            return 0

    ok = stage_rebuild(state)
    if not ok:
        print("\n  Rebuild failed. Reverting patch …")
        stage_revert(state)
        state.outcome = "BUILD_FAILED"
        _save_state(state, crash_file)
        _print_summary(state)
        return 1
    state.stage = "rebuilt"
    _save_state(state, crash_file)

    # ── Stage 5: Verify ───────────────────────────────────────────────────────
    fixed = stage_verify(state, reproducer)
    state.verified_fixed = fixed
    state.stage = "verified"

    if fixed:
        state.outcome = "FIXED"
        _save_state(state, crash_file)
        _print_summary(state)
        print("\n  To revert this patch later:")
        print(
            f"    python3 tools/patch_workflow.py --revert {analysis_dir}/workflow_state.json"
        )
        return 0
    else:
        state.outcome = "STILL_VULNERABLE"
        _save_state(state, crash_file)
        _print_summary(state)

        if not args.no_revert_on_failure:
            print("\n  Patch did not fix the crash. Auto-reverting …")
            stage_revert(state)
            state.outcome = "REVERTED_AFTER_FAILURE"
            _save_state(state, crash_file)
        else:
            print("\n  --no-revert-on-failure set: leaving patch in place.")
        return 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _save_state(state: WorkflowState, crash_file: Path) -> None:
    analysis_dir = (
        Path(state.analysis_dir)
        if state.analysis_dir
        else PROJECT_ROOT / "crashes" / "analysis" / crash_file.name
    )
    analysis_dir.mkdir(parents=True, exist_ok=True)
    out = analysis_dir / "workflow_state.json"
    out.write_text(json.dumps(asdict(state), indent=2))


def _print_summary(state: WorkflowState) -> None:
    OUTCOMES = {
        "FIXED": ("✓", "FIXED — patch applied and verified"),
        "STILL_VULNERABLE": ("✗", "STILL VULNERABLE — patch did not fix the crash"),
        "REVERTED_AFTER_FAILURE": (
            "↩",
            "REVERTED — patch removed after failed verification",
        ),
        "NOT_REPRODUCIBLE": ("?", "NOT REPRODUCIBLE — crash did not trigger"),
        "FALSE_POSITIVE": ("~", "FALSE POSITIVE — not a real bug"),
        "NO_PATCH": ("!", "NO AUTOMATED PATCH — manual fix required"),
        "ANALYSIS_FAILED": ("✗", "ANALYSIS FAILED"),
        "PATCH_FAILED": ("✗", "PATCH FAILED — could not apply diff"),
        "BUILD_FAILED": ("✗", "BUILD FAILED — reverted"),
        "SKIPPED": ("-", "SKIPPED by user"),
        "REVERTED": ("↩", "REVERTED successfully"),
    }
    icon, msg = OUTCOMES.get(state.outcome, ("?", state.outcome))

    print(f"\n{'═' * 62}")
    print(f"  OUTCOME: {icon}  {msg}")
    print(f"{'═' * 62}")
    if state.analysis_dir:
        print(f"  Analysis dir:  {state.analysis_dir}")
        print(f"  Report:        {state.analysis_dir}/report.md")
        print(f"  State file:    {state.analysis_dir}/workflow_state.json")
    print()


if __name__ == "__main__":
    sys.exit(main())
