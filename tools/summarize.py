#!/usr/bin/env python3
"""
tools/summarize.py — Generate a findings summary from all completed crash analyses.

Reads every crashes/analysis/*/analysis.json and workflow_state.json,
then prints a structured report to stdout and writes summary.json.

Called automatically by cleanup.sh before any deletion.  Can also be run
standalone at any time without affecting any files.

Usage:
    python3 tools/summarize.py [--output DIR]
"""

import json
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent


@dataclass
class FindingRecord:
    crash_file: str
    harness: str
    sanitizer_type: str
    bug_subtype: str
    runtime_error: str
    reproducible: bool
    is_false_positive: bool
    fp_reason: str
    has_patch: bool
    workflow_outcome: str  # FIXED / REVERTED / NO_PATCH / "" (not run)
    patch_file: Optional[str]
    report_file: Optional[str]
    reproducer_file: Optional[str]


def load_findings() -> List[FindingRecord]:
    analysis_root = PROJECT_ROOT / "crashes" / "analysis"
    findings = []

    if not analysis_root.exists():
        return findings

    for analysis_json in sorted(analysis_root.rglob("analysis.json")):
        try:
            a = json.loads(analysis_json.read_text())
        except Exception:
            continue

        # Load companion workflow state if present
        wf_json = analysis_json.parent / "workflow_state.json"
        wf = {}
        if wf_json.exists():
            try:
                wf = json.loads(wf_json.read_text())
            except Exception:
                pass

        patch_file = analysis_json.parent / "patch.diff"
        report_file = analysis_json.parent / "report.md"
        reproducer_file = analysis_json.parent / "reproducer.bin"

        findings.append(
            FindingRecord(
                crash_file=a.get("crash_file", ""),
                harness=a.get("harness", ""),
                sanitizer_type=a.get("sanitizer_type", ""),
                bug_subtype=a.get("bug_subtype", ""),
                runtime_error=a.get("runtime_error", ""),
                reproducible=a.get("reproducible", False),
                is_false_positive=a.get("is_false_positive", False),
                fp_reason=a.get("fp_reason", ""),
                has_patch=a.get("has_patch", False),
                workflow_outcome=wf.get("outcome", ""),
                patch_file=str(patch_file) if patch_file.exists() else None,
                report_file=str(report_file) if report_file.exists() else None,
                reproducer_file=str(reproducer_file)
                if reproducer_file.exists()
                else None,
            )
        )

    return findings


def disk_usage(path: Path) -> int:
    """Return total bytes used under path (0 if not present)."""
    if not path.exists():
        return 0
    total = 0
    if path.is_file():
        return path.stat().st_size
    for f in path.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def count_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for f in path.rglob("*") if f.is_file())


def print_summary(findings: List[FindingRecord]) -> None:
    real_bugs = [f for f in findings if f.reproducible and not f.is_false_positive]
    fps = [f for f in findings if f.is_false_positive]
    not_repro = [f for f in findings if not f.reproducible and not f.is_false_positive]
    patched = [f for f in real_bugs if f.workflow_outcome == "FIXED"]
    reverted = [f for f in real_bugs if f.workflow_outcome == "REVERTED"]
    no_patch = [f for f in real_bugs if not f.has_patch]

    raw_dir = PROJECT_ROOT / "crashes" / "raw"
    corpus_dir = PROJECT_ROOT / "corpus"
    builds_dir = PROJECT_ROOT / "builds"
    src_dir = PROJECT_ROOT / "src"

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              pkcs11-fuzzer  —  Session Summary               ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print()

    # ── Crash statistics ──────────────────────────────────────────────────
    print("  CRASH STATISTICS")
    print(f"  {'Total crash artifacts:':<32} {count_files(raw_dir)}")
    print(f"  {'Unique real bugs confirmed:':<32} {len(real_bugs)}")
    print(
        f"  {'  — with patch generated:':<32} {sum(1 for f in real_bugs if f.has_patch)}"
    )
    print(f"  {'  — patch applied & FIXED:':<32} {len(patched)}")
    print(f"  {'  — patch reverted:':<32} {len(reverted)}")
    print(f"  {'  — manual fix needed:':<32} {len(no_patch)}")
    print(f"  {'False positives classified:':<32} {len(fps)}")
    print(f"  {'Not reproducible:':<32} {len(not_repro)}")
    print()

    # ── Per-bug details ───────────────────────────────────────────────────
    if real_bugs:
        print("  CONFIRMED BUGS")
        for i, f in enumerate(real_bugs, 1):
            status = f.workflow_outcome or (
                "PATCH_READY" if f.has_patch else "NEEDS_MANUAL_FIX"
            )
            error = (
                (f.runtime_error[:55] + "…")
                if len(f.runtime_error) > 55
                else f.runtime_error
            )
            print(f"  [{i}] {f.bug_subtype:<22}  {status}")
            print(f"      Harness: {f.harness}")
            if error:
                print(f"      Error:   {error}")
            if f.report_file:
                rel = Path(f.report_file).relative_to(PROJECT_ROOT)
                print(f"      Report:  {rel}")
            if f.patch_file:
                rel = Path(f.patch_file).relative_to(PROJECT_ROOT)
                print(f"      Patch:   {rel}")
            print()

    if fps:
        print("  FALSE POSITIVES")
        for f in fps:
            print(f"  — {f.harness}: {f.fp_reason[:60]}")
        print()

    # ── Corpus ────────────────────────────────────────────────────────────
    corpus_files = count_files(corpus_dir)
    corpus_size = human_bytes(disk_usage(corpus_dir))
    print("  CORPUS & COVERAGE")
    print(f"  {'libFuzzer corpus entries:':<32} {corpus_files}  ({corpus_size})")
    print()

    # ── Disk usage ────────────────────────────────────────────────────────
    print("  DISK USAGE")
    dirs = [
        ("builds/libfuzzer/", builds_dir / "libfuzzer"),
        ("builds/tsan/", builds_dir / "tsan"),
        ("src/ (source clones)", src_dir),
        ("corpus/", corpus_dir),
        ("crashes/", PROJECT_ROOT / "crashes"),
        ("coverage/", PROJECT_ROOT / "coverage"),
    ]
    total = 0
    for label, path in dirs:
        size = disk_usage(path)
        total += size
        if size > 0:
            print(f"  {'  ' + label:<34} {human_bytes(size):>8}")
    print(f"  {'  TOTAL':<34} {human_bytes(total):>8}")
    print()
    print("─" * 64)


def write_summary_json(findings: List[FindingRecord], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / "findings_summary.json"
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(PROJECT_ROOT),
        "total_findings": len(findings),
        "real_bugs": sum(
            1 for f in findings if f.reproducible and not f.is_false_positive
        ),
        "false_positives": sum(1 for f in findings if f.is_false_positive),
        "findings": [asdict(f) for f in findings],
    }
    out.write_text(json.dumps(data, indent=2))
    return out


def main():
    import argparse

    ap = argparse.ArgumentParser(description="Generate a findings summary.")
    ap.add_argument(
        "--output",
        default=None,
        help="Directory to write findings_summary.json (default: crashes/)",
    )
    ap.add_argument(
        "--json-only",
        action="store_true",
        help="Skip the human-readable output; write JSON only",
    )
    args = ap.parse_args()

    findings = load_findings()

    if not args.json_only:
        print_summary(findings)

    out_dir = Path(args.output) if args.output else PROJECT_ROOT / "crashes"
    json_path = write_summary_json(findings, out_dir)

    if not args.json_only:
        print(f"  Summary JSON: {json_path.relative_to(PROJECT_ROOT)}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
