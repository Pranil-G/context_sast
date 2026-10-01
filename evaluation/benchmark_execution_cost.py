from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil


DEFAULT_APKS = (
    ("OVAA", "test/ovaa-master/app/build/outputs/apk/debug/app-debug.apk"),
    ("Motorola SecurityHub", "test/com.motorola.securityhub.apk"),
    ("Motorola Device Help", "test/com.motorola.genie.apk"),
    ("Motorola Smart Connect", "test/com.motorola.mobiledesktop.apk"),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def process_rss(process: psutil.Process) -> int:
    total = 0
    try:
        candidates = (process, *process.children(recursive=True))
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        candidates = ()
    for candidate in candidates:
        try:
            total += candidate.memory_info().rss
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return total


def run_once(repo: Path, apk: Path) -> dict[str, object]:
    command = [sys.executable, "-m", "context_sast.cli", "--apk", str(apk), "--json-only"]
    started = time.perf_counter()
    child = subprocess.Popen(command, cwd=repo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    observed = psutil.Process(child.pid)
    peak_rss = 0
    while child.poll() is None:
        peak_rss = max(peak_rss, process_rss(observed))
        time.sleep(0.05)
    peak_rss = max(peak_rss, process_rss(observed))
    elapsed = time.perf_counter() - started
    return {
        "wall_seconds": round(elapsed, 3),
        "peak_rss_bytes": peak_rss,
        "peak_rss_mib": round(peak_rss / (1024 * 1024), 3),
        "exit_status": child.returncode,
    }


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "median": round(statistics.median(values), 3),
        "minimum": round(min(values), 3),
        "maximum": round(max(values), 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark each APK in a fresh analyzer process.")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("results/execution-cost.json"))
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    repo = Path(__file__).resolve().parents[1]
    records = []
    for label, relative in DEFAULT_APKS:
        apk = repo / relative
        if not apk.is_file():
            raise FileNotFoundError(apk)
        trials = []
        for trial_number in range(1, args.runs + 1):
            result = run_once(repo, apk)
            result["trial"] = trial_number
            trials.append(result)
            print(f"{label}: trial {trial_number}/{args.runs}, {result['wall_seconds']} s, {result['peak_rss_mib']} MiB, exit {result['exit_status']}", flush=True)
        wall = [float(trial["wall_seconds"]) for trial in trials]
        memory = [float(trial["peak_rss_mib"]) for trial in trials]
        records.append(
            {
                "label": label,
                "apk_path": relative,
                "apk_sha256": sha256(apk),
                "apk_size_bytes": apk.stat().st_size,
                "apk_size_mib": round(apk.stat().st_size / (1024 * 1024), 3),
                "trials": trials,
                "wall_seconds": summarize(wall),
                "peak_rss_mib": summarize(memory),
            }
        )

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "runs_per_apk": args.runs,
        "process_policy": "one fresh analyzer process per APK trial",
        "memory_unit": "MiB (2^20 bytes)",
        "records": records,
    }
    output = args.output if args.output.is_absolute() else repo / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Archived {output}")


if __name__ == "__main__":
    main()
