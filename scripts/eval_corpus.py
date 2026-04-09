#!/usr/bin/env python3
"""
Evaluate the detection corpus against the YARA rules and produce precision/recall stats.

Usage:
  python scripts/eval_corpus.py                    # evaluate all
  python scripts/eval_corpus.py --label malicious  # only malicious
  python scripts/eval_corpus.py --ecosystem npm    # only npm
  python scripts/eval_corpus.py --json             # JSON output
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MALICIOUS_MANIFEST = REPO_ROOT / "fixtures" / "content-risk" / "malicious.ndjson"
BENIGN_MANIFEST = REPO_ROOT / "fixtures" / "content-risk" / "benign.ndjson"
SCAN_BINARY = REPO_ROOT / "target" / "debug" / "supply-stream"


def load_manifest(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(json.loads(line))
    return entries


def scan_entry(entry: dict) -> dict:
    """Scan a single corpus entry using the Rust scanner."""
    artifact_path = REPO_ROOT / entry["artifact_path"]
    if not artifact_path.exists():
        return {**entry, "scan_status": "artifact_missing"}

    ecosystem = entry["ecosystem"]
    package = entry["package"]
    version = entry.get("version", "0.0.0")

    # Determine artifact kind
    filename = artifact_path.name
    if filename.endswith(".tgz"):
        kind = "npm-tarball"
    elif filename.endswith(".whl"):
        kind = "bdist_wheel"
    elif filename.endswith(".tar.gz") and not filename.endswith(".crate"):
        kind = "sdist"
    elif filename.endswith(".crate"):
        kind = "crate"
    else:
        kind = "unknown"

    # Build minimal capture JSON for the scanner
    capture = {
        "event_id": f"{ecosystem}:{package}@{version}",
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "observed_at": "2026-04-04T00:00:00Z",
        "published_at": None,
        "captured_at": "2026-04-04T00:00:00Z",
        "status": "Active",
        "package_url": None,
        "release_url": None,
        "metadata_url": None,
        "raw_metadata_path": None,
        "artifacts": [{"filename": filename, "kind": kind, "url": None, "size_bytes": artifact_path.stat().st_size}],
        "upstream_repository": None,
        "details": {
            "local_artifact": {"path": str(artifact_path), "filename": filename},
            "dependencies": [],
            "bin": None,
            "main": None,
            "pkg_targets": [],
            "has_install_scripts": False,
        },
    }

    with tempfile.TemporaryDirectory() as tmp:
        capture_path = pathlib.Path(tmp) / "capture.json"
        capture_path.write_text(json.dumps(capture))

        proc = subprocess.run(
            [str(SCAN_BINARY), "history", "scan-content-risk", "--capture", str(capture_path)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if proc.returncode != 0:
            # Try to parse output anyway
            for line in (proc.stdout or "").strip().splitlines():
                try:
                    signal = json.loads(line)
                    return {**entry, "scan_status": "ok", "signal": signal}
                except json.JSONDecodeError:
                    continue
            return {**entry, "scan_status": "scan_failed", "error": (proc.stderr or "")[:200]}

        for line in proc.stdout.strip().splitlines():
            try:
                signal = json.loads(line)
                return {**entry, "scan_status": "ok", "signal": signal}
            except json.JSONDecodeError:
                continue

        return {**entry, "scan_status": "no_output"}


def evaluate(entries: list[dict], workers: int, label_filter: str | None, eco_filter: str | None):
    if label_filter:
        entries = [e for e in entries if e.get("label") == label_filter]
    if eco_filter:
        entries = [e for e in entries if e.get("ecosystem") == eco_filter]

    # Filter to only downloaded entries
    entries = [e for e in entries if e.get("status") == "downloaded"]

    print(f"Evaluating {len(entries)} samples...", file=sys.stderr)

    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_entry, e): e for e in entries}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            done += 1
            if done % 50 == 0:
                print(f"  {done}/{len(entries)}", file=sys.stderr)

    return results


def compute_stats(results: list[dict]) -> dict:
    tp = 0  # malicious correctly flagged
    fp = 0  # benign incorrectly flagged
    tn = 0  # benign correctly clean
    fn = 0  # malicious missed
    errors = 0
    rule_hits = {}

    for r in results:
        label = r.get("label", "unknown")
        signal = r.get("signal", {})
        scan_status = r.get("scan_status", "")

        if scan_status != "ok":
            errors += 1
            continue

        suspicious = signal.get("suspicious", False)
        matched_rules = [m.get("rule_id", "") for m in signal.get("matches", [])]

        for rule in matched_rules:
            rule_hits[rule] = rule_hits.get(rule, {"tp": 0, "fp": 0})
            if label == "malicious":
                rule_hits[rule]["tp"] += 1
            else:
                rule_hits[rule]["fp"] += 1

        if label == "malicious":
            if suspicious or matched_rules:
                tp += 1
            else:
                fn += 1
        elif label == "benign":
            if suspicious or matched_rules:
                fp += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "total": len(results),
        "errors": errors,
        "malicious_total": tp + fn,
        "benign_total": fp + tn,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 6),
        "rule_hits": dict(sorted(rule_hits.items(), key=lambda x: -(x[1]["tp"] + x[1]["fp"]))),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", choices=["malicious", "benign"])
    parser.add_argument("--ecosystem", choices=["npm", "pypi", "crates-io"])
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    entries = load_manifest(MALICIOUS_MANIFEST) + load_manifest(BENIGN_MANIFEST)
    results = evaluate(entries, args.workers, args.label, args.ecosystem)
    stats = compute_stats(results)

    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"DETECTION CORPUS EVALUATION")
        print(f"{'='*60}")
        print(f"Total samples:    {stats['total']} ({stats['errors']} scan errors)")
        print(f"Malicious:        {stats['malicious_total']}")
        print(f"Benign:           {stats['benign_total']}")
        print(f"")
        print(f"True Positives:   {stats['true_positives']}")
        print(f"False Positives:  {stats['false_positives']}")
        print(f"True Negatives:   {stats['true_negatives']}")
        print(f"False Negatives:  {stats['false_negatives']}")
        print(f"")
        print(f"Precision:        {stats['precision']:.2%}")
        print(f"Recall:           {stats['recall']:.2%}")
        print(f"F1 Score:         {stats['f1_score']:.2%}")
        print(f"FP Rate:          {stats['false_positive_rate']:.4%}")
        print(f"")
        if stats["rule_hits"]:
            print(f"Rule breakdown:")
            for rule, counts in stats["rule_hits"].items():
                print(f"  {rule}: {counts['tp']} TP / {counts['fp']} FP")

    # Write false positives and false negatives for review
    fps = [r for r in results if r.get("label") == "benign" and r.get("signal", {}).get("matches")]
    fns = [r for r in results if r.get("label") == "malicious" and not r.get("signal", {}).get("matches") and r.get("scan_status") == "ok"]

    if fps:
        fp_path = REPO_ROOT / ".artifacts" / "eval-false-positives.ndjson"
        fp_path.parent.mkdir(parents=True, exist_ok=True)
        with fp_path.open("w") as f:
            for r in fps:
                f.write(json.dumps({"package": r["package"], "version": r.get("version"), "ecosystem": r["ecosystem"],
                                     "rules": [m["rule_id"] for m in r.get("signal", {}).get("matches", [])]}) + "\n")
        print(f"\nFalse positives written to: {fp_path.relative_to(REPO_ROOT)}")

    if fns:
        fn_path = REPO_ROOT / ".artifacts" / "eval-false-negatives.ndjson"
        fn_path.parent.mkdir(parents=True, exist_ok=True)
        with fn_path.open("w") as f:
            for r in fns:
                f.write(json.dumps({"package": r["package"], "version": r.get("version"), "ecosystem": r["ecosystem"],
                                     "expected_rules": r.get("expected_rules", [])}) + "\n")
        print(f"False negatives written to: {fn_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    raise SystemExit(main())
