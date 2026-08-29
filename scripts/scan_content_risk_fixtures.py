#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import tempfile
from datetime import datetime, timezone


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_entries(paths):
    entries = []
    for rel in paths:
        path = REPO_ROOT / rel
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(json.loads(line))
    return entries


def build_capture(entry):
    ecosystem = entry["ecosystem"]
    version = entry.get("version") or "0.0.0"
    artifact_path = REPO_ROOT / entry["artifact_path"]
    filename = artifact_path.name
    if ecosystem == "npm":
        kind = "npm-tarball"
    elif ecosystem == "pypi":
        kind = "bdist_wheel" if filename.endswith(".whl") else "sdist"
    else:
        kind = "crate"

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "event_id": f"{ecosystem}:{entry['package']}@{version}",
        "ecosystem": ecosystem,
        "package": entry["package"],
        "version": version,
        "observed_at": now,
        "published_at": now,
        "captured_at": now,
        "status": "Active",
        "artifacts": [
            {
                "filename": filename,
                "kind": kind,
                "url": entry.get("artifact_url"),
            }
        ],
        "details": {
            "local_artifact": {"path": str(artifact_path)},
        },
    }


def scan_entry(entry):
    artifact_rel = entry.get("artifact_path")
    if not artifact_rel:
        return {
            "package": entry["package"],
            "version": entry.get("version"),
            "label": entry["label"],
            "status": "pending_artifact",
        }

    artifact_path = REPO_ROOT / artifact_rel
    if not artifact_path.exists():
        return {
            "package": entry["package"],
            "version": entry.get("version"),
            "label": entry["label"],
            "status": "missing_artifact",
            "artifact_path": entry["artifact_path"],
        }

    capture = build_capture(entry)
    with tempfile.TemporaryDirectory() as tmp:
        capture_path = pathlib.Path(tmp) / "capture.json"
        capture_path.write_text(json.dumps(capture))
        proc = subprocess.run(
            [
                str(REPO_ROOT / "target/debug/content-risk-scan"),
                str(capture_path),
                "--artifact",
                str(artifact_path),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return {
                "package": entry["package"],
                "version": entry.get("version"),
                "label": entry["label"],
                "status": "scan_failed",
                "stderr": proc.stderr.strip(),
            }
        signal = json.loads(proc.stdout)
        return {
            "package": entry["package"],
            "version": entry.get("version"),
            "label": entry["label"],
            "status": "ok",
            "suspicious": signal.get("suspicious", False),
            "score": signal.get("score", 0),
            "factors": signal.get("factors", []),
            "reason": signal.get("reason"),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        action="append",
        default=[],
        help="Manifest file under fixtures/content-risk (can be repeated)",
    )
    parser.add_argument("--label", choices=["malicious", "benign"], help="Filter by label")
    parser.add_argument("--ecosystem", choices=["npm", "pypi", "crates-io"], help="Filter by ecosystem")
    args = parser.parse_args()

    manifests = args.manifest or [
        "fixtures/content-risk/malicious.ndjson",
        "fixtures/content-risk/benign.ndjson",
    ]
    entries = load_entries(manifests)
    if args.label:
        entries = [e for e in entries if e["label"] == args.label]
    if args.ecosystem:
        entries = [e for e in entries if e["ecosystem"] == args.ecosystem]

    results = [scan_entry(entry) for entry in entries]
    summary = {
        "total": len(results),
        "ok": sum(1 for r in results if r["status"] == "ok"),
        "missing_artifact": sum(1 for r in results if r["status"] == "missing_artifact"),
        "scan_failed": sum(1 for r in results if r["status"] == "scan_failed"),
        "malicious_hits": sum(1 for r in results if r.get("label") == "malicious" and r.get("suspicious")),
        "malicious_misses": sum(1 for r in results if r.get("label") == "malicious" and r.get("status") == "ok" and not r.get("suspicious")),
        "benign_clean": sum(1 for r in results if r.get("label") == "benign" and r.get("status") == "ok" and not r.get("suspicious")),
        "benign_fp": sum(1 for r in results if r.get("label") == "benign" and r.get("suspicious")),
    }
    print(json.dumps({"summary": summary, "results": results}, indent=2))


if __name__ == "__main__":
    main()
