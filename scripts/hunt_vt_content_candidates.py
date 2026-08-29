#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
VT = pathlib.Path(os.environ.get("VT_BIN", "vt"))

QUERY_SPECS = [
    {
        "ecosystem": "pypi",
        "query": 'type:zip name:.whl "api.telegram.org/bot"',
    },
    {
        "ecosystem": "pypi",
        "query": 'type:zip name:.whl "discord.com/api/webhooks/"',
    },
    {
        "ecosystem": "pypi",
        "query": 'type:zip name:.whl "ptb.discord.com/api/webhooks/"',
    },
    {
        "ecosystem": "pypi",
        "query": 'type:zip name:.whl "discordapp.com/api/webhooks/"',
    },
]


def artifact_path_for(download_dir: pathlib.Path, metadata):
    name = metadata.get("meaningful_name") or metadata.get("sha256")
    return download_dir / name


def run_json(args, stdin_text=None):
    proc = subprocess.run(
        [str(VT), *args, "--format", "json"],
        cwd=REPO_ROOT,
        input=stdin_text,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    raw = proc.stdout.strip()
    if not raw:
        return None
    return json.loads(raw)


def search_hashes(query, limit):
    data = run_json(["search", query, "-I", "-n", str(limit)])
    if not data:
        return []
    return data if isinstance(data, list) else []


def fetch_file_metadata(hashes):
    if not hashes:
        return []
    return run_json(
        [
            "file",
            "-i",
            "sha256,meaningful_name,names,type_description,type_extension,downloadable,size,last_analysis_stats",
            "-",
        ],
        stdin_text="\n".join(hashes) + "\n",
    )


def normalize_candidate(spec, item):
    name = item.get("meaningful_name") or (item.get("names") or [""])[0]
    pkg = None
    version = None
    if spec["ecosystem"] == "pypi":
        m = re.match(r"(?P<package>.+)-(?P<version>[^-]+)-py3-none-any\.whl$", name)
        if m:
            pkg = m.group("package").replace("_", "-")
            version = m.group("version")
    return {
        "ecosystem": spec["ecosystem"],
        "query": spec["query"],
        "sha256": item.get("sha256"),
        "meaningful_name": name,
        "package": pkg,
        "version": version,
        "downloadable": item.get("downloadable", False),
        "type_description": item.get("type_description"),
        "type_extension": item.get("type_extension"),
        "size": item.get("size"),
        "last_analysis_stats": item.get("last_analysis_stats", {}),
    }


def download_files(candidates, download_dir: pathlib.Path):
    download_dir.mkdir(parents=True, exist_ok=True)
    hashes = [c["sha256"] for c in candidates if c.get("downloadable")]
    if not hashes:
        return
    proc = subprocess.run(
        [str(VT), "download", "-o", str(download_dir), "-"],
        cwd=REPO_ROOT,
        input="\n".join(hashes) + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    for candidate in candidates:
        hash_path = download_dir / candidate["sha256"]
        if hash_path.exists():
            target = artifact_path_for(download_dir, candidate)
            if target != hash_path:
                hash_path.rename(target)
            candidate["artifact_path"] = str(target.relative_to(REPO_ROOT))


def scan_candidate(candidate):
    artifact_rel = candidate.get("artifact_path")
    if not artifact_rel:
        return None
    artifact_path = REPO_ROOT / artifact_rel
    if not artifact_path.exists():
        return None
    if candidate["ecosystem"] == "npm":
        kind = "npm-tarball"
    elif candidate["ecosystem"] == "pypi":
        kind = "bdist_wheel" if artifact_path.name.endswith(".whl") else "sdist"
    else:
        kind = "crate"
    capture = {
        "event_id": f"{candidate['ecosystem']}:{candidate.get('package') or candidate['sha256']}@{candidate.get('version') or '0.0.0'}",
        "ecosystem": candidate["ecosystem"],
        "package": candidate.get("package") or candidate["sha256"],
        "version": candidate.get("version") or "0.0.0",
        "observed_at": "2026-04-01T00:00:00Z",
        "published_at": "2026-04-01T00:00:00Z",
        "captured_at": "2026-04-01T00:00:00Z",
        "status": "Active",
        "artifacts": [{"filename": artifact_path.name, "kind": kind, "url": None}],
        "details": {"local_artifact": {"path": str(artifact_path)}},
    }
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
            return {"status": "scan_failed", "stderr": proc.stderr.strip()}
        return json.loads(proc.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--download", action="store_true")
    parser.add_argument(
        "--download-dir",
        default=".artifacts/malicious/vt-hunt",
        help="Directory relative to repo root for VT downloads",
    )
    parser.add_argument("--scan", action="store_true")
    args = parser.parse_args()

    all_candidates = []
    for spec in QUERY_SPECS:
        hashes = search_hashes(spec["query"], args.limit)
        if not hashes:
            continue
        items = fetch_file_metadata(hashes)
        for item in items:
            all_candidates.append(normalize_candidate(spec, item))
    if args.download:
        download_files(all_candidates, REPO_ROOT / args.download_dir)
    if args.scan:
        for candidate in all_candidates:
            candidate["scan"] = scan_candidate(candidate)
    print(json.dumps(all_candidates, indent=2))


if __name__ == "__main__":
    main()
