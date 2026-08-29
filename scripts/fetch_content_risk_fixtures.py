#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import sys
import urllib.request
import urllib.error


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_entries(path: pathlib.Path):
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(json.loads(line))
    return entries


def resolve_download_url(entry: dict) -> str | None:
    artifact_url = entry.get("artifact_url")
    if not artifact_url:
        return None
    if artifact_url.endswith("/json"):
        with urllib.request.urlopen(artifact_url) as resp:
            data = json.load(resp)
        urls = data.get("urls", [])
        if not urls:
            return None
        wheels = [u for u in urls if u.get("packagetype") in {"bdist_wheel", "bdist_egg"}]
        sdists = [u for u in urls if u.get("packagetype") == "sdist"]
        chosen = (wheels or sdists or urls)[0]
        return chosen.get("url")
    return artifact_url


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(entry: dict, force: bool) -> tuple[str, str]:
    out_path = REPO_ROOT / entry["artifact_path"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() and not force:
        return ("skipped", f"{entry['package']}@{entry.get('version') or 'unknown'} already present")

    try:
        url = resolve_download_url(entry)
    except urllib.error.HTTPError as exc:
        return ("missing", f"{entry['package']} artifact metadata unavailable: HTTP {exc.code}")
    except urllib.error.URLError as exc:
        return ("missing", f"{entry['package']} artifact metadata unavailable: {exc.reason}")
    if not url:
        return ("missing", f"{entry['package']} has no downloadable artifact URL")

    try:
        with urllib.request.urlopen(url) as resp, out_path.open("wb") as out:
            out.write(resp.read())
    except urllib.error.HTTPError as exc:
        return ("missing", f"{entry['package']} artifact download failed: HTTP {exc.code}")
    except urllib.error.URLError as exc:
        return ("missing", f"{entry['package']} artifact download failed: {exc.reason}")

    expected = entry.get("sha256")
    if expected:
        actual = sha256_file(out_path)
        if actual != expected:
            return ("checksum_mismatch", f"{entry['package']} expected {expected} got {actual}")

    return ("downloaded", f"{entry['package']} -> {entry['artifact_path']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        action="append",
        default=[],
        help="Manifest file under fixtures/content-risk (can be repeated)",
    )
    parser.add_argument("--label", choices=["malicious", "benign"], help="Filter by label")
    parser.add_argument("--ecosystem", choices=["npm", "pypi", "crates-io"], help="Filter by ecosystem")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    manifests = args.manifest or [
        "fixtures/content-risk/malicious.ndjson",
        "fixtures/content-risk/benign.ndjson",
    ]

    entries = []
    for manifest in manifests:
        entries.extend(load_entries(REPO_ROOT / manifest))

    if args.label:
        entries = [entry for entry in entries if entry.get("label") == args.label]
    if args.ecosystem:
        entries = [entry for entry in entries if entry.get("ecosystem") == args.ecosystem]

    for entry in entries:
        status = entry.get("status")
        if status in {"pending_vt_lookup", "pending_manual_review"}:
            print(json.dumps({"status": "skipped", "package": entry["package"], "reason": status}))
            continue
        result, detail = download(entry, args.force)
        print(json.dumps({"status": result, "package": entry["package"], "version": entry.get("version"), "detail": detail}))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
