#!/usr/bin/env python3
"""
Build a large-scale detection corpus from:
  1. VirusTotal Intelligence (malicious samples)
  2. Package registries (benign baseline from popular packages)
  3. Existing captures (already-scanned packages from live runs)

Usage:
  # Fetch malicious from VT (requires VT_API_KEY env var)
  python scripts/build_corpus.py malicious --vt-limit 200

  # Fetch benign from registries
  python scripts/build_corpus.py benign --npm-top 5000 --pypi-top 3000 --crates-top 2000

  # Import from existing captures
  python scripts/build_corpus.py import-captures

  # Show corpus stats
  python scripts/build_corpus.py stats
"""
import argparse
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MALICIOUS_MANIFEST = REPO_ROOT / "fixtures" / "content-risk" / "malicious.ndjson"
BENIGN_MANIFEST = REPO_ROOT / "fixtures" / "content-risk" / "benign.ndjson"
ARTIFACTS_DIR = REPO_ROOT / ".artifacts"
CAPTURES_DIR = REPO_ROOT / ".supply-stream-data" / "captures"

VT_API_BASE = "https://www.virustotal.com/api/v3"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_JSON_API = "https://pypi.org/pypi"
CRATES_API = "https://crates.io/api/v1"

USER_AGENT = "supply-stream-corpus-builder/0.1.0"


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(json.loads(line))
    return entries


def save_manifest(path: pathlib.Path, entries: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    unique = []
    for e in entries:
        key = f"{e['ecosystem']}:{e['package']}@{e.get('version', '?')}"
        if key not in seen:
            seen.add(key)
            unique.append(e)
    unique.sort(key=lambda e: (e["ecosystem"], e["package"], e.get("version", "")))
    with path.open("w") as f:
        for entry in unique:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def vt_request(endpoint: str, api_key: str, params: dict | None = None) -> dict:
    url = f"{VT_API_BASE}/{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "x-apikey": api_key,
        "User-Agent": USER_AGENT,
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def vt_search(query: str, api_key: str, limit: int = 100) -> list[dict]:
    """Search VT Intelligence for files matching query."""
    results = []
    cursor = None
    while len(results) < limit:
        params = {"query": query, "limit": min(limit - len(results), 100)}
        if cursor:
            params["cursor"] = cursor
        try:
            data = vt_request("intelligence/search", api_key, params)
        except urllib.error.HTTPError as e:
            print(f"  VT search error: HTTP {e.code}", file=sys.stderr)
            break
        items = data.get("data", [])
        if not items:
            break
        results.extend(items)
        cursor = data.get("meta", {}).get("cursor")
        if not cursor:
            break
        time.sleep(0.25)  # rate limit
    return results[:limit]


def vt_download(sha256: str, api_key: str, dest: pathlib.Path) -> bool:
    """Download a file from VT by SHA256."""
    url = f"{VT_API_BASE}/files/{sha256}/download"
    req = urllib.request.Request(url, headers={
        "x-apikey": api_key,
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("wb") as f:
                f.write(resp.read())
        return True
    except urllib.error.HTTPError as e:
        print(f"  VT download failed for {sha256}: HTTP {e.code}", file=sys.stderr)
        return False


def parse_npm_name_from_tgz(filename: str) -> tuple[str | None, str | None]:
    """Extract package name and version from npm tarball filename."""
    import re
    # scoped: @scope-name-1.0.0.tgz or name-1.0.0.tgz
    m = re.match(r"^(.+)-(\d+\.\d+\.\d+.*)\.tgz$", filename)
    if m:
        return m.group(1), m.group(2)
    return None, None


def parse_pypi_name_from_whl(filename: str) -> tuple[str | None, str | None]:
    """Extract package name and version from wheel filename."""
    import re
    m = re.match(r"^(.+?)-([^-]+)-", filename)
    if m:
        return m.group(1).replace("_", "-"), m.group(2)
    return None, None


def parse_pypi_name_from_sdist(filename: str) -> tuple[str | None, str | None]:
    import re
    m = re.match(r"^(.+?)-([^-]+)\.tar\.gz$", filename)
    if m:
        return m.group(1).replace("_", "-"), m.group(2)
    return None, None


# ── VT Malicious Corpus Builder ──────────────────────────────────────────

VT_QUERIES = {
    "npm": [
        'type:gzip name:".tgz" content:"discord.com/api/webhooks/" content:"child_process"',
        'type:gzip name:".tgz" content:"api.telegram.org/bot" content:"child_process"',
        'type:gzip name:".tgz" content:"eval(" content:"Buffer.from(" content:"base64"',
        'type:gzip name:".tgz" content:"bash -i >& /dev/tcp/"',
        'type:gzip name:".tgz" content:"postinstall" content:"curl " content:"| sh"',
        'type:gzip name:".tgz" content:"postinstall" content:"powershell" content:"-ep bypass"',
        'type:gzip name:".tgz" content:"SANDWORM_MODE"',
        'type:gzip name:".tgz" content:"process.env.SANDWORM"',
        'type:gzip name:".tgz" content:".ssh/id_rsa" content:"http.request("',
        'type:gzip name:".tgz" content:"execSync(" content:".npmrc" content:"http"',
        'type:gzip name:".tgz" content:"(0,eval)(" content:"zlib.inflateSync"',
        'type:gzip name:".tgz" content:"trufflehog" content:"execSync"',
    ],
    "pypi": [
        'type:zip name:".whl" content:"discord.com/api/webhooks/"',
        'type:zip name:".whl" content:"api.telegram.org/bot"',
        'type:zip name:".whl" content:"base64.b64decode" content:"exec("',
        'type:zip name:".whl" content:"marshal.loads" content:"zlib.decompress"',
        'type:zip name:".whl" content:"__import__(\'builtins\').exec("',
        'type:zip name:".whl" content:"socket.socket" content:"subprocess.call" content:"/bin/bash"',
        'type:zip name:".whl" content:"pyperclip" content:"re.search" content:"0x"',
        'type:zip name:".whl" content:"fernet" content:".decrypt(" content:"exec("',
        'type:zip name:".whl" content:"os.environ" content:"requests.post("',
        'type:zip name:".whl" content:".ssh/id_rsa" content:"requests.post("',
        'name:".tar.gz" content:"setup(" content:"cmdclass" content:"subprocess"',
    ],
    "crates-io": [
        'type:gzip name:".crate" content:"reqwest" content:"Command::new"',
        'type:gzip name:".crate" content:"TcpStream::connect" content:"/bin/sh"',
        'type:gzip name:".crate" content:"#[ctor::ctor]" content:"reqwest"',
    ],
}


def build_malicious_vt(api_key: str, limit_per_query: int):
    """Search VT and download malicious package samples."""
    existing = load_manifest(MALICIOUS_MANIFEST)
    existing_keys = {f"{e['ecosystem']}:{e['package']}@{e.get('version')}" for e in existing}
    new_entries = []

    for ecosystem, queries in VT_QUERIES.items():
        for query in queries:
            print(f"[VT] Searching {ecosystem}: {query[:80]}...")
            results = vt_search(query, api_key, limit=limit_per_query)
            print(f"  Found {len(results)} results")

            for item in results:
                attrs = item.get("attributes", {})
                sha256 = attrs.get("sha256", "")
                filename = attrs.get("meaningful_name", "") or (attrs.get("names") or [""])[0]
                size = attrs.get("size", 0)
                stats = attrs.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)

                if malicious_count < 1:
                    continue
                if size > 50 * 1024 * 1024:
                    continue

                # Parse package name from filename
                if ecosystem == "npm":
                    pkg, version = parse_npm_name_from_tgz(filename)
                    artifact_dir = ARTIFACTS_DIR / "malicious" / "npm"
                elif ecosystem == "pypi":
                    if filename.endswith(".whl"):
                        pkg, version = parse_pypi_name_from_whl(filename)
                    else:
                        pkg, version = parse_pypi_name_from_sdist(filename)
                    artifact_dir = ARTIFACTS_DIR / "malicious" / "pypi"
                elif ecosystem == "crates-io":
                    pkg, version = filename.replace(".crate", "").rsplit("-", 1) if "-" in filename else (filename, None)
                    artifact_dir = ARTIFACTS_DIR / "malicious" / "crates-io"
                else:
                    continue

                if not pkg:
                    pkg = sha256[:16]
                if not version:
                    version = "0.0.0"

                key = f"{ecosystem}:{pkg}@{version}"
                if key in existing_keys:
                    continue
                existing_keys.add(key)

                dest = artifact_dir / filename if filename else artifact_dir / f"{sha256}.bin"
                artifact_path = str(dest.relative_to(REPO_ROOT))

                entry = {
                    "ecosystem": ecosystem,
                    "package": pkg,
                    "version": version,
                    "label": "malicious",
                    "status": "pending_download",
                    "source_kind": "vt_intelligence",
                    "sha256": sha256,
                    "artifact_path": artifact_path,
                    "vt_malicious_count": malicious_count,
                    "vt_query": query[:120],
                    "notes": f"VT Intelligence hit ({malicious_count} engines)",
                }

                # Download
                if vt_download(sha256, api_key, dest):
                    entry["status"] = "downloaded"
                    actual_sha = sha256_file(dest)
                    if actual_sha != sha256:
                        entry["status"] = "checksum_mismatch"
                else:
                    entry["status"] = "download_failed"

                new_entries.append(entry)
                print(f"  [{entry['status']}] {ecosystem}:{pkg}@{version} ({malicious_count} engines)")

            time.sleep(1)  # between queries

    all_entries = existing + new_entries
    save_manifest(MALICIOUS_MANIFEST, all_entries)
    print(f"\nMalicious manifest: {len(all_entries)} total ({len(new_entries)} new)")


# ── Registry Benign Corpus Builder ───────────────────────────────────────

def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.load(resp)


def fetch_npm_top(limit: int) -> list[dict]:
    """Fetch top npm packages by popularity."""
    entries = []
    page_size = 250
    offset = 0
    while len(entries) < limit:
        url = f"{NPM_REGISTRY}/-/v1/search?text=boost-exact:true&size={page_size}&from={offset}&quality=0.0&maintenance=0.0&popularity=1.0"
        try:
            data = fetch_json(url)
        except Exception as e:
            print(f"  npm search error at offset {offset}: {e}", file=sys.stderr)
            break
        objects = data.get("objects", [])
        if not objects:
            break
        for obj in objects:
            pkg = obj.get("package", {})
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if not name or not version:
                continue

            # Build tarball URL
            scope = ""
            if name.startswith("@"):
                scope = name.split("/")[0]
            tarball_url = f"{NPM_REGISTRY}/{name}/-/{name.split('/')[-1]}-{version}.tgz"
            filename = f"{name.replace('/', '-').replace('@', '')}-{version}.tgz"
            artifact_path = f".artifacts/benign/npm/{filename}"

            entries.append({
                "ecosystem": "npm",
                "package": name,
                "version": version,
                "label": "benign",
                "status": "pending_download",
                "source_kind": "registry_top",
                "artifact_url": tarball_url,
                "artifact_path": artifact_path,
            })
        offset += page_size
        time.sleep(0.1)
    return entries[:limit]


def fetch_pypi_top(limit: int) -> list[dict]:
    """Fetch top PyPI packages from the BigQuery dataset stats or top-packages API."""
    entries = []
    # Use the hugovk/top-pypi-packages dataset
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    try:
        data = fetch_json(url)
    except Exception as e:
        print(f"  PyPI top packages fetch error: {e}", file=sys.stderr)
        return entries

    rows = data.get("rows", [])[:limit]
    for row in rows:
        name = row.get("project", "")
        if not name:
            continue
        # Get latest version
        try:
            pkg_data = fetch_json(f"{PYPI_JSON_API}/{name}/json")
        except Exception:
            continue
        version = pkg_data.get("info", {}).get("version", "")
        urls = pkg_data.get("urls", [])
        # Prefer wheel
        wheel = next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None)
        sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
        chosen = wheel or sdist
        if not chosen:
            continue
        dl_url = chosen["url"]
        filename = chosen["filename"]
        artifact_path = f".artifacts/benign/pypi/{filename}"

        entries.append({
            "ecosystem": "pypi",
            "package": name,
            "version": version,
            "label": "benign",
            "status": "pending_download",
            "source_kind": "registry_top",
            "artifact_url": dl_url,
            "artifact_path": artifact_path,
            "sha256": chosen.get("digests", {}).get("sha256"),
        })
        time.sleep(0.05)
    return entries[:limit]


def fetch_crates_top(limit: int) -> list[dict]:
    """Fetch top crates.io crates by downloads."""
    entries = []
    page = 1
    per_page = 100
    while len(entries) < limit:
        url = f"{CRATES_API}/crates?page={page}&per_page={per_page}&sort=downloads"
        try:
            data = fetch_json(url)
        except Exception as e:
            print(f"  crates.io search error at page {page}: {e}", file=sys.stderr)
            break
        crates = data.get("crates", [])
        if not crates:
            break
        for crate in crates:
            name = crate.get("id", "")
            version = crate.get("newest_version", crate.get("max_version", ""))
            if not name or not version:
                continue
            dl_url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
            filename = f"{name}-{version}.crate"
            artifact_path = f".artifacts/benign/crates-io/{filename}"
            entries.append({
                "ecosystem": "crates-io",
                "package": name,
                "version": version,
                "label": "benign",
                "status": "pending_download",
                "source_kind": "registry_top",
                "artifact_url": dl_url,
                "artifact_path": artifact_path,
            })
        page += 1
        time.sleep(0.2)
    return entries[:limit]


def download_entry(entry: dict, force: bool = False) -> dict:
    """Download a single corpus entry artifact."""
    dest = REPO_ROOT / entry["artifact_path"]
    if dest.exists() and not force:
        entry["status"] = "downloaded"
        return entry
    url = entry.get("artifact_url")
    if not url:
        entry["status"] = "no_url"
        return entry
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("wb") as f:
                f.write(resp.read())
        entry["status"] = "downloaded"
        if entry.get("sha256"):
            actual = sha256_file(dest)
            if actual != entry["sha256"]:
                entry["status"] = "checksum_mismatch"
    except Exception as e:
        entry["status"] = "download_failed"
        entry["error"] = str(e)[:200]
    return entry


def build_benign(npm_top: int, pypi_top: int, crates_top: int, workers: int):
    """Download popular packages from registries as benign baseline."""
    existing = load_manifest(BENIGN_MANIFEST)
    existing_keys = {f"{e['ecosystem']}:{e['package']}@{e.get('version')}" for e in existing}

    new_entries = []

    if npm_top > 0:
        print(f"[npm] Fetching top {npm_top} packages...")
        npm_entries = fetch_npm_top(npm_top)
        npm_entries = [e for e in npm_entries if f"{e['ecosystem']}:{e['package']}@{e.get('version')}" not in existing_keys]
        print(f"  {len(npm_entries)} new npm entries to download")
        new_entries.extend(npm_entries)

    if pypi_top > 0:
        print(f"[pypi] Fetching top {pypi_top} packages...")
        pypi_entries = fetch_pypi_top(pypi_top)
        pypi_entries = [e for e in pypi_entries if f"{e['ecosystem']}:{e['package']}@{e.get('version')}" not in existing_keys]
        print(f"  {len(pypi_entries)} new pypi entries to download")
        new_entries.extend(pypi_entries)

    if crates_top > 0:
        print(f"[crates] Fetching top {crates_top} crates...")
        crates_entries = fetch_crates_top(crates_top)
        crates_entries = [e for e in crates_entries if f"{e['ecosystem']}:{e['package']}@{e.get('version')}" not in existing_keys]
        print(f"  {len(crates_entries)} new crate entries to download")
        new_entries.extend(crates_entries)

    # Download in parallel
    if new_entries:
        print(f"\nDownloading {len(new_entries)} artifacts ({workers} workers)...")
        downloaded = 0
        failed = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(download_entry, e): e for e in new_entries}
            for future in as_completed(futures):
                entry = future.result()
                if entry["status"] == "downloaded":
                    downloaded += 1
                else:
                    failed += 1
                total = downloaded + failed
                if total % 100 == 0:
                    print(f"  Progress: {total}/{len(new_entries)} ({downloaded} ok, {failed} failed)")
        print(f"  Done: {downloaded} downloaded, {failed} failed")

    all_entries = existing + new_entries
    save_manifest(BENIGN_MANIFEST, all_entries)
    print(f"\nBenign manifest: {len(all_entries)} total ({len(new_entries)} new)")


# ── Import Captures ──────────────────────────────────────────────────────

def import_captures():
    """Import already-captured packages into the benign corpus."""
    existing = load_manifest(BENIGN_MANIFEST)
    existing_keys = {f"{e['ecosystem']}:{e['package']}@{e.get('version')}" for e in existing}
    new_entries = []

    for ecosystem_dir in CAPTURES_DIR.iterdir():
        if not ecosystem_dir.is_dir():
            continue
        ecosystem = ecosystem_dir.name
        for pkg_dir in ecosystem_dir.iterdir():
            if not pkg_dir.is_dir():
                continue
            for ver_dir in pkg_dir.iterdir():
                if not ver_dir.is_dir():
                    continue
                capture_path = ver_dir / "capture.json"
                if not capture_path.exists():
                    continue
                artifacts_dir = ver_dir / "artifacts"
                if not artifacts_dir.exists():
                    continue
                artifact_files = list(artifacts_dir.iterdir())
                if not artifact_files:
                    continue

                try:
                    capture = json.loads(capture_path.read_text())
                except Exception:
                    continue

                pkg = capture.get("package", pkg_dir.name)
                version = capture.get("version", ver_dir.name)
                key = f"{ecosystem}:{pkg}@{version}"
                if key in existing_keys:
                    continue
                existing_keys.add(key)

                # Check if it had content-risk matches (→ skip for benign)
                cr = capture.get("details", {}).get("content_risk", {})
                if cr.get("suspicious"):
                    continue

                artifact = artifact_files[0]
                new_entries.append({
                    "ecosystem": ecosystem,
                    "package": pkg,
                    "version": version,
                    "label": "benign",
                    "status": "downloaded",
                    "source_kind": "live_capture",
                    "artifact_path": str(artifact.relative_to(REPO_ROOT)),
                })

    all_entries = existing + new_entries
    save_manifest(BENIGN_MANIFEST, all_entries)
    print(f"Benign manifest: {len(all_entries)} total ({len(new_entries)} imported from captures)")


# ── Stats ────────────────────────────────────────────────────────────────

def show_stats():
    mal = load_manifest(MALICIOUS_MANIFEST)
    ben = load_manifest(BENIGN_MANIFEST)

    def breakdown(entries):
        by_eco = {}
        by_status = {}
        for e in entries:
            eco = e.get("ecosystem", "?")
            status = e.get("status", "?")
            by_eco[eco] = by_eco.get(eco, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
        return by_eco, by_status

    print("=== Detection Corpus Stats ===\n")
    print(f"Malicious: {len(mal)}")
    eco, status = breakdown(mal)
    for k, v in sorted(eco.items()):
        print(f"  {k}: {v}")
    for k, v in sorted(status.items()):
        print(f"  [{k}]: {v}")

    print(f"\nBenign: {len(ben)}")
    eco, status = breakdown(ben)
    for k, v in sorted(eco.items()):
        print(f"  {k}: {v}")
    for k, v in sorted(status.items()):
        print(f"  [{k}]: {v}")

    print(f"\nTotal: {len(mal) + len(ben)}")


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Build detection corpus")
    sub = parser.add_subparsers(dest="command")

    mal_p = sub.add_parser("malicious", help="Fetch malicious samples from VT")
    mal_p.add_argument("--vt-limit", type=int, default=50, help="Results per VT query")

    ben_p = sub.add_parser("benign", help="Fetch benign packages from registries")
    ben_p.add_argument("--npm-top", type=int, default=5000)
    ben_p.add_argument("--pypi-top", type=int, default=3000)
    ben_p.add_argument("--crates-top", type=int, default=2000)
    ben_p.add_argument("--workers", type=int, default=8)

    sub.add_parser("import-captures", help="Import from existing captures")
    sub.add_parser("stats", help="Show corpus stats")

    args = parser.parse_args()

    if args.command == "malicious":
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            print("Set VT_API_KEY environment variable", file=sys.stderr)
            return 1
        build_malicious_vt(api_key, args.vt_limit)

    elif args.command == "benign":
        build_benign(args.npm_top, args.pypi_top, args.crates_top, args.workers)

    elif args.command == "import-captures":
        import_captures()

    elif args.command == "stats":
        show_stats()

    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
