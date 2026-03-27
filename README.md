# supply-stream

`supply-stream` is a Rust fan-in service for near-real-time package release events across ecosystems. It now has two jobs:

- emit normalized release events as NDJSON on stdout for downstream scanners such as `~/code/aegis`
- preserve a local evidence trail for each observed release so later incident reconstruction is possible
- apply package-level retention tiers from an offline score snapshot so capture and diff work stays focused on high-impact releases

## Scope

- Normalize release events across ecosystems from day one instead of building ecosystem-specific code paths into the core pipeline.
- Keep source adapters small and isolated so new ecosystems can be added with another adapter instead of a rewrite.
- Persist lightweight cursor and dedupe state on disk so restarts do not replay the most recent feed window.
- Append every observed release to a durable event ledger.
- Gate capture and diff work by package priority instead of treating every release equally.
- Emit stable `event_id` values so downstream scanners can dedupe safely if an upstream source produces repeated notifications.

## Current adapters

- `npm`: polls the npm replication `_changes` feed and fetches packuments from `registry.npmjs.org`. npm removed streaming `feed=continuous`/`feed=eventsource` support in 2025, so the adapter paginates by `since` and infers newly published versions from recent packument timestamps.
- `pypi`: uses the official PyPI XML-RPC mirroring journal (`changelog_last_serial` / `changelog_since_serial`) as the primary replayable source, with the latest updates RSS feed as fallback.
- `crates-io`: uses the official crates.io index as the primary replayable source, reading new versions from the `rust-lang/crates.io-index` git history and falling back to `https://crates.io/api/v1/summary` if the index fetch path is unavailable.

## Runtime layout

By default the service writes:

- state into `.supply-stream-state/`
- observed event history into `.supply-stream-data/observed-events.ndjson`
- reconstructed lineage history into `.supply-stream-data/reconstructed-events.ndjson`
- operational index into `.supply-stream-data/index.sqlite`
- captured evidence into `.supply-stream-data/captures/<ecosystem>/<package>/<version>/`
- optional score snapshot from `.supply-stream-data/priority-scores.ndjson`

`index.sqlite` is the operational source of truth for runtime state, graph lookups, repo identity, and release status. The NDJSON files such as `graph-input.ndjson`, `priority-scores.ndjson`, and `package-census.ndjson` are persisted snapshots and exchange formats derived from or merged into that store.

Priority tiers are package-level in v1:

- `high`: event + capture + diff
- `medium`: event + capture
- `low`: event only
- unknown packages default to `medium`

Each capture directory may contain:

- `event.json`: the normalized release event
- `capture.json`: normalized evidence summary and lifecycle status
- `diff.json`: normalized release diff status or diff body for high-priority releases
- `metadata.json`: raw registry metadata when still available
- `provenance/*.json`: PyPI provenance records when available

`diff.md` is optional and disabled on the live hot path by default. Markdown is treated as a derived view from `diff.json`, not as primary runtime output.

For repository release parity on GitHub, set `GITHUB_TOKEN` or `GH_TOKEN`. Without an authenticated token, GitHub may rate-limit tag/release checks and degrade those signals to `match_kind=unknown`.

## Event shape

Each line on stdout is one JSON object:

```json
{
  "event_id": "npm:left-pad@1.3.0",
  "ecosystem": "npm",
  "package": "left-pad",
  "version": "1.3.0",
  "published_at": "2026-03-25T10:00:00Z",
  "observed_at": "2026-03-25T10:00:04.121Z",
  "source": "npm.replication",
  "sequence": "71024831",
  "package_url": "https://www.npmjs.com/package/left-pad",
  "release_url": "https://www.npmjs.com/package/left-pad/v/1.3.0",
  "metadata_url": "https://registry.npmjs.org/left-pad",
  "priority": {
    "tier": "medium",
    "source": "known_package_stub",
    "direct_popularity": 0.0,
    "propagated_impact": 0.0,
    "hidden_leverage": 0.0
  },
  "resolution": {
    "knowledge": "runtime_observed",
    "score_hit": false,
    "local_graph_hit": false,
    "census_hit": false,
    "runtime_stub": true,
    "external_fallback": false,
    "provisional": true
  },
  "graph": {
    "known_in_local_graph": false,
    "known_in_census": true,
    "observed_count": 1,
    "direct_dependencies_seen": 0,
    "reverse_dependents_seen": 0
  },
  "plan": {
    "capture": {
      "requested": true,
      "planned_state": "pending",
      "reason": "priority policy requested capture"
    },
    "diff": {
      "requested": false,
      "planned_state": "skipped",
      "reason": "priority policy skipped diff"
    }
  }
}
```

`resolution` tells you how strong the local knowledge is for that package at emit time, `graph` shows the concrete local evidence behind that decision, and `plan` tells you what the runtime will do next for that release.

When a captured release later gets a diff, the runtime can also emit a fused `release_assessment` signal that combines:
- repo release parity
- graph/priority impact
- generic diff evidence like content churn and install-time execution

Example:

```json
{
  "kind": "release_assessment",
  "event_id": "pypi:demo@1.2.3",
  "signal_type": "repo_graph_diff_fusion",
  "severity": "warning",
  "priority_tier": "medium",
  "factors": ["stable_version", "high_or_medium_impact", "content_changed", "content_churn_large"],
  "reason": "large content churn on a package with observable downstream impact"
}
```

Priority score snapshots are NDJSON, one package per line:

```json
{"ecosystem":"npm","package":"left-pad","priority_tier":"high","direct_popularity":12000,"propagated_impact":480000,"hidden_leverage":3.7,"computed_at":"2026-03-25T10:00:00Z","score_source_version":"graph-v1"}
```

Scoring input is also NDJSON. Mix package popularity and dependency edges:

```json
{"type":"package","ecosystem":"npm","package":"consumer-app","direct_popularity":120000}
{"type":"package","ecosystem":"npm","package":"shared-lib","direct_popularity":500}
{"type":"dependency","ecosystem":"npm","package":"consumer-app","dependency":"shared-lib","weight":1.0}
```

## Usage

Prime state from current registry heads without emitting bootstrap events:

```bash
cargo run -- --state-dir .supply-stream-state --ecosystems npm,pypi,crates-io
```

Run one poll cycle and exit:

```bash
cargo run -- --once --state-dir .supply-stream-state
```

Run with an explicit offline score snapshot:

```bash
cargo run -- --state-dir .supply-stream-state --priority-file /path/to/priority-scores.ndjson
```

By default the runtime also uses a package-level `deps.dev` fallback for packages that are missing from the local score snapshot. That fallback resolves the package's default version, pulls direct and total dependent counts, and maps them back into the same `priority` object shape. You can disable or tune it:

```bash
cargo run -- \
  --state-dir .supply-stream-state \
  --priority-file .supply-stream-data/priority-scores.ndjson \
  --priority-online-fallback true \
  --priority-online-timeout-secs 3
```

`ecosyste.ms` remains a secondary fallback and metadata source. After checking the `ecosyste_ms_cli` surface, the stable package-level groups are `packages` and `resolve`; `supply-stream` treats the count-based `ecosyste.ms` package/repository usage endpoints as enrichment only, not as authoritative reverse-edge graph truth.

By default the runtime also tries to grow the local graph when it sees an unknown package. It returns the lightweight fallback priority immediately, then kicks off a focused graph expansion in the background and rewrites the local `graph-input.ndjson` and `priority-scores.ndjson` snapshots for later events:

```bash
cargo run -- \
  --state-dir .supply-stream-state \
  --priority-file .supply-stream-data/priority-scores.ndjson \
  --priority-graph-file .supply-stream-data/graph-input.ndjson \
  --priority-online-expand-unknown true \
  --priority-expand-reverse-depth 2 \
  --priority-expand-forward-depth 1
```

The runtime also builds a first-party local graph from captured releases. Capture writes package-level forward edges into `graph-input.ndjson` from registry metadata only:
- `npm`: `dependencies` from the captured version metadata
- `PyPI`: `info.requires_dist`
- `crates.io`: version dependency endpoint metadata

Those graph records are also indexed into the operational SQLite store, so local graph lookups and emitted `graph` evidence do not need to rescan the NDJSON file on every resolution. The resolver consults score snapshot, then SQLite-backed local graph, then census, and only then falls back to external providers.

The live runtime also emits a rolling priority view to logs. By default it reports every 30 seconds using the most recent 1000 observed events. You can tune or disable it:

```bash
cargo run -- \
  --state-dir .supply-stream-state \
  --priority-file .supply-stream-data/priority-scores.ndjson \
  --priority-view-interval-secs 30 \
  --priority-view-limit 10 \
  --priority-view-recent-capacity 1000
```

Set `--priority-view-interval-secs 0` to disable the live priority-view snapshots.

Build a score snapshot from package popularity and dependency edges:

```bash
cargo run -- priority build \
  --input /path/to/graph-input.ndjson \
  --output .supply-stream-data/priority-scores.ndjson \
  --score-source-version graph-v1
```

Grow the graph and rebuild the score snapshot in one command:

```bash
cargo run -- priority expand \
  --seeds .supply-stream-data/bootstrap/seed-packages.ndjson \
  --graph-output .supply-stream-data/graph-input.ndjson \
  --output .supply-stream-data/priority-scores.ndjson \
  --depth 3 \
  --max-packages 50000
```

Global `priority expand` can also try to widen the baseline directly from the public `deps.dev` BigQuery dataset:

```bash
cargo run -- priority expand \
  --seeds .supply-stream-data/bootstrap/seed-packages.ndjson \
  --graph-output .supply-stream-data/graph-input.ndjson \
  --output .supply-stream-data/priority-scores.ndjson \
  --bigquery-baseline-package-limit 2000 \
  --bigquery-baseline-edge-limit 50000
```

Set `--bigquery-baseline-package-limit 0` to disable the BigQuery baseline import. The importer is Rust-native and batched, but it still depends on local Google Cloud credentials and available BigQuery query quota.

Expand around a package when you want to pull it into the graph right now:

```bash
cargo run -- priority expand \
  --ecosystem pypi \
  --package litellm \
  --base-input .supply-stream-data/graph-input.ndjson \
  --graph-output .supply-stream-data/focus-graph.ndjson \
  --output .supply-stream-data/focus-scores.ndjson \
  --depth 2
```

Inspect the local graph evidence and bounded neighborhood for one package:

```bash
cargo run -- priority graph \
  --input .supply-stream-data/priority-scores.ndjson \
  --graph-file .supply-stream-data/graph-input.ndjson \
  --graph-store-file .supply-stream-data/index.sqlite \
  --limit 25 \
  pypi litellm --json
```

That command prefers the operational SQLite graph store and falls back to the NDJSON graph file if needed. It is the fastest way to understand why a package resolves as `local_graph`, including the local reverse dependents and direct dependencies that support the score.

For broader first-party graph growth from native registry metadata only:

```bash
cargo run -- priority broaden \
  --ecosystems pypi \
  --census-file /tmp/supply-stream-native-pypi-census.ndjson \
  --graph-output .supply-stream-data/graph-input.ndjson \
  --graph-store-file .supply-stream-data/index.sqlite \
  --output .supply-stream-data/priority-scores.ndjson \
  --progress-file .supply-stream-data/broaden-progress.json \
  --batch-size 100 \
  --iterations 10 \
  --max-depth 0 \
  --json
```

`priority broaden` is incremental and store-backed. It advances the saved cursor in `--progress-file`, appends only the new graph rows, and incrementally rescales touched roots when `--output` is set. The JSON summary includes `iterations_completed`, `total_selected`, and `collect_summary.external_fallback_fetches`. For a fully native widening pass, `external_fallback_fetches` should stay `0`.

Replay the fused assessment signal over already captured releases and diffs:

```bash
cargo run -- history \
  --data-dir .supply-stream-data \
  assessment-backfill --emit --limit 100
```

That command reads both legacy `events.ndjson` and modern `observed-events.ndjson`, joins them with `capture.json` and `diff.json`, and emits the same `release_assessment` NDJSON records the live runtime publishes after diff generation.

When local Google Cloud credentials and a project are available, focused `priority expand` automatically pulls reverse-dependent coverage from the public `deps.dev` BigQuery dataset in Rust, then merges that reverse frontier with the forward dependency crawl. If that live reverse path is unavailable, it falls back to the lighter `deps.dev` dependent-count snapshot.

Add reverse-dependent coverage when you have a `deps.dev` export:

```bash
cargo run -- priority expand \
  --seeds .supply-stream-data/bootstrap/seed-packages.ndjson \
  --deps-dev-input /path/to/deps-dev-export-dir \
  --graph-output .supply-stream-data/graph-input.ndjson \
  --output .supply-stream-data/priority-scores.ndjson \
  --score-source-version deps-dev-bootstrap-v1
```

`--deps-dev-input` accepts repeated files or directories. Supported inputs are `.ndjson`, `.jsonl`, `.json`, and their `.gz` variants. The importer defaults to `--deps-dev-direct-popularity-mode direct-dependent-count`, which uses the number of distinct direct dependents in the export as the base weight floor when explicit popularity data is not available.

`priority expand` is the main Rust-native workflow. The lower-level `priority collect`, `priority import-deps-dev`, `priority merge-graph`, `priority bootstrap`, and `priority focus` commands still exist, but they are implementation/debug surfaces rather than the primary interface.

Collect graph input by recursively crawling dependencies from seed packages:

```bash
cargo run -- priority collect \
  --seeds /path/to/seed-packages.ndjson \
  --popularity-file /path/to/package-popularity.ndjson \
  --output .supply-stream-data/graph-input.ndjson \
  --max-depth 3
```

Seed and popularity files use the same NDJSON shape:

```json
{"ecosystem":"npm","package":"react","direct_popularity":25000000}
{"ecosystem":"pypi","package":"requests","direct_popularity":180000000}
```

Merge multiple graph-input sources into one deduplicated file:

```bash
cargo run -- priority merge-graph \
  --input .supply-stream-data/bootstrap/graph-input.ndjson \
  --input /path/to/deps-dev-graph-input.ndjson \
  --output .supply-stream-data/graph-input.merged.ndjson
```

Package popularity is merged by strongest observed value, and duplicate dependency edges are deduplicated instead of double-counted.

Import `deps.dev` `DependentsLatest` export into graph input:

```bash
cargo run -- priority import-deps-dev \
  --input /path/to/deps-dev-export-dir \
  --output .supply-stream-data/graph-input.ndjson
```

This importer keeps direct edges by default and collapses version-level rows into package-level graph edges. It emits:

```json
{"type":"package","ecosystem":"pypi","package":"litellm","direct_popularity":1.0}
{"type":"dependency","ecosystem":"pypi","package":"open-webui","dependency":"litellm","weight":1.0}
```

If you want the imported package nodes to start with a stronger base weight than a flat constant:

```bash
cargo run -- priority import-deps-dev \
  --input /path/to/deps-dev-export-dir \
  --output .supply-stream-data/graph-input.ndjson \
  --direct-popularity-mode direct-dependent-count
```

Query one package score from a built snapshot:

```bash
cargo run -- priority score \
  --input .supply-stream-data/priority-scores.ndjson \
  pypi litellm
```

The score lookup reports the stored tier plus ecosystem-relative ranks by propagated impact and hidden leverage.

Resolve the runtime priority for a package, including the `deps.dev` fallback path:

```bash
cargo run -- priority resolve \
  --input /tmp/supply-stream-empty-priority.ndjson \
  pypi litellm --json
```

This is useful when a package is not yet present in the local graph-backed snapshot and you want to know what the live runtime would do.

Summarize a full score snapshot and preview the strongest packages per ecosystem:

```bash
cargo run -- priority score-stats \
  --input .supply-stream-data/priority-scores.ndjson \
  --top-limit 10
```

List the top packages by one score metric:

```bash
cargo run -- priority top \
  --input .supply-stream-data/priority-scores.ndjson \
  --ecosystem pypi \
  --metric hidden-leverage \
  --limit 25
```

Pipe the stream into another process:

```bash
cargo run -- --state-dir .supply-stream-state | uv run ~/code/aegis/path/to/consumer.py
```

The live runtime now defaults to JSON-only diffs. To turn on periodic queue and latency summaries in the logs every 10 seconds:

```bash
cargo run -- --state-dir .supply-stream-state --runtime-stats-interval-secs 10
```

Query observed history for one package:

```bash
cargo run -- history package pypi litellm
```

Query best-effort online history from the registry right now:

```bash
cargo run -- history package pypi litellm --online
```

Inspect one observed release with artifact and lifecycle details:

```bash
cargo run -- history event pypi:litellm@1.82.7
```

Inspect one release via online reconstruction instead of local evidence:

```bash
cargo run -- history event pypi:litellm@1.82.7 --online
```

Probe multiple current upstreams for one package or version:

```bash
cargo run -- history locate pypi litellm --version 1.82.7
cargo run -- history locate npm react --version 19.1.0
cargo run -- history locate crates-io serde --version 1.0.219 --json
```

Diff one release against another:

```bash
cargo run -- history diff npm react --version 19.1.0 --baseline 19.0.0 --online
cargo run -- history diff pypi litellm --version 1.82.8 --baseline previous --online
cargo run -- history diff pypi litellm --artifact /tmp/litellm-1.82.8-py3-none-any.whl --version 1.82.8 --baseline 1.82.6 --online
cargo run -- history diff pypi litellm --artifact /tmp/litellm-1.82.8-py3-none-any.whl --baseline-artifact /tmp/litellm-1.82.6-py3-none-any.whl --baseline 1.82.6
cargo run -- history diff pypi litellm --artifact /tmp/litellm-1.82.8-py3-none-any.whl --version 1.82.8 --baseline 1.82.6 --online --format markdown --output /tmp/litellm-report.md
cargo run -- history diff pypi litellm --artifact /tmp/litellm-1.82.8-py3-none-any.whl --version 1.82.8 --baseline 1.82.6 --online --patch --format markdown --output /tmp/litellm-patch-report.md
```

List the most recent locally observed releases:

```bash
cargo run -- history recent --ecosystem pypi --limit 50
```

Reconcile flat files into the operational index and inspect its counts:

```bash
cargo run -- history sync
cargo run -- history stats
cargo run -- history stats --json
```

Inspect historical events for one package:

```bash
rg '"package":"litellm"' .supply-stream-data/observed-events.ndjson .supply-stream-data/reconstructed-events.ndjson
```

Inspect captured evidence for one package:

```bash
find .supply-stream-data/captures/pypi -path '*litellm*' -maxdepth 4
cat .supply-stream-data/captures/pypi/<encoded-package>/<version>/capture.json
```

## Git hook

The repository ships a versioned pre-commit hook in `.githooks/pre-commit`. It runs:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace`

Enable it in this clone with:

```bash
git config core.hooksPath .githooks
```

## Design notes

- The repository is split into a CLI crate at the root and a reusable core crate in `crates/supply-stream-core/`. The root command surface stays small while streaming, history, and probe logic live behind a cleaner internal boundary.
- The service defaults to `tail` semantics. On first boot it snapshots the current cursor/feed window and starts emitting only releases observed after that point.
- The event ledgers are append-only. `observed-events.ndjson` is the ingestion truth for live releases, and `reconstructed-events.ndjson` stores lineage backfill discovered after the fact.
- The operational index in `index.sqlite` is the source of truth for history lookups, runtime graph state, repo identity, and job status. Runtime writes through to it directly, while `history sync` can bootstrap or repair it from the ledgers and capture tree.
- `graph-input.ndjson`, `priority-scores.ndjson`, and `package-census.ndjson` are derived/import-export artifacts. They should agree with `index.sqlite`, but they are not the hot-path authority.
- Priority scoring stays offline in v1. `supply-stream` enforces a package score snapshot at ingest time, `priority collect` can build forward dependency graph input from seed packages, `priority import-deps-dev` can import reverse-dependent edges from `deps.dev` export, and `priority build` turns graph input into the runtime score snapshot.
- If the process crashes after logging an event but before metadata capture completes, the capture worker replays missing captures from the observed ledger on the next start.
- Startup backfill respects skipped states. Low-priority event-only releases are not retroactively captured or diffed on restart.
- `history` commands reconstruct local observed history from the indexed store plus captured evidence. They do not invent releases that were never observed by this instance.
- `history ... --online` is a best-effort registry reconstruction mode. It uses current registry APIs, so it can recover visible releases and current yank/deprecation state, but it still cannot recover deleted artifacts or releases that the registry no longer exposes.
- `history locate ...` is a separate visibility probe mode. It checks multiple current upstreams per ecosystem so you can compare canonical registries with mirrors, CDNs, or index surfaces and see where a package version is still exposed.
- `history diff ...` compares a target release to an explicit baseline version or the immediately previous version. It can resolve either side from local observed history, current registry state via `--online`, or a local artifact path via `--artifact` and `--baseline-artifact`. When `--baseline previous` is used with a local target artifact, pass `--version` unless the version can be inferred from the filename.
- The runtime writes stored diffs only for high-priority captured releases. When a package's first local high-priority observation arrives, it will backfill the nearest previous release from current registry history when available so the stored diff still has lineage; only a true first release stays `no_baseline`.
- Automatic runtime diffs are JSON-first. Patches and Markdown reports are kept for explicit `history diff ...` use because they are materially more expensive than the summary diff needed on the ingest path.
- `history diff ... --format markdown --output <path>` writes a review-friendly report instead of a flat terminal summary. The renderer keeps the full file lists, structured file metadata, and optional patches so the report stays literal and exhaustive instead of heuristic.
- `history diff ... --patch` adds unified per-file patches for text files to the text, markdown, and JSON outputs. Use `--patch-context <n>` to widen or narrow the hunk context without changing the high-level summary.
- Runtime logs now emit queue-depth and latency summaries so throughput regressions can be measured without attaching a profiler first.
- PyPI now uses the replayable XML-RPC mirroring journal as its primary source, with RSS fallback; crates.io is still a summary poller.
- npm no longer exposes a true streaming changes feed. The adapter uses a recent publish window against packument timestamps to avoid replaying historical versions on every metadata change.
- PyPI captures optionally query the official Integrity API per file so publish attestations can be preserved when available.
- Downstream consumers should still treat `event_id` as the idempotency key because registry behavior is not perfectly exactly-once.

## Sources

- npm replication API migration discussion: <https://github.com/orgs/community/discussions/152515>
- PyPI RSS feeds: <https://docs.pypi.org/api/feeds/>
- PyPI XML-RPC API: <https://warehouse.pypa.io/api-reference/xml-rpc/>
- PyPI JSON API: <https://docs.pypi.org/api/json/>
- PyPI Integrity API: <https://docs.pypi.org/api/integrity/>
- Cargo registry index reference: <https://doc.rust-lang.org/cargo/reference/registry-index.html>
- crates.io summary response shape: <https://docs.rs/crates_io_api/latest/crates_io_api/struct.Summary.html>
