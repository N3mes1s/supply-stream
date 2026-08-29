# RFD 0001: Realtime Triage Pipeline

- Status: Accepted
- Date: 2026-03-28

## Summary

`supply-stream` is a realtime release triage and evidence pipeline.

Its job is to:
- observe package releases in near real time
- assign priority at ingest time
- decide whether to capture and diff
- emit one structured release evidence bundle per captured release

Its job is not to:
- prove that every new release is benign immediately
- grow the largest possible dependency graph for its own sake
- replace deeper investigation or downstream malware analysis

## Problem

The project had started drifting toward graph expansion and provider plumbing as the primary goal.
That is supporting infrastructure, not the product.

The real product loop is:
1. observe a release
2. resolve priority
3. capture metadata and artifacts when justified
4. diff against a baseline when available
5. enrich with upstream repository parity
6. persist and emit a single release evidence bundle

This loop needs to be:
- cheap enough to run continuously
- correct enough for immediate triage
- structured enough for any normal agent or operator to consume

## Decisions

### 1. Source of truth

The operational source of truth is:
- `.supply-stream-data/index.sqlite`

These files are derived or import/export artifacts:
- `.supply-stream-data/graph-input.ndjson`
- `.supply-stream-data/priority-scores.ndjson`
- `.supply-stream-data/package-census.ndjson`

Runtime should read and write the SQLite store first.
Derived files should agree with the store, but they are not the hot-path authority.

### 2. Runtime role

`supply-stream` is a realtime triage pipeline.

Priority decides:
- event only
- capture
- capture and diff

The output consumed by operators or agents is:
- `bundle.json`

Each bundle should contain:
- release event
- priority snapshot
- graph evidence
- package repository identity
- capture result
- diff result when available
- fused release assessment

### 3. Priority scope

Priority exists to spend work where it matters.

Priority inputs:
- offline score snapshot
- local graph evidence
- package census
- bounded online fallback for missing packages

Priority is useful if it improves:
- first-event resolution quality
- capture selectivity
- diff selectivity
- time to usable evidence

Priority is not useful if it only increases graph size without improving those outcomes.

### 4. Graph strategy

The graph should support triage, not dominate the product.

Accepted strategy:
- SQLite-backed local graph as the hot path
- native package census for breadth
- first-party graph growth from captures and broadening
- selective external enrichment only when it improves triage

Rejected strategy:
- paying to brute-force a giant graph with weak connection to ingest-time outcomes

### 5. Repository provenance

Repository parity is a low-cost signal, not a verdict.

It is useful for:
- missing tag or release parity
- source package mismatch
- fast spotting of `telnyx` or `litellm` style anomalies

It is not enough on its own because:
- monorepos are common
- prerelease and nightly builds are noisy
- many projects do not tag every package release

### 6. Replayability

Realtime feeds are not enough.

The system should prefer replayable or cursor-based sources where possible so fast-pulled malicious releases are less likely to be missed.

## Operating model

The standard operating loop is:

1. Start from the repo-local `.supply-stream-data/` dataset.
2. Run the monitor continuously.
3. Validate the local dataset regularly.
4. Review only the warning/high slice.
5. Keep broadening only if it improves event-time resolution.

## Success metrics

The system is worth keeping only if these metrics improve over time:
- event-time resolution from `offline_score_file`, `local_graph`, or `package_census`
- lower `known_package_stub` rate
- low capture failure rate
- low missing-bundle rate for ready captures
- warning/high release assessments that are reviewable
- acceptable false-positive rate after manual review
- low time from `observed_at` to generated `bundle.json`

## Trial scoreboard

The first operational scoreboard is a windowed history report over the local store and bundles.

It should answer:
- how many releases were observed in the window
- how they resolved at event time
- how many captures and diffs succeeded or failed
- whether bundles exist for ready captures
- what the release assessment mix looks like
- which suspicious examples deserve review first

## Deployment

Default low-cost deployment:
- self-host on an existing machine
- keep SQLite local
- replicate or back up the data directory separately

Optional:
- use sandboxes only for burst analysis of suspicious artifacts
- publish signed bundle manifests to a transparency log if desired

## Non-goals

- guaranteed instant benign verdicts
- public transparency logging of every raw event
- making `supply-stream` itself the final detector

## Immediate work from this RFD

1. Keep the operational source of truth in SQLite.
2. Add a daily or windowed report for the realtime trial.
3. Run the monitor from the merged repo-local dataset.
4. Judge the system by the scoreboard, not by graph size alone.
