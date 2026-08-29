# Content-Risk Fixture Corpus

This directory defines the labeled fixture corpus used to tune and regress
`supply-stream` content-risk rules.

Goals:
- keep a reproducible malicious corpus across `npm`, `pypi`, and `crates-io`
- keep a reproducible benign corpus to control false positives
- separate registry-ground-truth artifacts from VT-only recovery and enrichment

Files:
- `malicious.ndjson`: known-bad or high-confidence malicious package artifacts
- `benign.ndjson`: legitimate packages used as a negative baseline

Conventions:
- one JSON object per line
- `artifact_url` points at the preferred fetch source
- `artifact_path` is the local repo-relative destination under `.artifacts/`
- `status` is one of:
  - `downloaded`
  - `pending_download`
  - `pending_vt_lookup`
  - `pending_manual_review`
- `source_kind` is one of:
  - `registry`
  - `public_report`
  - `registry_plus_vt`
  - `vt_only`

Safety:
- do not upload new samples to VirusTotal without explicit approval
- VT can be used in read-only mode for hash queries and related metadata
- registry artifacts should be preferred when still publicly available

Typical workflow:
1. add or update entries in `malicious.ndjson` / `benign.ndjson`
2. fetch registry-backed artifacts with `scripts/fetch_content_risk_fixtures.py`
3. use the local artifacts to extend tests and tune YARA rules
4. use VT only for recovery or family expansion when public artifacts are gone
