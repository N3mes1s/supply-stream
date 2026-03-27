use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::{
    capture::{CapturedRelease, ReleaseStatus},
    event::{Ecosystem, PackageReleaseEvent},
    ledger::{self, EventLedger},
    store::{self, EventOrigin, OperationalStore},
    visibility::{ProbeResult, ProbeState, VisibilityReport},
};

static RECONSTRUCTION_WRITE_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub event: PackageReleaseEvent,
    pub capture: Option<CapturedRelease>,
    pub capture_dir: Option<PathBuf>,
}

pub async fn load_package_history(
    data_dir: &Path,
    ecosystem: Ecosystem,
    package: &str,
) -> Result<Vec<HistoryEntry>> {
    let mut entries = Vec::new();

    for event in local_store(data_dir)
        .await?
        .load_package_events(ecosystem, package)
        .await?
    {
        if event.ecosystem == ecosystem && event.package == package {
            entries.push(load_entry(data_dir, event).await?);
        }
    }

    entries.sort_by_key(history_sort_key);
    Ok(entries)
}

pub async fn load_event_history(data_dir: &Path, event_id: &str) -> Result<HistoryEntry> {
    let Some(event) = local_store(data_dir).await?.load_event(event_id).await? else {
        anyhow::bail!("event not found in local ledger: {event_id}");
    };

    load_entry(data_dir, event).await
}

pub async fn load_recent_history(
    data_dir: &Path,
    ecosystem: Option<Ecosystem>,
    limit: usize,
) -> Result<Vec<HistoryEntry>> {
    let mut entries = Vec::new();

    for event in local_store(data_dir)
        .await?
        .load_recent_events(ecosystem, limit)
        .await?
    {
        if ecosystem.is_none_or(|value| value == event.ecosystem) {
            entries.push(load_entry(data_dir, event).await?);
        }
    }

    entries.sort_by_key(history_sort_key);
    entries.reverse();
    entries.truncate(limit);
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageBackfill {
    Backfilled { event_id: String, version: String },
    NoPreviousRelease,
    TargetNotVisibleOnline,
}

pub async fn backfill_previous_lineage(
    data_dir: &Path,
    ecosystem: Ecosystem,
    package: &str,
    target_version: &str,
) -> Result<LineageBackfill> {
    let local_entries = load_package_history(data_dir, ecosystem, package).await?;
    let online_entries =
        dedupe_history_entries(load_package_history_online(ecosystem, package).await?);
    let Some(entry) = previous_lineage_candidate(&local_entries, &online_entries, target_version)
    else {
        let visible_online = online_entries
            .iter()
            .any(|entry| entry.event.version == target_version);
        return Ok(if visible_online {
            LineageBackfill::NoPreviousRelease
        } else {
            LineageBackfill::TargetNotVisibleOnline
        });
    };

    persist_history_entries(data_dir, std::slice::from_ref(&entry)).await?;
    Ok(LineageBackfill::Backfilled {
        event_id: entry.event.event_id,
        version: entry.event.version,
    })
}

pub async fn persist_history_entries(data_dir: &Path, entries: &[HistoryEntry]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let _guard = RECONSTRUCTION_WRITE_LOCK.lock().await;
    let reconstructed_ledger_path = reconstructed_ledger_path(data_dir);
    let store = local_store(data_dir).await?;
    let mut existing_event_ids = ledger::read_local_events(data_dir)
        .await?
        .into_iter()
        .map(|event| event.event_id)
        .collect::<HashSet<_>>();
    let ledger = EventLedger::open(reconstructed_ledger_path).await?;

    for entry in entries {
        if existing_event_ids.insert(entry.event.event_id.clone()) {
            ledger.append(&entry.event).await?;
        }
        store
            .record_event(&entry.event, EventOrigin::Reconstructed)
            .await?;

        let capture_dir = capture_dir_for_event(data_dir, &entry.event);
        tokio::fs::create_dir_all(&capture_dir)
            .await
            .with_context(|| format!("failed to create {}", capture_dir.display()))?;

        let event_path = capture_dir.join("event.json");
        if !event_path.exists() {
            write_json_pretty(&event_path, &entry.event).await?;
        }

        if let Some(capture) = &entry.capture {
            let capture_path = capture_dir.join("capture.json");
            if !capture_path.exists() {
                write_json_pretty(&capture_path, capture).await?;
            }
            store
                .record_capture(
                    &entry.event,
                    EventOrigin::Reconstructed,
                    &capture_dir,
                    capture,
                )
                .await?;
        }
    }

    Ok(())
}

async fn local_store(data_dir: &Path) -> Result<OperationalStore> {
    let store = OperationalStore::open(store::index_db_path(data_dir)).await?;
    if store.event_count().await? == 0 && local_ledger_exists(data_dir) {
        store.reconcile_local_data(data_dir).await?;
    }
    Ok(store)
}

fn local_ledger_exists(data_dir: &Path) -> bool {
    ledger::local_ledger_paths(data_dir)
        .into_iter()
        .any(|path| path.exists())
}

async fn load_entry(data_dir: &Path, event: PackageReleaseEvent) -> Result<HistoryEntry> {
    let capture_dir = capture_dir_for_event(data_dir, &event);
    let capture_path = capture_dir.join("capture.json");
    let capture = match tokio::fs::read(&capture_path).await {
        Ok(bytes) => Some(
            serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse {}", capture_path.display()))?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read {}", capture_path.display()));
        }
    };

    Ok(HistoryEntry {
        event,
        capture,
        capture_dir: capture_path.parent().map(Path::to_path_buf),
    })
}

pub async fn load_package_history_online(
    ecosystem: Ecosystem,
    package: &str,
) -> Result<Vec<HistoryEntry>> {
    let http = history_http_client()?;
    let mut entries = match ecosystem {
        Ecosystem::Pypi => load_pypi_history_online(&http, package).await?,
        Ecosystem::Npm => load_npm_history_online(&http, package).await?,
        Ecosystem::CratesIo => load_crates_history_online(&http, package).await?,
    };
    entries.sort_by_key(history_sort_key);
    Ok(entries)
}

pub async fn load_event_history_online(event_id: &str) -> Result<HistoryEntry> {
    let parsed = parse_event_id(event_id)?;
    let entries = load_package_history_online(parsed.ecosystem, &parsed.package).await?;
    entries
        .into_iter()
        .find(|entry| entry.event.version == parsed.version)
        .with_context(|| format!("event not visible online: {event_id}"))
}

fn history_sort_key(entry: &HistoryEntry) -> (DateTime<Utc>, DateTime<Utc>, String) {
    (
        entry.event.published_at.unwrap_or(entry.event.observed_at),
        entry.event.observed_at,
        entry.event.event_id.clone(),
    )
}

fn reconstructed_ledger_path(data_dir: &Path) -> PathBuf {
    ledger::reconstructed_ledger_path(data_dir)
}

pub fn capture_dir_for_event(data_dir: &Path, event: &PackageReleaseEvent) -> PathBuf {
    data_dir
        .join("captures")
        .join(event.ecosystem.as_str())
        .join(urlencoding::encode(&event.package).into_owned())
        .join(urlencoding::encode(&event.version).into_owned())
}

pub fn print_package_history(ecosystem: Ecosystem, package: &str, entries: &[HistoryEntry]) {
    println!(
        "{} {}: {} observed releases",
        ecosystem,
        package,
        entries.len()
    );

    for entry in entries {
        println!(
            "{}  {}  status={}  source={}  artifacts={}",
            format_timestamp(entry.event.published_at, entry.event.observed_at),
            entry.event.version,
            summarize_status(entry.capture.as_ref()),
            entry.event.source,
            entry
                .capture
                .as_ref()
                .map_or(0, |capture| capture.artifacts.len())
        );
        if let Some(reason) = yanked_reason(entry.capture.as_ref()) {
            println!("  reason={reason}");
        }
        if let Some(path) = &entry.capture_dir {
            println!("  capture={}", path.display());
        }
    }
}

pub fn print_event_history(entry: &HistoryEntry) {
    println!("event: {}", entry.event.event_id);
    println!("ecosystem: {}", entry.event.ecosystem);
    println!("package: {}", entry.event.package);
    println!("version: {}", entry.event.version);
    println!(
        "published: {}",
        entry
            .event
            .published_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("observed: {}", entry.event.observed_at.to_rfc3339());
    println!("source: {}", entry.event.source);
    println!("status: {}", summarize_status(entry.capture.as_ref()));
    if let Some(path) = &entry.capture_dir {
        println!("capture_dir: {}", path.display());
    }
    if let Some(capture) = &entry.capture {
        println!("artifacts: {}", capture.artifacts.len());
        if let Some(reason) = yanked_reason(Some(capture)) {
            println!("yanked_reason: {reason}");
        }
        for artifact in &capture.artifacts {
            println!(
                "artifact: {} kind={} sha256={} checksum={} yanked={}",
                artifact.filename,
                artifact.kind.as_deref().unwrap_or("unknown"),
                artifact.hashes.sha256.as_deref().unwrap_or("-"),
                artifact.hashes.checksum.as_deref().unwrap_or("-"),
                artifact
                    .yanked
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string())
            );
        }
    }
}

pub fn print_recent_history(ecosystem: Option<Ecosystem>, entries: &[HistoryEntry]) {
    match ecosystem {
        Some(ecosystem) => println!("recent {} events: {}", ecosystem, entries.len()),
        None => println!("recent events: {}", entries.len()),
    }

    for entry in entries {
        println!(
            "{}  {}:{}@{}  status={}",
            entry.event.observed_at.to_rfc3339(),
            entry.event.ecosystem,
            entry.event.package,
            entry.event.version,
            summarize_status(entry.capture.as_ref())
        );
    }
}

pub fn print_visibility_report(report: &VisibilityReport) {
    let target = match &report.version {
        Some(version) => format!("{}:{}@{}", report.ecosystem, report.package, version),
        None => format!("{}:{}", report.ecosystem, report.package),
    };
    println!("visibility {target}: {} probes", report.probes.len());
    println!(
        "visible={} missing={} unsupported={} error={}",
        count_probe_state(&report.probes, ProbeState::Visible),
        count_probe_state(&report.probes, ProbeState::Missing),
        count_probe_state(&report.probes, ProbeState::Unsupported),
        count_probe_state(&report.probes, ProbeState::Error),
    );

    for probe in &report.probes {
        println!(
            "{}  {}  {}",
            format_probe_state(probe.state),
            probe.name,
            probe.url
        );
        if let Some(marker) = &probe.marker {
            println!("  marker={marker}");
        }
        if let Some(summary) = summarize_probe_detail(&probe.detail) {
            println!("  {summary}");
        }
    }
}

fn previous_lineage_candidate(
    local_entries: &[HistoryEntry],
    online_entries: &[HistoryEntry],
    target_version: &str,
) -> Option<HistoryEntry> {
    let target_idx = online_entries
        .iter()
        .position(|entry| entry.event.version == target_version)?;
    let previous = online_entries.get(target_idx.checked_sub(1)?)?.clone();

    (!local_entries
        .iter()
        .any(|entry| entry.event.version == previous.event.version))
    .then_some(previous)
}

fn dedupe_history_entries(entries: Vec<HistoryEntry>) -> Vec<HistoryEntry> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for entry in entries.into_iter().rev() {
        if seen.insert(entry.event.version.clone()) {
            deduped.push(entry);
        }
    }

    deduped.reverse();
    deduped
}

fn format_timestamp(published_at: Option<DateTime<Utc>>, observed_at: DateTime<Utc>) -> String {
    published_at.unwrap_or(observed_at).to_rfc3339()
}

async fn write_json_pretty<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    tokio::fs::write(path, bytes)
        .await
        .with_context(|| format!("failed to write {}", path.display()))
}

fn summarize_status(capture: Option<&CapturedRelease>) -> &'static str {
    match capture.map(|capture| &capture.status) {
        Some(ReleaseStatus::Active) => "active",
        Some(ReleaseStatus::Yanked) => "yanked",
        Some(ReleaseStatus::Removed) => "removed",
        Some(ReleaseStatus::Unknown) => "unknown",
        None => "uncaptured",
    }
}

fn yanked_reason(capture: Option<&CapturedRelease>) -> Option<&str> {
    let capture = capture?;
    capture
        .details
        .get("yanked_reason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty())
}

fn count_probe_state(probes: &[ProbeResult], state: ProbeState) -> usize {
    probes.iter().filter(|probe| probe.state == state).count()
}

fn format_probe_state(state: ProbeState) -> &'static str {
    match state {
        ProbeState::Visible => "visible",
        ProbeState::Missing => "missing",
        ProbeState::Unsupported => "unsupported",
        ProbeState::Error => "error",
    }
}

fn summarize_probe_detail(detail: &Value) -> Option<String> {
    let mut parts = Vec::new();

    if let Some(status) = detail.get("http_status").and_then(Value::as_u64) {
        parts.push(format!("http_status={status}"));
    }
    if let Some(version_count) = detail.get("version_count").and_then(Value::as_u64) {
        parts.push(format!("versions={version_count}"));
    }
    if let Some(link_count) = detail.get("link_count").and_then(Value::as_u64) {
        parts.push(format!("links={link_count}"));
    }
    if let Some(row_count) = detail.get("row_count").and_then(Value::as_u64) {
        parts.push(format!("rows={row_count}"));
    }
    if let Some(artifact_count) = detail.get("artifact_count").and_then(Value::as_u64) {
        parts.push(format!("artifacts={artifact_count}"));
    }
    if let Some(published_at) = detail.get("published_at").and_then(Value::as_str) {
        parts.push(format!("published={published_at}"));
    }
    if let Some(latest) = detail.get("latest").and_then(Value::as_str) {
        parts.push(format!("latest={latest}"));
    }
    if let Some(yanked) = detail.get("yanked").and_then(Value::as_bool) {
        parts.push(format!("yanked={yanked}"));
    }
    if let Some(version) = detail.get("version").and_then(Value::as_str) {
        parts.push(format!("version={version}"));
    }
    if let Some(final_url) = detail.get("resolved_url").and_then(Value::as_str) {
        parts.push(format!("resolved_url={final_url}"));
    }
    if let Some(reason) = detail.get("reason").and_then(Value::as_str) {
        parts.push(format!("reason={reason}"));
    }
    if let Some(error) = detail.get("error").and_then(Value::as_str) {
        parts.push(format!("error={error}"));
    }
    if let Some(filenames) = detail.get("filenames").and_then(Value::as_array) {
        let sample = filenames
            .iter()
            .take(2)
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        if !sample.is_empty() {
            parts.push(format!("files={}", sample.join(",")));
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("  "))
    }
}

fn history_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("supply-stream-history/0.1.0")
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()
        .context("failed to build history HTTP client")
}

#[derive(Debug)]
struct ParsedEventId {
    ecosystem: Ecosystem,
    package: String,
    version: String,
}

fn parse_event_id(event_id: &str) -> Result<ParsedEventId> {
    let (ecosystem, rest) = event_id
        .split_once(':')
        .with_context(|| format!("invalid event id: {event_id}"))?;
    let version_at = rest
        .rfind('@')
        .with_context(|| format!("invalid event id: {event_id}"))?;

    let ecosystem = match ecosystem {
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::Pypi,
        "crates-io" => Ecosystem::CratesIo,
        other => anyhow::bail!("unsupported ecosystem in event id: {other}"),
    };

    Ok(ParsedEventId {
        ecosystem,
        package: rest[..version_at].to_string(),
        version: rest[version_at + 1..].to_string(),
    })
}

async fn load_pypi_history_online(
    http: &reqwest::Client,
    package: &str,
) -> Result<Vec<HistoryEntry>> {
    let encoded = urlencoding::encode(package);
    let metadata_url = format!("https://pypi.org/pypi/{encoded}/json");
    let raw = http
        .get(&metadata_url)
        .send()
        .await
        .with_context(|| format!("failed to fetch PyPI project metadata for {package}"))?
        .error_for_status()
        .with_context(|| format!("PyPI returned an error for {package}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("failed to decode PyPI project metadata for {package}"))?;

    let releases = raw
        .get("releases")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut entries = Vec::new();

    for (version, files) in releases {
        let files = files.as_array().cloned().unwrap_or_default();
        let published_at = files
            .iter()
            .filter_map(|file| {
                file.get("upload_time_iso_8601")
                    .and_then(Value::as_str)
                    .and_then(parse_rfc3339)
            })
            .min();
        let yanked = files
            .iter()
            .any(|file| file.get("yanked").and_then(Value::as_bool) == Some(true));
        let yanked_reason = files.iter().find_map(|file| {
            file.get("yanked_reason")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        });
        let event_id = format!("pypi:{package}@{version}");

        entries.push(HistoryEntry {
            event: PackageReleaseEvent {
                event_id: event_id.clone(),
                ecosystem: Ecosystem::Pypi,
                package: package.to_string(),
                version: version.clone(),
                published_at,
                observed_at: Utc::now(),
                source: "pypi.online.project-json".to_string(),
                sequence: None,
                package_url: Some(format!("https://pypi.org/project/{package}/")),
                release_url: Some(format!("https://pypi.org/project/{package}/{version}/")),
                metadata_url: Some(format!("https://pypi.org/pypi/{package}/{version}/json")),
                priority: None,
            },
            capture: Some(CapturedRelease {
                event_id,
                ecosystem: Ecosystem::Pypi,
                package: package.to_string(),
                version: version.clone(),
                observed_at: Utc::now(),
                published_at,
                captured_at: Utc::now(),
                status: if yanked {
                    ReleaseStatus::Yanked
                } else {
                    ReleaseStatus::Active
                },
                package_url: Some(format!("https://pypi.org/project/{package}/")),
                release_url: Some(format!("https://pypi.org/project/{package}/{version}/")),
                metadata_url: Some(format!("https://pypi.org/pypi/{package}/{version}/json")),
                raw_metadata_path: None,
                artifacts: files
                    .iter()
                    .filter_map(|file| {
                        let filename = file.get("filename")?.as_str()?.to_string();
                        Some(crate::capture::CapturedArtifact {
                            filename,
                            kind: file
                                .get("packagetype")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                            url: file.get("url").and_then(Value::as_str).map(str::to_string),
                            size_bytes: file.get("size").and_then(Value::as_u64),
                            uploaded_at: file
                                .get("upload_time_iso_8601")
                                .and_then(Value::as_str)
                                .and_then(parse_rfc3339),
                            yanked: file.get("yanked").and_then(Value::as_bool),
                            hashes: crate::capture::ArtifactHashes {
                                sha256: file
                                    .pointer("/digests/sha256")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                                sha512: file
                                    .pointer("/digests/sha512")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                                blake2b_256: file
                                    .pointer("/digests/blake2b_256")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                                md5: file
                                    .pointer("/digests/md5")
                                    .and_then(Value::as_str)
                                    .map(str::to_string)
                                    .or_else(|| {
                                        file.get("md5_digest")
                                            .and_then(Value::as_str)
                                            .map(str::to_string)
                                    }),
                                integrity: None,
                                shasum: None,
                                checksum: None,
                            },
                            provenance_path: None,
                        })
                    })
                    .collect(),
                upstream_repository: None,
                details: serde_json::json!({
                    "mode": "online-reconstruction",
                    "yanked_reason": yanked_reason,
                    "last_serial": raw.get("last_serial"),
                    "project_status": raw.pointer("/project-status/status")
                }),
            }),
            capture_dir: None,
        });
    }

    Ok(entries)
}

async fn load_npm_history_online(
    http: &reqwest::Client,
    package: &str,
) -> Result<Vec<HistoryEntry>> {
    let encoded = urlencoding::encode(package);
    let metadata_url = format!("https://registry.npmjs.org/{encoded}");
    let raw = http
        .get(&metadata_url)
        .send()
        .await
        .with_context(|| format!("failed to fetch npm packument for {package}"))?
        .error_for_status()
        .with_context(|| format!("npm returned an error for {package}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("failed to decode npm packument for {package}"))?;

    let times = raw
        .get("time")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let versions = raw
        .get("versions")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut entries = Vec::new();

    for (version, version_meta) in versions {
        let published_at = times
            .get(&version)
            .and_then(Value::as_str)
            .and_then(parse_rfc3339);
        let dist = version_meta.get("dist").cloned().unwrap_or(Value::Null);
        let event_id = format!("npm:{package}@{version}");

        entries.push(HistoryEntry {
            event: PackageReleaseEvent {
                event_id: event_id.clone(),
                ecosystem: Ecosystem::Npm,
                package: package.to_string(),
                version: version.clone(),
                published_at,
                observed_at: Utc::now(),
                source: "npm.online.packument".to_string(),
                sequence: None,
                package_url: Some(format!("https://www.npmjs.com/package/{package}")),
                release_url: Some(format!(
                    "https://www.npmjs.com/package/{package}/v/{version}"
                )),
                metadata_url: Some(metadata_url.clone()),
                priority: None,
            },
            capture: Some(CapturedRelease {
                event_id,
                ecosystem: Ecosystem::Npm,
                package: package.to_string(),
                version: version.clone(),
                observed_at: Utc::now(),
                published_at,
                captured_at: Utc::now(),
                status: ReleaseStatus::Active,
                package_url: Some(format!("https://www.npmjs.com/package/{package}")),
                release_url: Some(format!(
                    "https://www.npmjs.com/package/{package}/v/{version}"
                )),
                metadata_url: Some(metadata_url.clone()),
                raw_metadata_path: None,
                artifacts: vec![crate::capture::CapturedArtifact {
                    filename: format!("{}-{}.tgz", package.replace('/', "-"), version),
                    kind: Some("npm-tarball".to_string()),
                    url: dist
                        .get("tarball")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    size_bytes: dist.get("unpackedSize").and_then(Value::as_u64),
                    uploaded_at: published_at,
                    yanked: None,
                    hashes: crate::capture::ArtifactHashes {
                        integrity: dist
                            .get("integrity")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        shasum: dist
                            .get("shasum")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        ..crate::capture::ArtifactHashes::default()
                    },
                    provenance_path: None,
                }],
                upstream_repository: None,
                details: serde_json::json!({
                    "mode": "online-reconstruction",
                    "deprecated": version_meta.get("deprecated"),
                    "scripts": version_meta.get("scripts"),
                    "publisher": version_meta.get("_npmUser"),
                    "unpublished": raw.pointer("/time/unpublished")
                }),
            }),
            capture_dir: None,
        });
    }

    Ok(entries)
}

async fn load_crates_history_online(
    http: &reqwest::Client,
    package: &str,
) -> Result<Vec<HistoryEntry>> {
    let encoded = urlencoding::encode(package);
    let metadata_url = format!("https://crates.io/api/v1/crates/{encoded}");
    let raw = http
        .get(&metadata_url)
        .send()
        .await
        .with_context(|| format!("failed to fetch crates.io metadata for {package}"))?
        .error_for_status()
        .with_context(|| format!("crates.io returned an error for {package}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("failed to decode crates.io metadata for {package}"))?;

    let versions = raw
        .get("versions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut entries = Vec::new();

    for version_meta in versions {
        let Some(version) = version_meta.get("num").and_then(Value::as_str) else {
            continue;
        };
        let published_at = version_meta
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339);
        let yanked = version_meta
            .get("yanked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let event_id = format!("crates-io:{package}@{version}");
        let download_url = version_meta
            .get("dl_path")
            .and_then(Value::as_str)
            .map(|path| format!("https://crates.io{path}"))
            .unwrap_or_else(|| {
                format!("https://crates.io/api/v1/crates/{package}/{version}/download")
            });

        entries.push(HistoryEntry {
            event: PackageReleaseEvent {
                event_id: event_id.clone(),
                ecosystem: Ecosystem::CratesIo,
                package: package.to_string(),
                version: version.to_string(),
                published_at,
                observed_at: Utc::now(),
                source: "crates.online.api".to_string(),
                sequence: None,
                package_url: Some(format!("https://crates.io/crates/{package}")),
                release_url: Some(format!("https://crates.io/crates/{package}/{version}")),
                metadata_url: Some(metadata_url.clone()),
                priority: None,
            },
            capture: Some(CapturedRelease {
                event_id,
                ecosystem: Ecosystem::CratesIo,
                package: package.to_string(),
                version: version.to_string(),
                observed_at: Utc::now(),
                published_at,
                captured_at: Utc::now(),
                status: if yanked {
                    ReleaseStatus::Yanked
                } else {
                    ReleaseStatus::Active
                },
                package_url: Some(format!("https://crates.io/crates/{package}")),
                release_url: Some(format!("https://crates.io/crates/{package}/{version}")),
                metadata_url: Some(metadata_url.clone()),
                raw_metadata_path: None,
                artifacts: vec![crate::capture::CapturedArtifact {
                    filename: format!("{package}-{version}.crate"),
                    kind: Some("crate".to_string()),
                    url: Some(download_url),
                    size_bytes: None,
                    uploaded_at: published_at,
                    yanked: Some(yanked),
                    hashes: crate::capture::ArtifactHashes {
                        checksum: version_meta
                            .get("checksum")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        ..crate::capture::ArtifactHashes::default()
                    },
                    provenance_path: None,
                }],
                upstream_repository: None,
                details: serde_json::json!({
                    "mode": "online-reconstruction",
                    "crate_size": version_meta.get("crate_size"),
                    "downloads": version_meta.get("downloads"),
                    "license": version_meta.get("license")
                }),
            }),
            capture_dir: None,
        });
    }

    Ok(entries)
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        capture::{ArtifactHashes, CapturedArtifact},
        ledger::EventLedger,
    };

    #[tokio::test]
    async fn package_history_reads_ledger_and_capture() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path();
        let ledger = EventLedger::open(ledger::observed_ledger_path(data_dir))
            .await
            .unwrap();

        let event = PackageReleaseEvent {
            event_id: "pypi:litellm@1.82.7".to_string(),
            ecosystem: Ecosystem::Pypi,
            package: "litellm".to_string(),
            version: "1.82.7".to_string(),
            published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 8, 0, 0).unwrap()),
            observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 8, 1, 0).unwrap(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: None,
        };
        ledger.append(&event).await.unwrap();

        let capture_dir = capture_dir_for_event(data_dir, &event);
        tokio::fs::create_dir_all(&capture_dir).await.unwrap();
        tokio::fs::write(
            capture_dir.join("capture.json"),
            serde_json::to_vec(&CapturedRelease {
                event_id: event.event_id.clone(),
                ecosystem: event.ecosystem,
                package: event.package.clone(),
                version: event.version.clone(),
                observed_at: event.observed_at,
                published_at: event.published_at,
                captured_at: event.observed_at,
                status: ReleaseStatus::Yanked,
                package_url: None,
                release_url: None,
                metadata_url: None,
                raw_metadata_path: Some("metadata.json".to_string()),
                artifacts: vec![CapturedArtifact {
                    filename: "litellm-1.82.7.tar.gz".to_string(),
                    kind: Some("sdist".to_string()),
                    url: None,
                    size_bytes: None,
                    uploaded_at: None,
                    yanked: Some(true),
                    hashes: ArtifactHashes {
                        sha256: Some("abc".to_string()),
                        ..ArtifactHashes::default()
                    },
                    provenance_path: None,
                }],
                upstream_repository: None,
                details: serde_json::json!({
                    "yanked_reason": "retired after breach"
                }),
            })
            .unwrap(),
        )
        .await
        .unwrap();

        let entries = load_package_history(data_dir, Ecosystem::Pypi, "litellm")
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].capture.as_ref().unwrap().status,
            ReleaseStatus::Yanked
        );
        assert_eq!(
            yanked_reason(entries[0].capture.as_ref()),
            Some("retired after breach")
        );
    }

    #[tokio::test]
    async fn persist_history_entries_writes_event_and_capture() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path();
        let entry = HistoryEntry {
            event: PackageReleaseEvent {
                event_id: "pypi:demo@1.0.0".to_string(),
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                version: "1.0.0".to_string(),
                published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 8, 0, 0).unwrap()),
                observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 8, 1, 0).unwrap(),
                source: "pypi.online.project-json".to_string(),
                sequence: None,
                package_url: None,
                release_url: None,
                metadata_url: None,
                priority: None,
            },
            capture: Some(CapturedRelease {
                event_id: "pypi:demo@1.0.0".to_string(),
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                version: "1.0.0".to_string(),
                observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 8, 1, 0).unwrap(),
                published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 8, 0, 0).unwrap()),
                captured_at: Utc.with_ymd_and_hms(2026, 3, 25, 8, 2, 0).unwrap(),
                status: ReleaseStatus::Active,
                package_url: None,
                release_url: None,
                metadata_url: None,
                raw_metadata_path: None,
                artifacts: Vec::new(),
                upstream_repository: None,
                details: serde_json::json!({"mode":"online-reconstruction"}),
            }),
            capture_dir: None,
        };

        persist_history_entries(data_dir, &[entry]).await.unwrap();

        let observed_events = ledger::read_events(&ledger::observed_ledger_path(data_dir))
            .await
            .unwrap();
        assert!(observed_events.is_empty());
        let events = ledger::read_events(&reconstructed_ledger_path(data_dir))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        let capture_dir = capture_dir_for_event(data_dir, &events[0]);
        assert!(capture_dir.join("event.json").exists());
        assert!(capture_dir.join("capture.json").exists());
    }

    #[test]
    fn previous_lineage_candidate_uses_prior_online_release() {
        let local_entries = vec![HistoryEntry {
            event: PackageReleaseEvent {
                event_id: "pypi:demo@1.0.1".to_string(),
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                version: "1.0.1".to_string(),
                published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 8, 1, 0).unwrap()),
                observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 8, 2, 0).unwrap(),
                source: "test".to_string(),
                sequence: None,
                package_url: None,
                release_url: None,
                metadata_url: None,
                priority: None,
            },
            capture: None,
            capture_dir: None,
        }];
        let online_entries = vec![
            HistoryEntry {
                event: PackageReleaseEvent {
                    event_id: "pypi:demo@1.0.0".to_string(),
                    ecosystem: Ecosystem::Pypi,
                    package: "demo".to_string(),
                    version: "1.0.0".to_string(),
                    published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 8, 0, 0).unwrap()),
                    observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 8, 3, 0).unwrap(),
                    source: "test".to_string(),
                    sequence: None,
                    package_url: None,
                    release_url: None,
                    metadata_url: None,
                    priority: None,
                },
                capture: None,
                capture_dir: None,
            },
            local_entries[0].clone(),
        ];

        let candidate = previous_lineage_candidate(&local_entries, &online_entries, "1.0.1");
        assert_eq!(
            candidate.as_ref().map(|entry| entry.event.version.as_str()),
            Some("1.0.0")
        );
    }

    #[test]
    fn parses_scoped_npm_event_id() {
        let parsed = parse_event_id("npm:@scope/demo@1.2.3").unwrap();
        assert_eq!(parsed.ecosystem, Ecosystem::Npm);
        assert_eq!(parsed.package, "@scope/demo");
        assert_eq!(parsed.version, "1.2.3");
    }
}
