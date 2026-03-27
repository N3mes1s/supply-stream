use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use supply_stream_core::{
    assessment::{DiffAssessmentInput, assess_release},
    bundle,
    capture::CapturedRelease,
    diff,
    event::{
        Ecosystem, EmittedReleaseAssessmentSignal, EmittedRepositorySignal,
        RepositorySignalSeverity,
    },
    history,
    install_scripts::{npm_install_scripts_benign, npm_install_scripts_longstanding},
    ledger, repo_provenance,
    sink::{EventSink, StdoutNdjsonSink},
    store::{self, EventOrigin},
    visibility,
};
use tokio::fs;

use crate::config::{DiffOutputFormat, HistoryArgs, HistoryCommand};

pub async fn run(args: HistoryArgs) -> Result<()> {
    match args.command {
        HistoryCommand::Sync { json } => {
            let store = store::OperationalStore::open(store::index_db_path(&args.data_dir)).await?;
            let stats = store.reconcile_local_data(&args.data_dir).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!("reconciled local data into {}", store.path().display());
                println!("events: {}", stats.events);
                println!("captures: {}", stats.captures);
                println!("diffs: {}", stats.diffs);
            }
            Ok(())
        }
        HistoryCommand::Stats { json } => {
            let store = store::OperationalStore::open(store::index_db_path(&args.data_dir)).await?;
            if store.event_count().await? == 0 {
                store.reconcile_local_data(&args.data_dir).await?;
            }
            let stats = store.stats().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!("store: {}", store.path().display());
                println!("events: {}", stats.total_events);
                println!("observed: {}", stats.observed_events);
                println!("reconstructed: {}", stats.reconstructed_events);
                println!(
                    "priority: high={} medium={} low={} unknown={}",
                    stats.priorities.high,
                    stats.priorities.medium,
                    stats.priorities.low,
                    stats.priorities.unknown
                );
                println!(
                    "capture_states: pending={} ready={} skipped={} failed={}",
                    stats.capture_states.pending,
                    stats.capture_states.ready,
                    stats.capture_states.skipped,
                    stats.capture_states.failed
                );
                println!(
                    "diff_states: pending={} ready={} skipped={} failed={}",
                    stats.diff_states.pending,
                    stats.diff_states.ready,
                    stats.diff_states.skipped,
                    stats.diff_states.failed
                );
                for ecosystem in stats.ecosystems {
                    println!(
                        "{}: events={} observed={} reconstructed={} priority(high/medium/low/unknown)={}/{}/{}/{} capture(pending/ready/skipped/failed)={}/{}/{}/{} diff(pending/ready/skipped/failed)={}/{}/{}/{}",
                        ecosystem.ecosystem,
                        ecosystem.total_events,
                        ecosystem.observed_events,
                        ecosystem.reconstructed_events,
                        ecosystem.priorities.high,
                        ecosystem.priorities.medium,
                        ecosystem.priorities.low,
                        ecosystem.priorities.unknown,
                        ecosystem.capture_states.pending,
                        ecosystem.capture_states.ready,
                        ecosystem.capture_states.skipped,
                        ecosystem.capture_states.failed,
                        ecosystem.diff_states.pending,
                        ecosystem.diff_states.ready,
                        ecosystem.diff_states.skipped,
                        ecosystem.diff_states.failed
                    );
                }
            }
            Ok(())
        }
        HistoryCommand::Package {
            ecosystem,
            package,
            online,
            json,
        } => {
            let entries = if online {
                history::load_package_history_online(ecosystem, &package).await?
            } else {
                history::load_package_history(&args.data_dir, ecosystem, &package).await?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                history::print_package_history(ecosystem, &package, &entries);
            }
            Ok(())
        }
        HistoryCommand::Event {
            event_id,
            online,
            json,
        } => {
            let entry = if online {
                history::load_event_history_online(&event_id).await?
            } else {
                history::load_event_history(&args.data_dir, &event_id).await?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&entry)?);
            } else {
                history::print_event_history(&entry);
            }
            Ok(())
        }
        HistoryCommand::Locate {
            ecosystem,
            package,
            version,
            json,
        } => {
            let report =
                visibility::locate_release(ecosystem, &package, version.as_deref()).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                history::print_visibility_report(&report);
            }
            Ok(())
        }
        HistoryCommand::Provenance {
            ecosystem,
            package,
            version,
            artifact,
            json,
        } => {
            let http = reqwest::Client::builder()
                .user_agent("supply-stream/0.1.0")
                .http2_adaptive_window(true)
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .context("failed to build HTTP client")?;
            let report = repo_provenance::inspect_local_artifact_provenance(
                &http,
                ecosystem,
                &package,
                version.as_deref(),
                &artifact,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_provenance_report(&report);
            }
            Ok(())
        }
        HistoryCommand::ProvenanceBackfill {
            ecosystem,
            package,
            force,
            emit,
            limit,
            json,
        } => {
            let summary = run_provenance_backfill(
                &args.data_dir,
                ecosystem,
                package.as_deref(),
                force,
                emit,
                limit,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("events_scanned: {}", summary.events_scanned);
                println!("captures_found: {}", summary.captures_found);
                println!("recomputed: {}", summary.recomputed);
                println!("reused_existing: {}", summary.reused_existing);
                println!("repository_resolved: {}", summary.repository_resolved);
                println!("suspicious: {}", summary.suspicious);
                println!("emitted: {}", summary.emitted);
                println!("missing_capture: {}", summary.missing_capture);
                println!("errors: {}", summary.errors);
            }
            Ok(())
        }
        HistoryCommand::AssessmentBackfill {
            ecosystem,
            package,
            emit,
            limit,
            json,
        } => {
            let summary =
                run_assessment_backfill(&args.data_dir, ecosystem, package.as_deref(), emit, limit)
                    .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("events_scanned: {}", summary.events_scanned);
                println!("captures_found: {}", summary.captures_found);
                println!("diffs_found: {}", summary.diffs_found);
                println!("suspicious: {}", summary.suspicious);
                println!("high: {}", summary.high);
                println!("warning: {}", summary.warning);
                println!("informational: {}", summary.informational);
                println!("emitted: {}", summary.emitted);
                println!("missing_capture: {}", summary.missing_capture);
                println!("missing_diff: {}", summary.missing_diff);
            }
            Ok(())
        }
        HistoryCommand::Bundle {
            event_id,
            write,
            json,
        } => {
            let store = store::OperationalStore::open(store::index_db_path(&args.data_dir)).await?;
            if store.event_count().await? == 0 {
                store.reconcile_local_data(&args.data_dir).await?;
            }
            let Some(event) = store.load_event(&event_id).await? else {
                anyhow::bail!("event not found in local history: {event_id}");
            };
            let built =
                bundle::build_release_bundle(&args.data_dir, &store, &event, None, None).await?;
            if write {
                bundle::write_release_bundle(
                    &args.data_dir,
                    &store,
                    &event,
                    built.capture.as_ref(),
                    built.diff.as_ref(),
                )
                .await?;
            }
            let _ = json;
            println!("{}", serde_json::to_string_pretty(&built)?);
            Ok(())
        }
        HistoryCommand::Validate {
            ecosystem,
            package,
            limit,
            write_missing_bundles,
            json,
        } => {
            let summary = run_validation(
                &args.data_dir,
                ecosystem,
                package.as_deref(),
                limit,
                write_missing_bundles,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("events_scanned: {}", summary.events_scanned);
                println!("captures_present: {}", summary.captures_present);
                println!("diffs_present: {}", summary.diffs_present);
                println!("bundles_present: {}", summary.bundles_present);
                println!("bundles_written: {}", summary.bundles_written);
                println!("findings: {}", summary.findings.len());
                for finding in summary.findings.iter().take(20) {
                    println!(
                        "{} {} {} {}",
                        finding.severity, finding.code, finding.event_id, finding.message
                    );
                }
            }
            Ok(())
        }
        HistoryCommand::Diff {
            ecosystem,
            package,
            version,
            baseline,
            artifact,
            baseline_artifact,
            patch,
            patch_context,
            format,
            output,
            online,
            json,
        } => {
            let release_diff = diff::load_release_diff(diff::ReleaseDiffRequest {
                data_dir: &args.data_dir,
                ecosystem,
                package: &package,
                target_version: version.as_deref(),
                baseline_selector: baseline.as_deref(),
                online,
                target_artifact_path: artifact.as_deref(),
                baseline_artifact_path: baseline_artifact.as_deref(),
                include_patches: patch,
                patch_context,
            })
            .await?;
            let format = resolve_diff_output_format(format, json)?;
            let body = match format {
                DiffOutputFormat::Text => diff::render_release_diff_text(&release_diff),
                DiffOutputFormat::Markdown => diff::render_release_diff_markdown(&release_diff),
                DiffOutputFormat::Json => serde_json::to_string_pretty(&release_diff)?,
            };

            if let Some(path) = output {
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent).await.with_context(|| {
                        format!("failed to create output dir {}", parent.display())
                    })?;
                }
                fs::write(&path, body)
                    .await
                    .with_context(|| format!("failed to write {}", path.display()))?;
                println!("{}", path.display());
            } else {
                print!("{body}");
            }
            Ok(())
        }
        HistoryCommand::Recent {
            ecosystem,
            limit,
            json,
        } => {
            let entries = history::load_recent_history(&args.data_dir, ecosystem, limit).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                history::print_recent_history(ecosystem, &entries);
            }
            Ok(())
        }
    }
}

fn resolve_diff_output_format(
    format: Option<DiffOutputFormat>,
    json: bool,
) -> Result<DiffOutputFormat> {
    match (format, json) {
        (Some(DiffOutputFormat::Text | DiffOutputFormat::Markdown), true) => {
            anyhow::bail!("--json conflicts with --format text/markdown")
        }
        (Some(format), _) => Ok(format),
        (None, true) => Ok(DiffOutputFormat::Json),
        (None, false) => Ok(DiffOutputFormat::Text),
    }
}

fn print_provenance_report(report: &repo_provenance::LocalArtifactProvenanceReport) {
    println!(
        "provenance {}:{} {}",
        report.ecosystem, report.package, report.version
    );
    println!("artifact: {}", report.artifact_path);
    println!("artifact_kind: {}", report.artifact_kind.as_str());
    match &report.repository {
        Some(repository) => {
            println!(
                "repository: {} ({})",
                repository.normalized_repository_url,
                repository.provider.as_str()
            );
            println!(
                "match: {}{}",
                match repository.match_kind {
                    repo_provenance::RepositoryMatchKind::Tag => "tag",
                    repo_provenance::RepositoryMatchKind::Release => "release",
                    repo_provenance::RepositoryMatchKind::None => "none",
                    repo_provenance::RepositoryMatchKind::Unknown => "unknown",
                },
                repository
                    .matched_ref
                    .as_ref()
                    .map(|value| format!(" ({value})"))
                    .unwrap_or_default()
            );
            println!("suspicious: {}", repository.suspicious);
            println!("reason: {}", repository.reason);
        }
        None => {
            println!("repository: unresolved");
        }
    }
}

#[derive(Debug, Serialize)]
struct ProvenanceBackfillSummary {
    events_scanned: usize,
    captures_found: usize,
    recomputed: usize,
    reused_existing: usize,
    repository_resolved: usize,
    suspicious: usize,
    emitted: usize,
    missing_capture: usize,
    errors: usize,
}

#[derive(Debug, Serialize)]
struct AssessmentBackfillSummary {
    events_scanned: usize,
    captures_found: usize,
    diffs_found: usize,
    suspicious: usize,
    high: usize,
    warning: usize,
    informational: usize,
    emitted: usize,
    missing_capture: usize,
    missing_diff: usize,
}

#[derive(Debug, Serialize)]
struct ValidationSummary {
    events_scanned: usize,
    captures_present: usize,
    diffs_present: usize,
    bundles_present: usize,
    bundles_written: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    findings: Vec<ValidationFinding>,
}

#[derive(Debug, Serialize)]
struct ValidationFinding {
    severity: &'static str,
    code: &'static str,
    event_id: String,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AssessmentStoredReleaseDiffStatusRecord {
    Ready,
    NoBaseline,
}

impl AssessmentStoredReleaseDiffStatusRecord {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NoBaseline => "no_baseline",
        }
    }
}

#[derive(Debug, Deserialize)]
struct AssessmentContentRecord {
    available: bool,
    patches_included: bool,
    files_added_count: usize,
    files_removed_count: usize,
    files_changed_count: usize,
    #[serde(default)]
    files_added: Vec<String>,
    #[serde(default)]
    files_removed: Vec<String>,
    #[serde(default)]
    files_changed: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AssessmentReleaseDiffRecord {
    content: AssessmentContentRecord,
}

#[derive(Debug, Deserialize)]
struct AssessmentStoredReleaseDiffRecord {
    #[allow(dead_code)]
    event_id: String,
    #[allow(dead_code)]
    package: String,
    #[allow(dead_code)]
    version: String,
    baseline_version: Option<String>,
    status: AssessmentStoredReleaseDiffStatusRecord,
    diff: Option<AssessmentReleaseDiffRecord>,
}

async fn run_assessment_backfill(
    data_dir: &Path,
    ecosystem: Option<Ecosystem>,
    package: Option<&str>,
    emit: bool,
    limit: Option<usize>,
) -> Result<AssessmentBackfillSummary> {
    let store = store::OperationalStore::open(store::index_db_path(data_dir)).await?;
    if store.event_count().await? == 0 {
        store.reconcile_local_data(data_dir).await?;
    }

    let mut observed = load_observed_history_events(data_dir).await?;
    let mut reconstructed =
        ledger::read_events(&ledger::reconstructed_ledger_path(data_dir)).await?;
    observed.append(&mut reconstructed);
    observed.sort_by_key(|event| {
        (
            event.published_at.unwrap_or(event.observed_at),
            event.observed_at,
            event.event_id.clone(),
        )
    });

    let sink: Option<Arc<dyn EventSink>> = if emit {
        Some(Arc::new(StdoutNdjsonSink::new()))
    } else {
        None
    };

    let mut summary = AssessmentBackfillSummary {
        events_scanned: 0,
        captures_found: 0,
        diffs_found: 0,
        suspicious: 0,
        high: 0,
        warning: 0,
        informational: 0,
        emitted: 0,
        missing_capture: 0,
        missing_diff: 0,
    };

    for event in observed {
        if let Some(value) = ecosystem
            && event.ecosystem != value
        {
            continue;
        }
        if let Some(value) = package
            && event.package != value
        {
            continue;
        }
        if let Some(value) = limit
            && summary.events_scanned >= value
        {
            break;
        }

        summary.events_scanned += 1;
        let capture_dir = history::capture_dir_for_event(data_dir, &event);
        let capture_path = capture_dir.join("capture.json");
        let capture_bytes = match fs::read(&capture_path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                summary.missing_capture += 1;
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", capture_path.display()));
            }
        };
        summary.captures_found += 1;
        let capture = serde_json::from_slice::<CapturedRelease>(&capture_bytes)
            .with_context(|| format!("failed to parse {}", capture_path.display()))?;

        let diff_path = capture_dir.join("diff.json");
        let diff_bytes = match fs::read(&diff_path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                summary.missing_diff += 1;
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", diff_path.display()));
            }
        };
        summary.diffs_found += 1;
        let stored_diff = serde_json::from_slice::<AssessmentStoredReleaseDiffRecord>(&diff_bytes)
            .with_context(|| format!("failed to parse {}", diff_path.display()))?;
        let diff_input = DiffAssessmentInput {
            status: stored_diff.status.as_str(),
            baseline_version: stored_diff.baseline_version.clone(),
            available: stored_diff
                .diff
                .as_ref()
                .map(|diff| diff.content.available)
                .unwrap_or(false),
            patches_included: stored_diff
                .diff
                .as_ref()
                .map(|diff| diff.content.patches_included)
                .unwrap_or(false),
            files_added_count: stored_diff
                .diff
                .as_ref()
                .map(|diff| diff.content.files_added_count)
                .unwrap_or(0),
            files_removed_count: stored_diff
                .diff
                .as_ref()
                .map(|diff| diff.content.files_removed_count)
                .unwrap_or(0),
            files_changed_count: stored_diff
                .diff
                .as_ref()
                .map(|diff| diff.content.files_changed_count)
                .unwrap_or(0),
            package_manifest_only: stored_diff
                .diff
                .as_ref()
                .map(|diff| {
                    diff.content.files_added.is_empty()
                        && diff.content.files_removed.is_empty()
                        && !diff.content.files_changed.is_empty()
                        && diff.content.files_changed.iter().all(|path| {
                            matches!(
                                path.as_str(),
                                "package.json"
                                    | "Cargo.toml"
                                    | "pyproject.toml"
                                    | "setup.py"
                                    | "setup.cfg"
                            ) || path.ends_with("/package.json")
                                || path.ends_with("/Cargo.toml")
                                || path.ends_with("/pyproject.toml")
                                || path.ends_with("/setup.py")
                                || path.ends_with("/setup.cfg")
                        })
                })
                .unwrap_or(false),
        };

        let graph = store
            .load_graph_evidence(event.ecosystem, &event.package)
            .await?;
        let repository = capture.upstream_repository.clone();
        let assessment = assess_release(
            &event,
            graph.as_ref(),
            &capture,
            repository.as_ref(),
            Some(&diff_input),
        );

        if assessment.suspicious {
            summary.suspicious += 1;
        }
        match assessment.severity {
            supply_stream_core::event::ReleaseAssessmentSeverity::High => summary.high += 1,
            supply_stream_core::event::ReleaseAssessmentSeverity::Warning => summary.warning += 1,
            supply_stream_core::event::ReleaseAssessmentSeverity::Informational => {
                summary.informational += 1
            }
        }

        if let Some(sink) = &sink {
            sink.publish_release_assessment(&EmittedReleaseAssessmentSignal {
                kind: "release_assessment",
                event_id: event.event_id.clone(),
                ecosystem: event.ecosystem,
                package: event.package.clone(),
                version: event.version.clone(),
                suspicious: assessment.suspicious,
                signal_type: "repo_graph_diff_fusion",
                severity: assessment.severity,
                priority_tier: event.priority_snapshot().tier,
                graph: assessment.graph,
                factors: assessment.factors,
                reason: assessment.reason,
                repository,
                diff: assessment.diff,
            })
            .await?;
            summary.emitted += 1;
        }
    }

    Ok(summary)
}

async fn run_validation(
    data_dir: &Path,
    ecosystem: Option<Ecosystem>,
    package: Option<&str>,
    limit: Option<usize>,
    write_missing_bundles: bool,
) -> Result<ValidationSummary> {
    let store = store::OperationalStore::open(store::index_db_path(data_dir)).await?;
    store.reconcile_local_data(data_dir).await?;

    let mut observed = load_observed_history_events(data_dir).await?;
    let mut reconstructed =
        ledger::read_events(&ledger::reconstructed_ledger_path(data_dir)).await?;
    observed.append(&mut reconstructed);
    observed.sort_by_key(|event| {
        (
            event.published_at.unwrap_or(event.observed_at),
            event.observed_at,
            event.event_id.clone(),
        )
    });

    let mut summary = ValidationSummary {
        events_scanned: 0,
        captures_present: 0,
        diffs_present: 0,
        bundles_present: 0,
        bundles_written: 0,
        findings: Vec::new(),
    };

    for event in observed {
        if let Some(value) = ecosystem
            && event.ecosystem != value
        {
            continue;
        }
        if let Some(value) = package
            && event.package != value
        {
            continue;
        }
        if let Some(value) = limit
            && summary.events_scanned >= value
        {
            break;
        }
        summary.events_scanned += 1;

        let release = store.load_release_record(&event.event_id).await?;
        if release.is_none() {
            summary.findings.push(ValidationFinding {
                severity: "high",
                code: "missing_release_index",
                event_id: event.event_id.clone(),
                message: "event is present in local history but missing from the operational store"
                    .to_string(),
                path: None,
            });
            continue;
        }
        let release = release.expect("checked is_some");
        if release.event.package != event.package
            || release.event.version != event.version
            || release.event.ecosystem != event.ecosystem
        {
            summary.findings.push(ValidationFinding {
                severity: "high",
                code: "store_event_mismatch",
                event_id: event.event_id.clone(),
                message: "operational store core event fields do not match the local ledger"
                    .to_string(),
                path: None,
            });
        }

        let capture_dir = history::capture_dir_for_event(data_dir, &event);
        let capture_path = capture_dir.join("capture.json");
        let diff_path = capture_dir.join("diff.json");
        let bundle_path = bundle::bundle_path_for_event(data_dir, &event);

        let capture = read_json_if_exists::<CapturedRelease>(&capture_path).await?;
        if capture.is_some() {
            summary.captures_present += 1;
        }
        if release.capture_state == "ready" && capture.is_none() {
            summary.findings.push(ValidationFinding {
                severity: "high",
                code: "missing_capture_for_ready_release",
                event_id: event.event_id.clone(),
                message: "store marks capture ready but capture.json is missing".to_string(),
                path: Some(capture_path.display().to_string()),
            });
        }
        if let Some(capture) = &capture {
            if capture.event_id != event.event_id {
                summary.findings.push(ValidationFinding {
                    severity: "high",
                    code: "capture_event_mismatch",
                    event_id: event.event_id.clone(),
                    message: "capture.json event_id does not match the ledger event".to_string(),
                    path: Some(capture_path.display().to_string()),
                });
            }
            if store
                .load_graph_evidence(event.ecosystem, &event.package)
                .await?
                .is_none()
            {
                summary.findings.push(ValidationFinding {
                    severity: "warning",
                    code: "missing_graph_for_captured_release",
                    event_id: event.event_id.clone(),
                    message: "captured release has no corresponding local graph evidence"
                        .to_string(),
                    path: Some(capture_path.display().to_string()),
                });
            }
            if capture.upstream_repository.is_some()
                && store
                    .load_package_repository_identity(event.ecosystem, &event.package)
                    .await?
                    .is_none()
            {
                summary.findings.push(ValidationFinding {
                    severity: "warning",
                    code: "missing_repo_index_for_captured_release",
                    event_id: event.event_id.clone(),
                    message: "capture has upstream repository provenance but package_repository_index has no entry".to_string(),
                    path: Some(capture_path.display().to_string()),
                });
            }
        }

        let diff = read_json_if_exists::<serde_json::Value>(&diff_path).await?;
        if diff.is_some() {
            summary.diffs_present += 1;
        }
        if release.diff_state == "ready" && diff.is_none() {
            summary.findings.push(ValidationFinding {
                severity: "high",
                code: "missing_diff_for_ready_release",
                event_id: event.event_id.clone(),
                message: "store marks diff ready but diff.json is missing".to_string(),
                path: Some(diff_path.display().to_string()),
            });
        }

        let bundle_value = read_json_if_exists::<serde_json::Value>(&bundle_path).await?;
        if bundle_value.is_some() {
            summary.bundles_present += 1;
        }
        if capture.is_some() && bundle_value.is_none() && write_missing_bundles {
            bundle::write_release_bundle(data_dir, &store, &event, capture.as_ref(), diff.as_ref())
                .await?;
            summary.bundles_written += 1;
        }
        let bundle_value = if bundle_value.is_some() || !write_missing_bundles {
            bundle_value
        } else {
            read_json_if_exists::<serde_json::Value>(&bundle_path).await?
        };
        if capture.is_some() && bundle_value.is_none() {
            summary.findings.push(ValidationFinding {
                severity: "warning",
                code: "missing_bundle_for_captured_release",
                event_id: event.event_id.clone(),
                message: "captured release has no persisted bundle.json".to_string(),
                path: Some(bundle_path.display().to_string()),
            });
        }
        if let Some(actual_bundle) = bundle_value {
            let expected_bundle = bundle::build_release_bundle(
                data_dir,
                &store,
                &event,
                capture.as_ref(),
                diff.as_ref(),
            )
            .await?;
            let expected_value = normalize_bundle_value(serde_json::to_value(&expected_bundle)?);
            let actual_value = normalize_bundle_value(actual_bundle);
            if actual_value != expected_value {
                if write_missing_bundles {
                    bundle::write_release_bundle(
                        data_dir,
                        &store,
                        &event,
                        capture.as_ref(),
                        diff.as_ref(),
                    )
                    .await?;
                    summary.bundles_written += 1;
                    continue;
                }
                summary.findings.push(ValidationFinding {
                    severity: "high",
                    code: "bundle_mismatch",
                    event_id: event.event_id.clone(),
                    message: "bundle.json does not match the current release evidence reconstructed from local files and store state".to_string(),
                    path: Some(bundle_path.display().to_string()),
                });
            }
        }
    }

    Ok(summary)
}

async fn run_provenance_backfill(
    data_dir: &Path,
    ecosystem: Option<Ecosystem>,
    package: Option<&str>,
    force: bool,
    emit: bool,
    limit: Option<usize>,
) -> Result<ProvenanceBackfillSummary> {
    let http = reqwest::Client::builder()
        .user_agent("supply-stream/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .context("failed to build HTTP client")?;
    let store = store::OperationalStore::open(store::index_db_path(data_dir)).await?;
    if store.event_count().await? == 0 {
        store.reconcile_local_data(data_dir).await?;
    }

    let mut observed = load_observed_history_events(data_dir).await?;
    let mut reconstructed =
        ledger::read_events(&ledger::reconstructed_ledger_path(data_dir)).await?;

    let mut origin_by_event = std::collections::HashMap::new();
    for event in &observed {
        origin_by_event.insert(event.event_id.clone(), EventOrigin::Observed);
    }
    for event in &reconstructed {
        origin_by_event
            .entry(event.event_id.clone())
            .or_insert(EventOrigin::Reconstructed);
    }

    observed.append(&mut reconstructed);
    observed.sort_by_key(|event| {
        (
            event.published_at.unwrap_or(event.observed_at),
            event.observed_at,
            event.event_id.clone(),
        )
    });

    let sink: Option<Arc<dyn EventSink>> = if emit {
        Some(Arc::new(StdoutNdjsonSink::new()))
    } else {
        None
    };

    let mut summary = ProvenanceBackfillSummary {
        events_scanned: 0,
        captures_found: 0,
        recomputed: 0,
        reused_existing: 0,
        repository_resolved: 0,
        suspicious: 0,
        emitted: 0,
        missing_capture: 0,
        errors: 0,
    };

    for event in observed {
        if let Some(value) = ecosystem
            && event.ecosystem != value
        {
            continue;
        }
        if let Some(value) = package
            && event.package != value
        {
            continue;
        }
        if let Some(value) = limit
            && summary.events_scanned >= value
        {
            break;
        }

        summary.events_scanned += 1;
        let capture_dir = history::capture_dir_for_event(data_dir, &event);
        let capture_path = capture_dir.join("capture.json");
        let bytes = match fs::read(&capture_path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                summary.missing_capture += 1;
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", capture_path.display()));
            }
        };
        summary.captures_found += 1;

        let mut capture = serde_json::from_slice::<CapturedRelease>(&bytes)
            .with_context(|| format!("failed to parse {}", capture_path.display()))?;
        enrich_capture_details_from_raw_metadata(&capture_dir, &mut capture).await?;
        let repository = if !force {
            capture
                .upstream_repository
                .clone()
                .filter(|repository| !should_recompute_existing_provenance(repository))
        } else {
            None
        };

        let repository = match repository {
            Some(repository) => {
                summary.reused_existing += 1;
                Some(repository)
            }
            None => {
                let repository = match repo_provenance::check_release_provenance(
                    &http,
                    event.ecosystem,
                    &event.version,
                    &capture.details,
                )
                .await
                {
                    Ok(repository) => repository,
                    Err(error) => {
                        summary.errors += 1;
                        eprintln!(
                            "warning: failed provenance for {}: {}",
                            event.event_id, error
                        );
                        continue;
                    }
                };
                capture.upstream_repository = repository.clone();
                write_json_pretty(&capture_path, &capture).await?;
                let origin = origin_by_event
                    .get(&event.event_id)
                    .copied()
                    .unwrap_or(EventOrigin::Observed);
                store
                    .record_capture(&event, origin, &capture_dir, &capture)
                    .await?;
                summary.recomputed += 1;
                repository
            }
        };

        if let Some(repository) = repository {
            summary.repository_resolved += 1;
            if repository.suspicious {
                summary.suspicious += 1;
            }
            store
                .record_package_repository_identity(
                    event.ecosystem,
                    &event.package,
                    Some(&event.version),
                    &repository,
                    if force {
                        "provenance_backfill_force"
                    } else {
                        "provenance_backfill_existing"
                    },
                )
                .await?;
            if let Some(sink) = &sink {
                let (severity, mut factors) =
                    historical_repository_signal_assessment(&event, &capture, &repository);
                factors.insert(0, "historical_backfill".to_string());
                sink.publish_repository_signal(&EmittedRepositorySignal::repo_release_parity(
                    &event, repository, severity, factors,
                ))
                .await?;
                summary.emitted += 1;
            }
        }
    }

    Ok(summary)
}

fn should_recompute_existing_provenance(
    repository: &repo_provenance::RepositoryReleaseProvenance,
) -> bool {
    repository.provider == repo_provenance::RepositoryProvider::Github
        && repository.match_kind == repo_provenance::RepositoryMatchKind::Unknown
        && (repository.reason.contains("403 Forbidden")
            || repository.reason.contains("401 Unauthorized"))
}

async fn enrich_capture_details_from_raw_metadata(
    capture_dir: &Path,
    capture: &mut CapturedRelease,
) -> Result<()> {
    if capture.ecosystem != Ecosystem::Npm
        || (capture
            .details
            .get("install_scripts_longstanding")
            .is_some()
            && capture.details.get("install_scripts_benign").is_some())
    {
        return Ok(());
    }
    let metadata_rel = capture
        .raw_metadata_path
        .as_deref()
        .unwrap_or("metadata.json");
    let metadata_path = capture_dir.join(metadata_rel);
    let bytes = match fs::read(&metadata_path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read {}", metadata_path.display()));
        }
    };
    let raw: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", metadata_path.display()))?;
    let longstanding = npm_install_scripts_longstanding(&raw, &capture.version);
    capture.details["install_scripts_longstanding"] = json!(longstanding);
    if let Some(version_meta) = raw
        .get("versions")
        .and_then(Value::as_object)
        .and_then(|versions| versions.get(&capture.version))
    {
        capture.details["install_scripts_benign"] = json!(npm_install_scripts_benign(version_meta));
    }
    Ok(())
}

async fn load_observed_history_events(
    data_dir: &Path,
) -> Result<Vec<supply_stream_core::event::PackageReleaseEvent>> {
    let mut observed = ledger::read_events(&ledger::observed_ledger_path(data_dir)).await?;
    let mut legacy = ledger::read_events(&ledger::legacy_ledger_path(data_dir)).await?;
    observed.append(&mut legacy);

    let mut seen = std::collections::HashSet::new();
    observed.retain(|event| seen.insert(event.event_id.clone()));
    Ok(observed)
}

fn historical_repository_signal_assessment(
    event: &supply_stream_core::event::PackageReleaseEvent,
    capture: &CapturedRelease,
    repository: &repo_provenance::RepositoryReleaseProvenance,
) -> (RepositorySignalSeverity, Vec<String>) {
    let mut factors = Vec::new();
    let prerelease = is_prerelease_version(&event.version);
    let install_time_execution = capture
        .details
        .get("has_install_scripts")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let install_time_execution_longstanding = capture
        .details
        .get("install_scripts_longstanding")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let install_time_execution_benign = capture
        .details
        .get("install_scripts_benign")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let risky_install_time_execution = install_time_execution
        && !install_time_execution_longstanding
        && !install_time_execution_benign;
    let high_impact = matches!(
        event.priority_snapshot().tier,
        supply_stream_core::priority::PriorityTier::High
            | supply_stream_core::priority::PriorityTier::Medium
    );

    if repository.suspicious {
        factors.push("repo_release_mismatch".to_string());
    }
    if prerelease {
        factors.push("prerelease_or_nightly".to_string());
    } else {
        factors.push("stable_version".to_string());
    }
    if install_time_execution {
        factors.push("install_time_execution".to_string());
    }
    if install_time_execution_longstanding {
        factors.push("install_time_execution_longstanding".to_string());
    }
    if install_time_execution_benign {
        factors.push("install_time_execution_benign".to_string());
    }
    if high_impact {
        factors.push("high_or_medium_impact".to_string());
    }

    let severity = if !repository.suspicious {
        RepositorySignalSeverity::Informational
    } else if risky_install_time_execution {
        RepositorySignalSeverity::High
    } else if prerelease {
        RepositorySignalSeverity::Informational
    } else {
        let _ = high_impact;
        RepositorySignalSeverity::Warning
    };

    (severity, factors)
}

fn is_prerelease_version(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    ["nightly", "alpha", "beta", "rc", "dev", "canary", "preview"]
        .iter()
        .any(|marker| lower.contains(marker))
}

async fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create output dir {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(value)?;
    fs::write(path, body)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

async fn read_json_if_exists<T>(path: &Path) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn normalize_bundle_value(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("generated_at");
    }
    value
}
