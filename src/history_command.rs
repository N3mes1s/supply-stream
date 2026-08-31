use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use supply_stream_core::{
    assessment::{DiffAssessmentInput, VersionBurstConfig, assess_release},
    bundle,
    capture::{CaptureRequest, CaptureWorker, CapturedRelease},
    config::{CaptureConfig, PriorityConfig},
    detection, diff,
    event::{
        Ecosystem, EmittedReleaseAssessmentSignal, EmittedRepositorySignal,
        RepositorySignalSeverity,
    },
    history,
    install_scripts::{npm_install_scripts_benign, npm_install_scripts_longstanding},
    ledger,
    perf::RuntimeStats,
    priority,
    priority::PriorityResolver,
    repo_provenance,
    sink::{EventSink, StdoutNdjsonSink},
    store::{self, EventOrigin},
    visibility,
};
use tokio::{fs, sync::mpsc};

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
        HistoryCommand::Report {
            ecosystem,
            since_hours,
            limit,
            json,
        } => {
            let summary = run_report(&args.data_dir, ecosystem, since_hours, limit).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("data_dir: {}", summary.data_dir);
                println!(
                    "window: {} -> {} ({}h)",
                    summary.since, summary.until, summary.hours
                );
                println!("events_scanned: {}", summary.events_scanned);
                println!("unique_packages: {}", summary.unique_packages);
                println!(
                    "observed_releases_per_hour: {:.2}",
                    summary.observed_releases_per_hour
                );
                println!(
                    "origins: observed={} reconstructed={}",
                    summary.origin_counts.get("observed").copied().unwrap_or(0),
                    summary
                        .origin_counts
                        .get("reconstructed")
                        .copied()
                        .unwrap_or(0),
                );
                println!(
                    "resolution: graph/scored/census={} ({:.1}%), stub={} ({:.1}%), external={} ({:.1}%), unknown={} ({:.1}%)",
                    summary.observed_resolution.graph_scored_or_census,
                    summary.observed_resolution.graph_scored_or_census_rate * 100.0,
                    summary.observed_resolution.runtime_stub,
                    summary.observed_resolution.runtime_stub_rate * 100.0,
                    summary.observed_resolution.external,
                    summary.observed_resolution.external_rate * 100.0,
                    summary.observed_resolution.unknown,
                    summary.observed_resolution.unknown_rate * 100.0,
                );
                println!(
                    "observed_only_resolution: graph/scored/census={} ({:.1}%), stub={} ({:.1}%), external={} ({:.1}%), unknown={} ({:.1}%)",
                    summary.observed_only_resolution.graph_scored_or_census,
                    summary.observed_only_resolution.graph_scored_or_census_rate * 100.0,
                    summary.observed_only_resolution.runtime_stub,
                    summary.observed_only_resolution.runtime_stub_rate * 100.0,
                    summary.observed_only_resolution.external,
                    summary.observed_only_resolution.external_rate * 100.0,
                    summary.observed_only_resolution.unknown,
                    summary.observed_only_resolution.unknown_rate * 100.0,
                );
                println!(
                    "current_knowledge_gap: missing_current_census={} ({:.1}%), stub_missing_current_census={} ({:.1}%)",
                    summary.current_knowledge.missing_current_census,
                    summary.current_knowledge.missing_current_census_rate * 100.0,
                    summary.current_knowledge.stub_missing_current_census,
                    summary.current_knowledge.stub_missing_current_census_rate * 100.0,
                );
                println!(
                    "bundles: ready_capture={} present={} missing={}",
                    summary.bundles.captures_ready,
                    summary.bundles.bundles_present,
                    summary.bundles.bundles_missing
                );
                println!(
                    "capture_states: pending={} ready={} skipped={} failed={}",
                    summary.capture_states.pending,
                    summary.capture_states.ready,
                    summary.capture_states.skipped,
                    summary.capture_states.failed
                );
                println!(
                    "diff_states: pending={} ready={} skipped={} failed={}",
                    summary.diff_states.pending,
                    summary.diff_states.ready,
                    summary.diff_states.skipped,
                    summary.diff_states.failed
                );
                println!(
                    "assessments: high={} warning={} informational={} suspicious={}",
                    summary.assessments.high,
                    summary.assessments.warning,
                    summary.assessments.informational,
                    summary.assessments.suspicious
                );
                println!(
                    "active_assessments: high={} warning={} suspicious={} cleaned={}",
                    summary.active_assessments.high,
                    summary.active_assessments.warning,
                    summary.active_assessments.suspicious,
                    summary.active_assessments.cleaned
                );
                if let Some(latency) = &summary.bundle_latency_seconds {
                    println!(
                        "bundle_latency_seconds: avg={:.2} p50={:.2} p95={:.2} max={:.2} samples={}",
                        latency.average, latency.p50, latency.p95, latency.max, latency.samples
                    );
                }
                for entry in summary.capture_failure_categories.iter().take(10) {
                    println!("capture_failure_category: {} {}", entry.count, entry.name);
                }
                for entry in summary.capture_failure_reasons.iter().take(10) {
                    println!("capture_failure_reason: {} {}", entry.count, entry.name);
                }
                for finding in summary.suspicious_examples.iter().take(10) {
                    println!(
                        "signal: {} {} {} {} {}",
                        finding.severity,
                        finding.event_id,
                        finding.package,
                        finding.version,
                        finding.reason
                    );
                }
                for finding in summary.cleaned_examples.iter().take(10) {
                    if let Some(cleaned_at) = finding.cleaned_at {
                        println!(
                            "cleaned_signal: {} {} {} {} cleaned_at={} cleaned_by={}",
                            finding.severity,
                            finding.event_id,
                            finding.package,
                            finding.version,
                            cleaned_at.to_rfc3339(),
                            finding.cleaned_by_version.as_deref().unwrap_or("unknown")
                        );
                    }
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
        HistoryCommand::RetryCaptures { workers, json } => {
            let summary = run_retry_captures(&args.data_dir, workers).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("data_dir: {}", summary.data_dir);
                println!("workers: {}", summary.workers);
                println!(
                    "captures_ready: {} -> {}",
                    summary.captures_ready_before, summary.captures_ready_after
                );
                println!(
                    "captures_failed: {} -> {}",
                    summary.captures_failed_before, summary.captures_failed_after
                );
            }
            Ok(())
        }
        HistoryCommand::RetrySkippedCaptures {
            ecosystem,
            package,
            since_hours,
            limit,
            workers,
            json,
        } => {
            let summary = run_retry_skipped_captures(
                &args.data_dir,
                ecosystem,
                package.as_deref(),
                since_hours,
                limit,
                workers,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("data_dir: {}", summary.data_dir);
                println!("workers: {}", summary.workers);
                println!("ecosystem: {}", summary.ecosystem.unwrap_or(Ecosystem::Npm));
                if let Some(package) = &summary.package {
                    println!("package: {package}");
                }
                println!(
                    "window: {} -> {} ({}h)",
                    summary.since, summary.until, summary.hours
                );
                println!("skipped_candidates: {}", summary.skipped_candidates);
                println!("captures_ready_before: {}", summary.captures_ready_before);
                println!("captures_ready_after: {}", summary.captures_ready_after);
                println!("diffs_ready_before: {}", summary.diffs_ready_before);
                println!("diffs_ready_after: {}", summary.diffs_ready_after);
                println!(
                    "captures_promoted: {}",
                    summary
                        .captures_ready_after
                        .saturating_sub(summary.captures_ready_before)
                );
                println!(
                    "diffs_promoted: {}",
                    summary
                        .diffs_ready_after
                        .saturating_sub(summary.diffs_ready_before)
                );
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
        HistoryCommand::RepairBundles {
            ecosystem,
            since_hours,
            limit,
            json,
        } => {
            let summary = run_repair_bundles(&args.data_dir, ecosystem, since_hours, limit).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("data_dir: {}", summary.data_dir);
                println!(
                    "window: {} -> {} ({}h)",
                    summary.since, summary.until, summary.hours
                );
                println!("events_scanned: {}", summary.events_scanned);
                println!("captures_ready: {}", summary.captures_ready);
                println!("bundles_written: {}", summary.bundles_written);
                println!("missing_captures: {}", summary.missing_captures);
                println!("missing_diffs: {}", summary.missing_diffs);
            }
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
        HistoryCommand::DetectionEval { manifest, json } => {
            let report = detection::evaluate_detection_corpus(&manifest).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("manifest: {}", report.manifest_path);
                println!(
                    "fixtures: total={} passed={} failed={}",
                    report.fixtures_total, report.fixtures_passed, report.fixtures_failed
                );
                for fixture in report
                    .fixture_results
                    .iter()
                    .filter(|fixture| !fixture.failures.is_empty())
                {
                    println!(
                        "fixture_failed: {} {}@{} verdict={} severity={} failures={}",
                        fixture.id,
                        fixture.package,
                        fixture.version,
                        fixture.actual_verdict_class.as_str(),
                        fixture.actual_severity.as_str(),
                        fixture.failures.join("; ")
                    );
                }
                for stat in report
                    .rule_stats
                    .iter()
                    .filter(|stat| stat.missing_hits > 0 || stat.unexpected_hits > 0)
                {
                    println!(
                        "rule_stat: {} expected={} actual={} missing={} unexpected={}",
                        stat.rule_id,
                        stat.expected_hits,
                        stat.actual_hits,
                        stat.missing_hits,
                        stat.unexpected_hits
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
                    repo_provenance::RepositoryMatchKind::Commit => "commit",
                    repo_provenance::RepositoryMatchKind::None => "none",
                    repo_provenance::RepositoryMatchKind::Unknown => "unknown",
                },
                repository
                    .matched_ref
                    .as_ref()
                    .map(|value| format!(" ({value})"))
                    .or_else(|| {
                        repository
                            .matched_commit
                            .as_ref()
                            .map(|value| format!(" ({value})"))
                    })
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
struct RepairBundlesSummary {
    data_dir: String,
    ecosystem: Option<Ecosystem>,
    since: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
    hours: u64,
    limit: Option<usize>,
    events_scanned: usize,
    captures_ready: usize,
    bundles_written: usize,
    missing_captures: usize,
    missing_diffs: usize,
}

#[derive(Debug, Serialize)]
struct RetryCapturesSummary {
    data_dir: String,
    workers: usize,
    captures_ready_before: usize,
    captures_failed_before: usize,
    captures_ready_after: usize,
    captures_failed_after: usize,
}

#[derive(Debug, Serialize)]
struct RetrySkippedCapturesSummary {
    data_dir: String,
    ecosystem: Option<Ecosystem>,
    package: Option<String>,
    since: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
    hours: u64,
    workers: usize,
    skipped_candidates: usize,
    captures_ready_before: usize,
    diffs_ready_before: usize,
    captures_ready_after: usize,
    diffs_ready_after: usize,
}

#[derive(Debug, Serialize)]
struct HistoryReportSummary {
    generated_at: chrono::DateTime<chrono::Utc>,
    data_dir: String,
    ecosystem: Option<Ecosystem>,
    since: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
    hours: u64,
    limit: Option<usize>,
    truncated: bool,
    events_scanned: usize,
    unique_packages: usize,
    observed_releases_per_hour: f64,
    origin_counts: BTreeMap<String, usize>,
    observed_resolution: ReportResolutionSummary,
    observed_only_resolution: ReportResolutionSummary,
    current_knowledge: ReportCurrentKnowledgeSummary,
    priority_sources: BTreeMap<String, usize>,
    priority_tiers: BTreeMap<String, usize>,
    capture_states: store::JobStateCounts,
    diff_states: store::JobStateCounts,
    bundles: ReportBundleCoverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_latency_seconds: Option<LatencySummary>,
    assessments: ReportAssessmentCounts,
    active_assessments: ReportFlaggedAssessmentCounts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ecosystems: Vec<HistoryReportEcosystemSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capture_failure_categories: Vec<CountEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capture_failure_reasons: Vec<CountEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    suspicious_examples: Vec<ReportAssessmentFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cleaned_examples: Vec<ReportAssessmentFinding>,
}

#[derive(Debug, Default, Serialize)]
struct ReportResolutionSummary {
    graph_scored_or_census: usize,
    graph_scored_or_census_rate: f64,
    runtime_stub: usize,
    runtime_stub_rate: f64,
    external: usize,
    external_rate: f64,
    unknown: usize,
    unknown_rate: f64,
}

#[derive(Debug, Default, Serialize)]
struct ReportCurrentKnowledgeSummary {
    missing_current_census: usize,
    missing_current_census_rate: f64,
    stub_missing_current_census: usize,
    stub_missing_current_census_rate: f64,
}

#[derive(Debug, Default, Serialize)]
struct ReportBundleCoverage {
    captures_ready: usize,
    bundles_present: usize,
    bundles_missing: usize,
}

#[derive(Debug, Default, Serialize)]
struct ReportAssessmentCounts {
    high: usize,
    warning: usize,
    informational: usize,
    suspicious: usize,
}

#[derive(Debug, Default, Serialize)]
struct ReportFlaggedAssessmentCounts {
    high: usize,
    warning: usize,
    suspicious: usize,
    cleaned: usize,
}

#[derive(Debug, Clone, Serialize)]
struct HistoryReportEcosystemSummary {
    ecosystem: Ecosystem,
    events: usize,
    unique_packages: usize,
    priority_sources: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
struct CountEntry {
    name: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ReportAssessmentFinding {
    event_id: String,
    ecosystem: Ecosystem,
    package: String,
    version: String,
    severity: String,
    suspicious: bool,
    reason: String,
    bundle_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleaned_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleaned_by_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleaned_by_version: Option<String>,
}

#[derive(Debug, Clone)]
struct ReportAssessmentCandidate {
    finding: ReportAssessmentFinding,
    observed_at: chrono::DateTime<chrono::Utc>,
    flagged: bool,
}

#[derive(Debug, Clone, Serialize)]
struct LatencySummary {
    samples: usize,
    average: f64,
    p50: f64,
    p95: f64,
    max: f64,
}

#[derive(Debug, Deserialize)]
struct ReportBundleSnapshot {
    generated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    capture: Option<ReportBundleCaptureSnapshot>,
    #[serde(default)]
    diff: Option<ReportBundleDiffSnapshot>,
    #[serde(default)]
    release_assessment: Option<ReportBundleAssessmentSnapshot>,
}

#[derive(Debug, Deserialize)]
struct ReportBundleCaptureSnapshot {
    captured_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct ReportBundleDiffSnapshot {
    #[serde(default)]
    generated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
struct ReportBundleAssessmentSnapshot {
    severity: String,
    suspicious: bool,
    reason: String,
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
    npm_install_hook: Option<AssessmentNpmInstallHookRecord>,
    #[serde(default)]
    files_added: Vec<String>,
    #[serde(default)]
    files_removed: Vec<String>,
    #[serde(default)]
    files_changed: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AssessmentNpmInstallHookRecord {
    target_has_install_scripts: bool,
    longstanding_unchanged: bool,
    effective_changed: bool,
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
            target_has_install_scripts: stored_diff
                .diff
                .as_ref()
                .and_then(|diff| diff.content.npm_install_hook.as_ref())
                .map(|hook| hook.target_has_install_scripts),
            install_scripts_longstanding: stored_diff
                .diff
                .as_ref()
                .and_then(|diff| diff.content.npm_install_hook.as_ref())
                .map(|hook| hook.longstanding_unchanged),
            install_hook_changed: stored_diff
                .diff
                .as_ref()
                .and_then(|diff| diff.content.npm_install_hook.as_ref())
                .map(|hook| hook.effective_changed),
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
                verdict_class: assessment.verdict_class,
                priority_tier: event.priority_snapshot().tier,
                graph: assessment.graph,
                factors: assessment.factors,
                behavior_tags: assessment.behavior_tags,
                matched_rules: assessment.matched_rules,
                matched_evidence: assessment.matched_evidence,
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

async fn run_repair_bundles(
    data_dir: &Path,
    ecosystem: Option<Ecosystem>,
    since_hours: u64,
    limit: Option<usize>,
) -> Result<RepairBundlesSummary> {
    let store = store::OperationalStore::open(store::index_db_path(data_dir)).await?;
    if store.event_count().await? == 0 {
        store.reconcile_local_data(data_dir).await?;
    }

    let until = chrono::Utc::now();
    let since = until - chrono::Duration::hours(i64::try_from(since_hours)?);
    let records = store
        .load_release_records_since(ecosystem, since, limit)
        .await?;

    let mut summary = RepairBundlesSummary {
        data_dir: data_dir.display().to_string(),
        ecosystem,
        since,
        until,
        hours: since_hours,
        limit,
        events_scanned: records.len(),
        captures_ready: 0,
        bundles_written: 0,
        missing_captures: 0,
        missing_diffs: 0,
    };

    for record in records {
        if record.capture_state != "ready" {
            continue;
        }
        summary.captures_ready += 1;
        let capture_dir = history::capture_dir_for_event(data_dir, &record.event);
        let capture =
            read_json_if_exists::<CapturedRelease>(&capture_dir.join("capture.json")).await?;
        let diff = read_json_if_exists::<serde_json::Value>(&capture_dir.join("diff.json")).await?;
        if capture.is_none() {
            summary.missing_captures += 1;
            continue;
        }
        if diff.is_none() {
            summary.missing_diffs += 1;
        }
        bundle::write_release_bundle(
            data_dir,
            &store,
            &record.event,
            capture.as_ref(),
            diff.as_ref(),
        )
        .await?;
        summary.bundles_written += 1;
    }

    Ok(summary)
}

async fn run_retry_captures(data_dir: &Path, workers: usize) -> Result<RetryCapturesSummary> {
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
    let before = store.stats().await?;
    let failed_records = store.load_failed_capture_records(None).await?;
    if failed_records.is_empty() {
        return Ok(RetryCapturesSummary {
            data_dir: data_dir.display().to_string(),
            workers: workers.max(1),
            captures_ready_before: before.capture_states.ready,
            captures_failed_before: before.capture_states.failed,
            captures_ready_after: before.capture_states.ready,
            captures_failed_after: before.capture_states.failed,
        });
    }
    let priority = PriorityResolver::load(&PriorityConfig {
        score_file: data_dir.join("priority-scores.ndjson"),
        graph_file: data_dir.join("graph-input.ndjson"),
        census_file: data_dir.join("package-census.ndjson"),
        graph_store_file: Some(store::index_db_path(data_dir)),
        online_fallback: false,
        online_expand_unknown: false,
        online_expand_min_observations: 2,
        online_request_timeout: Duration::from_secs(3),
        deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
        deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
        expand_focus: supply_stream_core::deps_dev::FocusDependentsConfig {
            reverse_depth: 2,
            max_frontier_packages: 1000,
            include_non_highest_dependent_releases: false,
            default_direct_popularity: 1.0,
            direct_popularity_strategy:
                supply_stream_core::deps_dev::DirectPopularityStrategy::DirectDependentCount,
        },
        expand_collect: supply_stream_core::collector::CollectConfig {
            max_depth: 1,
            max_packages: 512,
            request_concurrency: 16,
            allow_external_fallback: true,
        },
        expand_score_build: supply_stream_core::scoring::ScoreBuildConfig {
            alpha: 0.85,
            max_iterations: 64,
            epsilon: 1e-6,
            high_quantile: 0.99,
            medium_quantile: 0.90,
            score_source_version: Some("runtime_expand_v1".to_string()),
        },
    })
    .await?;

    let queue_capacity = failed_records.len().clamp(1, 1024);
    let (tx, rx) = mpsc::channel::<CaptureRequest>(queue_capacity);
    let perf = RuntimeStats::default();
    let worker = CaptureWorker::new(
        http,
        CaptureConfig {
            queue_capacity: 1,
            worker_concurrency: workers.max(1),
            data_dir: data_dir.to_path_buf(),
            observed_event_log_path: ledger::observed_ledger_path(data_dir),
            capture_dir: data_dir.join("captures"),
            staging_dir: data_dir.join("staging-captures"),
            staging_cache_ttl: Duration::from_secs(60 * 60 * 6),
            staging_cache_max_bytes: 20 * 1024 * 1024 * 1024,
            staging_cache_sweep_interval: Duration::from_secs(300),
            graph_file: data_dir.join("graph-input.ndjson"),
            pypi_provenance: true,
            github_api_base: "https://api.github.com".to_string(),
            gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
            version_burst: VersionBurstConfig::default(),
        },
        rx,
        None,
        Some(priority),
        None,
        store.clone(),
        perf,
    );
    let send_task = tokio::spawn(async move {
        for record in failed_records {
            let origin = parse_event_origin(&record.origin);
            let notify_diff = record.event.diff_requested();
            let request = match origin {
                store::EventOrigin::Observed => CaptureRequest::observed(record.event, notify_diff),
                store::EventOrigin::Reconstructed => {
                    CaptureRequest::reconstructed(record.event, notify_diff)
                }
            };
            if tx.send(request).await.is_err() {
                break;
            }
        }
    });
    worker.run_requests_only().await?;
    send_task
        .await
        .context("retry capture enqueue task failed")?;

    let after = store.stats().await?;
    Ok(RetryCapturesSummary {
        data_dir: data_dir.display().to_string(),
        workers: workers.max(1),
        captures_ready_before: before.capture_states.ready,
        captures_failed_before: before.capture_states.failed,
        captures_ready_after: after.capture_states.ready,
        captures_failed_after: after.capture_states.failed,
    })
}

async fn run_retry_skipped_captures(
    data_dir: &Path,
    ecosystem: Option<Ecosystem>,
    package: Option<&str>,
    since_hours: u64,
    limit: Option<usize>,
    workers: usize,
) -> Result<RetrySkippedCapturesSummary> {
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

    let until = chrono::Utc::now();
    let since = until - chrono::Duration::hours(since_hours as i64);
    let before = store.stats().await?;
    let skipped_records = store
        .load_skipped_capture_records(ecosystem, package, Some(since), limit)
        .await?;

    if skipped_records.is_empty() {
        return Ok(RetrySkippedCapturesSummary {
            data_dir: data_dir.display().to_string(),
            ecosystem,
            package: package.map(str::to_string),
            since,
            until,
            hours: since_hours,
            workers: workers.max(1),
            skipped_candidates: 0,
            captures_ready_before: before.capture_states.ready,
            diffs_ready_before: before.diffs_ready,
            captures_ready_after: before.capture_states.ready,
            diffs_ready_after: before.diffs_ready,
        });
    }

    let priority = PriorityResolver::load(&PriorityConfig {
        score_file: data_dir.join("priority-scores.ndjson"),
        graph_file: data_dir.join("graph-input.ndjson"),
        census_file: data_dir.join("package-census.ndjson"),
        graph_store_file: Some(store::index_db_path(data_dir)),
        online_fallback: false,
        online_expand_unknown: false,
        online_expand_min_observations: 2,
        online_request_timeout: Duration::from_secs(3),
        deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
        deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
        expand_focus: supply_stream_core::deps_dev::FocusDependentsConfig {
            reverse_depth: 2,
            max_frontier_packages: 1000,
            include_non_highest_dependent_releases: false,
            default_direct_popularity: 1.0,
            direct_popularity_strategy:
                supply_stream_core::deps_dev::DirectPopularityStrategy::DirectDependentCount,
        },
        expand_collect: supply_stream_core::collector::CollectConfig {
            max_depth: 1,
            max_packages: 512,
            request_concurrency: 16,
            allow_external_fallback: true,
        },
        expand_score_build: supply_stream_core::scoring::ScoreBuildConfig {
            alpha: 0.85,
            max_iterations: 64,
            epsilon: 1e-6,
            high_quantile: 0.99,
            medium_quantile: 0.90,
            score_source_version: Some("runtime_expand_v1".to_string()),
        },
    })
    .await?;

    let queue_capacity = skipped_records.len().clamp(1, 1024);
    let (tx, rx) = mpsc::channel::<CaptureRequest>(queue_capacity);
    let perf = RuntimeStats::default();
    let worker = CaptureWorker::new(
        http,
        CaptureConfig {
            queue_capacity: 1,
            worker_concurrency: workers.max(1),
            data_dir: data_dir.to_path_buf(),
            observed_event_log_path: ledger::observed_ledger_path(data_dir),
            capture_dir: data_dir.join("captures"),
            staging_dir: data_dir.join("staging-captures"),
            staging_cache_ttl: Duration::from_secs(60 * 60 * 6),
            staging_cache_max_bytes: 20 * 1024 * 1024 * 1024,
            staging_cache_sweep_interval: Duration::from_secs(300),
            graph_file: data_dir.join("graph-input.ndjson"),
            pypi_provenance: true,
            github_api_base: "https://api.github.com".to_string(),
            gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
            version_burst: VersionBurstConfig::default(),
        },
        rx,
        None,
        Some(priority),
        None,
        store.clone(),
        perf,
    );
    let skipped_candidates = skipped_records.len();
    let send_task = tokio::spawn(async move {
        for record in skipped_records {
            let request = match parse_event_origin(&record.origin) {
                store::EventOrigin::Observed => CaptureRequest::observed(record.event, false),
                store::EventOrigin::Reconstructed => {
                    CaptureRequest::reconstructed(record.event, false)
                }
            };
            if tx.send(request).await.is_err() {
                break;
            }
        }
    });
    worker.run_requests_only().await?;
    send_task
        .await
        .context("retry skipped capture enqueue task failed")?;

    let after = store.stats().await?;
    Ok(RetrySkippedCapturesSummary {
        data_dir: data_dir.display().to_string(),
        ecosystem,
        package: package.map(str::to_string),
        since,
        until,
        hours: since_hours,
        workers: workers.max(1),
        skipped_candidates,
        captures_ready_before: before.capture_states.ready,
        diffs_ready_before: before.diffs_ready,
        captures_ready_after: after.capture_states.ready,
        diffs_ready_after: after.diffs_ready,
    })
}

fn parse_event_origin(origin: &str) -> store::EventOrigin {
    match origin {
        "reconstructed" => store::EventOrigin::Reconstructed,
        _ => store::EventOrigin::Observed,
    }
}

async fn run_report(
    data_dir: &Path,
    ecosystem: Option<Ecosystem>,
    since_hours: u64,
    limit: Option<usize>,
) -> Result<HistoryReportSummary> {
    let store = store::OperationalStore::open(store::index_db_path(data_dir)).await?;
    if store.event_count().await? == 0 {
        store.reconcile_local_data(data_dir).await?;
    }

    let until = chrono::Utc::now();
    let since = until - chrono::Duration::hours(i64::try_from(since_hours)?);
    let records = store
        .load_release_records_since(ecosystem, since, limit)
        .await?;
    let current_census =
        priority::load_package_census_records(&data_dir.join("package-census.ndjson"))
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|record| (record.ecosystem, record.package))
            .collect::<BTreeSet<_>>();

    let mut unique_packages = BTreeSet::<(Ecosystem, String)>::new();
    let mut origin_counts = BTreeMap::<String, usize>::new();
    let mut priority_sources = BTreeMap::<String, usize>::new();
    let mut priority_tiers = BTreeMap::<String, usize>::new();
    let mut capture_failure_reasons = BTreeMap::<String, usize>::new();
    let mut capture_failure_categories = BTreeMap::<String, usize>::new();
    let mut ecosystem_rollups =
        BTreeMap::<Ecosystem, (usize, BTreeSet<String>, BTreeMap<String, usize>)>::new();

    let mut capture_states = store::JobStateCounts::default();
    let mut diff_states = store::JobStateCounts::default();
    let mut bundles = ReportBundleCoverage::default();
    let mut assessments = ReportAssessmentCounts::default();
    let mut latency_samples = Vec::<f64>::new();
    let mut assessment_candidates = Vec::<ReportAssessmentCandidate>::new();

    let mut graph_scored_or_census = 0usize;
    let mut runtime_stub = 0usize;
    let mut external = 0usize;
    let mut unknown = 0usize;
    let mut observed_only_graph_scored_or_census = 0usize;
    let mut observed_only_runtime_stub = 0usize;
    let mut observed_only_external = 0usize;
    let mut observed_only_unknown = 0usize;
    let mut missing_current_census = 0usize;
    let mut stub_missing_current_census = 0usize;

    for record in &records {
        let event = &record.event;
        *origin_counts.entry(record.origin.clone()).or_default() += 1;
        unique_packages.insert((event.ecosystem, event.package.clone()));
        let source = event.priority_snapshot().source.as_str().to_string();
        let tier = event.priority_snapshot().tier.as_str().to_string();
        *priority_sources.entry(source.clone()).or_default() += 1;
        *priority_tiers.entry(tier).or_default() += 1;

        let ecosystem_entry = ecosystem_rollups
            .entry(event.ecosystem)
            .or_insert_with(|| (0, BTreeSet::new(), BTreeMap::new()));
        ecosystem_entry.0 += 1;
        ecosystem_entry.1.insert(event.package.clone());
        *ecosystem_entry.2.entry(source.clone()).or_default() += 1;

        match event.priority_snapshot().source {
            supply_stream_core::priority::PrioritySource::OfflineScoreFile
            | supply_stream_core::priority::PrioritySource::LocalGraph
            | supply_stream_core::priority::PrioritySource::PackageCensus => {
                graph_scored_or_census += 1;
                if record.origin == "observed" {
                    observed_only_graph_scored_or_census += 1;
                }
            }
            supply_stream_core::priority::PrioritySource::KnownPackageStub => {
                runtime_stub += 1;
                if record.origin == "observed" {
                    observed_only_runtime_stub += 1;
                }
            }
            supply_stream_core::priority::PrioritySource::DepsDevDependentsApi
            | supply_stream_core::priority::PrioritySource::EcosysteMsCountsApi => {
                external += 1;
                if record.origin == "observed" {
                    observed_only_external += 1;
                }
            }
            supply_stream_core::priority::PrioritySource::DefaultUnknown => {
                unknown += 1;
                if record.origin == "observed" {
                    observed_only_unknown += 1;
                }
            }
        }
        if !current_census.contains(&(event.ecosystem, event.package.clone())) {
            missing_current_census += 1;
            if matches!(
                event.priority_snapshot().source,
                supply_stream_core::priority::PrioritySource::KnownPackageStub
            ) {
                stub_missing_current_census += 1;
            }
        }

        match record.capture_state.as_str() {
            "pending" => capture_states.pending += 1,
            "ready" => capture_states.ready += 1,
            "skipped" => capture_states.skipped += 1,
            "failed" => {
                capture_states.failed += 1;
                let reason = record
                    .capture_reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                let category = categorize_capture_failure_reason(&reason);
                *capture_failure_reasons.entry(reason).or_default() += 1;
                *capture_failure_categories.entry(category).or_default() += 1;
            }
            _ => {}
        }

        match record.diff_state.as_str() {
            "pending" => diff_states.pending += 1,
            "ready" => diff_states.ready += 1,
            "skipped" => diff_states.skipped += 1,
            "failed" => diff_states.failed += 1,
            _ => {}
        }

        if record.capture_state == "ready" {
            bundles.captures_ready += 1;
            let bundle_path = bundle::bundle_path_for_event(data_dir, event);
            if let Some(bundle) = read_json_if_exists::<ReportBundleSnapshot>(&bundle_path).await? {
                bundles.bundles_present += 1;
                let evidence_ready_at = bundle
                    .diff
                    .as_ref()
                    .and_then(|diff| diff.generated_at)
                    .or_else(|| bundle.capture.as_ref().map(|capture| capture.captured_at))
                    .unwrap_or(bundle.generated_at);
                let latency =
                    (evidence_ready_at - event.observed_at).num_milliseconds() as f64 / 1000.0;
                if latency >= 0.0 {
                    latency_samples.push(latency);
                }
                if let Some(assessment) = bundle.release_assessment {
                    match assessment.severity.as_str() {
                        "high" => assessments.high += 1,
                        "warning" => assessments.warning += 1,
                        _ => assessments.informational += 1,
                    }
                    if assessment.suspicious {
                        assessments.suspicious += 1;
                    }
                    let flagged = assessment.suspicious || assessment.severity != "informational";
                    assessment_candidates.push(ReportAssessmentCandidate {
                        observed_at: event.observed_at,
                        flagged,
                        finding: ReportAssessmentFinding {
                            event_id: event.event_id.clone(),
                            ecosystem: event.ecosystem,
                            package: event.package.clone(),
                            version: event.version.clone(),
                            severity: assessment.severity,
                            suspicious: assessment.suspicious,
                            reason: assessment.reason,
                            bundle_path: bundle_path.display().to_string(),
                            cleaned_at: None,
                            cleaned_by_event_id: None,
                            cleaned_by_version: None,
                        },
                    });
                }
            } else {
                bundles.bundles_missing += 1;
            }
        }
    }

    let events_scanned = records.len();
    let observed_releases_per_hour = if since_hours == 0 {
        0.0
    } else {
        events_scanned as f64 / since_hours as f64
    };
    let total = events_scanned as f64;
    let observed_total = origin_counts.get("observed").copied().unwrap_or(0) as f64;
    let observed_resolution = ReportResolutionSummary {
        graph_scored_or_census,
        graph_scored_or_census_rate: rate(graph_scored_or_census, total),
        runtime_stub,
        runtime_stub_rate: rate(runtime_stub, total),
        external,
        external_rate: rate(external, total),
        unknown,
        unknown_rate: rate(unknown, total),
    };
    let observed_only_resolution = ReportResolutionSummary {
        graph_scored_or_census: observed_only_graph_scored_or_census,
        graph_scored_or_census_rate: rate(observed_only_graph_scored_or_census, observed_total),
        runtime_stub: observed_only_runtime_stub,
        runtime_stub_rate: rate(observed_only_runtime_stub, observed_total),
        external: observed_only_external,
        external_rate: rate(observed_only_external, observed_total),
        unknown: observed_only_unknown,
        unknown_rate: rate(observed_only_unknown, observed_total),
    };
    let current_knowledge = ReportCurrentKnowledgeSummary {
        missing_current_census,
        missing_current_census_rate: rate(missing_current_census, total),
        stub_missing_current_census,
        stub_missing_current_census_rate: rate(stub_missing_current_census, total),
    };

    let bundle_latency_seconds = summarize_latencies(&mut latency_samples);

    let ecosystems = ecosystem_rollups
        .into_iter()
        .map(
            |(ecosystem, (events, packages, sources))| HistoryReportEcosystemSummary {
                ecosystem,
                events,
                unique_packages: packages.len(),
                priority_sources: sources,
            },
        )
        .collect::<Vec<_>>();

    let mut capture_failure_reasons = capture_failure_reasons
        .into_iter()
        .map(|(name, count)| CountEntry { name, count })
        .collect::<Vec<_>>();
    capture_failure_reasons.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    capture_failure_reasons.truncate(25);

    let mut capture_failure_categories = capture_failure_categories
        .into_iter()
        .map(|(name, count)| CountEntry { name, count })
        .collect::<Vec<_>>();
    capture_failure_categories.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });

    let (mut suspicious_examples, mut cleaned_examples, active_assessments) =
        partition_active_and_cleaned_findings(assessment_candidates);
    suspicious_examples.truncate(10);
    cleaned_examples.truncate(10);

    Ok(HistoryReportSummary {
        generated_at: until,
        data_dir: data_dir.display().to_string(),
        ecosystem,
        since,
        until,
        hours: since_hours,
        limit,
        truncated: limit.is_some_and(|value| events_scanned >= value),
        events_scanned,
        unique_packages: unique_packages.len(),
        observed_releases_per_hour,
        origin_counts,
        observed_resolution,
        observed_only_resolution,
        current_knowledge,
        priority_sources,
        priority_tiers,
        capture_states,
        diff_states,
        bundles,
        bundle_latency_seconds,
        assessments,
        active_assessments,
        ecosystems,
        capture_failure_categories,
        capture_failure_reasons,
        suspicious_examples,
        cleaned_examples,
    })
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

fn rate(count: usize, total: f64) -> f64 {
    if total <= 0.0 {
        0.0
    } else {
        count as f64 / total
    }
}

fn partition_active_and_cleaned_findings(
    mut candidates: Vec<ReportAssessmentCandidate>,
) -> (
    Vec<ReportAssessmentFinding>,
    Vec<ReportAssessmentFinding>,
    ReportFlaggedAssessmentCounts,
) {
    candidates.sort_by(|left, right| {
        left.observed_at
            .cmp(&right.observed_at)
            .then_with(|| left.finding.event_id.cmp(&right.finding.event_id))
    });

    let mut active_by_package =
        BTreeMap::<(Ecosystem, String), Vec<ReportAssessmentCandidate>>::new();
    let mut cleaned = Vec::<ReportAssessmentFinding>::new();

    for candidate in candidates {
        let key = (
            candidate.finding.ecosystem,
            candidate.finding.package.clone(),
        );
        if candidate.flagged {
            active_by_package.entry(key).or_default().push(candidate);
            continue;
        }

        let Some(active_candidates) = active_by_package.get_mut(&key) else {
            continue;
        };
        if active_candidates.is_empty() {
            continue;
        }

        let cleaned_at = candidate.observed_at;
        let cleaned_by_event_id = candidate.finding.event_id.clone();
        let cleaned_by_version = candidate.finding.version.clone();
        for mut active in active_candidates.drain(..) {
            active.finding.cleaned_at = Some(cleaned_at);
            active.finding.cleaned_by_event_id = Some(cleaned_by_event_id.clone());
            active.finding.cleaned_by_version = Some(cleaned_by_version.clone());
            cleaned.push(active.finding);
        }
    }

    let mut active = active_by_package
        .into_values()
        .flatten()
        .collect::<Vec<_>>();
    active.sort_by(|left, right| {
        severity_rank(&right.finding.severity)
            .cmp(&severity_rank(&left.finding.severity))
            .then_with(|| right.observed_at.cmp(&left.observed_at))
            .then_with(|| right.finding.event_id.cmp(&left.finding.event_id))
    });

    cleaned.sort_by(|left, right| {
        right
            .cleaned_at
            .cmp(&left.cleaned_at)
            .then_with(|| severity_rank(&right.severity).cmp(&severity_rank(&left.severity)))
            .then_with(|| right.event_id.cmp(&left.event_id))
    });

    let mut counts = ReportFlaggedAssessmentCounts::default();
    for candidate in &active {
        match candidate.finding.severity.as_str() {
            "high" => counts.high += 1,
            "warning" => counts.warning += 1,
            _ => {}
        }
        if candidate.finding.suspicious {
            counts.suspicious += 1;
        }
    }
    counts.cleaned = cleaned.len();

    (
        active
            .into_iter()
            .map(|candidate| candidate.finding)
            .collect(),
        cleaned,
        counts,
    )
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "warning" => 2,
        _ => 1,
    }
}

fn categorize_capture_failure_reason(reason: &str) -> String {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("failed to decode npm metadata") {
        "npm_decode_metadata".to_string()
    } else if lower.contains("failed to fetch npm metadata") {
        "npm_fetch_metadata".to_string()
    } else if lower.contains("failed to read npm metadata response body") {
        "npm_read_metadata_body".to_string()
    } else if lower.contains("failed to fetch pypi metadata") {
        "pypi_fetch_metadata".to_string()
    } else if lower.contains("failed to decode pypi metadata") {
        "pypi_decode_metadata".to_string()
    } else if lower.contains("failed to read pypi metadata response body") {
        "pypi_read_metadata_body".to_string()
    } else if lower.contains("crates.io") || lower.contains("crates index") {
        "crates_io_metadata".to_string()
    } else {
        "other".to_string()
    }
}

fn summarize_latencies(samples: &mut [f64]) -> Option<LatencySummary> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_by(|left, right| left.total_cmp(right));
    let sum = samples.iter().sum::<f64>();
    let p50_index = ((samples.len() - 1) as f64 * 0.50).round() as usize;
    let p95_index = ((samples.len() - 1) as f64 * 0.95).round() as usize;
    Some(LatencySummary {
        samples: samples.len(),
        average: sum / samples.len() as f64,
        p50: samples[p50_index],
        p95: samples[p95_index],
        max: *samples.last().unwrap_or(&0.0),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn candidate(
        event_id: &str,
        package: &str,
        version: &str,
        severity: &str,
        suspicious: bool,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> ReportAssessmentCandidate {
        ReportAssessmentCandidate {
            observed_at,
            flagged: suspicious || severity != "informational",
            finding: ReportAssessmentFinding {
                event_id: event_id.to_string(),
                ecosystem: Ecosystem::Npm,
                package: package.to_string(),
                version: version.to_string(),
                severity: severity.to_string(),
                suspicious,
                reason: "test".to_string(),
                bundle_path: "/tmp/bundle.json".to_string(),
                cleaned_at: None,
                cleaned_by_event_id: None,
                cleaned_by_version: None,
            },
        }
    }

    #[test]
    fn later_clean_release_removes_package_from_active_findings() {
        let start = chrono::Utc
            .with_ymd_and_hms(2026, 3, 31, 10, 0, 0)
            .single()
            .expect("valid datetime");
        let (active, cleaned, counts) = partition_active_and_cleaned_findings(vec![
            candidate("evt-1", "pkg", "1.0.0", "high", true, start),
            candidate(
                "evt-2",
                "pkg",
                "1.0.1",
                "informational",
                false,
                start + chrono::Duration::minutes(5),
            ),
        ]);

        assert!(active.is_empty());
        assert_eq!(cleaned.len(), 1);
        assert_eq!(cleaned[0].event_id, "evt-1");
        assert_eq!(cleaned[0].cleaned_by_event_id.as_deref(), Some("evt-2"));
        assert_eq!(cleaned[0].cleaned_by_version.as_deref(), Some("1.0.1"));
        assert_eq!(
            cleaned[0].cleaned_at,
            Some(start + chrono::Duration::minutes(5))
        );
        assert_eq!(counts.high, 0);
        assert_eq!(counts.warning, 0);
        assert_eq!(counts.suspicious, 0);
        assert_eq!(counts.cleaned, 1);
    }

    #[test]
    fn later_flagged_release_does_not_mark_package_as_cleaned() {
        let start = chrono::Utc
            .with_ymd_and_hms(2026, 3, 31, 10, 0, 0)
            .single()
            .expect("valid datetime");
        let (active, cleaned, counts) = partition_active_and_cleaned_findings(vec![
            candidate("evt-1", "pkg", "1.0.0", "warning", false, start),
            candidate(
                "evt-2",
                "pkg",
                "1.0.1",
                "high",
                true,
                start + chrono::Duration::minutes(5),
            ),
        ]);

        assert_eq!(active.len(), 2);
        assert!(cleaned.is_empty());
        assert_eq!(counts.high, 1);
        assert_eq!(counts.warning, 1);
        assert_eq!(counts.suspicious, 1);
        assert_eq!(counts.cleaned, 0);
    }
}
