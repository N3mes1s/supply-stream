use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{sync::mpsc, task::JoinSet, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    assessment::{VersionBurstSignal, evaluate_version_burst},
    bundle,
    config::CaptureConfig,
    content_risk::{captured_content_risk, scan_captured_release},
    event::{
        Ecosystem, EmittedPrioritySignal, EmittedRepositorySignal, PackageReleaseEvent,
        RepositorySignalSeverity,
    },
    history,
    install_scripts::{has_npm_install_script, npm_install_scripts_benign},
    ledger,
    perf::RuntimeStats,
    priority::{PriorityResolver, PrioritySource, PriorityUpdate, normalize_package_name},
    repo_provenance::{self, PackageRepositoryIdentity, RepositoryReleaseProvenance},
    scoring::ScoreInputRecord,
    sink::EventSink,
    store::{EventOrigin, OperationalStore},
};

const PYPI_INTEGRITY_ACCEPT: &str = "application/vnd.pypi.integrity.v1+json";
const METADATA_FETCH_MAX_ATTEMPTS: usize = 2;
const METADATA_RETRY_DELAY_MS: u64 = 250;
const METADATA_BODY_PREVIEW_BYTES: usize = 256;
static LOCAL_GRAPH_APPEND_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

impl CaptureContext {
    /// Computes the rapid version-burst signal for a freshly captured release
    /// and embeds it in the capture details (the same pattern as
    /// `metadata_risk` / `content_risk`), so every assessment path (live
    /// autodiff, history backfill, evidence bundles) reads it from the
    /// persisted capture without further store queries.
    ///
    /// The candidate release itself is added to the release set: for High
    /// priority it is already recorded in the store by the time post-capture
    /// runs, while ephemeral triaged captures are not, and in both cases the
    /// burst must be measured as of this release.
    async fn compute_version_burst(
        &self,
        event: &PackageReleaseEvent,
        capture: &CapturedRelease,
    ) -> VersionBurstSignal {
        let config = self.config.version_burst;
        let since = chrono::Utc::now() - config.window();
        let mut timestamps = match self
            .store
            .load_package_release_times_since(event.ecosystem, &event.package, since)
            .await
        {
            Ok(times) => times,
            Err(error) => {
                warn!(
                    event_id = event.event_id,
                    error = %error,
                    "failed to load package release times for version-burst evaluation"
                );
                Vec::new()
            }
        };
        let candidate_at = capture
            .published_at
            .unwrap_or(capture.observed_at)
            .max(event.observed_at);
        timestamps.push((capture.version.clone(), candidate_at));
        evaluate_version_burst(&timestamps, &config)
    }
}

#[derive(Debug, Clone)]
struct StagingCacheEntry {
    path: PathBuf,
    modified_at: std::time::SystemTime,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct StagingCacheStats {
    entries: usize,
    bytes: u64,
    pruned_dirs: usize,
}

#[derive(Debug)]
struct MetadataFetchError {
    message: String,
    retryable: bool,
}

#[derive(Clone)]
struct CaptureContext {
    http: reqwest::Client,
    config: CaptureConfig,
    diff_tx: Option<mpsc::Sender<crate::autodiff::DiffRequest>>,
    priority: Option<PriorityResolver>,
    sink: Option<std::sync::Arc<dyn EventSink>>,
    store: OperationalStore,
    perf: RuntimeStats,
}

pub struct CaptureWorker {
    context: CaptureContext,
    rx: mpsc::Receiver<CaptureRequest>,
}

#[derive(Debug, Clone)]
struct PostCaptureRequest {
    event: PackageReleaseEvent,
    origin: EventOrigin,
    notify_diff: bool,
    retention: CaptureRetention,
    capture_dir: PathBuf,
    final_capture_dir: PathBuf,
    capture: CapturedRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRetention {
    Permanent,
    Ephemeral,
}

#[derive(Debug, Clone)]
pub struct CaptureRequest {
    pub event: PackageReleaseEvent,
    pub origin: EventOrigin,
    pub notify_diff: bool,
    pub retention: CaptureRetention,
    pub enqueued_at: Instant,
}

impl CaptureRequest {
    pub fn observed(event: PackageReleaseEvent, notify_diff: bool) -> Self {
        Self {
            event,
            origin: EventOrigin::Observed,
            notify_diff,
            retention: CaptureRetention::Permanent,
            enqueued_at: Instant::now(),
        }
    }

    pub fn triaged(event: PackageReleaseEvent, notify_diff: bool) -> Self {
        Self {
            event,
            origin: EventOrigin::Observed,
            notify_diff,
            retention: CaptureRetention::Ephemeral,
            enqueued_at: Instant::now(),
        }
    }

    pub fn reconstructed(event: PackageReleaseEvent, notify_diff: bool) -> Self {
        Self {
            event,
            origin: EventOrigin::Reconstructed,
            notify_diff,
            retention: CaptureRetention::Permanent,
            enqueued_at: Instant::now(),
        }
    }
}

impl CaptureWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        http: reqwest::Client,
        config: CaptureConfig,
        rx: mpsc::Receiver<CaptureRequest>,
        diff_tx: Option<mpsc::Sender<crate::autodiff::DiffRequest>>,
        priority: Option<PriorityResolver>,
        sink: Option<std::sync::Arc<dyn EventSink>>,
        store: OperationalStore,
        perf: RuntimeStats,
    ) -> Self {
        Self {
            context: CaptureContext {
                http,
                config,
                diff_tx,
                priority,
                sink,
                store,
                perf,
            },
            rx,
        }
    }

    pub async fn run(self) -> Result<()> {
        self.backfill_from_ledger().await?;
        self.run_requests_only().await
    }

    pub async fn run_requests_only(mut self) -> Result<()> {
        self.run_requests_loop().await;
        Ok(())
    }

    async fn run_requests_loop(&mut self) {
        let mut capture_in_flight = JoinSet::new();
        let mut post_in_flight = JoinSet::new();
        let concurrency = self.context.config.worker_concurrency.max(1);
        let post_concurrency = concurrency;

        while let Some(request) = self.rx.recv().await {
            self.spawn_capture(&mut capture_in_flight, request);
            self.drain_capture_to_limit(
                &mut capture_in_flight,
                &mut post_in_flight,
                concurrency,
                post_concurrency,
                "capture failed",
                "post-capture analysis failed",
            )
            .await;
            self.drain_post_to_limit(
                &mut post_in_flight,
                post_concurrency,
                "post-capture analysis failed",
            )
            .await;
        }

        self.drain_all_captures(
            &mut capture_in_flight,
            &mut post_in_flight,
            post_concurrency,
            "capture failed",
            "post-capture analysis failed",
        )
        .await;
        self.drain_all_posts(&mut post_in_flight, "post-capture analysis failed")
            .await;
    }

    async fn backfill_from_ledger(&self) -> Result<()> {
        let mut observed_events =
            ledger::read_events(&self.context.config.observed_event_log_path).await?;
        observed_events.extend(
            ledger::read_events(&ledger::legacy_ledger_path(&self.context.config.data_dir)).await?,
        );
        let mut seen_event_ids = HashSet::new();
        observed_events.retain(|event| seen_event_ids.insert(event.event_id.clone()));
        let reconstructed_events = ledger::read_events(&ledger::reconstructed_ledger_path(
            &self.context.config.data_dir,
        ))
        .await?;
        if observed_events.is_empty() && reconstructed_events.is_empty() {
            return Ok(());
        }

        let mut pending = 0usize;
        let mut capture_in_flight = JoinSet::new();
        let mut post_in_flight = JoinSet::new();
        let concurrency = self.context.config.worker_concurrency.max(1);
        let post_concurrency = concurrency;
        for event in observed_events {
            if let Some(priority) = &self.context.priority {
                priority.seed_event_snapshot(&event).await;
            }
            if self
                .context
                .store
                .load_release_record(&event.event_id)
                .await?
                .is_some_and(|record| record.capture_state == "skipped")
            {
                self.context.perf.record_capture_skipped();
                self.context.perf.record_diff_skipped();
                continue;
            }
            let capture_dir = self.context.capture_path_for_event(&event);
            if capture_dir.join("capture.json").exists() {
                self.context
                    .index_existing_capture(&event, EventOrigin::Observed, &capture_dir)
                    .await?;
                if event.diff_requested() {
                    self.context.notify_diff_worker(&event, None).await;
                }
                continue;
            }

            if !event.capture_requested() {
                self.context.perf.record_capture_skipped();
                self.context.perf.record_diff_skipped();
                continue;
            }

            pending += 1;
            self.context.perf.record_capture_enqueued();
            let notify_diff = event.diff_requested();
            if !notify_diff {
                self.context.perf.record_diff_skipped();
            }
            self.spawn_capture(
                &mut capture_in_flight,
                CaptureRequest::observed(event, notify_diff),
            );
            self.drain_capture_to_limit(
                &mut capture_in_flight,
                &mut post_in_flight,
                concurrency,
                post_concurrency,
                "ledger backfill capture failed",
                "ledger backfill post-capture analysis failed",
            )
            .await;
            self.drain_post_to_limit(
                &mut post_in_flight,
                post_concurrency,
                "ledger backfill post-capture analysis failed",
            )
            .await;
        }

        for event in reconstructed_events {
            if self
                .context
                .store
                .load_release_record(&event.event_id)
                .await?
                .is_some_and(|record| record.capture_state == "skipped")
            {
                self.context.perf.record_capture_skipped();
                self.context.perf.record_diff_skipped();
                continue;
            }
            let capture_dir = self.context.capture_path_for_event(&event);
            if capture_dir.join("capture.json").exists() {
                self.context
                    .index_existing_capture(&event, EventOrigin::Reconstructed, &capture_dir)
                    .await?;
                continue;
            }

            pending += 1;
            self.context.perf.record_capture_enqueued();
            self.spawn_capture(
                &mut capture_in_flight,
                CaptureRequest::reconstructed(event, false),
            );
            self.drain_capture_to_limit(
                &mut capture_in_flight,
                &mut post_in_flight,
                concurrency,
                post_concurrency,
                "ledger backfill capture failed",
                "ledger backfill post-capture analysis failed",
            )
            .await;
            self.drain_post_to_limit(
                &mut post_in_flight,
                post_concurrency,
                "ledger backfill post-capture analysis failed",
            )
            .await;
        }

        self.drain_all_captures(
            &mut capture_in_flight,
            &mut post_in_flight,
            post_concurrency,
            "ledger backfill capture failed",
            "ledger backfill post-capture analysis failed",
        )
        .await;
        self.drain_all_posts(
            &mut post_in_flight,
            "ledger backfill post-capture analysis failed",
        )
        .await;

        if pending > 0 {
            info!(pending, "replayed uncaptured events from event ledger");
        }

        Ok(())
    }

    fn spawn_capture(
        &self,
        in_flight: &mut JoinSet<(String, Result<Option<PostCaptureRequest>>)>,
        request: CaptureRequest,
    ) {
        let context = self.context.clone();
        in_flight.spawn(async move {
            let event_id = request.event.event_id.clone();
            let result = context.fetch_capture_if_missing(&request).await;
            (event_id, result)
        });
    }

    fn spawn_post_capture(
        &self,
        in_flight: &mut JoinSet<(String, Result<()>)>,
        request: PostCaptureRequest,
    ) {
        let context = self.context.clone();
        in_flight.spawn(async move {
            let event_id = request.event.event_id.clone();
            let result = context.post_process_capture(request).await;
            (event_id, result)
        });
    }

    async fn drain_capture_to_limit(
        &self,
        capture_in_flight: &mut JoinSet<(String, Result<Option<PostCaptureRequest>>)>,
        post_in_flight: &mut JoinSet<(String, Result<()>)>,
        concurrency: usize,
        post_concurrency: usize,
        failure_message: &'static str,
        post_failure_message: &'static str,
    ) {
        while capture_in_flight.len() >= concurrency {
            self.join_next_capture(
                capture_in_flight,
                post_in_flight,
                post_concurrency,
                failure_message,
                post_failure_message,
            )
            .await;
        }
    }

    async fn drain_all_captures(
        &self,
        capture_in_flight: &mut JoinSet<(String, Result<Option<PostCaptureRequest>>)>,
        post_in_flight: &mut JoinSet<(String, Result<()>)>,
        post_concurrency: usize,
        failure_message: &'static str,
        post_failure_message: &'static str,
    ) {
        while !capture_in_flight.is_empty() {
            self.join_next_capture(
                capture_in_flight,
                post_in_flight,
                post_concurrency,
                failure_message,
                post_failure_message,
            )
            .await;
        }
    }

    async fn drain_post_to_limit(
        &self,
        in_flight: &mut JoinSet<(String, Result<()>)>,
        concurrency: usize,
        failure_message: &'static str,
    ) {
        while in_flight.len() >= concurrency {
            self.join_next_post(in_flight, failure_message).await;
        }
    }

    async fn drain_all_posts(
        &self,
        in_flight: &mut JoinSet<(String, Result<()>)>,
        failure_message: &'static str,
    ) {
        while !in_flight.is_empty() {
            self.join_next_post(in_flight, failure_message).await;
        }
    }

    async fn join_next_capture(
        &self,
        capture_in_flight: &mut JoinSet<(String, Result<Option<PostCaptureRequest>>)>,
        post_in_flight: &mut JoinSet<(String, Result<()>)>,
        post_concurrency: usize,
        failure_message: &'static str,
        post_failure_message: &'static str,
    ) {
        let Some(outcome) = capture_in_flight.join_next().await else {
            return;
        };

        match outcome {
            Ok((_, Ok(Some(post_request)))) => {
                self.spawn_post_capture(post_in_flight, post_request);
                self.drain_post_to_limit(post_in_flight, post_concurrency, post_failure_message)
                    .await;
            }
            Ok((_, Ok(None))) => {}
            Ok((event_id, Err(error))) => {
                warn!(event_id, error = %error, "{failure_message}");
            }
            Err(error) => warn!(error = %error, "{failure_message} task join failed"),
        }
    }

    async fn join_next_post(
        &self,
        in_flight: &mut JoinSet<(String, Result<()>)>,
        failure_message: &'static str,
    ) {
        let Some(outcome) = in_flight.join_next().await else {
            return;
        };

        match outcome {
            Ok((_, Ok(()))) => {}
            Ok((event_id, Err(error))) => {
                warn!(event_id, error = %error, "{failure_message}");
            }
            Err(error) => warn!(error = %error, "{failure_message} task join failed"),
        }
    }
}

pub async fn run_staging_cache_sweeper(
    config: CaptureConfig,
    perf: RuntimeStats,
    shutdown: CancellationToken,
) -> Result<()> {
    loop {
        if let Err(error) = prune_staging_cache(&config, &perf).await {
            warn!(
                path = %config.staging_dir.display(),
                error = %error,
                "failed to prune staging cache"
            );
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = sleep(config.staging_cache_sweep_interval) => {}
        }
    }

    Ok(())
}

impl CaptureContext {
    async fn fetch_capture_if_missing(
        &self,
        request: &CaptureRequest,
    ) -> Result<Option<PostCaptureRequest>> {
        let started_at = Instant::now();
        self.perf
            .record_capture_started(request.enqueued_at.elapsed());
        let event = &request.event;
        let origin = request.origin;
        let notify_diff = request.notify_diff;
        let retention = request.retention;
        let final_capture_dir = self.capture_path_for_event(event);
        let capture_dir = self.capture_workspace_path_for_request(event, retention);
        let result: Result<Option<PostCaptureRequest>> = async {
            if final_capture_dir.join("capture.json").exists() {
                self.index_existing_capture(event, origin, &final_capture_dir)
                    .await?;
                if notify_diff {
                    self.notify_diff_worker(event, None).await;
                }
                return Ok(None);
            }

            if matches!(retention, CaptureRetention::Ephemeral) {
                remove_capture_dir(&capture_dir).await;
            }

            tokio::fs::create_dir_all(&capture_dir)
                .await
                .with_context(|| format!("failed to create capture dir {}", capture_dir.display()))?;
            write_json_pretty(&capture_dir.join("event.json"), event).await?;

            let capture = match event.ecosystem {
                Ecosystem::Pypi => self.capture_pypi(event, &capture_dir).await?,
                Ecosystem::Npm => self.capture_npm(event, &capture_dir).await?,
                Ecosystem::CratesIo => self.capture_crates_io(event, &capture_dir).await?,
            };

            write_json_pretty(&capture_dir.join("capture.json"), &capture).await?;
            if matches!(retention, CaptureRetention::Permanent) {
                self.store
                    .record_capture(event, origin, &capture_dir, &capture)
                    .await?;
            }
            debug!(event_id = event.event_id, dir = %capture_dir.display(), "captured release evidence");
            Ok(Some(PostCaptureRequest {
                event: event.clone(),
                origin,
                notify_diff,
                retention,
                capture_dir: capture_dir.clone(),
                final_capture_dir: final_capture_dir.clone(),
                capture,
            }))
        }
        .await;

        let elapsed = started_at.elapsed();
        match &result {
            Ok(_) => self.perf.record_capture_completed(elapsed),
            Err(error) => {
                self.perf.record_capture_failed(elapsed);
                self.write_capture_error_file(&capture_dir, event, error)
                    .await;
                self.store
                    .mark_capture_failed(&request.event.event_id, &error.to_string())
                    .await?;
            }
        }
        result
    }

    async fn post_process_capture(&self, request: PostCaptureRequest) -> Result<()> {
        let event = &request.event;
        let mut capture = request.capture;
        let capture_dir = request.capture_dir;
        let final_capture_dir = request.final_capture_dir;
        let notify_diff = request.notify_diff;
        let origin = request.origin;
        let retention = request.retention;
        let result: Result<()> = async {
            if let Err(error) = materialize_primary_artifact_into_capture_dir(
                &self.http,
                &capture_dir,
                &mut capture,
            )
            .await
            {
                warn!(
                    event_id = event.event_id,
                    error = %error,
                    "failed to persist local artifact for capture; falling back to URL-based scan"
                );
            }
            let scan_started = Instant::now();
            let content_risk = scan_captured_release(&self.http, &capture_dir, &capture).await;
            self.perf.record_content_scan(scan_started.elapsed());
            set_capture_detail(&mut capture.details, "content_risk", &content_risk);
            let version_burst = self.compute_version_burst(event, &capture).await;
            set_capture_detail(&mut capture.details, "version_burst", &version_burst);
            write_json_pretty(&capture_dir.join("capture.json"), &capture).await?;

            let graph_records = graph_records_from_captured_release(&capture);
            self.append_local_graph_records(&graph_records).await?;
            if !graph_records.is_empty() {
                self.store.record_graph_records(&graph_records).await?;
            }
            if let Some(repository) =
                package_repository_identity_from_captured_release(event.ecosystem, &capture)
            {
                self.store
                    .record_package_repository_ref(&repository, Some(&capture.version))
                    .await?;
            }
            if let Some(priority) = &self.priority {
                let updates = priority.record_captured_release(&capture).await;
                self.emit_priority_signal(event, priority, &updates).await;
            }
            let force_diff_reason = if notify_diff {
                None
            } else {
                self.diff_escalation_reason(event, &capture).await?
            };
            let retain_capture = matches!(retention, CaptureRetention::Permanent)
                || should_retain_captured_release(&capture)
                || notify_diff
                || force_diff_reason.is_some()
                || version_burst.suspicious;
            if !retain_capture {
                self.perf.record_staging_cache_discarded();
                self.store
                    .mark_capture_skipped(
                        &event.event_id,
                        "post-analysis dropped low-signal triaged capture",
                    )
                    .await?;
                remove_capture_dir(&capture_dir).await;
                return Ok(());
            }
            let retained_capture_dir = if matches!(retention, CaptureRetention::Ephemeral) {
                promote_capture_dir(&capture_dir, &final_capture_dir).await?;
                self.perf.record_staging_cache_promoted();
                final_capture_dir.clone()
            } else {
                capture_dir.clone()
            };
            self.store
                .record_capture(event, origin, &retained_capture_dir, &capture)
                .await?;
            self.emit_repository_signal(event, &capture).await;
            self.emit_release_bundle(event, Some(&capture), None).await;
            if notify_diff || force_diff_reason.is_some() {
                self.notify_diff_worker(event, force_diff_reason).await;
            }
            Ok(())
        }
        .await;

        if let Err(error) = &result {
            self.write_capture_error_file(&capture_dir, event, error)
                .await;
            self.store
                .mark_capture_failed(&event.event_id, &error.to_string())
                .await?;
        }

        result
    }

    async fn write_capture_error_file(
        &self,
        capture_dir: &Path,
        event: &PackageReleaseEvent,
        error: &anyhow::Error,
    ) {
        let path = capture_dir.join("capture-error.json");
        let payload = json!({
            "event_id": event.event_id,
            "ecosystem": event.ecosystem.as_str(),
            "package": event.package,
            "version": event.version,
            "observed_at": event.observed_at,
            "captured_at": Utc::now(),
            "error": error.to_string(),
        });
        if let Err(write_error) = tokio::fs::write(
            &path,
            serde_json::to_vec_pretty(&payload).unwrap_or_else(|_| b"{}".to_vec()),
        )
        .await
        {
            warn!(event_id = event.event_id, error = %write_error, path = %path.display(), "failed to persist capture error details");
        }
    }

    async fn notify_diff_worker(&self, event: &PackageReleaseEvent, force_reason: Option<String>) {
        let Some(diff_tx) = &self.diff_tx else {
            return;
        };
        let request = match force_reason {
            Some(reason) => crate::autodiff::DiffRequest::forced(event.clone(), reason),
            None => crate::autodiff::DiffRequest::new(event.clone()),
        };
        if let Err(error) = diff_tx.send(request).await {
            warn!(event_id = event.event_id, error = %error, "diff worker channel closed");
        } else {
            self.perf.record_diff_enqueued();
        }
    }

    async fn diff_escalation_reason(
        &self,
        event: &PackageReleaseEvent,
        capture: &CapturedRelease,
    ) -> Result<Option<String>> {
        let prerelease = is_prerelease_version(&event.version);
        let install_time_execution = capture_has_install_time_execution(capture);
        let install_time_execution_longstanding =
            capture_has_longstanding_install_time_execution(capture);
        let install_time_execution_benign = capture_has_benign_install_time_execution(capture);
        let risky_install_time_execution = install_time_execution
            && !install_time_execution_longstanding
            && !install_time_execution_benign;
        let graph = self
            .store
            .load_graph_evidence(event.ecosystem, &event.package)
            .await?;
        let downstream_impact = matches!(
            event.priority_snapshot().tier,
            crate::priority::PriorityTier::Medium | crate::priority::PriorityTier::High
        ) || graph
            .as_ref()
            .is_some_and(|graph| graph.reverse_dependents_seen > 0);
        let metadata_risk = captured_metadata_risk(capture);
        let content_risk = captured_content_risk(capture);

        if metadata_risk.suspicious {
            return Ok(Some(format!(
                "post-capture diff escalation: malware-shaped metadata [{}]",
                metadata_risk.factors.join(", ")
            )));
        }

        if content_risk.suspicious {
            return Ok(Some(format!(
                "post-capture diff escalation: malware-shaped content [{}]",
                content_risk.factors.join(", ")
            )));
        }

        if risky_install_time_execution {
            return Ok(Some(
                "post-capture diff escalation: install-time execution observed".to_string(),
            ));
        }

        if capture
            .upstream_repository
            .as_ref()
            .is_some_and(|repository| repository.suspicious)
            && !prerelease
            && downstream_impact
        {
            return Ok(Some(
                "post-capture diff escalation: stable upstream mismatch on impacted package"
                    .to_string(),
            ));
        }

        let new_dependencies = self
            .new_dependencies_since_previous_capture(event, capture)
            .await?;
        if !new_dependencies.is_empty() && downstream_impact {
            return Ok(Some(format!(
                "post-capture diff escalation: introduced new dependencies [{}]",
                new_dependencies.join(", ")
            )));
        }

        Ok(None)
    }

    async fn new_dependencies_since_previous_capture(
        &self,
        event: &PackageReleaseEvent,
        capture: &CapturedRelease,
    ) -> Result<Vec<String>> {
        let current_dependencies = captured_dependency_names(capture);
        if current_dependencies.is_empty() {
            return Ok(Vec::new());
        }

        let mut entries =
            history::load_package_history(&self.config.data_dir, event.ecosystem, &event.package)
                .await?;
        let mut previous_capture =
            previous_captured_release_from_history(&entries, &event.version).cloned();
        if previous_capture.is_none() {
            let _ = history::backfill_previous_lineage(
                &self.config.data_dir,
                event.ecosystem,
                &event.package,
                &event.version,
            )
            .await?;
            entries = history::load_package_history(
                &self.config.data_dir,
                event.ecosystem,
                &event.package,
            )
            .await?;
            previous_capture =
                previous_captured_release_from_history(&entries, &event.version).cloned();
        }

        if let Some(previous_capture) = previous_capture {
            let previous_dependencies = captured_dependency_names(&previous_capture)
                .into_iter()
                .collect::<HashSet<_>>();
            let mut introduced = current_dependencies
                .into_iter()
                .filter(|dependency| !previous_dependencies.contains(dependency))
                .collect::<Vec<_>>();
            introduced.sort();
            introduced.dedup();
            Ok(introduced)
        } else {
            Ok(Vec::new())
        }
    }

    async fn emit_repository_signal(&self, event: &PackageReleaseEvent, capture: &CapturedRelease) {
        let Some(repository) = capture.upstream_repository.clone() else {
            return;
        };
        let (severity, factors) = repository_signal_assessment(event, capture, &repository);
        if repository.suspicious {
            warn!(
                event_id = event.event_id,
                repository = repository.normalized_repository_url,
                provider = repository.provider.as_str(),
                reason = repository.reason.clone(),
                "repository release parity mismatch detected"
            );
        }
        let Some(sink) = &self.sink else {
            return;
        };
        if let Err(error) = sink
            .publish_repository_signal(&EmittedRepositorySignal::repo_release_parity(
                event, repository, severity, factors,
            ))
            .await
        {
            warn!(event_id = event.event_id, error = %error, "failed to publish repository signal");
        }
    }

    async fn emit_priority_signal(
        &self,
        event: &PackageReleaseEvent,
        priority: &PriorityResolver,
        updates: &[PriorityUpdate],
    ) {
        let package = normalize_package_name(event.ecosystem, &event.package);
        let update = updates
            .iter()
            .find(|update| update.ecosystem == event.ecosystem && update.package == package);
        let previous = event
            .priority
            .clone()
            .or_else(|| update.and_then(|update| update.previous.clone()));
        let current = match update {
            Some(update) => update.current.clone(),
            None => priority.resolve(event.ecosystem, &event.package).await,
        };
        if current.source != PrioritySource::LocalGraph
            || previous
                .as_ref()
                .map(|snapshot| snapshot.source == PrioritySource::LocalGraph)
                .unwrap_or(true)
        {
            return;
        }
        let Some(sink) = &self.sink else {
            return;
        };
        let graph = priority
            .emitted_graph_evidence(event.ecosystem, &event.package)
            .await;
        if let Err(error) = sink
            .publish_priority_signal(&EmittedPrioritySignal::local_graph_promotion(
                event, previous, current, graph,
            ))
            .await
        {
            warn!(event_id = event.event_id, error = %error, "failed to publish priority signal");
        }
    }

    async fn emit_release_bundle(
        &self,
        event: &PackageReleaseEvent,
        capture: Option<&CapturedRelease>,
        diff: Option<&serde_json::Value>,
    ) {
        let Ok(bundle) =
            bundle::write_release_bundle(&self.config.data_dir, &self.store, event, capture, diff)
                .await
        else {
            warn!(
                event_id = event.event_id,
                "failed to write release evidence bundle"
            );
            return;
        };
        let Some(sink) = &self.sink else {
            return;
        };
        if !bundle::should_publish_live_bundle(&bundle) {
            return;
        }
        if let Err(error) = sink.publish_release_bundle(&bundle).await {
            warn!(event_id = event.event_id, error = %error, "failed to publish release bundle");
        }
    }

    fn capture_path_for_event(&self, event: &PackageReleaseEvent) -> PathBuf {
        self.config
            .capture_dir
            .join(event.ecosystem.as_str())
            .join(urlencoding::encode(&event.package).into_owned())
            .join(urlencoding::encode(&event.version).into_owned())
    }

    fn capture_workspace_path_for_request(
        &self,
        event: &PackageReleaseEvent,
        retention: CaptureRetention,
    ) -> PathBuf {
        match retention {
            CaptureRetention::Permanent => self.capture_path_for_event(event),
            CaptureRetention::Ephemeral => self
                .config
                .staging_dir
                .join(urlencoding::encode(&event.event_id).into_owned()),
        }
    }

    async fn index_existing_capture(
        &self,
        event: &PackageReleaseEvent,
        origin: EventOrigin,
        capture_dir: &Path,
    ) -> Result<()> {
        let capture_path = capture_dir.join("capture.json");
        let bytes = tokio::fs::read(&capture_path)
            .await
            .with_context(|| format!("failed to read {}", capture_path.display()))?;
        let capture = serde_json::from_slice::<CapturedRelease>(&bytes)
            .with_context(|| format!("failed to parse {}", capture_path.display()))?;
        self.store
            .record_capture(event, origin, capture_dir, &capture)
            .await
    }

    async fn append_local_graph_records(&self, records: &[ScoreInputRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let _guard = LOCAL_GRAPH_APPEND_LOCK.lock().await;
        if let Some(parent) = self.config.graph_file.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let mut body = String::new();
        for record in records {
            body.push_str(&serde_json::to_string(&record).with_context(|| {
                format!("failed to encode {}", self.config.graph_file.display())
            })?);
            body.push('\n');
        }

        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.graph_file)
            .await
            .with_context(|| format!("failed to open {}", self.config.graph_file.display()))?;
        file.write_all(body.as_bytes())
            .await
            .with_context(|| format!("failed to append {}", self.config.graph_file.display()))
    }

    async fn capture_pypi(
        &self,
        event: &PackageReleaseEvent,
        capture_dir: &Path,
    ) -> Result<CapturedRelease> {
        let metadata_url = event.metadata_url.clone().unwrap_or_else(|| {
            format!(
                "https://pypi.org/pypi/{}/{}/json",
                urlencoding::encode(&event.package),
                urlencoding::encode(&event.version)
            )
        });

        let Some(raw) =
            fetch_json_metadata(&self.http, &metadata_url, "PyPI metadata", &event.event_id)
                .await?
        else {
            return Ok(CapturedRelease::removed(event));
        };

        write_json_pretty(&capture_dir.join("metadata.json"), &raw).await?;

        let mut artifacts = extract_pypi_artifacts(&raw);
        let dependencies = extract_pypi_dependencies(&raw);
        let yanked = raw
            .pointer("/info/yanked")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| {
                artifacts
                    .iter()
                    .any(|artifact| artifact.yanked == Some(true))
            });

        if self.config.pypi_provenance {
            let provenance_dir = capture_dir.join("provenance");
            tokio::fs::create_dir_all(&provenance_dir)
                .await
                .with_context(|| {
                    format!(
                        "failed to create PyPI provenance dir {}",
                        provenance_dir.display()
                    )
                })?;

            for artifact in &mut artifacts {
                let integrity_url = format!(
                    "https://pypi.org/integrity/{}/{}/{}/provenance",
                    urlencoding::encode(&event.package),
                    urlencoding::encode(&event.version),
                    urlencoding::encode(&artifact.filename)
                );
                let provenance = self
                    .http
                    .get(&integrity_url)
                    .header("Accept", PYPI_INTEGRITY_ACCEPT)
                    .send()
                    .await;

                match provenance {
                    Ok(response) if response.status() == StatusCode::OK => {
                        let raw = response.json::<Value>().await.with_context(|| {
                            format!(
                                "failed to decode PyPI provenance for {} {}",
                                event.event_id, artifact.filename
                            )
                        })?;
                        let path = provenance_dir
                            .join(format!("{}.json", urlencoding::encode(&artifact.filename)));
                        write_json_pretty(&path, &raw).await?;
                        artifact.provenance_path = Some(
                            relative_path(capture_dir, &path)
                                .to_string_lossy()
                                .into_owned(),
                        );
                    }
                    Ok(response) if response.status() == StatusCode::NOT_FOUND => {}
                    Ok(response) => {
                        warn!(
                            event_id = event.event_id,
                            filename = artifact.filename,
                            status = %response.status(),
                            "PyPI provenance request returned an unexpected status"
                        );
                    }
                    Err(error) => {
                        warn!(
                            event_id = event.event_id,
                            filename = artifact.filename,
                            error = %error,
                            "PyPI provenance request failed"
                        );
                    }
                }
            }
        }

        let details = json!({
            "last_serial": raw.get("last_serial"),
            "requires_python": raw.pointer("/info/requires_python"),
            "summary": raw.pointer("/info/summary"),
            "home_page": raw.pointer("/info/home_page"),
            "project_urls": raw.pointer("/info/project_urls"),
            "dependencies": dependencies,
            "ownership": raw.pointer("/info/ownership"),
            "yanked": raw.pointer("/info/yanked"),
            "yanked_reason": raw.pointer("/info/yanked_reason")
        });
        let upstream_repository = match repo_provenance::check_release_provenance_with_api_bases(
            &self.http,
            event.ecosystem,
            &event.version,
            &details,
            &self.config.github_api_base,
            &self.config.gitlab_api_base,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    event_id = event.event_id,
                    error = %error,
                    "failed to compute upstream repository provenance"
                );
                None
            }
        };

        Ok(CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc::now(),
            status: if yanked {
                ReleaseStatus::Yanked
            } else {
                ReleaseStatus::Active
            },
            package_url: event.package_url.clone(),
            release_url: event.release_url.clone(),
            metadata_url: Some(metadata_url),
            raw_metadata_path: Some("metadata.json".to_string()),
            artifacts,
            upstream_repository,
            details,
        })
    }

    async fn capture_npm(
        &self,
        event: &PackageReleaseEvent,
        capture_dir: &Path,
    ) -> Result<CapturedRelease> {
        let packument_url = event.metadata_url.clone().unwrap_or_else(|| {
            format!(
                "https://registry.npmjs.org/{}",
                urlencoding::encode(&event.package)
            )
        });
        let version_metadata_url = npm_version_metadata_url(&packument_url, &event.version);
        let Some(version_meta) = fetch_json_metadata(
            &self.http,
            &version_metadata_url,
            "npm metadata",
            &event.event_id,
        )
        .await?
        else {
            return Ok(CapturedRelease::removed(event));
        };

        write_json_pretty(&capture_dir.join("metadata.json"), &version_meta).await?;

        let details = build_npm_capture_details(&event.package, &version_meta);
        let upstream_repository = match repo_provenance::check_release_provenance_with_api_bases(
            &self.http,
            event.ecosystem,
            &event.version,
            &details,
            &self.config.github_api_base,
            &self.config.gitlab_api_base,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    event_id = event.event_id,
                    error = %error,
                    "failed to compute upstream repository provenance"
                );
                None
            }
        };

        Ok(CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: event.package_url.clone(),
            release_url: event.release_url.clone(),
            metadata_url: Some(version_metadata_url),
            raw_metadata_path: Some("metadata.json".to_string()),
            artifacts: extract_npm_artifacts(event, &version_meta),
            upstream_repository,
            details,
        })
    }

    async fn capture_crates_io(
        &self,
        event: &PackageReleaseEvent,
        capture_dir: &Path,
    ) -> Result<CapturedRelease> {
        let metadata_url = event.metadata_url.clone().unwrap_or_else(|| {
            format!(
                "https://crates.io/api/v1/crates/{}",
                urlencoding::encode(&event.package)
            )
        });
        let response = self.http.get(&metadata_url).send().await.with_context(|| {
            format!("failed to fetch crates.io metadata for {}", event.event_id)
        })?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(CapturedRelease::removed(event));
        }

        let response = response.error_for_status().with_context(|| {
            format!(
                "crates.io metadata returned an error for {}",
                event.event_id
            )
        })?;
        let raw = response.json::<Value>().await.with_context(|| {
            format!("failed to decode crates.io metadata for {}", event.event_id)
        })?;

        write_json_pretty(&capture_dir.join("metadata.json"), &raw).await?;
        let dependencies = self
            .fetch_crates_dependencies(&event.package, &event.version)
            .await
            .unwrap_or_default();

        let version_meta = raw
            .get("versions")
            .and_then(Value::as_array)
            .and_then(|versions| {
                versions.iter().find(|version| {
                    version
                        .get("num")
                        .and_then(Value::as_str)
                        .is_some_and(|num| num == event.version)
                })
            })
            .cloned();

        let status = version_meta
            .as_ref()
            .and_then(|version| version.get("yanked").and_then(Value::as_bool))
            .map(|yanked| {
                if yanked {
                    ReleaseStatus::Yanked
                } else {
                    ReleaseStatus::Active
                }
            })
            .unwrap_or(ReleaseStatus::Unknown);

        let details = json!({
            "crate": raw.get("crate"),
            "dependencies": dependencies,
            "version": version_meta,
        });
        let upstream_repository = match repo_provenance::check_release_provenance_with_api_bases(
            &self.http,
            event.ecosystem,
            &event.version,
            &details,
            &self.config.github_api_base,
            &self.config.gitlab_api_base,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    event_id = event.event_id,
                    error = %error,
                    "failed to compute upstream repository provenance"
                );
                None
            }
        };

        Ok(CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc::now(),
            status,
            package_url: event.package_url.clone(),
            release_url: event.release_url.clone(),
            metadata_url: Some(metadata_url),
            raw_metadata_path: Some("metadata.json".to_string()),
            artifacts: extract_crates_artifacts(event, version_meta.as_ref()),
            upstream_repository,
            details,
        })
    }

    async fn fetch_crates_dependencies(&self, package: &str, version: &str) -> Result<Vec<String>> {
        let encoded = urlencoding::encode(package);
        let url = format!(
            "https://crates.io/api/v1/crates/{}/{}/dependencies",
            encoded,
            urlencoding::encode(version)
        );
        let raw = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| {
                format!("failed to fetch crates.io dependencies for {package}@{version}")
            })?
            .error_for_status()
            .with_context(|| {
                format!("crates.io dependency endpoint returned an error for {package}@{version}")
            })?
            .json::<Value>()
            .await
            .with_context(|| {
                format!("failed to decode crates.io dependencies for {package}@{version}")
            })?;

        Ok(raw
            .get("dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|dependency| {
                dependency
                    .get("kind")
                    .and_then(Value::as_str)
                    .is_none_or(|kind| kind == "normal")
                    && !dependency
                        .get("optional")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
            })
            .filter_map(|dependency| dependency.get("crate_id").and_then(Value::as_str))
            .map(|name| normalize_package_name(Ecosystem::CratesIo, name))
            .collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReleaseStatus {
    Active,
    Yanked,
    Removed,
    Unknown,
}

impl ReleaseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Yanked => "yanked",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedRelease {
    pub event_id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<DateTime<Utc>>,
    pub captured_at: DateTime<Utc>,
    pub status: ReleaseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_metadata_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<CapturedArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_repository: Option<RepositoryReleaseProvenance>,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MetadataRiskSignal {
    pub suspicious: bool,
    pub score: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<String>,
    pub reason: String,
}

fn set_capture_detail<T>(details: &mut Value, key: &str, value: &T)
where
    T: Serialize,
{
    if !details.is_object() {
        *details = json!({});
    }
    if let Some(object) = details.as_object_mut()
        && let Ok(value) = serde_json::to_value(value)
    {
        object.insert(key.to_string(), value);
    }
}

impl CapturedRelease {
    fn removed(event: &PackageReleaseEvent) -> Self {
        Self {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc::now(),
            status: ReleaseStatus::Removed,
            package_url: event.package_url.clone(),
            release_url: event.release_url.clone(),
            metadata_url: event.metadata_url.clone(),
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({}),
        }
    }
}

pub fn captured_metadata_risk(capture: &CapturedRelease) -> MetadataRiskSignal {
    if let Some(signal) = capture
        .details
        .get("metadata_risk")
        .cloned()
        .and_then(|value| serde_json::from_value::<MetadataRiskSignal>(value).ok())
    {
        return signal;
    }

    match capture.ecosystem {
        Ecosystem::Npm => npm_metadata_risk_from_details(&capture.package, &capture.details),
        Ecosystem::Pypi | Ecosystem::CratesIo => MetadataRiskSignal::default(),
    }
}

pub async fn hydrate_release_metadata_for_priority(
    http: &reqwest::Client,
    event: &PackageReleaseEvent,
) -> Result<Option<CapturedRelease>> {
    match event.ecosystem {
        Ecosystem::Pypi => hydrate_priority_pypi(http, event).await,
        Ecosystem::Npm => hydrate_priority_npm(http, event).await,
        Ecosystem::CratesIo => hydrate_priority_crates_io(http, event).await,
    }
}

async fn hydrate_priority_pypi(
    http: &reqwest::Client,
    event: &PackageReleaseEvent,
) -> Result<Option<CapturedRelease>> {
    let metadata_url = event.metadata_url.clone().unwrap_or_else(|| {
        format!(
            "https://pypi.org/pypi/{}/{}/json",
            urlencoding::encode(&event.package),
            urlencoding::encode(&event.version)
        )
    });
    let Some(raw) =
        fetch_json_metadata(http, &metadata_url, "PyPI metadata", &event.event_id).await?
    else {
        return Ok(None);
    };

    let artifacts = extract_pypi_artifacts(&raw);
    let dependencies = extract_pypi_dependencies(&raw);
    let yanked = raw
        .pointer("/info/yanked")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            artifacts
                .iter()
                .any(|artifact| artifact.yanked == Some(true))
        });
    let details = json!({
        "last_serial": raw.get("last_serial"),
        "requires_python": raw.pointer("/info/requires_python"),
        "summary": raw.pointer("/info/summary"),
        "home_page": raw.pointer("/info/home_page"),
        "project_urls": raw.pointer("/info/project_urls"),
        "dependencies": dependencies,
        "ownership": raw.pointer("/info/ownership"),
        "yanked": raw.pointer("/info/yanked"),
        "yanked_reason": raw.pointer("/info/yanked_reason")
    });

    Ok(Some(CapturedRelease {
        event_id: event.event_id.clone(),
        ecosystem: event.ecosystem,
        package: event.package.clone(),
        version: event.version.clone(),
        observed_at: event.observed_at,
        published_at: event.published_at,
        captured_at: Utc::now(),
        status: if yanked {
            ReleaseStatus::Yanked
        } else {
            ReleaseStatus::Active
        },
        package_url: event.package_url.clone(),
        release_url: event.release_url.clone(),
        metadata_url: Some(metadata_url),
        raw_metadata_path: None,
        artifacts,
        upstream_repository: None,
        details,
    }))
}

async fn hydrate_priority_npm(
    http: &reqwest::Client,
    event: &PackageReleaseEvent,
) -> Result<Option<CapturedRelease>> {
    let packument_url = event.metadata_url.clone().unwrap_or_else(|| {
        format!(
            "https://registry.npmjs.org/{}",
            urlencoding::encode(&event.package)
        )
    });
    let version_metadata_url = npm_version_metadata_url(&packument_url, &event.version);
    let Some(version_meta) =
        fetch_json_metadata(http, &version_metadata_url, "npm metadata", &event.event_id).await?
    else {
        return Ok(None);
    };

    let details = build_npm_capture_details(&event.package, &version_meta);

    Ok(Some(CapturedRelease {
        event_id: event.event_id.clone(),
        ecosystem: event.ecosystem,
        package: event.package.clone(),
        version: event.version.clone(),
        observed_at: event.observed_at,
        published_at: event.published_at,
        captured_at: Utc::now(),
        status: ReleaseStatus::Active,
        package_url: event.package_url.clone(),
        release_url: event.release_url.clone(),
        metadata_url: Some(version_metadata_url),
        raw_metadata_path: None,
        artifacts: extract_npm_artifacts(event, &version_meta),
        upstream_repository: None,
        details,
    }))
}

async fn hydrate_priority_crates_io(
    http: &reqwest::Client,
    event: &PackageReleaseEvent,
) -> Result<Option<CapturedRelease>> {
    let metadata_url = event.metadata_url.clone().unwrap_or_else(|| {
        format!(
            "https://crates.io/api/v1/crates/{}",
            urlencoding::encode(&event.package)
        )
    });
    let Some(raw) =
        fetch_json_metadata(http, &metadata_url, "crates.io metadata", &event.event_id).await?
    else {
        return Ok(None);
    };

    let dependencies = fetch_crates_dependencies_for_priority(http, &event.package, &event.version)
        .await
        .unwrap_or_default();
    let version_meta = raw
        .get("versions")
        .and_then(Value::as_array)
        .and_then(|versions| {
            versions.iter().find(|version| {
                version
                    .get("num")
                    .and_then(Value::as_str)
                    .is_some_and(|num| num == event.version)
            })
        })
        .cloned();
    let status = version_meta
        .as_ref()
        .and_then(|version| version.get("yanked").and_then(Value::as_bool))
        .map(|yanked| {
            if yanked {
                ReleaseStatus::Yanked
            } else {
                ReleaseStatus::Active
            }
        })
        .unwrap_or(ReleaseStatus::Unknown);
    let details = json!({
        "crate": raw.get("crate"),
        "dependencies": dependencies,
        "version": version_meta,
    });

    Ok(Some(CapturedRelease {
        event_id: event.event_id.clone(),
        ecosystem: event.ecosystem,
        package: event.package.clone(),
        version: event.version.clone(),
        observed_at: event.observed_at,
        published_at: event.published_at,
        captured_at: Utc::now(),
        status,
        package_url: event.package_url.clone(),
        release_url: event.release_url.clone(),
        metadata_url: Some(metadata_url),
        raw_metadata_path: None,
        artifacts: extract_crates_artifacts(event, version_meta.as_ref()),
        upstream_repository: None,
        details,
    }))
}

async fn fetch_crates_dependencies_for_priority(
    http: &reqwest::Client,
    package: &str,
    version: &str,
) -> Result<Vec<String>> {
    let encoded = urlencoding::encode(package);
    let url = format!(
        "https://crates.io/api/v1/crates/{}/{}/dependencies",
        encoded,
        urlencoding::encode(version)
    );
    let Some(raw) = fetch_json_metadata(
        http,
        &url,
        "crates.io dependency metadata",
        &format!("crates-io:{package}@{version}"),
    )
    .await?
    else {
        return Ok(Vec::new());
    };

    Ok(raw
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|dependency| {
            dependency
                .get("kind")
                .and_then(Value::as_str)
                .is_none_or(|kind| kind == "normal")
                && !dependency
                    .get("optional")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        })
        .filter_map(|dependency| dependency.get("crate_id").and_then(Value::as_str))
        .map(|name| normalize_package_name(Ecosystem::CratesIo, name))
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactHashes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake2b_256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shasum: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

impl ArtifactHashes {
    pub fn is_empty(&self) -> bool {
        self.sha256.is_none()
            && self.sha512.is_none()
            && self.blake2b_256.is_none()
            && self.md5.is_none()
            && self.integrity.is_none()
            && self.shasum.is_none()
            && self.checksum.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedArtifact {
    pub filename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yanked: Option<bool>,
    #[serde(default, skip_serializing_if = "ArtifactHashes::is_empty")]
    pub hashes: ArtifactHashes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_path: Option<String>,
}

fn extract_pypi_artifacts(raw: &Value) -> Vec<CapturedArtifact> {
    raw.get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|artifact| {
            let filename = artifact.get("filename")?.as_str()?.to_string();
            Some(CapturedArtifact {
                filename,
                kind: artifact
                    .get("packagetype")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                url: artifact
                    .get("url")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                size_bytes: artifact.get("size").and_then(Value::as_u64),
                uploaded_at: artifact
                    .get("upload_time_iso_8601")
                    .and_then(Value::as_str)
                    .and_then(parse_rfc3339)
                    .or_else(|| {
                        artifact
                            .get("upload_time")
                            .and_then(Value::as_str)
                            .and_then(parse_rfc3339)
                    }),
                yanked: artifact.get("yanked").and_then(Value::as_bool),
                hashes: ArtifactHashes {
                    sha256: artifact
                        .pointer("/digests/sha256")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    sha512: artifact
                        .pointer("/digests/sha512")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    blake2b_256: artifact
                        .pointer("/digests/blake2b_256")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    md5: artifact
                        .pointer("/digests/md5")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .or_else(|| {
                            artifact
                                .get("md5_digest")
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
        .collect()
}

fn extract_npm_artifacts(
    event: &PackageReleaseEvent,
    version_meta: &Value,
) -> Vec<CapturedArtifact> {
    let dist = version_meta.get("dist").cloned().unwrap_or(Value::Null);
    let filename = format!("{}-{}.tgz", event.package.replace('/', "-"), event.version);

    vec![CapturedArtifact {
        filename,
        kind: Some("npm-tarball".to_string()),
        url: dist
            .get("tarball")
            .and_then(Value::as_str)
            .map(str::to_string),
        size_bytes: dist.get("unpackedSize").and_then(Value::as_u64),
        uploaded_at: None,
        yanked: None,
        hashes: ArtifactHashes {
            sha256: None,
            sha512: None,
            blake2b_256: None,
            md5: None,
            integrity: dist
                .get("integrity")
                .and_then(Value::as_str)
                .map(str::to_string),
            shasum: dist
                .get("shasum")
                .and_then(Value::as_str)
                .map(str::to_string),
            checksum: None,
        },
        provenance_path: None,
    }]
}

fn extract_crates_artifacts(
    event: &PackageReleaseEvent,
    version_meta: Option<&Value>,
) -> Vec<CapturedArtifact> {
    let Some(version_meta) = version_meta else {
        return Vec::new();
    };

    let url = version_meta
        .get("dl_path")
        .and_then(Value::as_str)
        .map(|path| {
            if path.starts_with("http://") || path.starts_with("https://") {
                path.to_string()
            } else {
                format!("https://crates.io{path}")
            }
        })
        .or_else(|| {
            Some(format!(
                "https://crates.io/api/v1/crates/{}/{}/download",
                urlencoding::encode(&event.package),
                urlencoding::encode(&event.version)
            ))
        });

    vec![CapturedArtifact {
        filename: format!("{}-{}.crate", event.package, event.version),
        kind: Some("crate".to_string()),
        url,
        size_bytes: None,
        uploaded_at: version_meta
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339),
        yanked: version_meta.get("yanked").and_then(Value::as_bool),
        hashes: ArtifactHashes {
            checksum: version_meta
                .get("checksum")
                .and_then(Value::as_str)
                .map(str::to_string),
            ..ArtifactHashes::default()
        },
        provenance_path: None,
    }]
}

fn local_artifact_relative_path(filename: &str) -> PathBuf {
    PathBuf::from("artifacts").join(filename)
}

async fn materialize_primary_artifact_into_capture_dir(
    http: &reqwest::Client,
    capture_dir: &Path,
    capture: &mut CapturedRelease,
) -> Result<()> {
    if capture
        .details
        .pointer("/local_artifact/path")
        .and_then(Value::as_str)
        .is_some()
    {
        return Ok(());
    }

    let Some(artifact) = capture
        .artifacts
        .iter()
        .find(|artifact| artifact.url.is_some())
    else {
        return Ok(());
    };
    let Some(url) = artifact.url.as_deref() else {
        return Ok(());
    };

    let relative_path = local_artifact_relative_path(&artifact.filename);
    let destination = capture_dir.join(&relative_path);
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let response = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to request artifact {url}"))?
        .error_for_status()
        .with_context(|| format!("artifact download returned an error for {url}"))?;
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("failed to read artifact body from {url}"))?;
    tokio::fs::write(&destination, &bytes)
        .await
        .with_context(|| format!("failed to write {}", destination.display()))?;

    set_capture_detail(
        &mut capture.details,
        "local_artifact",
        &json!({
            "path": relative_path.to_string_lossy(),
            "filename": artifact.filename,
        }),
    );

    Ok(())
}

fn extract_pypi_dependencies(raw: &Value) -> Vec<String> {
    raw.pointer("/info/requires_dist")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(parse_pypi_requirement_name)
        .map(|name| normalize_package_name(Ecosystem::Pypi, &name))
        .collect()
}

fn extract_npm_dependencies(version_meta: &Value) -> Vec<String> {
    version_meta
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(name, _)| normalize_package_name(Ecosystem::Npm, name))
        .collect()
}

fn build_npm_capture_details(package: &str, version_meta: &Value) -> Value {
    let dependencies = extract_npm_dependencies(version_meta);
    let install_scripts_benign = npm_install_scripts_benign(version_meta);
    let metadata_risk = assess_npm_metadata_risk(
        package,
        &dependencies,
        version_meta.get("bin"),
        version_meta.get("main"),
        version_meta.pointer("/pkg/targets"),
    );

    json!({
        "dist_tags": Value::Null,
        "maintainers": Value::Null,
        "publisher": version_meta.get("_npmUser"),
        "repository": version_meta.get("repository"),
        "dependencies": dependencies,
        "deprecated": version_meta.get("deprecated"),
        "scripts": version_meta.get("scripts"),
        "has_install_scripts": has_npm_install_script(version_meta),
        "install_scripts_longstanding": false,
        "install_scripts_benign": install_scripts_benign,
        "unpublished": Value::Null,
        "bin": version_meta.get("bin"),
        "main": version_meta.get("main"),
        "pkg_targets": version_meta.pointer("/pkg/targets"),
        "metadata_risk": metadata_risk
    })
}

fn npm_metadata_risk_from_details(package: &str, details: &Value) -> MetadataRiskSignal {
    let dependencies = details
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();

    assess_npm_metadata_risk(
        package,
        &dependencies,
        details.get("bin"),
        details.get("main"),
        details.get("pkg_targets"),
    )
}

fn assess_npm_metadata_risk(
    package: &str,
    dependencies: &[String],
    bin: Option<&Value>,
    main: Option<&Value>,
    pkg_targets: Option<&Value>,
) -> MetadataRiskSignal {
    let dependency_set = dependencies
        .iter()
        .map(|dependency| dependency.as_str())
        .collect::<std::collections::HashSet<_>>();

    let native_credential_hits = matching_dependencies(
        &dependency_set,
        &[
            "@primno/dpapi",
            "node-dpapi",
            "koffi",
            "ffi-napi",
            "ref-napi",
        ],
    );
    let browser_data_hits =
        matching_dependencies(&dependency_set, &["sqlite3", "better-sqlite3", "level"]);
    let screen_capture_hits =
        matching_dependencies(&dependency_set, &["screenshot-desktop", "node-webcam"]);
    let windows_tooling_hits = matching_dependencies(
        &dependency_set,
        &["rcedit", "resedit", "node-windows", "winreg"],
    );
    let archive_hits = matching_dependencies(&dependency_set, &["archiver", "adm-zip", "tar"]);
    let c2_hits = matching_dependencies(&dependency_set, &["ws", "socket.io-client"]);

    let windows_pkg_target = pkg_targets
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|target| target.to_ascii_lowercase().contains("win"));
    let has_bin_entrypoint = match bin {
        Some(Value::String(_)) => true,
        Some(Value::Object(object)) => !object.is_empty(),
        _ => false,
    };
    let main_is_plain_js = main
        .and_then(Value::as_str)
        .is_some_and(|entrypoint| entrypoint.ends_with(".js"));
    let executable_cli_shape = has_bin_entrypoint && main_is_plain_js;
    let confusable_core = confusable_npm_package_core(package);

    let mut score = 0u32;
    let mut factors = Vec::new();

    if !native_credential_hits.is_empty() {
        score += 5;
        factors.push("native_credential_access_dependency".to_string());
    }
    if !browser_data_hits.is_empty() {
        score += 2;
        factors.push("browser_data_store_dependency".to_string());
    }
    if !screen_capture_hits.is_empty() {
        score += 2;
        factors.push("screen_capture_dependency".to_string());
    }
    if !windows_tooling_hits.is_empty() {
        score += 2;
        factors.push("windows_binary_tooling_dependency".to_string());
    }
    if !archive_hits.is_empty() {
        score += 1;
        factors.push("archive_exfiltration_dependency".to_string());
    }
    if !c2_hits.is_empty() {
        score += 1;
        factors.push("realtime_c2_dependency".to_string());
    }
    if windows_pkg_target {
        score += 1;
        factors.push("windows_binary_target".to_string());
    }
    if executable_cli_shape {
        score += 1;
        factors.push("bin_executes_javascript_entrypoint".to_string());
    }
    if confusable_core {
        score += 2;
        factors.push("confusable_package_name".to_string());
    }
    if !native_credential_hits.is_empty()
        && (!browser_data_hits.is_empty()
            || !screen_capture_hits.is_empty()
            || !windows_tooling_hits.is_empty())
    {
        score += 2;
        factors.push("credential_theft_capability_combo".to_string());
    }

    let suspicious = score >= 6;
    let reason = if suspicious {
        format!(
            "npm metadata for {package} combines high-risk native credential, surveillance, or exfiltration dependencies"
        )
    } else {
        "no malware-shaped npm metadata pattern observed".to_string()
    };

    MetadataRiskSignal {
        suspicious,
        score,
        factors,
        reason,
    }
}

fn matching_dependencies(
    dependency_set: &std::collections::HashSet<&str>,
    candidates: &[&'static str],
) -> Vec<String> {
    candidates
        .iter()
        .copied()
        .filter(|candidate| dependency_set.contains(candidate))
        .map(str::to_string)
        .collect()
}

fn confusable_npm_package_core(package: &str) -> bool {
    let unscoped = package.rsplit('/').next().unwrap_or(package);
    let core = unscoped
        .split(['-', '_', '.'])
        .next()
        .unwrap_or(unscoped)
        .to_ascii_lowercase();
    if core.len() < 5 {
        return false;
    }

    [
        "undici",
        "axios",
        "react",
        "lodash",
        "express",
        "chalk",
        "minimatch",
        "request",
    ]
    .iter()
    .any(|candidate| core != *candidate && levenshtein_distance(&core, candidate) <= 1)
}

fn levenshtein_distance(left: &str, right: &str) -> usize {
    if left == right {
        return 0;
    }
    if left.is_empty() {
        return right.chars().count();
    }
    if right.is_empty() {
        return left.chars().count();
    }

    let right_chars = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right_chars.len()).collect::<Vec<_>>();
    let mut current = vec![0; right_chars.len() + 1];

    for (left_index, left_char) in left.chars().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_char) in right_chars.iter().enumerate() {
            let cost = usize::from(left_char != *right_char);
            current[right_index + 1] = (current[right_index] + 1)
                .min(previous[right_index + 1] + 1)
                .min(previous[right_index] + cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[right_chars.len()]
}

fn parse_pypi_requirement_name(requirement: &str) -> Option<String> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return None;
    }

    let mut name = String::new();
    for ch in requirement.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            name.push(ch);
        } else {
            break;
        }
    }

    (!name.is_empty()).then_some(name)
}

pub fn graph_records_from_captured_release(capture: &CapturedRelease) -> Vec<ScoreInputRecord> {
    if !matches!(
        capture.status,
        ReleaseStatus::Active | ReleaseStatus::Yanked
    ) {
        return Vec::new();
    }

    let direct_popularity = match capture.ecosystem {
        Ecosystem::CratesIo => capture
            .details
            .pointer("/crate/downloads")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        Ecosystem::Npm | Ecosystem::Pypi => 0.0,
    };

    let mut records = vec![ScoreInputRecord::Package {
        ecosystem: capture.ecosystem,
        package: normalize_package_name(capture.ecosystem, &capture.package),
        direct_popularity,
    }];

    for dependency in capture
        .details
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        records.push(ScoreInputRecord::Dependency {
            ecosystem: capture.ecosystem,
            package: normalize_package_name(capture.ecosystem, &capture.package),
            dependency: normalize_package_name(capture.ecosystem, dependency),
            weight: 1.0,
            sources: vec!["capture_metadata".to_string()],
            confidence: Some(1.0),
        });
    }

    records
}

pub fn package_repository_identity_from_captured_release(
    ecosystem: Ecosystem,
    capture: &CapturedRelease,
) -> Option<PackageRepositoryIdentity> {
    repo_provenance::extract_package_repository_identity(
        ecosystem,
        &capture.package,
        &capture.details,
        "capture_metadata",
        Some(1.0),
    )
}

fn repository_signal_assessment(
    event: &PackageReleaseEvent,
    capture: &CapturedRelease,
    repository: &RepositoryReleaseProvenance,
) -> (RepositorySignalSeverity, Vec<String>) {
    let mut factors = Vec::new();
    let prerelease = is_prerelease_version(&event.version);
    let install_time_execution = capture_has_install_time_execution(capture);
    let install_time_execution_longstanding =
        capture_has_longstanding_install_time_execution(capture);
    let install_time_execution_benign = capture_has_benign_install_time_execution(capture);
    let risky_install_time_execution = install_time_execution
        && !install_time_execution_longstanding
        && !install_time_execution_benign;
    let high_impact = matches!(
        event.priority_snapshot().tier,
        crate::priority::PriorityTier::High | crate::priority::PriorityTier::Medium
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
    if matches!(
        capture.status,
        ReleaseStatus::Yanked | ReleaseStatus::Removed
    ) {
        factors.push("removed_or_yanked".to_string());
    }

    let severity = if !repository.suspicious {
        RepositorySignalSeverity::Informational
    } else if risky_install_time_execution {
        RepositorySignalSeverity::High
    } else {
        let _ = high_impact;
        if prerelease {
            RepositorySignalSeverity::Informational
        } else {
            RepositorySignalSeverity::Warning
        }
    };

    (severity, factors)
}

fn captured_dependency_names(capture: &CapturedRelease) -> Vec<String> {
    capture
        .details
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|dependency| normalize_package_name(capture.ecosystem, dependency))
        .collect()
}

fn previous_captured_release_from_history<'a>(
    entries: &'a [history::HistoryEntry],
    target_version: &str,
) -> Option<&'a CapturedRelease> {
    entries
        .iter()
        .rev()
        .find(|entry| entry.event.version != target_version && entry.capture.is_some())
        .and_then(|entry| entry.capture.as_ref())
}

fn is_prerelease_version(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    if ["nightly", "alpha", "beta", "rc", "dev", "canary", "preview"]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return true;
    }

    if lower.contains('-') {
        return true;
    }

    lower.chars().any(|ch| !(ch.is_ascii_digit() || ch == '.'))
}

pub(crate) fn capture_has_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("has_install_scripts")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn capture_has_longstanding_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("install_scripts_longstanding")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn capture_has_benign_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("install_scripts_benign")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn should_retain_captured_release(capture: &CapturedRelease) -> bool {
    if matches!(
        capture.status,
        ReleaseStatus::Removed | ReleaseStatus::Yanked
    ) {
        return true;
    }

    if captured_metadata_risk(capture).suspicious || captured_content_risk(capture).suspicious {
        return true;
    }

    if capture
        .upstream_repository
        .as_ref()
        .is_some_and(|repository| repository.suspicious)
    {
        return true;
    }

    let risky_install_time_execution = capture_has_install_time_execution(capture)
        && !capture_has_longstanding_install_time_execution(capture)
        && !capture_has_benign_install_time_execution(capture);
    if risky_install_time_execution {
        return true;
    }

    false
}

async fn remove_capture_dir(capture_dir: &Path) {
    match tokio::fs::remove_dir_all(capture_dir).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            warn!(path = %capture_dir.display(), error = %error, "failed to remove discarded capture dir")
        }
    }
}

async fn promote_capture_dir(staging_dir: &Path, final_dir: &Path) -> Result<()> {
    if let Some(parent) = final_dir.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create capture dir {}", parent.display()))?;
    }
    remove_capture_dir(final_dir).await;
    tokio::fs::rename(staging_dir, final_dir)
        .await
        .with_context(|| {
            format!(
                "failed to promote staged capture {} to {}",
                staging_dir.display(),
                final_dir.display()
            )
        })?;
    Ok(())
}

async fn prune_staging_cache(config: &CaptureConfig, perf: &RuntimeStats) -> Result<()> {
    let staging_dir = config.staging_dir.clone();
    let ttl = config.staging_cache_ttl;
    let max_bytes = config.staging_cache_max_bytes;
    let stats = tokio::task::spawn_blocking(move || {
        prune_staging_cache_blocking(&staging_dir, ttl, max_bytes)
    })
    .await
    .context("staging cache prune task join failed")??;
    perf.record_staging_cache_snapshot(stats.entries, stats.bytes);
    perf.record_staging_cache_pruned(stats.pruned_dirs);
    Ok(())
}

fn prune_staging_cache_blocking(
    staging_dir: &Path,
    ttl: Duration,
    max_bytes: u64,
) -> Result<StagingCacheStats> {
    if !staging_dir.exists() {
        return Ok(StagingCacheStats::default());
    }

    let now = std::time::SystemTime::now();
    let mut retained = Vec::new();
    let mut total_bytes = 0u64;
    let mut pruned_dirs = 0usize;

    for entry in std::fs::read_dir(staging_dir)
        .with_context(|| format!("failed to read staging dir {}", staging_dir.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to read entry under staging dir {}",
                staging_dir.display()
            )
        })?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat staging path {}", path.display()))?;
        if !metadata.is_dir() {
            continue;
        }

        let modified_at = metadata
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let bytes = staging_dir_bytes(&path)?;
        if ttl > Duration::ZERO && now.duration_since(modified_at).unwrap_or(Duration::ZERO) >= ttl
        {
            std::fs::remove_dir_all(&path).with_context(|| {
                format!("failed to remove expired staging dir {}", path.display())
            })?;
            pruned_dirs += 1;
            continue;
        }

        total_bytes = total_bytes.saturating_add(bytes);
        retained.push(StagingCacheEntry {
            path,
            modified_at,
            bytes,
        });
    }

    if max_bytes == 0 || total_bytes <= max_bytes {
        return Ok(StagingCacheStats {
            entries: retained.len(),
            bytes: total_bytes,
            pruned_dirs,
        });
    }

    retained.sort_by_key(|entry| entry.modified_at);
    for entry in &retained {
        if total_bytes <= max_bytes {
            break;
        }
        std::fs::remove_dir_all(&entry.path).with_context(|| {
            format!(
                "failed to evict staging dir {} to satisfy cache cap",
                entry.path.display()
            )
        })?;
        total_bytes = total_bytes.saturating_sub(entry.bytes);
        pruned_dirs += 1;
    }

    Ok(StagingCacheStats {
        entries: retained
            .into_iter()
            .filter(|entry| entry.path.exists())
            .count(),
        bytes: total_bytes,
        pruned_dirs,
    })
}

fn staging_dir_bytes(path: &Path) -> Result<u64> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat staging path {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(0);
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }

    let mut total = 0u64;
    for entry in std::fs::read_dir(path)
        .with_context(|| format!("failed to read staging dir {}", path.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read staging entry {}", path.display()))?;
        total = total.saturating_add(staging_dir_bytes(&entry.path())?);
    }
    Ok(total)
}

async fn fetch_json_metadata(
    http: &reqwest::Client,
    url: &str,
    source: &str,
    event_id: &str,
) -> Result<Option<Value>> {
    let mut last_error = None;
    for attempt in 1..=METADATA_FETCH_MAX_ATTEMPTS {
        match fetch_json_metadata_once(http, url, source, event_id).await {
            Ok(value) => return Ok(value),
            Err(error) if error.retryable && attempt < METADATA_FETCH_MAX_ATTEMPTS => {
                warn!(
                    event_id,
                    source,
                    attempt,
                    max_attempts = METADATA_FETCH_MAX_ATTEMPTS,
                    error = %error.message,
                    "metadata fetch attempt failed; retrying"
                );
                last_error = Some(error);
                sleep(Duration::from_millis(
                    METADATA_RETRY_DELAY_MS * attempt as u64,
                ))
                .await;
            }
            Err(error) => return Err(anyhow!(error.message)),
        }
    }

    let message = last_error
        .map(|error| error.message)
        .unwrap_or_else(|| format!("failed to fetch {source} for {event_id}"));
    Err(anyhow!(message))
}

async fn fetch_json_metadata_once(
    http: &reqwest::Client,
    url: &str,
    source: &str,
    event_id: &str,
) -> std::result::Result<Option<Value>, MetadataFetchError> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|error| MetadataFetchError {
            message: format!("failed to fetch {source} for {event_id}: {error}"),
            retryable: true,
        })?;

    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<unknown>")
        .to_string();
    let bytes = response.bytes().await.map_err(|error| MetadataFetchError {
        message: format!("failed to read {source} response body for {event_id}: {error}"),
        retryable: true,
    })?;

    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !status.is_success() {
        let prefix = if source == "PyPI metadata" {
            format!("PyPI metadata returned HTTP {status} for {event_id}")
        } else {
            format!("{source} returned HTTP {status} for {event_id}")
        };
        return Err(MetadataFetchError {
            message: format!(
                "{prefix}; content_type={content_type}; body_preview={}",
                summarize_body_preview(&bytes)
            ),
            retryable: status.is_server_error()
                || status == StatusCode::TOO_MANY_REQUESTS
                || status == StatusCode::REQUEST_TIMEOUT,
        });
    }

    serde_json::from_slice::<Value>(&bytes)
        .map(Some)
        .map_err(|error| MetadataFetchError {
            message: format!(
                "failed to decode {source} for {event_id}: {error}; content_type={content_type}; body_preview={}",
                summarize_body_preview(&bytes)
            ),
            retryable: true,
        })
}

fn summarize_body_preview(bytes: &[u8]) -> String {
    let preview = String::from_utf8_lossy(&bytes[..bytes.len().min(METADATA_BODY_PREVIEW_BYTES)]);
    let compact = preview.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        format!("<{} bytes binary/empty>", bytes.len())
    } else if bytes.len() > METADATA_BODY_PREVIEW_BYTES {
        format!("{compact}…")
    } else {
        compact
    }
}

fn npm_version_metadata_url(packument_url: &str, version: &str) -> String {
    format!(
        "{}/{}",
        packument_url.trim_end_matches('/'),
        urlencoding::encode(version)
    )
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
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

fn relative_path(base: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(base).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assessment::VersionBurstConfig,
        event::{
            EmittedPackageReleaseEvent, EmittedPrioritySignal, EmittedReleaseAssessmentSignal,
        },
        ledger::EventLedger,
        priority::{PrioritySnapshot, PrioritySource, PriorityTier},
        sink::EventSink,
        store,
    };
    use async_trait::async_trait;
    use chrono::TimeZone;
    use flate2::{Compression, write::GzEncoder};
    use std::sync::Arc;
    use tar::Builder as TarBuilder;
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex,
    };

    #[derive(Default)]
    struct RecordingSink {
        priority_signals: Mutex<Vec<EmittedPrioritySignal>>,
    }

    #[async_trait]
    impl EventSink for RecordingSink {
        async fn publish(&self, _event: &EmittedPackageReleaseEvent) -> Result<()> {
            Ok(())
        }

        async fn publish_release_bundle(
            &self,
            _bundle: &crate::bundle::ReleaseEvidenceBundle,
        ) -> Result<()> {
            Ok(())
        }

        async fn publish_priority_signal(&self, signal: &EmittedPrioritySignal) -> Result<()> {
            self.priority_signals.lock().await.push(signal.clone());
            Ok(())
        }

        async fn publish_repository_signal(
            &self,
            _signal: &crate::event::EmittedRepositorySignal,
        ) -> Result<()> {
            Ok(())
        }

        async fn publish_release_assessment(
            &self,
            _signal: &EmittedReleaseAssessmentSignal,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn extracts_pypi_hashes_and_yank_state() {
        let raw = json!({
            "info": {"yanked": true},
            "urls": [{
                "filename": "litellm-1.0.0.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/packages/example",
                "size": 123,
                "upload_time_iso_8601": "2026-03-25T08:00:00Z",
                "yanked": true,
                "digests": {
                    "sha256": "abc",
                    "blake2b_256": "def"
                }
            }]
        });

        let artifacts = extract_pypi_artifacts(&raw);
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].hashes.sha256.as_deref(), Some("abc"));
        assert_eq!(artifacts[0].yanked, Some(true));
    }

    #[test]
    fn extracts_npm_integrity_and_install_signal() {
        let version_meta = json!({
            "dist": {
                "tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                "integrity": "sha512-demo",
                "shasum": "deadbeef",
                "unpackedSize": 42
            },
            "scripts": {
                "postinstall": "node install.js"
            }
        });

        let event = PackageReleaseEvent {
            event_id: "npm:demo@1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: None,
        };

        let artifacts = extract_npm_artifacts(&event, &version_meta);
        assert_eq!(
            artifacts[0].hashes.integrity.as_deref(),
            Some("sha512-demo")
        );
        assert!(has_npm_install_script(&version_meta));
    }

    #[test]
    fn detects_lofygang_style_npm_metadata_risk() {
        let details = build_npm_capture_details(
            "undicy-http",
            &json!({
                "main": "index.js",
                "bin": "index.js",
                "pkg": {"targets": ["node20-win-x64"]},
                "dependencies": {
                    "@primno/dpapi": "^2.0.1",
                    "adm-zip": "^0.5.16",
                    "archiver": "^7.0.1",
                    "koffi": "^2.15.2",
                    "rcedit": "^4.0.1",
                    "screenshot-desktop": "^1.15.3",
                    "sqlite3": "^5.1.7",
                    "ws": "^8.18.2"
                }
            }),
        );

        let signal = serde_json::from_value::<MetadataRiskSignal>(
            details.get("metadata_risk").cloned().unwrap(),
        )
        .unwrap();

        assert!(signal.suspicious);
        assert!(signal.score >= 8);
        assert!(
            signal
                .factors
                .iter()
                .any(|factor| factor == "confusable_package_name")
        );
        assert!(
            signal
                .factors
                .iter()
                .any(|factor| factor == "credential_theft_capability_combo")
        );
    }

    #[test]
    fn extracts_crates_checksum_and_yank_state() {
        let version_meta = json!({
            "num": "1.0.0",
            "yanked": true,
            "checksum": "abc123",
            "dl_path": "/api/v1/crates/demo/1.0.0/download",
            "created_at": "2026-03-25T08:00:00Z"
        });

        let event = PackageReleaseEvent {
            event_id: "crates-io:demo@1.0.0".to_string(),
            ecosystem: Ecosystem::CratesIo,
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: None,
        };

        let artifacts = extract_crates_artifacts(&event, Some(&version_meta));
        assert_eq!(artifacts[0].hashes.checksum.as_deref(), Some("abc123"));
        assert_eq!(artifacts[0].yanked, Some(true));
    }

    #[test]
    fn repo_signal_demotes_prerelease_mismatch() {
        let event = PackageReleaseEvent {
            event_id: "npm:demo@1.0.0-nightly.1".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.0-nightly.1".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: None,
                propagated_impact: None,
                hidden_leverage: None,
                computed_at: None,
                score_source_version: None,
            }),
        };
        let capture = CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({ "has_install_scripts": false }),
        };
        let repository = RepositoryReleaseProvenance {
            provider: repo_provenance::RepositoryProvider::Github,
            repository_url: "https://github.com/example/demo".to_string(),
            normalized_repository_url: "https://github.com/example/demo".to_string(),
            package_version: event.version.clone(),
            checked_at: Utc::now(),
            candidate_refs: vec!["1.0.0-nightly.1".to_string()],
            match_kind: repo_provenance::RepositoryMatchKind::None,
            matched_ref: None,
            matched_commit: None,
            suspicious: true,
            reason: "repository resolved on GitHub but no matching tag or release was found for the package version".to_string(),
        };

        let (severity, factors) = repository_signal_assessment(&event, &capture, &repository);
        assert_eq!(severity, RepositorySignalSeverity::Informational);
        assert!(
            factors
                .iter()
                .any(|factor| factor == "prerelease_or_nightly")
        );
    }

    #[test]
    fn repo_signal_escalates_stable_install_time_mismatch() {
        let event = PackageReleaseEvent {
            event_id: "npm:demo@1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Low,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: None,
                propagated_impact: None,
                hidden_leverage: None,
                computed_at: None,
                score_source_version: None,
            }),
        };
        let capture = CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({ "has_install_scripts": true }),
        };
        let repository = RepositoryReleaseProvenance {
            provider: repo_provenance::RepositoryProvider::Github,
            repository_url: "https://github.com/example/demo".to_string(),
            normalized_repository_url: "https://github.com/example/demo".to_string(),
            package_version: event.version.clone(),
            checked_at: Utc::now(),
            candidate_refs: vec!["1.0.0".to_string()],
            match_kind: repo_provenance::RepositoryMatchKind::None,
            matched_ref: None,
            matched_commit: None,
            suspicious: true,
            reason: "repository resolved on GitHub but no matching tag or release was found for the package version".to_string(),
        };

        let (severity, factors) = repository_signal_assessment(&event, &capture, &repository);
        assert_eq!(severity, RepositorySignalSeverity::High);
        assert!(
            factors
                .iter()
                .any(|factor| factor == "install_time_execution")
        );
    }

    #[test]
    fn repo_signal_downgrades_longstanding_install_time_mismatch() {
        let event = PackageReleaseEvent {
            event_id: "npm:demo@1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: None,
                propagated_impact: None,
                hidden_leverage: None,
                computed_at: None,
                score_source_version: None,
            }),
        };
        let capture = CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({
                "has_install_scripts": true,
                "install_scripts_longstanding": true
            }),
        };
        let repository = RepositoryReleaseProvenance {
            provider: repo_provenance::RepositoryProvider::Github,
            repository_url: "https://github.com/example/demo".to_string(),
            normalized_repository_url: "https://github.com/example/demo".to_string(),
            package_version: event.version.clone(),
            checked_at: Utc::now(),
            candidate_refs: vec!["1.0.0".to_string(), "v1.0.0".to_string()],
            match_kind: repo_provenance::RepositoryMatchKind::None,
            matched_ref: None,
            matched_commit: None,
            suspicious: true,
            reason: "repository resolved on GitHub but no matching tag or release was found for the package version".to_string(),
        };

        let (severity, factors) = repository_signal_assessment(&event, &capture, &repository);
        assert_eq!(severity, RepositorySignalSeverity::Warning);
        assert!(
            factors
                .iter()
                .any(|factor| factor == "install_time_execution_longstanding")
        );
    }

    #[test]
    fn repo_signal_downgrades_benign_install_time_mismatch() {
        let event = PackageReleaseEvent {
            event_id: "npm:demo@1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: None,
                propagated_impact: None,
                hidden_leverage: None,
                computed_at: None,
                score_source_version: None,
            }),
        };
        let capture = CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({
                "has_install_scripts": true,
                "install_scripts_benign": true
            }),
        };
        let repository = RepositoryReleaseProvenance {
            provider: repo_provenance::RepositoryProvider::Github,
            repository_url: "https://github.com/example/demo".to_string(),
            normalized_repository_url: "https://github.com/example/demo".to_string(),
            package_version: event.version.clone(),
            checked_at: Utc::now(),
            candidate_refs: vec!["1.0.0".to_string(), "v1.0.0".to_string()],
            match_kind: repo_provenance::RepositoryMatchKind::None,
            matched_ref: None,
            matched_commit: None,
            suspicious: true,
            reason: "repository resolved on GitHub but no matching tag or release was found for the package version".to_string(),
        };

        let (severity, factors) = repository_signal_assessment(&event, &capture, &repository);
        assert_eq!(severity, RepositorySignalSeverity::Warning);
        assert!(
            factors
                .iter()
                .any(|factor| factor == "install_time_execution_benign")
        );
    }

    #[tokio::test]
    async fn diff_escalation_reason_escalates_stable_repo_mismatch_on_impacted_package() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let store = store::OperationalStore::open(store::index_db_path(&data_dir))
            .await
            .unwrap();
        let context = CaptureContext {
            http: reqwest::Client::builder().build().unwrap(),
            config: CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 1,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger::observed_ledger_path(&data_dir),
                capture_dir: data_dir.join("captures"),
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file: data_dir.join("graph-input.ndjson"),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            diff_tx: None,
            priority: None,
            sink: None,
            store,
            perf: RuntimeStats::default(),
        };

        let event = PackageReleaseEvent {
            event_id: "npm:demo@1.0.1".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.1".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: None,
                propagated_impact: None,
                hidden_leverage: None,
                computed_at: None,
                score_source_version: None,
            }),
        };
        let capture = CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: Some(RepositoryReleaseProvenance {
                provider: repo_provenance::RepositoryProvider::Github,
                repository_url: "https://github.com/example/demo".to_string(),
                normalized_repository_url: "https://github.com/example/demo".to_string(),
                package_version: event.version.clone(),
                checked_at: Utc::now(),
                candidate_refs: vec!["1.0.1".to_string()],
                match_kind: repo_provenance::RepositoryMatchKind::None,
                matched_ref: None,
                matched_commit: None,
                suspicious: true,
                reason: "repository resolved on GitHub but no matching tag or release was found for the package version".to_string(),
            }),
            details: json!({ "dependencies": ["dep-a"] }),
        };

        let reason = context
            .diff_escalation_reason(&event, &capture)
            .await
            .unwrap();
        assert_eq!(
            reason.as_deref(),
            Some("post-capture diff escalation: stable upstream mismatch on impacted package")
        );
    }

    #[tokio::test]
    async fn diff_escalation_reason_uses_previous_release_dependencies() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let store = store::OperationalStore::open(store::index_db_path(&data_dir))
            .await
            .unwrap();
        let context = CaptureContext {
            http: reqwest::Client::builder().build().unwrap(),
            config: CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 1,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger::observed_ledger_path(&data_dir),
                capture_dir: data_dir.join("captures"),
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file: data_dir.join("graph-input.ndjson"),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            diff_tx: None,
            priority: None,
            sink: None,
            store: store.clone(),
            perf: RuntimeStats::default(),
        };

        let previous_event = PackageReleaseEvent {
            event_id: "npm:demo@1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: None,
                propagated_impact: None,
                hidden_leverage: None,
                computed_at: None,
                score_source_version: None,
            }),
        };
        let previous_capture = CapturedRelease {
            event_id: previous_event.event_id.clone(),
            ecosystem: previous_event.ecosystem,
            package: previous_event.package.clone(),
            version: previous_event.version.clone(),
            observed_at: previous_event.observed_at,
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({ "dependencies": ["dep-a"] }),
        };
        let previous_capture_dir = history::capture_dir_for_event(&data_dir, &previous_event);
        tokio::fs::create_dir_all(&previous_capture_dir)
            .await
            .unwrap();
        write_json_pretty(
            &previous_capture_dir.join("capture.json"),
            &previous_capture,
        )
        .await
        .unwrap();
        store
            .record_event(&previous_event, EventOrigin::Observed)
            .await
            .unwrap();
        store
            .record_capture(
                &previous_event,
                EventOrigin::Observed,
                &previous_capture_dir,
                &previous_capture,
            )
            .await
            .unwrap();

        let current_event = PackageReleaseEvent {
            event_id: "npm:demo@1.0.1".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.1".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: None,
                propagated_impact: None,
                hidden_leverage: None,
                computed_at: None,
                score_source_version: None,
            }),
        };
        let current_capture = CapturedRelease {
            event_id: current_event.event_id.clone(),
            ecosystem: current_event.ecosystem,
            package: current_event.package.clone(),
            version: current_event.version.clone(),
            observed_at: current_event.observed_at,
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({ "dependencies": ["dep-a", "plain-crypto-js"] }),
        };

        let reason = context
            .diff_escalation_reason(&current_event, &current_capture)
            .await
            .unwrap()
            .unwrap();
        assert!(reason.contains("introduced new dependencies"));
        assert!(reason.contains("plain-crypto-js"));
    }

    #[test]
    fn summarize_body_preview_compacts_and_truncates() {
        let preview = summarize_body_preview(
            b"{\n  \"error\": \"upstream exploded badly and kept talking for a while\"\n}\n",
        );
        assert!(
            preview.contains("\"error\": \"upstream exploded badly and kept talking for a while\"")
        );
        assert!(!preview.contains('\n'));
    }

    #[test]
    fn npm_version_metadata_url_appends_encoded_version() {
        let url =
            npm_version_metadata_url("https://registry.npmjs.org/%40scope%2Fdemo", "1.2.3-beta.1");
        assert_eq!(
            url,
            "https://registry.npmjs.org/%40scope%2Fdemo/1.2.3-beta.1"
        );
    }

    #[tokio::test]
    async fn worker_backfills_from_event_ledger_and_writes_capture_files() {
        let metadata = json!({
            "info": {
                "yanked": false,
                "summary": "demo package"
            },
            "urls": [{
                "filename": "demo-1.2.3.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/packages/demo",
                "size": 321,
                "upload_time_iso_8601": "2026-03-25T08:00:00Z",
                "digests": {
                    "sha256": "feedface"
                }
            }]
        });
        let metadata_url = serve_json_once(metadata).await;

        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let capture_dir = data_dir.join("captures");
        let store = store::OperationalStore::open(store::index_db_path(&data_dir))
            .await
            .unwrap();
        let ledger_path = ledger::observed_ledger_path(&data_dir);
        let ledger = EventLedger::open(ledger_path.clone()).await.unwrap();

        ledger
            .append(&PackageReleaseEvent {
                event_id: "pypi:demo@1.2.3".to_string(),
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                version: "1.2.3".to_string(),
                published_at: Some(
                    DateTime::parse_from_rfc3339("2026-03-25T08:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
                observed_at: Utc::now(),
                source: "test".to_string(),
                sequence: None,
                package_url: Some("https://pypi.org/project/demo/".to_string()),
                release_url: Some("https://pypi.org/project/demo/1.2.3/".to_string()),
                metadata_url: Some(metadata_url),
                priority: None,
            })
            .await
            .unwrap();
        drop(ledger);

        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let worker = CaptureWorker::new(
            reqwest::Client::builder().build().unwrap(),
            CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 2,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger_path,
                capture_dir: capture_dir.clone(),
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file: data_dir.join("graph-input.ndjson"),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            rx,
            None,
            None,
            None,
            store,
            RuntimeStats::default(),
        );

        worker.run().await.unwrap();

        let encoded_package = urlencoding::encode("demo");
        let encoded_version = urlencoding::encode("1.2.3");
        let capture_json = capture_dir
            .join("pypi")
            .join(encoded_package.as_ref())
            .join(encoded_version.as_ref())
            .join("capture.json");
        let metadata_json = capture_json.parent().unwrap().join("metadata.json");

        let capture: CapturedRelease =
            serde_json::from_slice(&tokio::fs::read(&capture_json).await.unwrap()).unwrap();
        assert_eq!(capture.status, ReleaseStatus::Active);
        assert_eq!(capture.artifacts.len(), 1);
        assert_eq!(
            capture.artifacts[0].hashes.sha256.as_deref(),
            Some("feedface")
        );
        assert!(metadata_json.exists());
    }

    #[tokio::test]
    async fn worker_writes_local_graph_records_from_capture_metadata() {
        let metadata = json!({
            "info": {
                "yanked": false,
                "summary": "demo package",
                "requires_dist": [
                    "urllib3>=2",
                    "requests-toolbelt"
                ]
            },
            "urls": [{
                "filename": "demo-1.2.3.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/packages/demo",
                "size": 321,
                "upload_time_iso_8601": "2026-03-25T08:00:00Z",
                "yanked": false,
                "digests": {
                    "sha256": "feedface"
                }
            }]
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            let body = metadata.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let capture_dir = data_dir.join("captures");
        let graph_file = data_dir.join("graph-input.ndjson");
        let store = store::OperationalStore::open(store::index_db_path(&data_dir))
            .await
            .unwrap();
        let ledger_path = ledger::observed_ledger_path(&data_dir);
        let ledger = EventLedger::open(ledger_path.clone()).await.unwrap();
        let metadata_url = format!("http://{addr}/pypi/demo/1.2.3/json");

        ledger
            .append(&PackageReleaseEvent {
                event_id: "pypi:demo@1.2.3".to_string(),
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                version: "1.2.3".to_string(),
                published_at: Some(
                    DateTime::parse_from_rfc3339("2026-03-25T08:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
                observed_at: Utc::now(),
                source: "test".to_string(),
                sequence: None,
                package_url: Some("https://pypi.org/project/demo/".to_string()),
                release_url: Some("https://pypi.org/project/demo/1.2.3/".to_string()),
                metadata_url: Some(metadata_url),
                priority: None,
            })
            .await
            .unwrap();
        drop(ledger);

        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let worker = CaptureWorker::new(
            reqwest::Client::builder().build().unwrap(),
            CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 1,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger_path,
                capture_dir,
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file: graph_file.clone(),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            rx,
            None,
            None,
            None,
            store,
            RuntimeStats::default(),
        );

        worker.run().await.unwrap();
        server.await.unwrap();

        let graph_body = tokio::fs::read_to_string(&graph_file).await.unwrap();
        assert!(
            graph_body.contains("\"type\":\"package\",\"ecosystem\":\"pypi\",\"package\":\"demo\"")
        );
        assert!(graph_body.contains("\"type\":\"dependency\",\"ecosystem\":\"pypi\",\"package\":\"demo\",\"dependency\":\"urllib3\""));
        assert!(graph_body.contains("\"type\":\"dependency\",\"ecosystem\":\"pypi\",\"package\":\"demo\",\"dependency\":\"requests-toolbelt\""));
    }

    #[tokio::test]
    async fn worker_emits_priority_signal_when_capture_promotes_stub_to_local_graph() {
        let metadata = json!({
            "info": {
                "yanked": false,
                "summary": "demo package",
                "requires_dist": [
                    "urllib3>=2"
                ]
            },
            "urls": [{
                "filename": "demo-1.2.3.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/packages/demo",
                "size": 321,
                "upload_time_iso_8601": "2026-03-25T08:00:00Z",
                "yanked": false,
                "digests": {
                    "sha256": "feedface"
                }
            }]
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            let body = metadata.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let capture_dir = data_dir.join("captures");
        let graph_file = data_dir.join("graph-input.ndjson");
        let score_file = data_dir.join("priority-scores.ndjson");
        let census_file = data_dir.join("package-census.ndjson");
        tokio::fs::create_dir_all(&data_dir).await.unwrap();
        tokio::fs::write(&score_file, "").await.unwrap();
        tokio::fs::write(&graph_file, "").await.unwrap();
        tokio::fs::write(&census_file, "").await.unwrap();
        let store_path = store::index_db_path(&data_dir);
        let store = store::OperationalStore::open(store_path.clone())
            .await
            .unwrap();
        let ledger_path = ledger::observed_ledger_path(&data_dir);
        let ledger = EventLedger::open(ledger_path.clone()).await.unwrap();
        let metadata_url = format!("http://{addr}/pypi/demo/1.2.3/json");

        ledger
            .append(&PackageReleaseEvent {
                event_id: "pypi:demo@1.2.3".to_string(),
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                version: "1.2.3".to_string(),
                published_at: Some(
                    DateTime::parse_from_rfc3339("2026-03-25T08:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
                observed_at: Utc::now(),
                source: "test".to_string(),
                sequence: None,
                package_url: Some("https://pypi.org/project/demo/".to_string()),
                release_url: Some("https://pypi.org/project/demo/1.2.3/".to_string()),
                metadata_url: Some(metadata_url),
                priority: None,
            })
            .await
            .unwrap();
        drop(ledger);

        let resolver = crate::priority::PriorityResolver::load(&crate::config::PriorityConfig {
            score_file,
            graph_file: graph_file.clone(),
            census_file,
            graph_store_file: Some(store_path),
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: false,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();
        let initial = resolver
            .resolve_observed_release(Ecosystem::Pypi, "demo")
            .await;
        assert_eq!(initial.source, PrioritySource::KnownPackageStub);

        let sink = Arc::new(RecordingSink::default());
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let worker = CaptureWorker::new(
            reqwest::Client::builder().build().unwrap(),
            CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 1,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger_path,
                capture_dir,
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file,
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            rx,
            None,
            Some(resolver),
            Some(sink.clone()),
            store,
            RuntimeStats::default(),
        );

        worker.run().await.unwrap();
        server.await.unwrap();

        let signals = sink.priority_signals.lock().await.clone();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, "local_graph_promotion");
        assert_eq!(
            signals[0]
                .previous_priority
                .as_ref()
                .map(|priority| priority.source),
            Some(PrioritySource::KnownPackageStub)
        );
        assert_eq!(
            signals[0].current_priority.source,
            PrioritySource::LocalGraph
        );
        assert!(signals[0].graph.known_in_local_graph);
        assert_eq!(signals[0].package, "demo");
    }

    #[tokio::test]
    async fn worker_backfill_uses_persisted_event_priority_for_local_graph_promotion() {
        let metadata = json!({
            "info": {
                "yanked": false,
                "summary": "demo package",
                "requires_dist": [
                    "urllib3>=2"
                ]
            },
            "urls": [{
                "filename": "demo-1.2.3.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/packages/demo",
                "size": 321,
                "upload_time_iso_8601": "2026-03-25T08:00:00Z",
                "yanked": false,
                "digests": {
                    "sha256": "feedface"
                }
            }]
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            let body = metadata.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let capture_dir = data_dir.join("captures");
        let graph_file = data_dir.join("graph-input.ndjson");
        let score_file = data_dir.join("priority-scores.ndjson");
        let census_file = data_dir.join("package-census.ndjson");
        tokio::fs::create_dir_all(&data_dir).await.unwrap();
        tokio::fs::write(&score_file, "").await.unwrap();
        tokio::fs::write(&graph_file, "").await.unwrap();
        tokio::fs::write(&census_file, "").await.unwrap();
        let store_path = store::index_db_path(&data_dir);
        let store = store::OperationalStore::open(store_path.clone())
            .await
            .unwrap();
        let ledger_path = ledger::observed_ledger_path(&data_dir);
        let ledger = EventLedger::open(ledger_path.clone()).await.unwrap();
        let metadata_url = format!("http://{addr}/pypi/demo/1.2.3/json");

        ledger
            .append(&PackageReleaseEvent {
                event_id: "pypi:demo@1.2.3".to_string(),
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                version: "1.2.3".to_string(),
                published_at: Some(
                    DateTime::parse_from_rfc3339("2026-03-25T08:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
                observed_at: Utc::now(),
                source: "test".to_string(),
                sequence: None,
                package_url: Some("https://pypi.org/project/demo/".to_string()),
                release_url: Some("https://pypi.org/project/demo/1.2.3/".to_string()),
                metadata_url: Some(metadata_url),
                priority: Some(PrioritySnapshot::known_package_stub()),
            })
            .await
            .unwrap();
        drop(ledger);

        let resolver = crate::priority::PriorityResolver::load(&crate::config::PriorityConfig {
            score_file,
            graph_file: graph_file.clone(),
            census_file,
            graph_store_file: Some(store_path),
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: false,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let sink = Arc::new(RecordingSink::default());
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let worker = CaptureWorker::new(
            reqwest::Client::builder().build().unwrap(),
            CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 1,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger_path,
                capture_dir,
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file,
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            rx,
            None,
            Some(resolver),
            Some(sink.clone()),
            store,
            RuntimeStats::default(),
        );

        worker.run().await.unwrap();
        server.await.unwrap();

        let signals = sink.priority_signals.lock().await.clone();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, "local_graph_promotion");
        assert_eq!(
            signals[0]
                .previous_priority
                .as_ref()
                .map(|priority| priority.source),
            Some(PrioritySource::KnownPackageStub)
        );
        assert_eq!(
            signals[0].current_priority.source,
            PrioritySource::LocalGraph
        );
        assert!(signals[0].graph.known_in_local_graph);
        assert_eq!(signals[0].package, "demo");
    }

    #[tokio::test]
    async fn worker_backfill_skips_low_priority_observed_events() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let store = store::OperationalStore::open(store::index_db_path(&data_dir))
            .await
            .unwrap();
        let ledger = EventLedger::open(ledger::observed_ledger_path(&data_dir))
            .await
            .unwrap();

        let event = PackageReleaseEvent {
            event_id: "pypi:demo@9.9.9".to_string(),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: "9.9.9".to_string(),
            published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 8, 0, 0).unwrap()),
            observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 8, 1, 0).unwrap(),
            source: "test".to_string(),
            sequence: None,
            package_url: Some("https://pypi.org/project/demo/".to_string()),
            release_url: Some("https://pypi.org/project/demo/9.9.9/".to_string()),
            metadata_url: Some("https://pypi.org/pypi/demo/9.9.9/json".to_string()),
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Low,
                source: PrioritySource::OfflineScoreFile,
                direct_popularity: Some(1.0),
                propagated_impact: Some(3.0),
                hidden_leverage: Some(0.1),
                computed_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 7, 0, 0).unwrap()),
                score_source_version: Some("scores-v1".to_string()),
            }),
        };
        ledger.append(&event).await.unwrap();
        store
            .record_event(&event, EventOrigin::Observed)
            .await
            .unwrap();
        drop(ledger);

        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        CaptureWorker::new(
            reqwest::Client::builder().build().unwrap(),
            CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 1,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger::observed_ledger_path(&data_dir),
                capture_dir: data_dir.join("captures"),
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file: data_dir.join("graph-input.ndjson"),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            rx,
            None,
            None,
            None,
            store.clone(),
            RuntimeStats::default(),
        )
        .run()
        .await
        .unwrap();

        let capture_json = data_dir
            .join("captures")
            .join("pypi")
            .join("demo")
            .join("9.9.9")
            .join("capture.json");
        assert!(!capture_json.exists());

        let stats = store.stats().await.unwrap();
        assert_eq!(stats.capture_states.skipped, 1);
        assert_eq!(stats.diff_states.skipped, 1);
        assert_eq!(stats.priorities.low, 1);
    }

    #[tokio::test]
    async fn triaged_post_process_discards_low_signal_capture_from_staging() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let store = store::OperationalStore::open(store::index_db_path(&data_dir))
            .await
            .unwrap();
        let context = CaptureContext {
            http: reqwest::Client::builder().build().unwrap(),
            config: CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 1,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger::observed_ledger_path(&data_dir),
                capture_dir: data_dir.join("captures"),
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file: data_dir.join("graph-input.ndjson"),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            diff_tx: None,
            priority: None,
            sink: None,
            store: store.clone(),
            perf: RuntimeStats::default(),
        };

        let event = PackageReleaseEvent {
            event_id: "pypi:demo@2.0.0".to_string(),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: "2.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot::known_package_stub()),
        };
        store
            .record_event(&event, EventOrigin::Observed)
            .await
            .unwrap();

        let staging_dir = data_dir
            .join("staging-captures")
            .join(urlencoding::encode(&event.event_id).into_owned());
        tokio::fs::create_dir_all(&staging_dir).await.unwrap();
        let capture = CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({
                "dependencies": [],
                "has_install_scripts": false,
                "metadata_risk": {
                    "suspicious": false,
                    "score": 0,
                    "factors": [],
                    "reason": "clean"
                }
            }),
        };
        write_json_pretty(&staging_dir.join("capture.json"), &capture)
            .await
            .unwrap();

        context
            .post_process_capture(PostCaptureRequest {
                event: event.clone(),
                origin: EventOrigin::Observed,
                notify_diff: false,
                retention: CaptureRetention::Ephemeral,
                capture_dir: staging_dir.clone(),
                final_capture_dir: context.capture_path_for_event(&event),
                capture,
            })
            .await
            .unwrap();

        assert!(!staging_dir.exists());
        assert!(!context.capture_path_for_event(&event).exists());
        let record = store
            .load_release_record(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.capture_state, "skipped");
        assert_eq!(
            record.capture_reason.as_deref(),
            Some("post-analysis dropped low-signal triaged capture")
        );
    }

    #[tokio::test]
    async fn triaged_post_process_promotes_suspicious_capture_from_staging() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let store = store::OperationalStore::open(store::index_db_path(&data_dir))
            .await
            .unwrap();
        let context = CaptureContext {
            http: reqwest::Client::builder().build().unwrap(),
            config: CaptureConfig {
                queue_capacity: 1,
                worker_concurrency: 1,
                data_dir: data_dir.clone(),
                observed_event_log_path: ledger::observed_ledger_path(&data_dir),
                capture_dir: data_dir.join("captures"),
                staging_dir: data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(60),
                staging_cache_max_bytes: 1024 * 1024,
                staging_cache_sweep_interval: Duration::from_secs(1),
                graph_file: data_dir.join("graph-input.ndjson"),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
                version_burst: VersionBurstConfig::default(),
            },
            diff_tx: None,
            priority: None,
            sink: None,
            store: store.clone(),
            perf: RuntimeStats::default(),
        };

        let event = PackageReleaseEvent {
            event_id: "pypi:demo@2.0.1".to_string(),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: "2.0.1".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot::known_package_stub()),
        };
        store
            .record_event(&event, EventOrigin::Observed)
            .await
            .unwrap();

        let staging_dir = data_dir
            .join("staging-captures")
            .join(urlencoding::encode(&event.event_id).into_owned());
        tokio::fs::create_dir_all(&staging_dir).await.unwrap();
        let capture = CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({
                "dependencies": [],
                "has_install_scripts": false,
                "metadata_risk": {
                    "suspicious": true,
                    "score": 8,
                    "factors": ["test_factor"],
                    "reason": "test suspicious metadata"
                }
            }),
        };
        write_json_pretty(&staging_dir.join("capture.json"), &capture)
            .await
            .unwrap();

        let final_capture_dir = context.capture_path_for_event(&event);
        context
            .post_process_capture(PostCaptureRequest {
                event: event.clone(),
                origin: EventOrigin::Observed,
                notify_diff: false,
                retention: CaptureRetention::Ephemeral,
                capture_dir: staging_dir.clone(),
                final_capture_dir: final_capture_dir.clone(),
                capture,
            })
            .await
            .unwrap();

        assert!(!staging_dir.exists());
        assert!(final_capture_dir.join("capture.json").exists());
        let record = store
            .load_release_record(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.capture_state, "ready");
    }

    #[tokio::test]
    async fn staging_cache_prune_enforces_ttl_and_size_cap() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let staging_dir = data_dir.join("staging-captures");
        tokio::fs::create_dir_all(&staging_dir).await.unwrap();

        let expired_dir = staging_dir.join("expired");
        tokio::fs::create_dir_all(&expired_dir).await.unwrap();
        tokio::fs::write(expired_dir.join("capture.json"), b"{}")
            .await
            .unwrap();
        sleep(Duration::from_millis(25)).await;

        let older_dir = staging_dir.join("older");
        tokio::fs::create_dir_all(&older_dir).await.unwrap();
        tokio::fs::write(older_dir.join("artifact.bin"), vec![0u8; 1024])
            .await
            .unwrap();
        sleep(Duration::from_millis(25)).await;

        let newer_dir = staging_dir.join("newer");
        tokio::fs::create_dir_all(&newer_dir).await.unwrap();
        tokio::fs::write(newer_dir.join("artifact.bin"), vec![0u8; 1024])
            .await
            .unwrap();

        let config = CaptureConfig {
            queue_capacity: 1,
            worker_concurrency: 1,
            data_dir: data_dir.clone(),
            observed_event_log_path: ledger::observed_ledger_path(&data_dir),
            capture_dir: data_dir.join("captures"),
            staging_dir: staging_dir.clone(),
            staging_cache_ttl: Duration::from_millis(10),
            staging_cache_max_bytes: 1024,
            staging_cache_sweep_interval: Duration::from_secs(1),
            graph_file: data_dir.join("graph-input.ndjson"),
            pypi_provenance: false,
            github_api_base: "https://api.github.com".to_string(),
            gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
            version_burst: VersionBurstConfig::default(),
        };

        prune_staging_cache(&config, &RuntimeStats::default())
            .await
            .unwrap();

        assert!(!expired_dir.exists());
        assert!(!older_dir.exists());
        assert!(newer_dir.exists());
    }

    async fn serve_bytes_once(content_type: &str, body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let content_type = content_type.to_string();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();

            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });

        format!("http://{addr}/artifact.bin")
    }

    fn write_test_npm_archive(base: &Path, files: &[(&str, &str)]) -> String {
        let source_root = base.join("archive-source");
        std::fs::create_dir_all(&source_root).unwrap();
        for (relative, content) in files {
            let path = source_root.join("package").join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, content).unwrap();
        }

        let archive_path = base.join("package.tgz");
        let archive_file = std::fs::File::create(&archive_path).unwrap();
        let encoder = GzEncoder::new(archive_file, Compression::default());
        let mut builder = TarBuilder::new(encoder);
        builder
            .append_dir_all("package", source_root.join("package"))
            .unwrap();
        builder.finish().unwrap();
        archive_path.to_string_lossy().to_string()
    }

    #[tokio::test]
    async fn materializes_primary_artifact_into_capture_dir_and_records_relative_path() {
        let temp_dir = tempdir().unwrap();
        let archive_bytes = tokio::fs::read(write_test_npm_archive(
            temp_dir.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "demo",
                        "version": "1.0.0",
                        "main": "index.js"
                    }))
                    .unwrap(),
                ),
                ("index.js", "module.exports = 1;"),
            ],
        ))
        .await
        .unwrap();
        let artifact_url = serve_bytes_once("application/octet-stream", archive_bytes).await;
        let capture_dir = temp_dir.path().join("capture");
        tokio::fs::create_dir_all(&capture_dir).await.unwrap();

        let mut capture = CapturedRelease {
            event_id: "npm:demo@1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            observed_at: Utc::now(),
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({}),
        };
        capture.artifacts = vec![CapturedArtifact {
            filename: "demo-1.0.0.tgz".to_string(),
            kind: Some("npm-tarball".to_string()),
            url: Some(artifact_url),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: ArtifactHashes::default(),
            provenance_path: None,
        }];

        materialize_primary_artifact_into_capture_dir(
            &reqwest::Client::new(),
            &capture_dir,
            &mut capture,
        )
        .await
        .unwrap();

        let relative = capture
            .details
            .pointer("/local_artifact/path")
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(relative, "artifacts/demo-1.0.0.tgz");
        assert!(capture_dir.join(relative).exists());
    }

    async fn serve_json_once(body: Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = serde_json::to_string(&body).unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        format!("http://{addr}/metadata.json")
    }
}
