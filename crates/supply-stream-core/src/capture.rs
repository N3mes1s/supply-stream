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
use tracing::{debug, info, warn};

use crate::{
    bundle,
    config::CaptureConfig,
    event::{
        Ecosystem, EmittedPrioritySignal, EmittedRepositorySignal, PackageReleaseEvent,
        RepositorySignalSeverity,
    },
    install_scripts::{
        has_npm_install_script, npm_install_scripts_benign, npm_install_scripts_longstanding,
    },
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
pub struct CaptureRequest {
    pub event: PackageReleaseEvent,
    pub origin: EventOrigin,
    pub notify_diff: bool,
    pub enqueued_at: Instant,
}

impl CaptureRequest {
    pub fn observed(event: PackageReleaseEvent, notify_diff: bool) -> Self {
        Self {
            event,
            origin: EventOrigin::Observed,
            notify_diff,
            enqueued_at: Instant::now(),
        }
    }

    pub fn reconstructed(event: PackageReleaseEvent, notify_diff: bool) -> Self {
        Self {
            event,
            origin: EventOrigin::Reconstructed,
            notify_diff,
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

    pub async fn run(mut self) -> Result<()> {
        self.backfill_from_ledger().await?;

        let mut in_flight = JoinSet::new();
        let concurrency = self.context.config.worker_concurrency.max(1);

        while let Some(request) = self.rx.recv().await {
            self.spawn_capture(&mut in_flight, request);
            self.drain_to_limit(&mut in_flight, concurrency, "capture failed")
                .await;
        }

        self.drain_all(&mut in_flight, "capture failed").await;
        Ok(())
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
        let mut in_flight = JoinSet::new();
        let concurrency = self.context.config.worker_concurrency.max(1);
        for event in observed_events {
            if let Some(priority) = &self.context.priority {
                priority.seed_event_snapshot(&event).await;
            }
            let capture_dir = self.context.capture_path_for_event(&event);
            if capture_dir.join("capture.json").exists() {
                self.context
                    .index_existing_capture(&event, EventOrigin::Observed, &capture_dir)
                    .await?;
                if event.diff_requested() {
                    self.context.notify_diff_worker(&event).await;
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
            self.spawn_capture(&mut in_flight, CaptureRequest::observed(event, notify_diff));
            self.drain_to_limit(
                &mut in_flight,
                concurrency,
                "ledger backfill capture failed",
            )
            .await;
        }

        for event in reconstructed_events {
            let capture_dir = self.context.capture_path_for_event(&event);
            if capture_dir.join("capture.json").exists() {
                self.context
                    .index_existing_capture(&event, EventOrigin::Reconstructed, &capture_dir)
                    .await?;
                continue;
            }

            pending += 1;
            self.context.perf.record_capture_enqueued();
            self.spawn_capture(&mut in_flight, CaptureRequest::reconstructed(event, false));
            self.drain_to_limit(
                &mut in_flight,
                concurrency,
                "ledger backfill capture failed",
            )
            .await;
        }

        self.drain_all(&mut in_flight, "ledger backfill capture failed")
            .await;

        if pending > 0 {
            info!(pending, "replayed uncaptured events from event ledger");
        }

        Ok(())
    }

    fn spawn_capture(
        &self,
        in_flight: &mut JoinSet<(String, Result<()>)>,
        request: CaptureRequest,
    ) {
        let context = self.context.clone();
        in_flight.spawn(async move {
            let event_id = request.event.event_id.clone();
            let result = context.capture_if_missing(&request).await;
            (event_id, result)
        });
    }

    async fn drain_to_limit(
        &self,
        in_flight: &mut JoinSet<(String, Result<()>)>,
        concurrency: usize,
        failure_message: &'static str,
    ) {
        while in_flight.len() >= concurrency {
            self.join_next(in_flight, failure_message).await;
        }
    }

    async fn drain_all(
        &self,
        in_flight: &mut JoinSet<(String, Result<()>)>,
        failure_message: &'static str,
    ) {
        while !in_flight.is_empty() {
            self.join_next(in_flight, failure_message).await;
        }
    }

    async fn join_next(
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

impl CaptureContext {
    async fn capture_if_missing(&self, request: &CaptureRequest) -> Result<()> {
        let started_at = Instant::now();
        self.perf
            .record_capture_started(request.enqueued_at.elapsed());
        let event = &request.event;
        let origin = request.origin;
        let notify_diff = request.notify_diff;
        let capture_dir = self.capture_path_for_event(event);
        let result: Result<()> = async {
            if capture_dir.join("capture.json").exists() {
                self.index_existing_capture(event, origin, &capture_dir)
                    .await?;
                if notify_diff {
                    self.notify_diff_worker(event).await;
                }
                return Ok(());
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
            let package_repository =
                package_repository_identity_from_captured_release(event.ecosystem, &capture);

            write_json_pretty(&capture_dir.join("capture.json"), &capture).await?;
            let graph_records = graph_records_from_captured_release(&capture);
            self.append_local_graph_records(&graph_records).await?;
            if !graph_records.is_empty() {
                self.store.record_graph_records(&graph_records).await?;
            }
            if let Some(repository) = &package_repository {
                self.store
                    .record_package_repository_ref(repository, Some(&capture.version))
                    .await?;
            }
            if let Some(priority) = &self.priority {
                let updates = priority.record_captured_release(&capture).await;
                self.emit_priority_signal(event, priority, &updates).await;
            }
            self.store
                .record_capture(event, origin, &capture_dir, &capture)
                .await?;
            self.emit_repository_signal(event, &capture).await;
            self.emit_release_bundle(event, Some(&capture), None).await;
            if notify_diff {
                self.notify_diff_worker(event).await;
            }
            debug!(event_id = event.event_id, dir = %capture_dir.display(), "captured release evidence");
            Ok(())
        }
        .await;

        let elapsed = started_at.elapsed();
        match &result {
            Ok(()) => self.perf.record_capture_completed(elapsed),
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

    async fn notify_diff_worker(&self, event: &PackageReleaseEvent) {
        let Some(diff_tx) = &self.diff_tx else {
            return;
        };
        let request = crate::autodiff::DiffRequest::new(event.clone());
        if let Err(error) = diff_tx.send(request).await {
            warn!(event_id = event.event_id, error = %error, "diff worker channel closed");
        } else {
            self.perf.record_diff_enqueued();
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
        let metadata_url = event.metadata_url.clone().unwrap_or_else(|| {
            format!(
                "https://registry.npmjs.org/{}",
                urlencoding::encode(&event.package)
            )
        });
        let Some(raw) =
            fetch_json_metadata(&self.http, &metadata_url, "npm metadata", &event.event_id).await?
        else {
            return Ok(CapturedRelease::removed(event));
        };

        write_json_pretty(&capture_dir.join("metadata.json"), &raw).await?;

        let Some(version_meta) = raw
            .get("versions")
            .and_then(Value::as_object)
            .and_then(|versions| versions.get(&event.version))
        else {
            let unpublished = raw
                .pointer("/time/unpublished")
                .cloned()
                .unwrap_or(Value::Null);
            return Ok(CapturedRelease {
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
                metadata_url: Some(metadata_url),
                raw_metadata_path: Some("metadata.json".to_string()),
                artifacts: Vec::new(),
                upstream_repository: None,
                details: json!({
                    "unpublished": unpublished,
                    "dist_tags": raw.get("dist-tags"),
                    "maintainers": raw.get("maintainers")
                }),
            });
        };
        let dependencies = extract_npm_dependencies(version_meta);
        let install_scripts_longstanding = npm_install_scripts_longstanding(&raw, &event.version);
        let install_scripts_benign = npm_install_scripts_benign(version_meta);

        let details = json!({
            "dist_tags": raw.get("dist-tags"),
            "maintainers": raw.get("maintainers"),
            "publisher": version_meta.get("_npmUser"),
            "repository": version_meta.get("repository"),
            "dependencies": dependencies,
            "deprecated": version_meta.get("deprecated"),
            "scripts": version_meta.get("scripts"),
            "has_install_scripts": has_npm_install_script(version_meta),
            "install_scripts_longstanding": install_scripts_longstanding,
            "install_scripts_benign": install_scripts_benign,
            "unpublished": raw.pointer("/time/unpublished")
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
            status: ReleaseStatus::Active,
            package_url: event.package_url.clone(),
            release_url: event.release_url.clone(),
            metadata_url: Some(metadata_url),
            raw_metadata_path: Some("metadata.json".to_string()),
            artifacts: extract_npm_artifacts(event, version_meta),
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

fn capture_has_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("has_install_scripts")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn capture_has_longstanding_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("install_scripts_longstanding")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn capture_has_benign_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("install_scripts_benign")
        .and_then(Value::as_bool)
        .unwrap_or(false)
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
    use std::sync::Arc;
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
                graph_file: data_dir.join("graph-input.ndjson"),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
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
                graph_file: graph_file.clone(),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
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
                graph_file,
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
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
                graph_file,
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
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
                graph_file: data_dir.join("graph-input.ndjson"),
                pypi_provenance: false,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
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
