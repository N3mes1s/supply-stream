use std::{path::Path, time::Instant};

use anyhow::{Context, Result};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, warn};

use crate::{
    assessment::{DiffAssessmentInput, assess_release},
    bundle,
    capture::CapturedRelease,
    config::AutoDiffConfig,
    diff::{self, StoredReleaseDiffRequest, StoredReleaseDiffStatus},
    event::{EmittedReleaseAssessmentSignal, PackageReleaseEvent},
    history,
    perf::RuntimeStats,
    sink::EventSink,
    store::{EventOrigin, OperationalStore},
};
use std::sync::Arc;

#[derive(Clone)]
struct DiffContext {
    config: AutoDiffConfig,
    store: OperationalStore,
    perf: RuntimeStats,
    sink: Option<Arc<dyn EventSink>>,
}

pub struct DiffWorker {
    context: DiffContext,
    rx: mpsc::Receiver<DiffRequest>,
}

#[derive(Debug, Clone)]
pub struct DiffRequest {
    pub event: PackageReleaseEvent,
    pub enqueued_at: Instant,
}

impl DiffRequest {
    pub fn new(event: PackageReleaseEvent) -> Self {
        Self {
            event,
            enqueued_at: Instant::now(),
        }
    }
}

impl DiffWorker {
    pub fn new(
        config: AutoDiffConfig,
        rx: mpsc::Receiver<DiffRequest>,
        store: OperationalStore,
        perf: RuntimeStats,
        sink: Option<Arc<dyn EventSink>>,
    ) -> Self {
        Self {
            context: DiffContext {
                config,
                store,
                perf,
                sink,
            },
            rx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let mut in_flight = JoinSet::new();
        let concurrency = self.context.config.worker_concurrency.max(1);

        while let Some(request) = self.rx.recv().await {
            self.spawn_diff(&mut in_flight, request);
            self.drain_to_limit(&mut in_flight, concurrency).await;
        }

        self.drain_all(&mut in_flight).await;
        Ok(())
    }

    fn spawn_diff(&self, in_flight: &mut JoinSet<(String, Result<()>)>, request: DiffRequest) {
        let context = self.context.clone();
        in_flight.spawn(async move {
            let event_id = request.event.event_id.clone();
            let result = context.generate_if_missing(&request).await;
            (event_id, result)
        });
    }

    async fn drain_to_limit(
        &self,
        in_flight: &mut JoinSet<(String, Result<()>)>,
        concurrency: usize,
    ) {
        while in_flight.len() >= concurrency {
            self.join_next(in_flight).await;
        }
    }

    async fn drain_all(&self, in_flight: &mut JoinSet<(String, Result<()>)>) {
        while !in_flight.is_empty() {
            self.join_next(in_flight).await;
        }
    }

    async fn join_next(&self, in_flight: &mut JoinSet<(String, Result<()>)>) {
        let Some(outcome) = in_flight.join_next().await else {
            return;
        };

        match outcome {
            Ok((_, Ok(()))) => {}
            Ok((event_id, Err(error))) => {
                warn!(event_id, error = %error, "diff generation failed");
            }
            Err(error) => warn!(error = %error, "diff generation task join failed"),
        }
    }
}

impl DiffContext {
    async fn generate_if_missing(&self, request: &DiffRequest) -> Result<()> {
        let started_at = Instant::now();
        self.perf.record_diff_started(request.enqueued_at.elapsed());
        let event = &request.event;
        let capture_dir = history::capture_dir_for_event(&self.config.data_dir, event);
        let result: Result<()> = async {
            if !event.diff_requested() {
                self.store
                    .mark_diff_skipped(&event.event_id, "priority policy skipped diff")
                    .await?;
                self.perf.record_diff_skipped();
                return Ok(());
            }

            tokio::fs::create_dir_all(&capture_dir)
                .await
                .with_context(|| format!("failed to create diff dir {}", capture_dir.display()))?;

            let diff_json_path = capture_dir.join("diff.json");
            let diff_markdown_path = capture_dir.join("diff.md");
            let markdown_missing = self.config.write_markdown && !diff_markdown_path.exists();
            let allow_lineage_upgrade = self.config.backfill_lineage
                && existing_diff_status(&diff_json_path)
                    .await?
                    .is_some_and(|status| status == "no_baseline");
            if diff_json_path.exists() && !markdown_missing && !allow_lineage_upgrade {
                return Ok(());
            }

            let mut stored = diff::build_stored_release_diff(StoredReleaseDiffRequest {
                data_dir: &self.config.data_dir,
                ecosystem: event.ecosystem,
                package: &event.package,
                target_version: &event.version,
                include_patches: self.config.include_patches,
                patch_context: self.config.patch_context,
            })
            .await?;

            if self.config.backfill_lineage && stored.status == StoredReleaseDiffStatus::NoBaseline
            {
                match history::backfill_previous_lineage(
                    &self.config.data_dir,
                    event.ecosystem,
                    &event.package,
                    &event.version,
                )
                .await
                {
                    Ok(history::LineageBackfill::Backfilled { .. }) => {
                        stored = diff::build_stored_release_diff(StoredReleaseDiffRequest {
                            data_dir: &self.config.data_dir,
                            ecosystem: event.ecosystem,
                            package: &event.package,
                            target_version: &event.version,
                            include_patches: self.config.include_patches,
                            patch_context: self.config.patch_context,
                        })
                        .await?;
                    }
                    Ok(history::LineageBackfill::NoPreviousRelease)
                    | Ok(history::LineageBackfill::TargetNotVisibleOnline) => {}
                    Err(error) => {
                        let base_reason = stored
                            .reason
                            .take()
                            .unwrap_or_else(|| "lineage backfill unavailable".to_string());
                        stored.reason =
                            Some(format!("{base_reason}; lineage backfill failed: {error}"));
                    }
                }
            }

            write_json_pretty(&diff_json_path, &stored).await?;

            if self.config.write_markdown {
                let body = diff::render_stored_release_diff_markdown(&stored);
                tokio::fs::write(&diff_markdown_path, body)
                    .await
                    .with_context(|| format!("failed to write {}", diff_markdown_path.display()))?;
            }

            self.store
                .record_diff(event, EventOrigin::Observed, &capture_dir, &stored)
                .await?;
            self.emit_release_assessment(event, &capture_dir, &stored)
                .await;
            self.emit_release_bundle(event, &stored).await;

            debug!(event_id = event.event_id, dir = %capture_dir.display(), "wrote release diff");
            Ok(())
        }
        .await;

        let elapsed = started_at.elapsed();
        match &result {
            Ok(()) => self.perf.record_diff_completed(elapsed),
            Err(error) => {
                self.perf.record_diff_failed(elapsed);
                self.store
                    .mark_diff_failed(&event.event_id, &error.to_string())
                    .await?;
            }
        }
        result
    }

    async fn emit_release_assessment(
        &self,
        event: &PackageReleaseEvent,
        capture_dir: &Path,
        stored: &diff::StoredReleaseDiff,
    ) {
        let Some(sink) = &self.sink else {
            return;
        };
        let capture_path = capture_dir.join("capture.json");
        let capture = match load_capture(&capture_path).await {
            Ok(capture) => capture,
            Err(error) => {
                warn!(event_id = event.event_id, error = %error, "failed to load capture for release assessment");
                return;
            }
        };
        let graph = match self
            .store
            .load_graph_evidence(event.ecosystem, &event.package)
            .await
        {
            Ok(graph) => graph,
            Err(error) => {
                warn!(event_id = event.event_id, error = %error, "failed to load graph evidence for release assessment");
                None
            }
        };
        let repository = capture.upstream_repository.clone();
        let assessment = assess_release(
            event,
            graph.as_ref(),
            &capture,
            repository.as_ref(),
            Some(&DiffAssessmentInput::from(stored)),
        );
        if let Err(error) = sink
            .publish_release_assessment(&EmittedReleaseAssessmentSignal {
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
            .await
        {
            warn!(event_id = event.event_id, error = %error, "failed to publish release assessment");
        }
    }

    async fn emit_release_bundle(
        &self,
        event: &PackageReleaseEvent,
        stored: &diff::StoredReleaseDiff,
    ) {
        let diff_value = match serde_json::to_value(stored) {
            Ok(value) => value,
            Err(error) => {
                warn!(event_id = event.event_id, error = %error, "failed to encode diff bundle payload");
                return;
            }
        };
        let bundle = match bundle::write_release_bundle(
            &self.config.data_dir,
            &self.store,
            event,
            None,
            Some(&diff_value),
        )
        .await
        {
            Ok(bundle) => bundle,
            Err(error) => {
                warn!(event_id = event.event_id, error = %error, "failed to write release evidence bundle");
                return;
            }
        };
        let Some(sink) = &self.sink else {
            return;
        };
        if let Err(error) = sink.publish_release_bundle(&bundle).await {
            warn!(event_id = event.event_id, error = %error, "failed to publish release bundle");
        }
    }
}

async fn write_json_pretty<T>(path: &Path, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    tokio::fs::write(path, bytes)
        .await
        .with_context(|| format!("failed to write {}", path.display()))
}

async fn existing_diff_status(path: &Path) -> Result<Option<String>> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string))
}

async fn load_capture(path: &Path) -> Result<CapturedRelease> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::{path::Path, process::Command as StdCommand};

    use super::*;
    use crate::{
        capture::{ArtifactHashes, CapturedArtifact, CapturedRelease, ReleaseStatus},
        event::{Ecosystem, PackageReleaseEvent},
        ledger::EventLedger,
        priority::{PrioritySnapshot, PrioritySource, PriorityTier},
        store,
    };
    use chrono::{TimeZone, Utc};
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn worker_writes_diff_artifacts_for_observed_release() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let store = store::OperationalStore::open(store::index_db_path(&data_dir))
            .await
            .unwrap();
        let artifact_dir = temp.path().join("artifacts");
        tokio::fs::create_dir_all(&artifact_dir).await.unwrap();

        let baseline_artifact = artifact_dir.join("pkg-1.0.0.tgz");
        let target_artifact = artifact_dir.join("pkg-1.1.0.tgz");
        create_tgz(
            &baseline_artifact,
            &[("package/index.js", "module.exports = 'safe';\n")],
        );
        create_tgz(
            &target_artifact,
            &[("package/index.js", "module.exports = 'changed';\n")],
        );

        let baseline_event = sample_event("1.0.0");
        let target_event = sample_event("1.1.0");
        let ledger = EventLedger::open(crate::ledger::observed_ledger_path(&data_dir))
            .await
            .unwrap();
        ledger.append(&baseline_event).await.unwrap();
        ledger.append(&target_event).await.unwrap();

        write_capture(
            &history::capture_dir_for_event(&data_dir, &baseline_event),
            sample_capture("1.0.0", &baseline_artifact),
        )
        .await;
        write_capture(
            &history::capture_dir_for_event(&data_dir, &target_event),
            sample_capture("1.1.0", &target_artifact),
        )
        .await;

        let (tx, rx) = mpsc::channel(1);
        tx.send(DiffRequest::new(target_event.clone()))
            .await
            .unwrap();
        drop(tx);

        DiffWorker::new(
            AutoDiffConfig {
                queue_capacity: 1,
                worker_concurrency: 2,
                data_dir: data_dir.clone(),
                include_patches: false,
                patch_context: 2,
                write_markdown: true,
                backfill_lineage: false,
            },
            rx,
            store,
            RuntimeStats::default(),
            None,
        )
        .run()
        .await
        .unwrap();

        let capture_dir = history::capture_dir_for_event(&data_dir, &target_event);
        let diff_json = capture_dir.join("diff.json");
        let diff_md = capture_dir.join("diff.md");
        assert!(diff_json.exists());
        assert!(diff_md.exists());

        let stored: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&diff_json).await.unwrap()).unwrap();
        assert_eq!(stored["status"], "ready");
        assert_eq!(stored["baseline_version"], "1.0.0");
        assert!(stored["diff"].is_object());

        let markdown = tokio::fs::read_to_string(&diff_md).await.unwrap();
        assert!(markdown.contains("# Release Diff: `npm:pkg`"));
        assert!(markdown.contains("- Baseline: `1.0.0`"));
    }

    fn sample_event(version: &str) -> PackageReleaseEvent {
        PackageReleaseEvent {
            event_id: format!("npm:pkg@{version}"),
            ecosystem: Ecosystem::Npm,
            package: "pkg".to_string(),
            version: version.to_string(),
            published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 11, 0, 0).unwrap()),
            observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::High,
                source: PrioritySource::OfflineScoreFile,
                direct_popularity: Some(10.0),
                propagated_impact: Some(100.0),
                hidden_leverage: Some(2.0),
                computed_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 10, 0, 0).unwrap()),
                score_source_version: Some("test".to_string()),
            }),
        }
    }

    fn sample_capture(version: &str, artifact_path: &Path) -> CapturedRelease {
        CapturedRelease {
            event_id: format!("npm:pkg@{version}"),
            ecosystem: Ecosystem::Npm,
            package: "pkg".to_string(),
            version: version.to_string(),
            observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
            published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 11, 0, 0).unwrap()),
            captured_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 5, 0).unwrap(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: vec![CapturedArtifact {
                filename: format!("pkg-{version}.tgz"),
                kind: Some("npm-tarball".to_string()),
                url: None,
                size_bytes: None,
                uploaded_at: None,
                yanked: None,
                hashes: ArtifactHashes::default(),
                provenance_path: None,
            }],
            upstream_repository: None,
            details: serde_json::json!({
                "local_artifact": {
                    "path": artifact_path.display().to_string(),
                }
            }),
        }
    }

    async fn write_capture(dir: &Path, capture: CapturedRelease) {
        tokio::fs::create_dir_all(dir).await.unwrap();
        tokio::fs::write(
            dir.join("capture.json"),
            serde_json::to_vec_pretty(&capture).unwrap(),
        )
        .await
        .unwrap();
    }

    fn create_tgz(destination: &Path, files: &[(&str, &str)]) {
        let staging = tempdir().unwrap();
        for (relative, body) in files {
            let path = staging.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }

        let status = StdCommand::new("tar")
            .arg("-czf")
            .arg(destination)
            .arg("-C")
            .arg(staging.path())
            .arg(".")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
