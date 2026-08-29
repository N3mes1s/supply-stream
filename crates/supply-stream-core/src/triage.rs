use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::Arc,
    time::Instant,
};

use anyhow::Result;
use chrono::{Duration as ChronoDuration, Utc};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    bounded_map::BoundedMap,
    capture::{
        CaptureRequest, CapturedRelease, capture_has_benign_install_time_execution,
        capture_has_install_time_execution, captured_metadata_risk,
        hydrate_release_metadata_for_priority,
    },
    config::TriageConfig,
    event::{Ecosystem, EmittedGraphEvidence, PackageReleaseEvent},
    perf::RuntimeStats,
    priority::{PriorityResolver, PriorityTier},
    store::OperationalStore,
};

#[derive(Debug, Clone)]
pub struct TriageRequest {
    pub event: PackageReleaseEvent,
    pub graph: EmittedGraphEvidence,
    pub notify_diff: bool,
    pub enqueued_at: Instant,
}

impl TriageRequest {
    pub fn observed(
        event: PackageReleaseEvent,
        graph: EmittedGraphEvidence,
        notify_diff: bool,
    ) -> Self {
        Self {
            event,
            graph,
            notify_diff,
            enqueued_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageDecision {
    pub promote: bool,
    pub reason: String,
}

pub struct TriageWorker {
    http: reqwest::Client,
    config: TriageConfig,
    rx: mpsc::Receiver<TriageRequest>,
    capture_tx: mpsc::Sender<CaptureRequest>,
    priority: Option<PriorityResolver>,
    store: OperationalStore,
    perf: RuntimeStats,
}

impl TriageWorker {
    pub fn new(
        http: reqwest::Client,
        config: TriageConfig,
        rx: mpsc::Receiver<TriageRequest>,
        capture_tx: mpsc::Sender<CaptureRequest>,
        priority: Option<PriorityResolver>,
        store: OperationalStore,
        perf: RuntimeStats,
    ) -> Self {
        Self {
            http,
            config,
            rx,
            capture_tx,
            priority,
            store,
            perf,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let concurrency = self.config.worker_concurrency.max(1);
        let mut in_flight = JoinSet::new();

        while let Some(request) = self.rx.recv().await {
            let http = self.http.clone();
            let config = self.config.clone();
            let capture_tx = self.capture_tx.clone();
            let priority = self.priority.clone();
            let store = self.store.clone();
            let perf = self.perf.clone();
            in_flight.spawn(async move {
                let event_id = request.event.event_id.clone();
                let result =
                    handle_triage_request(http, config, capture_tx, priority, store, perf, request)
                        .await;
                (event_id, result)
            });

            while in_flight.len() >= concurrency {
                join_next_triage(&mut in_flight).await;
            }
        }

        while !in_flight.is_empty() {
            join_next_triage(&mut in_flight).await;
        }

        Ok(())
    }
}

async fn join_next_triage(in_flight: &mut JoinSet<(String, Result<()>)>) {
    let Some(outcome) = in_flight.join_next().await else {
        return;
    };

    match outcome {
        Ok((_, Ok(()))) => {}
        Ok((event_id, Err(error))) => warn!(event_id, error = %error, "metadata triage failed"),
        Err(error) => warn!(error = %error, "metadata triage task join failed"),
    }
}

async fn handle_triage_request(
    http: reqwest::Client,
    config: TriageConfig,
    capture_tx: mpsc::Sender<CaptureRequest>,
    priority: Option<PriorityResolver>,
    store: OperationalStore,
    perf: RuntimeStats,
    request: TriageRequest,
) -> Result<()> {
    let started_at = Instant::now();
    perf.record_triage_started(request.enqueued_at.elapsed());
    let result: Result<()> = async {
        if store
            .load_release_record(&request.event.event_id)
            .await?
            .is_some_and(|record| matches!(record.capture_state.as_str(), "ready" | "skipped"))
        {
            return Ok(());
        }

        if let Some(decision) = fast_triage_decision(&request.event, &request.graph, &config) {
            perf.record_triage_dropped();
            perf.record_capture_skipped();
            store
                .mark_capture_skipped(&request.event.event_id, &decision.reason)
                .await?;
            return Ok(());
        }

        let hydrated = hydrate_release_metadata_for_priority(&http, &request.event).await?;
        let decision = triage_decision(&request.event, &request.graph, hydrated.as_ref(), &config);
        if decision.promote {
            perf.record_triage_promoted();
            perf.record_capture_enqueued();
            capture_tx
                .send(CaptureRequest::triaged(
                    request.event.clone(),
                    request.notify_diff,
                ))
                .await
                .map_err(|error| anyhow::anyhow!("capture worker channel closed: {error}"))?;
        } else {
            if let (Some(priority), Some(capture)) = (priority.as_ref(), hydrated.as_ref()) {
                priority
                    .record_hydrated_release_metadata(&request.event, capture)
                    .await?;
            }
            perf.record_triage_dropped();
            perf.record_capture_skipped();
            store
                .mark_capture_skipped(&request.event.event_id, &decision.reason)
                .await?;
        }
        Ok(())
    }
    .await;

    match &result {
        Ok(()) => perf.record_triage_completed(started_at.elapsed()),
        Err(_) => perf.record_triage_failed(started_at.elapsed()),
    }
    result
}

fn fast_triage_decision(
    event: &PackageReleaseEvent,
    graph: &EmittedGraphEvidence,
    config: &TriageConfig,
) -> Option<TriageDecision> {
    if config.ephemeral_scan_max_artifact_bytes > 0 {
        return None;
    }

    if event.ecosystem == Ecosystem::CratesIo
        && matches!(event.priority_snapshot().tier, PriorityTier::Medium)
        && graph.reverse_dependents_seen == 0
    {
        return Some(TriageDecision {
            promote: false,
            reason: "metadata triage dropped low-impact crates release before metadata hydrate"
                .to_string(),
        });
    }

    None
}

pub fn triage_decision(
    event: &PackageReleaseEvent,
    graph: &EmittedGraphEvidence,
    hydrated: Option<&CapturedRelease>,
    config: &TriageConfig,
) -> TriageDecision {
    if matches!(event.priority_snapshot().tier, PriorityTier::High) {
        return TriageDecision {
            promote: true,
            reason: "high-priority release bypassed metadata triage".to_string(),
        };
    }

    let Some(capture) = hydrated else {
        return TriageDecision {
            promote: false,
            reason: "metadata triage could not resolve release metadata".to_string(),
        };
    };

    let metadata_risk = captured_metadata_risk(capture);
    if metadata_risk.suspicious {
        return TriageDecision {
            promote: true,
            reason: format!("metadata triage promoted release: {}", metadata_risk.reason),
        };
    }

    if let Some(reason) = suspicious_throwaway_installer_reason(event, graph, capture, config) {
        return TriageDecision {
            promote: true,
            reason,
        };
    }

    if capture_has_install_time_execution(capture) {
        let reason = if capture_has_benign_install_time_execution(capture) {
            "metadata triage promoted release: install-time execution present".to_string()
        } else {
            "metadata triage promoted release: risky install-time execution present".to_string()
        };
        return TriageDecision {
            promote: true,
            reason,
        };
    }

    if graph.reverse_dependents_seen > 0 && metadata_risk.score > 0 {
        return TriageDecision {
            promote: true,
            reason:
                "metadata triage promoted release: graph impact strengthened suspicious metadata"
                    .to_string(),
        };
    }

    if let Some(reason) = broad_ephemeral_scan_reason(capture, config) {
        return TriageDecision {
            promote: true,
            reason,
        };
    }

    TriageDecision {
        promote: false,
        reason: "metadata triage dropped low-signal release before capture".to_string(),
    }
}

fn suspicious_throwaway_installer_reason(
    event: &PackageReleaseEvent,
    graph: &EmittedGraphEvidence,
    capture: &CapturedRelease,
    config: &TriageConfig,
) -> Option<String> {
    if !capture_has_install_time_execution(capture) {
        return None;
    }
    if graph.reverse_dependents_seen > 0 {
        return None;
    }

    let repository_missing = capture.upstream_repository.is_none()
        && capture
            .details
            .get("repository")
            .map(serde_json::Value::is_null)
            .unwrap_or(true);
    if !repository_missing {
        return None;
    }

    let artifact_bytes = capture
        .artifacts
        .iter()
        .filter_map(|artifact| artifact.size_bytes)
        .min()
        .unwrap_or(u64::MAX);
    if artifact_bytes > config.suspicious_small_artifact_max_bytes {
        return None;
    }

    let dependency_count = capture
        .details
        .get("dependencies")
        .and_then(serde_json::Value::as_array)
        .map(|dependencies| dependencies.len())
        .unwrap_or(0);
    if dependency_count > 1 {
        return None;
    }

    Some(format!(
        "metadata triage promoted release: small no-repo install-hook package required deep analysis ({})",
        event.package
    ))
}

fn broad_ephemeral_scan_reason(capture: &CapturedRelease, config: &TriageConfig) -> Option<String> {
    if config.ephemeral_scan_max_artifact_bytes == 0 {
        return None;
    }

    let artifact_bytes = capture
        .artifacts
        .iter()
        .filter_map(|artifact| artifact.size_bytes)
        .min()?;
    if artifact_bytes > config.ephemeral_scan_max_artifact_bytes {
        return None;
    }

    Some(format!(
        "metadata triage promoted release: artifact eligible for ephemeral content-risk scan ({} bytes)",
        artifact_bytes
    ))
}

pub async fn run_dropped_capture_audit_loop(
    config: TriageConfig,
    store: OperationalStore,
    capture_tx: mpsc::Sender<CaptureRequest>,
    perf: RuntimeStats,
    shutdown: CancellationToken,
) -> Result<()> {
    let Some(interval_duration) = config.dropped_audit_interval else {
        return Ok(());
    };
    if config.dropped_audit_sample_size == 0 && config.dropped_backfill_batch_size == 0 {
        return Ok(());
    }

    let recently_seen = Arc::new(Mutex::new(BoundedMap::<String, ()>::new(
        config.dropped_history_size.max(1),
    )));
    let mut ticker = interval(interval_duration);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                run_dropped_capture_audit_once(
                    &config,
                    &store,
                    &capture_tx,
                    &perf,
                    &recently_seen,
                ).await?;
            }
        }
    }

    Ok(())
}

async fn run_dropped_capture_audit_once(
    config: &TriageConfig,
    store: &OperationalStore,
    capture_tx: &mpsc::Sender<CaptureRequest>,
    perf: &RuntimeStats,
    recently_seen: &Arc<Mutex<BoundedMap<String, ()>>>,
) -> Result<()> {
    let candidate_limit = (config
        .dropped_audit_sample_size
        .saturating_add(config.dropped_backfill_batch_size))
    .saturating_mul(20)
    .max(32);
    let since = Utc::now() - ChronoDuration::from_std(config.dropped_audit_window)?;
    let records = store
        .load_skipped_capture_records(None, None, Some(since), Some(candidate_limit))
        .await?;
    if records.is_empty() {
        return Ok(());
    }

    let mut selected = Vec::new();
    {
        let mut seen = recently_seen.lock().await;

        for record in records.iter().take(config.dropped_backfill_batch_size) {
            if seen.contains_key(&record.event.event_id) {
                continue;
            }
            selected.push(record.event.clone());
            seen.insert(record.event.event_id.clone(), ());
        }

        if config.dropped_audit_sample_size > 0 {
            let mut sample_records = records;
            sample_records.sort_by_key(|record| stable_event_hash(&record.event.event_id));
            let max_selected = config
                .dropped_backfill_batch_size
                .saturating_add(config.dropped_audit_sample_size);
            for record in sample_records
                .into_iter()
                .take(config.dropped_audit_sample_size.saturating_mul(8))
            {
                if selected.len() >= max_selected {
                    break;
                }
                if seen.contains_key(&record.event.event_id) {
                    continue;
                }
                selected.push(record.event.clone());
                seen.insert(record.event.event_id.clone(), ());
            }
        }
    }

    for event in selected {
        enqueue_dropped_audit_capture(capture_tx, perf, event).await?;
    }

    Ok(())
}

async fn enqueue_dropped_audit_capture(
    capture_tx: &mpsc::Sender<CaptureRequest>,
    perf: &RuntimeStats,
    event: PackageReleaseEvent,
) -> Result<()> {
    capture_tx
        .send(CaptureRequest::triaged(event, false))
        .await
        .map_err(|error| {
            anyhow::anyhow!("capture worker channel closed during dropped-package audit: {error}")
        })?;
    perf.record_capture_enqueued();
    Ok(())
}

fn stable_event_hash(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::{
        capture::{CapturedArtifact, ReleaseStatus},
        event::Ecosystem,
        priority::{PrioritySnapshot, PrioritySource},
    };

    fn sample_config() -> TriageConfig {
        TriageConfig {
            queue_capacity: 32,
            worker_concurrency: 1,
            suspicious_small_artifact_max_bytes: 32 * 1024,
            ephemeral_scan_max_artifact_bytes: 64 * 1024 * 1024,
            dropped_audit_interval: None,
            dropped_audit_window: std::time::Duration::from_secs(3600),
            dropped_audit_sample_size: 0,
            dropped_backfill_batch_size: 0,
            dropped_history_size: 128,
        }
    }

    fn sample_event() -> PackageReleaseEvent {
        PackageReleaseEvent {
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
        }
    }

    fn sample_capture(details: serde_json::Value) -> CapturedRelease {
        let event = sample_event();
        CapturedRelease {
            event_id: event.event_id,
            ecosystem: event.ecosystem,
            package: event.package,
            version: event.version,
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::<CapturedArtifact>::new(),
            upstream_repository: None,
            details,
        }
    }

    #[test]
    fn triage_promotes_install_hooks() {
        let decision = triage_decision(
            &sample_event(),
            &EmittedGraphEvidence::default(),
            Some(&sample_capture(json!({
                "has_install_scripts": true,
                "install_scripts_benign": false
            }))),
            &sample_config(),
        );
        assert!(decision.promote);
    }

    #[test]
    fn triage_drops_clean_low_signal_release() {
        let mut config = sample_config();
        config.ephemeral_scan_max_artifact_bytes = 0;
        let decision = triage_decision(
            &sample_event(),
            &EmittedGraphEvidence::default(),
            Some(&sample_capture(json!({
                "dependencies": [],
                "has_install_scripts": false,
                "metadata_risk": {
                    "suspicious": false,
                    "score": 0,
                    "factors": [],
                    "reason": "clean"
                }
            }))),
            &config,
        );
        assert!(!decision.promote);
    }

    #[test]
    fn triage_promotes_small_no_repo_install_hook_package() {
        let mut capture = sample_capture(json!({
            "dependencies": [],
            "repository": null,
            "has_install_scripts": true,
            "install_scripts_benign": false,
            "metadata_risk": {
                "suspicious": false,
                "score": 0,
                "factors": [],
                "reason": "clean"
            }
        }));
        capture.artifacts.push(CapturedArtifact {
            filename: "demo-1.0.0.tgz".to_string(),
            kind: Some("npm-tarball".to_string()),
            url: None,
            size_bytes: Some(4096),
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        });

        let decision = triage_decision(
            &sample_event(),
            &EmittedGraphEvidence::default(),
            Some(&capture),
            &sample_config(),
        );
        assert!(decision.promote);
        assert!(
            decision
                .reason
                .contains("small no-repo install-hook package")
        );
    }

    #[test]
    fn fast_triage_drops_medium_crates_without_reverse_dependents() {
        let mut event = sample_event();
        event.ecosystem = Ecosystem::CratesIo;
        event.event_id = "crates-io:demo@1.0.0".to_string();
        let mut config = sample_config();
        config.ephemeral_scan_max_artifact_bytes = 0;
        let decision = fast_triage_decision(&event, &EmittedGraphEvidence::default(), &config);
        assert!(decision.is_some());
        assert!(!decision.expect("decision").promote);
    }

    #[test]
    fn fast_triage_keeps_npm_on_metadata_path() {
        let decision = fast_triage_decision(
            &sample_event(),
            &EmittedGraphEvidence::default(),
            &sample_config(),
        );
        assert!(decision.is_none());
    }

    #[test]
    fn triage_promotes_ephemeral_scan_for_small_clean_release() {
        let mut capture = sample_capture(json!({
            "dependencies": [],
            "has_install_scripts": false,
            "metadata_risk": {
                "suspicious": false,
                "score": 0,
                "factors": [],
                "reason": "clean"
            }
        }));
        capture.artifacts.push(CapturedArtifact {
            filename: "demo-1.0.0.tgz".to_string(),
            kind: Some("npm-tarball".to_string()),
            url: Some("https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string()),
            size_bytes: Some(4096),
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        });

        let decision = triage_decision(
            &sample_event(),
            &EmittedGraphEvidence::default(),
            Some(&capture),
            &sample_config(),
        );
        assert!(decision.promote);
        assert!(decision.reason.contains("ephemeral content-risk scan"));
    }
}
