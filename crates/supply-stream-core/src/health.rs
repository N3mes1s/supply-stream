use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::perf::{RuntimeSnapshot, RuntimeStats};

#[derive(Clone, Debug)]
pub struct HealthState {
    inner: Arc<HealthInner>,
}

#[derive(Debug)]
struct HealthInner {
    configured_sources: u64,
    stopped_sources: AtomicU64,
    failed_sources: AtomicU64,
    triage_worker_failed: AtomicBool,
    capture_worker_failed: AtomicBool,
    diff_worker_failed: AtomicBool,
    shutting_down: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub configured_sources: u64,
    pub stopped_sources: u64,
    pub failed_sources: u64,
    pub triage_worker_failed: bool,
    pub capture_worker_failed: bool,
    pub diff_worker_failed: bool,
    pub shutting_down: bool,
}

impl HealthState {
    pub fn new(configured_sources: usize) -> Self {
        Self {
            inner: Arc::new(HealthInner {
                configured_sources: configured_sources as u64,
                stopped_sources: AtomicU64::new(0),
                failed_sources: AtomicU64::new(0),
                triage_worker_failed: AtomicBool::new(false),
                capture_worker_failed: AtomicBool::new(false),
                diff_worker_failed: AtomicBool::new(false),
                shutting_down: AtomicBool::new(false),
            }),
        }
    }

    pub fn record_source_exit(&self, success: bool) {
        self.inner.stopped_sources.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.inner.failed_sources.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_capture_worker_exit(&self, success: bool) {
        if !success {
            self.inner
                .capture_worker_failed
                .store(true, Ordering::Relaxed);
        }
    }

    pub fn record_triage_worker_exit(&self, success: bool) {
        if !success {
            self.inner
                .triage_worker_failed
                .store(true, Ordering::Relaxed);
        }
    }

    pub fn record_diff_worker_exit(&self, success: bool) {
        if !success {
            self.inner.diff_worker_failed.store(true, Ordering::Relaxed);
        }
    }

    pub fn mark_shutting_down(&self) {
        self.inner.shutting_down.store(true, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        HealthSnapshot {
            configured_sources: self.inner.configured_sources,
            stopped_sources: self.inner.stopped_sources.load(Ordering::Relaxed),
            failed_sources: self.inner.failed_sources.load(Ordering::Relaxed),
            triage_worker_failed: self.inner.triage_worker_failed.load(Ordering::Relaxed),
            capture_worker_failed: self.inner.capture_worker_failed.load(Ordering::Relaxed),
            diff_worker_failed: self.inner.diff_worker_failed.load(Ordering::Relaxed),
            shutting_down: self.inner.shutting_down.load(Ordering::Relaxed),
        }
    }
}

pub async fn run_server(
    bind: SocketAddr,
    runtime_stats: RuntimeStats,
    health_state: HealthState,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind health server on {bind}"))?;
    info!(bind = %bind, "health server listening");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accept = listener.accept() => {
                let (stream, peer) = accept.with_context(|| format!("health server accept failed on {bind}"))?;
                let runtime_stats = runtime_stats.clone();
                let health_state = health_state.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, runtime_stats, health_state).await {
                        warn!(peer = %peer, error = %error, "health server request failed");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    runtime_stats: RuntimeStats,
    health_state: HealthState,
) -> Result<()> {
    let mut buffer = [0u8; 2048];
    let bytes_read = stream
        .read(&mut buffer)
        .await
        .context("failed to read health request")?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let snapshot = runtime_stats.snapshot();
    let health = health_state.snapshot();
    let ready = !health.shutting_down
        && health.failed_sources == 0
        && !health.triage_worker_failed
        && !health.capture_worker_failed
        && !health.diff_worker_failed;

    let (status_code, content_type, body) = match path {
        "/health" => (
            "200 OK",
            "application/json",
            serde_json::to_vec(&render_health_json(&snapshot, &health, ready))
                .context("failed to serialize /health response")?,
        ),
        "/ready" => (
            if ready {
                "200 OK"
            } else {
                "503 Service Unavailable"
            },
            "application/json",
            serde_json::to_vec(&render_ready_json(&health, ready))
                .context("failed to serialize /ready response")?,
        ),
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4",
            render_metrics(&snapshot, &health, ready).into_bytes(),
        ),
        _ => (
            "404 Not Found",
            "application/json",
            serde_json::to_vec(&json!({"error":"not_found"}))
                .context("failed to serialize not_found response")?,
        ),
    };
    let response = format!(
        "HTTP/1.1 {status_code}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("failed to write health response header")?;
    stream
        .write_all(&body)
        .await
        .context("failed to write health response body")?;
    Ok(())
}

fn render_health_json(
    snapshot: &RuntimeSnapshot,
    health: &HealthSnapshot,
    ready: bool,
) -> serde_json::Value {
    json!({
        "status": if ready { "ok" } else if health.shutting_down { "shutting_down" } else { "degraded" },
        "runtime": {
            "elapsed_secs": snapshot.elapsed.as_secs_f64(),
            "observed_events": snapshot.observed_events,
            "observed_per_sec": snapshot.observed_per_sec,
            "staging_cache_entries": snapshot.staging_cache_entries,
            "staging_cache_bytes": snapshot.staging_cache_bytes,
            "triage_queue_backlog": snapshot.triage_queue_backlog,
            "triage_in_flight": snapshot.triage_in_flight,
            "capture_queue_backlog": snapshot.capture_queue_backlog,
            "capture_in_flight": snapshot.capture_in_flight,
            "diff_queue_backlog": snapshot.diff_queue_backlog,
            "diff_in_flight": snapshot.diff_in_flight,
        },
        "sources": {
            "configured": health.configured_sources,
            "stopped": health.stopped_sources,
            "failed": health.failed_sources,
        },
        "workers": {
            "triage_failed": health.triage_worker_failed,
            "capture_failed": health.capture_worker_failed,
            "diff_failed": health.diff_worker_failed,
        }
    })
}

fn render_ready_json(health: &HealthSnapshot, ready: bool) -> serde_json::Value {
    json!({
        "ready": ready,
        "shutting_down": health.shutting_down,
        "failed_sources": health.failed_sources,
        "triage_worker_failed": health.triage_worker_failed,
        "capture_worker_failed": health.capture_worker_failed,
        "diff_worker_failed": health.diff_worker_failed,
    })
}

fn render_metrics(snapshot: &RuntimeSnapshot, health: &HealthSnapshot, ready: bool) -> String {
    let mut output = String::new();

    push_metric_help(
        &mut output,
        "supply_stream_ready",
        "Whether the service is currently ready to serve.",
        "gauge",
    );
    push_metric_value(&mut output, "supply_stream_ready", ready as u8 as f64);

    push_metric_help(
        &mut output,
        "supply_stream_shutting_down",
        "Whether the service is shutting down.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_shutting_down",
        health.shutting_down as u8 as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_sources_configured",
        "Number of configured package sources.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_sources_configured",
        health.configured_sources as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_sources_stopped_total",
        "Number of package sources that have stopped.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_sources_stopped_total",
        health.stopped_sources as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_sources_failed_total",
        "Number of package sources that have failed.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_sources_failed_total",
        health.failed_sources as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_worker_failed",
        "Whether the triage worker has failed.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_worker_failed",
        health.triage_worker_failed as u8 as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_worker_failed",
        "Whether the capture worker has failed.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_worker_failed",
        health.capture_worker_failed as u8 as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_worker_failed",
        "Whether the diff worker has failed.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_worker_failed",
        health.diff_worker_failed as u8 as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_runtime_elapsed_seconds",
        "Time elapsed since the service started.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_runtime_elapsed_seconds",
        snapshot.elapsed.as_secs_f64(),
    );

    push_metric_help(
        &mut output,
        "supply_stream_observed_events_total",
        "Total number of observed package release events.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_observed_events_total",
        snapshot.observed_events as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_observed_events_per_second",
        "Current rate of observed events per second.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_observed_events_per_second",
        snapshot.observed_per_sec,
    );

    push_metric_help(
        &mut output,
        "supply_stream_priority_events_total",
        "Total observed events by priority tier.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_priority_events_total{bucket=\"high\"}",
        snapshot.priority_high as f64,
    );
    push_metric_value(
        &mut output,
        "supply_stream_priority_events_total{bucket=\"medium\"}",
        snapshot.priority_medium as f64,
    );
    push_metric_value(
        &mut output,
        "supply_stream_priority_events_total{bucket=\"low\"}",
        snapshot.priority_low as f64,
    );
    push_metric_value(
        &mut output,
        "supply_stream_priority_events_total{bucket=\"unknown\"}",
        snapshot.priority_unknown as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_enqueued_total",
        "Total triage requests enqueued.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_enqueued_total",
        snapshot.triage_enqueued as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_started_total",
        "Total triage requests started.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_started_total",
        snapshot.triage_started as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_completed_total",
        "Total triage requests completed.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_completed_total",
        snapshot.triage_completed as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_failed_total",
        "Total triage requests that failed.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_failed_total",
        snapshot.triage_failed as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_dropped_total",
        "Total triage requests dropped without promotion.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_dropped_total",
        snapshot.triage_dropped as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_promoted_total",
        "Total triage requests promoted to capture.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_promoted_total",
        snapshot.triage_promoted as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_queue_backlog",
        "Current triage queue depth.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_queue_backlog",
        snapshot.triage_queue_backlog as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_in_flight",
        "Number of triage requests currently in flight.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_in_flight",
        snapshot.triage_in_flight as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_queue_avg_ms",
        "Average triage queue wait time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_queue_avg_ms",
        snapshot.triage_queue_avg_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_run_avg_ms",
        "Average triage processing time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_run_avg_ms",
        snapshot.triage_run_avg_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_triage_run_max_ms",
        "Maximum triage processing time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_triage_run_max_ms",
        snapshot.triage_run_max_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_staging_cache_entries",
        "Number of entries in the artifact staging cache.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_staging_cache_entries",
        snapshot.staging_cache_entries as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_staging_cache_bytes",
        "Total bytes used by the artifact staging cache.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_staging_cache_bytes",
        snapshot.staging_cache_bytes as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_staging_cache_pruned_total",
        "Total entries pruned from the staging cache.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_staging_cache_pruned_total",
        snapshot.staging_cache_pruned as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_staging_cache_promoted_total",
        "Total entries promoted from staging to permanent capture.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_staging_cache_promoted_total",
        snapshot.staging_cache_promoted as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_staging_cache_discarded_total",
        "Total entries discarded from the staging cache.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_staging_cache_discarded_total",
        snapshot.staging_cache_discarded as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_enqueued_total",
        "Total capture requests enqueued.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_enqueued_total",
        snapshot.capture_enqueued as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_skipped_total",
        "Total capture requests skipped.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_skipped_total",
        snapshot.capture_skipped as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_started_total",
        "Total capture requests started.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_started_total",
        snapshot.capture_started as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_completed_total",
        "Total capture requests completed.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_completed_total",
        snapshot.capture_completed as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_failed_total",
        "Total capture requests that failed.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_failed_total",
        snapshot.capture_failed as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_queue_backlog",
        "Current capture queue depth.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_queue_backlog",
        snapshot.capture_queue_backlog as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_in_flight",
        "Number of capture requests currently in flight.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_in_flight",
        snapshot.capture_in_flight as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_queue_avg_ms",
        "Average capture queue wait time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_queue_avg_ms",
        snapshot.capture_queue_avg_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_run_avg_ms",
        "Average capture processing time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_run_avg_ms",
        snapshot.capture_run_avg_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_capture_run_max_ms",
        "Maximum capture processing time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_capture_run_max_ms",
        snapshot.capture_run_max_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_content_scan_completed_total",
        "Total content-risk scans completed.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_content_scan_completed_total",
        snapshot.content_scan_completed as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_content_scan_avg_ms",
        "Average content-risk scan time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_content_scan_avg_ms",
        snapshot.content_scan_avg_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_content_scan_max_ms",
        "Maximum content-risk scan time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_content_scan_max_ms",
        snapshot.content_scan_max_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_enqueued_total",
        "Total diff requests enqueued.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_enqueued_total",
        snapshot.diff_enqueued as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_skipped_total",
        "Total diff requests skipped.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_skipped_total",
        snapshot.diff_skipped as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_started_total",
        "Total diff requests started.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_started_total",
        snapshot.diff_started as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_completed_total",
        "Total diff requests completed.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_completed_total",
        snapshot.diff_completed as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_failed_total",
        "Total diff requests that failed.",
        "counter",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_failed_total",
        snapshot.diff_failed as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_queue_backlog",
        "Current diff queue depth.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_queue_backlog",
        snapshot.diff_queue_backlog as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_in_flight",
        "Number of diff requests currently in flight.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_in_flight",
        snapshot.diff_in_flight as f64,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_queue_avg_ms",
        "Average diff queue wait time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_queue_avg_ms",
        snapshot.diff_queue_avg_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_run_avg_ms",
        "Average diff processing time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_run_avg_ms",
        snapshot.diff_run_avg_ms,
    );

    push_metric_help(
        &mut output,
        "supply_stream_diff_run_max_ms",
        "Maximum diff processing time in milliseconds.",
        "gauge",
    );
    push_metric_value(
        &mut output,
        "supply_stream_diff_run_max_ms",
        snapshot.diff_run_max_ms,
    );

    output
}

fn push_metric_help(output: &mut String, name: &str, help: &str, metric_type: &str) {
    output.push_str(&format!("# HELP {name} {help}\n"));
    output.push_str(&format!("# TYPE {name} {metric_type}\n"));
}

fn push_metric_value(output: &mut String, name: &str, value: f64) {
    output.push_str(&format!("{name} {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_reflects_failed_workers() {
        let state = HealthState::new(3);
        assert_eq!(
            state.snapshot(),
            HealthSnapshot {
                configured_sources: 3,
                stopped_sources: 0,
                failed_sources: 0,
                triage_worker_failed: false,
                capture_worker_failed: false,
                diff_worker_failed: false,
                shutting_down: false,
            }
        );

        state.record_capture_worker_exit(false);
        let snapshot = state.snapshot();
        assert!(snapshot.capture_worker_failed);
        assert!(!snapshot.diff_worker_failed);
        assert_eq!(snapshot.failed_sources, 0);
    }

    #[test]
    fn metrics_output_includes_readiness_and_runtime_counters() {
        let metrics = render_metrics(
            &RuntimeSnapshot {
                elapsed: std::time::Duration::from_secs(10),
                observed_events: 42,
                observed_per_sec: 4.2,
                ledger_append_avg_ms: 1.0,
                store_event_write_avg_ms: 2.0,
                sink_publish_avg_ms: 3.0,
                priority_high: 1,
                priority_medium: 2,
                priority_low: 3,
                priority_unknown: 4,
                triage_enqueued: 5,
                triage_started: 6,
                triage_completed: 7,
                triage_failed: 8,
                triage_dropped: 9,
                triage_promoted: 10,
                triage_queue_backlog: 11,
                triage_in_flight: 12,
                triage_queue_avg_ms: 13.0,
                triage_run_avg_ms: 14.0,
                triage_run_max_ms: 15.0,
                staging_cache_entries: 16,
                staging_cache_bytes: 2048,
                staging_cache_pruned: 17,
                staging_cache_promoted: 18,
                staging_cache_discarded: 19,
                capture_enqueued: 20,
                capture_skipped: 21,
                capture_started: 22,
                capture_completed: 23,
                capture_failed: 24,
                capture_queue_backlog: 25,
                capture_in_flight: 26,
                capture_queue_avg_ms: 27.0,
                capture_run_avg_ms: 28.0,
                capture_run_max_ms: 29.0,
                content_scan_completed: 43,
                content_scan_avg_ms: 12.0,
                content_scan_max_ms: 44.0,
                diff_enqueued: 30,
                diff_skipped: 31,
                diff_started: 32,
                diff_completed: 33,
                diff_failed: 34,
                diff_queue_backlog: 35,
                diff_in_flight: 36,
                diff_queue_avg_ms: 37.0,
                diff_run_avg_ms: 38.0,
                diff_run_max_ms: 39.0,
            },
            &HealthSnapshot {
                configured_sources: 3,
                stopped_sources: 1,
                failed_sources: 0,
                triage_worker_failed: false,
                capture_worker_failed: false,
                diff_worker_failed: true,
                shutting_down: false,
            },
            false,
        );

        assert!(metrics.contains("# HELP supply_stream_ready"));
        assert!(metrics.contains("supply_stream_ready 0"));
        assert!(metrics.contains("supply_stream_observed_events_total 42"));
        assert!(metrics.contains("supply_stream_staging_cache_entries 16"));
        assert!(metrics.contains("supply_stream_priority_events_total{bucket=\"high\"} 1"));
        assert!(metrics.contains("supply_stream_diff_worker_failed 1"));
    }
}
