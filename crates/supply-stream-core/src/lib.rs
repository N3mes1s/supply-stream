pub mod assessment;
pub mod autodiff;
pub mod bounded_map;
pub mod bundle;
pub mod capture;
pub mod census;
pub mod collector;
pub mod config;
pub mod content_risk;
pub mod deps_dev;
pub mod deps_dev_bigquery;
pub mod detection;
pub mod diff;
pub mod event;
pub mod health;
pub mod history;
pub mod install_scripts;
pub mod ledger;
pub mod perf;
pub mod priority;
pub mod priority_view;
pub mod repo_provenance;
pub mod scoring;
pub mod sink;
pub mod sources;
pub mod state;
pub mod store;
pub mod triage;
pub mod visibility;

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use config::AppConfig;
use health::HealthState;
use ledger::EventLedger;
use perf::RuntimeStats;
use priority::PriorityResolver;
use priority_view::PriorityViewTracker;
use sink::{EventSink, StdoutNdjsonSink};
use store::{EventOrigin, OperationalStore};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

pub async fn run(config: AppConfig) -> Result<()> {
    let http = reqwest::Client::builder()
        .user_agent("supply-stream/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .context("failed to build HTTP client")?;

    let state_store = state::FileStateStore::new(config.state_dir.clone());
    let sink: Arc<dyn EventSink> = Arc::new(StdoutNdjsonSink::new());
    let event_ledger =
        Arc::new(EventLedger::open(config.capture.observed_event_log_path.clone()).await?);
    let store = OperationalStore::open(store::index_db_path(&config.data_dir)).await?;
    let runtime_stats = RuntimeStats::default();
    let health_state = HealthState::new(config.ecosystems.len());
    let priority_view = PriorityViewTracker::new(config.priority_view.recent_capacity);
    if store.event_count().await? == 0 {
        let reconcile = store.reconcile_local_data(&config.data_dir).await?;
        if reconcile.events > 0 || reconcile.captures > 0 || reconcile.diffs > 0 {
            info!(
                events = reconcile.events,
                captures = reconcile.captures,
                diffs = reconcile.diffs,
                path = %store.path().display(),
                "reconciled operational store from local data"
            );
        }
    }
    let priority = PriorityResolver::load(&config.priority).await?;
    let source_shutdown = CancellationToken::new();
    let health_shutdown = CancellationToken::new();
    let perf_shutdown = CancellationToken::new();
    let staging_cache_shutdown = CancellationToken::new();
    let dropped_audit_shutdown = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(config.channel_capacity);
    let (triage_tx, triage_rx) = mpsc::channel(config.triage.queue_capacity);
    let (capture_tx, capture_rx) = mpsc::channel(config.capture.queue_capacity);
    let (diff_tx, diff_rx) = mpsc::channel(config.autodiff.queue_capacity);
    let mut handles = Vec::new();
    let perf_task = tokio::spawn(perf::run_periodic_reporter(
        runtime_stats.clone(),
        config.runtime_stats_interval,
        perf_shutdown.clone(),
    ));
    let priority_view_task = tokio::spawn(priority_view::run_periodic_reporter(
        priority_view.clone(),
        config.priority_view.interval,
        config.priority_view.top_limit,
        perf_shutdown.clone(),
    ));
    let health_task = config.health.bind.map(|bind| {
        tokio::spawn(health::run_server(
            bind,
            runtime_stats.clone(),
            health_state.clone(),
            health_shutdown.clone(),
        ))
    });
    let capture_worker_health = health_state.clone();
    let capture_http = http.clone();
    let capture_config = config.capture.clone();
    let capture_priority = priority.clone();
    let capture_sink = sink.clone();
    let capture_store = store.clone();
    let capture_runtime_stats = runtime_stats.clone();
    let capture_diff_tx = diff_tx.clone();
    let capture_worker = tokio::spawn(async move {
        let result = capture::CaptureWorker::new(
            capture_http,
            capture_config,
            capture_rx,
            Some(capture_diff_tx),
            Some(capture_priority),
            Some(capture_sink),
            capture_store,
            capture_runtime_stats,
        )
        .run_requests_only()
        .await;
        capture_worker_health.record_capture_worker_exit(result.is_ok());
        result
    });
    let staging_cache_config = config.capture.clone();
    let staging_cache_task = tokio::spawn(capture::run_staging_cache_sweeper(
        staging_cache_config,
        runtime_stats.clone(),
        staging_cache_shutdown.clone(),
    ));
    let triage_worker_health = health_state.clone();
    let triage_http = http.clone();
    let triage_config = config.triage.clone();
    let triage_store = store.clone();
    let triage_capture_tx = capture_tx.clone();
    let triage_priority = Some(priority.clone());
    let triage_runtime_stats = runtime_stats.clone();
    let triage_worker = tokio::spawn(async move {
        let result = triage::TriageWorker::new(
            triage_http,
            triage_config,
            triage_rx,
            triage_capture_tx,
            triage_priority,
            triage_store,
            triage_runtime_stats,
        )
        .run()
        .await;
        triage_worker_health.record_triage_worker_exit(result.is_ok());
        result
    });
    let dropped_audit_config = config.triage.clone();
    let dropped_audit_store = store.clone();
    let dropped_audit_capture_tx = capture_tx.clone();
    let dropped_audit_runtime_stats = runtime_stats.clone();
    let dropped_audit_task = tokio::spawn(triage::run_dropped_capture_audit_loop(
        dropped_audit_config,
        dropped_audit_store,
        dropped_audit_capture_tx,
        dropped_audit_runtime_stats,
        dropped_audit_shutdown.clone(),
    ));
    let diff_worker_health = health_state.clone();
    let diff_config = config.autodiff.clone();
    let diff_store = store.clone();
    let diff_runtime_stats = runtime_stats.clone();
    let diff_sink = sink.clone();
    let diff_worker = tokio::spawn(async move {
        let result = autodiff::DiffWorker::new(
            diff_config,
            diff_rx,
            diff_store,
            diff_runtime_stats,
            Some(diff_sink),
        )
        .run()
        .await;
        diff_worker_health.record_diff_worker_exit(result.is_ok());
        result
    });

    for source in sources::build_sources(
        &config,
        &http,
        tx.clone(),
        state_store.clone(),
        source_shutdown.clone(),
    ) {
        let source_name = source.name();
        let source_health = health_state.clone();
        handles.push((
            source_name,
            tokio::spawn(async move {
                let result = source.run().await;
                source_health.record_source_exit(result.is_ok());
                result
            }),
        ));
    }
    drop(tx);

    let mut shutting_down = false;
    loop {
        tokio::select! {
            maybe_event = rx.recv() => match maybe_event {
                Some(event) => {
                    let event = priority.apply(event).await;
                    let priority_snapshot = event.priority_snapshot();
                    priority_view.record(&event);
                    runtime_stats.record_observed_event();
                    runtime_stats.record_priority(&priority_snapshot);

                    let started = std::time::Instant::now();
                    event_ledger.append(&event).await?;
                    runtime_stats.record_ledger_append(started.elapsed());

                    let started = std::time::Instant::now();
                    store.record_event(&event, EventOrigin::Observed).await?;
                    runtime_stats.record_store_event_write(started.elapsed());

                    let started = std::time::Instant::now();
                    let graph = priority
                        .emitted_graph_evidence(event.ecosystem, &event.package)
                        .await;
                    let diff_requested = event.diff_requested_with_graph(&graph);
                    let emitted = event.emitted_view(graph.clone());
                    sink.publish(&emitted).await?;
                    runtime_stats.record_sink_publish(started.elapsed());

                    if matches!(priority_snapshot.tier, crate::priority::PriorityTier::High) {
                        let capture_request =
                            capture::CaptureRequest::observed(event, diff_requested);
                        if let Err(error) = capture_tx.send(capture_request).await {
                            warn!(error = %error, "capture worker channel closed");
                        } else {
                            runtime_stats.record_capture_enqueued();
                            if !diff_requested {
                                runtime_stats.record_diff_skipped();
                            }
                        }
                    } else {
                        let triage_request =
                            triage::TriageRequest::observed(event, graph, diff_requested);
                        if let Err(error) = triage_tx.send(triage_request).await {
                            warn!(error = %error, "triage worker channel closed");
                        } else {
                            runtime_stats.record_triage_enqueued();
                            if !diff_requested {
                            runtime_stats.record_diff_skipped();
                            }
                        }
                    }
                }
                None => break,
            },
            result = tokio::signal::ctrl_c(), if !shutting_down => {
                result.context("failed to listen for ctrl-c")?;
                info!("received shutdown signal");
                health_state.mark_shutting_down();
                source_shutdown.cancel();
                shutting_down = true;
            }
        }
    }

    drop(triage_tx);
    match triage_worker.await {
        Ok(Ok(())) => info!("triage worker stopped"),
        Ok(Err(error)) => warn!(error = %error, "triage worker exited with error"),
        Err(error) => warn!(error = %error, "triage worker task join failed"),
    }

    drop(capture_tx);

    for (source_name, handle) in handles {
        match handle.await {
            Ok(Ok(())) => info!(source = source_name, "source stopped"),
            Ok(Err(error)) => {
                warn!(source = source_name, error = %error, "source exited with error")
            }
            Err(error) => warn!(source = source_name, error = %error, "source task join failed"),
        }
    }

    match capture_worker.await {
        Ok(Ok(())) => info!("capture worker stopped"),
        Ok(Err(error)) => warn!(error = %error, "capture worker exited with error"),
        Err(error) => warn!(error = %error, "capture worker task join failed"),
    }

    drop(diff_tx);
    match diff_worker.await {
        Ok(Ok(())) => info!("diff worker stopped"),
        Ok(Err(error)) => warn!(error = %error, "diff worker exited with error"),
        Err(error) => warn!(error = %error, "diff worker task join failed"),
    }

    perf_shutdown.cancel();
    health_shutdown.cancel();
    staging_cache_shutdown.cancel();
    dropped_audit_shutdown.cancel();
    let _ = perf_task.await;
    let _ = priority_view_task.await;
    match staging_cache_task.await {
        Ok(Ok(())) => info!("staging cache sweeper stopped"),
        Ok(Err(error)) => warn!(error = %error, "staging cache sweeper exited with error"),
        Err(error) => warn!(error = %error, "staging cache sweeper task join failed"),
    }
    if let Some(task) = health_task {
        match task.await {
            Ok(Ok(())) => info!("health server stopped"),
            Ok(Err(error)) => warn!(error = %error, "health server exited with error"),
            Err(error) => warn!(error = %error, "health server task join failed"),
        }
    }
    match dropped_audit_task.await {
        Ok(Ok(())) => info!("dropped-package audit loop stopped"),
        Ok(Err(error)) => warn!(error = %error, "dropped-package audit loop exited with error"),
        Err(error) => warn!(error = %error, "dropped-package audit loop task join failed"),
    }
    runtime_stats.log_snapshot("shutdown");
    priority_view.log_snapshot("shutdown", config.priority_view.top_limit);

    Ok(())
}

pub fn init_tracing(filter: &str) -> Result<()> {
    let env_filter = EnvFilter::try_new(filter)
        .or_else(|_| EnvFilter::try_new("info"))
        .context("failed to parse log filter")?;

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .compact()
        .try_init()
        .map_err(|error| anyhow::anyhow!(error))
        .context("failed to initialize tracing")
}
