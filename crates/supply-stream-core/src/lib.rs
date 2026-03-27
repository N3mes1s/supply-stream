pub mod assessment;
pub mod autodiff;
pub mod bundle;
pub mod capture;
pub mod census;
pub mod collector;
pub mod config;
pub mod deps_dev;
pub mod deps_dev_bigquery;
pub mod diff;
pub mod event;
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
pub mod visibility;

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use config::AppConfig;
use ledger::EventLedger;
use perf::RuntimeStats;
use priority::{PriorityResolver, hydrate_local_graph_scores};
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
    let hydration =
        hydrate_local_graph_scores(&config.priority, &config.ecosystems, 256, 128).await?;
    if hydration.hydrated_scores > 0 {
        info!(
            graph_packages = hydration.graph_packages,
            existing_scores = hydration.existing_scores,
            missing_graph_packages = hydration.missing_graph_packages,
            hydrated_scores = hydration.hydrated_scores,
            batches = hydration.batches,
            "hydrated local graph scores from operational store"
        );
    }
    let priority = PriorityResolver::load(&config.priority).await?;
    let source_shutdown = CancellationToken::new();
    let perf_shutdown = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(config.channel_capacity);
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
    let capture_worker = tokio::spawn(
        capture::CaptureWorker::new(
            http.clone(),
            config.capture.clone(),
            capture_rx,
            Some(diff_tx.clone()),
            Some(priority.clone()),
            Some(sink.clone()),
            store.clone(),
            runtime_stats.clone(),
        )
        .run(),
    );
    let diff_worker = tokio::spawn(
        autodiff::DiffWorker::new(
            config.autodiff.clone(),
            diff_rx,
            store.clone(),
            runtime_stats.clone(),
            Some(sink.clone()),
        )
        .run(),
    );

    for source in sources::build_sources(
        &config,
        &http,
        tx.clone(),
        state_store.clone(),
        source_shutdown.clone(),
    ) {
        let source_name = source.name();
        handles.push((source_name, tokio::spawn(async move { source.run().await })));
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
                    let capture_requested = event.capture_requested_with_graph(&graph);
                    let diff_requested = event.diff_requested_with_graph(&graph);
                    let emitted = event.emitted_view(graph);
                    sink.publish(&emitted).await?;
                    runtime_stats.record_sink_publish(started.elapsed());

                    if capture_requested {
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
                        runtime_stats.record_capture_skipped();
                        runtime_stats.record_diff_skipped();
                    }
                }
                None => break,
            },
            result = tokio::signal::ctrl_c(), if !shutting_down => {
                result.context("failed to listen for ctrl-c")?;
                info!("received shutdown signal");
                source_shutdown.cancel();
                shutting_down = true;
            }
        }
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
    let _ = perf_task.await;
    let _ = priority_view_task.await;
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
