use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::priority::PrioritySnapshot;

#[derive(Clone, Debug)]
pub struct RuntimeStats {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    started_at: Instant,
    observed_events: AtomicU64,
    ledger_appends: AtomicU64,
    ledger_append_us: AtomicU64,
    store_event_writes: AtomicU64,
    store_event_write_us: AtomicU64,
    sink_publishes: AtomicU64,
    sink_publish_us: AtomicU64,
    priority_high: AtomicU64,
    priority_medium: AtomicU64,
    priority_low: AtomicU64,
    priority_unknown: AtomicU64,
    capture_enqueued: AtomicU64,
    capture_skipped: AtomicU64,
    capture_started: AtomicU64,
    capture_completed: AtomicU64,
    capture_failed: AtomicU64,
    capture_queue_wait_us: AtomicU64,
    capture_run_us: AtomicU64,
    capture_run_max_us: AtomicU64,
    diff_enqueued: AtomicU64,
    diff_skipped: AtomicU64,
    diff_started: AtomicU64,
    diff_completed: AtomicU64,
    diff_failed: AtomicU64,
    diff_queue_wait_us: AtomicU64,
    diff_run_us: AtomicU64,
    diff_run_max_us: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct RuntimeSnapshot {
    pub elapsed: Duration,
    pub observed_events: u64,
    pub observed_per_sec: f64,
    pub ledger_append_avg_ms: f64,
    pub store_event_write_avg_ms: f64,
    pub sink_publish_avg_ms: f64,
    pub priority_high: u64,
    pub priority_medium: u64,
    pub priority_low: u64,
    pub priority_unknown: u64,
    pub capture_enqueued: u64,
    pub capture_skipped: u64,
    pub capture_started: u64,
    pub capture_completed: u64,
    pub capture_failed: u64,
    pub capture_queue_backlog: u64,
    pub capture_in_flight: u64,
    pub capture_queue_avg_ms: f64,
    pub capture_run_avg_ms: f64,
    pub capture_run_max_ms: f64,
    pub diff_enqueued: u64,
    pub diff_skipped: u64,
    pub diff_started: u64,
    pub diff_completed: u64,
    pub diff_failed: u64,
    pub diff_queue_backlog: u64,
    pub diff_in_flight: u64,
    pub diff_queue_avg_ms: f64,
    pub diff_run_avg_ms: f64,
    pub diff_run_max_ms: f64,
}

impl Default for RuntimeStats {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                started_at: Instant::now(),
                observed_events: AtomicU64::new(0),
                ledger_appends: AtomicU64::new(0),
                ledger_append_us: AtomicU64::new(0),
                store_event_writes: AtomicU64::new(0),
                store_event_write_us: AtomicU64::new(0),
                sink_publishes: AtomicU64::new(0),
                sink_publish_us: AtomicU64::new(0),
                priority_high: AtomicU64::new(0),
                priority_medium: AtomicU64::new(0),
                priority_low: AtomicU64::new(0),
                priority_unknown: AtomicU64::new(0),
                capture_enqueued: AtomicU64::new(0),
                capture_skipped: AtomicU64::new(0),
                capture_started: AtomicU64::new(0),
                capture_completed: AtomicU64::new(0),
                capture_failed: AtomicU64::new(0),
                capture_queue_wait_us: AtomicU64::new(0),
                capture_run_us: AtomicU64::new(0),
                capture_run_max_us: AtomicU64::new(0),
                diff_enqueued: AtomicU64::new(0),
                diff_skipped: AtomicU64::new(0),
                diff_started: AtomicU64::new(0),
                diff_completed: AtomicU64::new(0),
                diff_failed: AtomicU64::new(0),
                diff_queue_wait_us: AtomicU64::new(0),
                diff_run_us: AtomicU64::new(0),
                diff_run_max_us: AtomicU64::new(0),
            }),
        }
    }
}

impl RuntimeStats {
    pub fn record_observed_event(&self) {
        self.inner.observed_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ledger_append(&self, duration: Duration) {
        self.inner.ledger_appends.fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.ledger_append_us, duration);
    }

    pub fn record_store_event_write(&self, duration: Duration) {
        self.inner
            .store_event_writes
            .fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.store_event_write_us, duration);
    }

    pub fn record_sink_publish(&self, duration: Duration) {
        self.inner.sink_publishes.fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.sink_publish_us, duration);
    }

    pub fn record_priority(&self, snapshot: &PrioritySnapshot) {
        match snapshot.bucket() {
            crate::priority::PriorityBucket::High => {
                self.inner.priority_high.fetch_add(1, Ordering::Relaxed);
            }
            crate::priority::PriorityBucket::Medium => {
                self.inner.priority_medium.fetch_add(1, Ordering::Relaxed);
            }
            crate::priority::PriorityBucket::Low => {
                self.inner.priority_low.fetch_add(1, Ordering::Relaxed);
            }
            crate::priority::PriorityBucket::Unknown => {
                self.inner.priority_unknown.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_capture_enqueued(&self) {
        self.inner.capture_enqueued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_capture_skipped(&self) {
        self.inner.capture_skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_capture_started(&self, queue_wait: Duration) {
        self.inner.capture_started.fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.capture_queue_wait_us, queue_wait);
    }

    pub fn record_capture_completed(&self, duration: Duration) {
        self.inner.capture_completed.fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.capture_run_us, duration);
        update_max(&self.inner.capture_run_max_us, duration);
    }

    pub fn record_capture_failed(&self, duration: Duration) {
        self.inner.capture_failed.fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.capture_run_us, duration);
        update_max(&self.inner.capture_run_max_us, duration);
    }

    pub fn record_diff_enqueued(&self) {
        self.inner.diff_enqueued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_diff_skipped(&self) {
        self.inner.diff_skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_diff_started(&self, queue_wait: Duration) {
        self.inner.diff_started.fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.diff_queue_wait_us, queue_wait);
    }

    pub fn record_diff_completed(&self, duration: Duration) {
        self.inner.diff_completed.fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.diff_run_us, duration);
        update_max(&self.inner.diff_run_max_us, duration);
    }

    pub fn record_diff_failed(&self, duration: Duration) {
        self.inner.diff_failed.fetch_add(1, Ordering::Relaxed);
        add_duration(&self.inner.diff_run_us, duration);
        update_max(&self.inner.diff_run_max_us, duration);
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        let elapsed = self.inner.started_at.elapsed();
        let observed_events = self.inner.observed_events.load(Ordering::Relaxed);
        let ledger_appends = self.inner.ledger_appends.load(Ordering::Relaxed);
        let store_event_writes = self.inner.store_event_writes.load(Ordering::Relaxed);
        let sink_publishes = self.inner.sink_publishes.load(Ordering::Relaxed);
        let priority_high = self.inner.priority_high.load(Ordering::Relaxed);
        let priority_medium = self.inner.priority_medium.load(Ordering::Relaxed);
        let priority_low = self.inner.priority_low.load(Ordering::Relaxed);
        let priority_unknown = self.inner.priority_unknown.load(Ordering::Relaxed);
        let capture_enqueued = self.inner.capture_enqueued.load(Ordering::Relaxed);
        let capture_skipped = self.inner.capture_skipped.load(Ordering::Relaxed);
        let capture_started = self.inner.capture_started.load(Ordering::Relaxed);
        let capture_completed = self.inner.capture_completed.load(Ordering::Relaxed);
        let capture_failed = self.inner.capture_failed.load(Ordering::Relaxed);
        let diff_enqueued = self.inner.diff_enqueued.load(Ordering::Relaxed);
        let diff_skipped = self.inner.diff_skipped.load(Ordering::Relaxed);
        let diff_started = self.inner.diff_started.load(Ordering::Relaxed);
        let diff_completed = self.inner.diff_completed.load(Ordering::Relaxed);
        let diff_failed = self.inner.diff_failed.load(Ordering::Relaxed);

        RuntimeSnapshot {
            elapsed,
            observed_events,
            observed_per_sec: rate_per_sec(observed_events, elapsed),
            ledger_append_avg_ms: average_ms(
                self.inner.ledger_append_us.load(Ordering::Relaxed),
                ledger_appends,
            ),
            store_event_write_avg_ms: average_ms(
                self.inner.store_event_write_us.load(Ordering::Relaxed),
                store_event_writes,
            ),
            sink_publish_avg_ms: average_ms(
                self.inner.sink_publish_us.load(Ordering::Relaxed),
                sink_publishes,
            ),
            priority_high,
            priority_medium,
            priority_low,
            priority_unknown,
            capture_enqueued,
            capture_skipped,
            capture_started,
            capture_completed,
            capture_failed,
            capture_queue_backlog: capture_enqueued.saturating_sub(capture_started),
            capture_in_flight: capture_started
                .saturating_sub(capture_completed.saturating_add(capture_failed)),
            capture_queue_avg_ms: average_ms(
                self.inner.capture_queue_wait_us.load(Ordering::Relaxed),
                capture_started,
            ),
            capture_run_avg_ms: average_ms(
                self.inner.capture_run_us.load(Ordering::Relaxed),
                capture_completed.saturating_add(capture_failed),
            ),
            capture_run_max_ms: micros_to_ms(self.inner.capture_run_max_us.load(Ordering::Relaxed)),
            diff_enqueued,
            diff_skipped,
            diff_started,
            diff_completed,
            diff_failed,
            diff_queue_backlog: diff_enqueued.saturating_sub(diff_started),
            diff_in_flight: diff_started.saturating_sub(diff_completed.saturating_add(diff_failed)),
            diff_queue_avg_ms: average_ms(
                self.inner.diff_queue_wait_us.load(Ordering::Relaxed),
                diff_started,
            ),
            diff_run_avg_ms: average_ms(
                self.inner.diff_run_us.load(Ordering::Relaxed),
                diff_completed.saturating_add(diff_failed),
            ),
            diff_run_max_ms: micros_to_ms(self.inner.diff_run_max_us.load(Ordering::Relaxed)),
        }
    }

    pub fn log_snapshot(&self, reason: &str) {
        let snapshot = self.snapshot();
        info!(
            target: "supply_stream_core::perf",
            reason,
            elapsed_secs = snapshot.elapsed.as_secs_f64(),
            observed_events = snapshot.observed_events,
            observed_per_sec = snapshot.observed_per_sec,
            ledger_append_avg_ms = snapshot.ledger_append_avg_ms,
            store_event_write_avg_ms = snapshot.store_event_write_avg_ms,
            sink_publish_avg_ms = snapshot.sink_publish_avg_ms,
            priority_high = snapshot.priority_high,
            priority_medium = snapshot.priority_medium,
            priority_low = snapshot.priority_low,
            priority_unknown = snapshot.priority_unknown,
            capture_enqueued = snapshot.capture_enqueued,
            capture_skipped = snapshot.capture_skipped,
            capture_started = snapshot.capture_started,
            capture_completed = snapshot.capture_completed,
            capture_failed = snapshot.capture_failed,
            capture_queue_backlog = snapshot.capture_queue_backlog,
            capture_in_flight = snapshot.capture_in_flight,
            capture_queue_avg_ms = snapshot.capture_queue_avg_ms,
            capture_run_avg_ms = snapshot.capture_run_avg_ms,
            capture_run_max_ms = snapshot.capture_run_max_ms,
            diff_enqueued = snapshot.diff_enqueued,
            diff_skipped = snapshot.diff_skipped,
            diff_started = snapshot.diff_started,
            diff_completed = snapshot.diff_completed,
            diff_failed = snapshot.diff_failed,
            diff_queue_backlog = snapshot.diff_queue_backlog,
            diff_in_flight = snapshot.diff_in_flight,
            diff_queue_avg_ms = snapshot.diff_queue_avg_ms,
            diff_run_avg_ms = snapshot.diff_run_avg_ms,
            diff_run_max_ms = snapshot.diff_run_max_ms,
            "runtime performance snapshot"
        );
    }
}

pub async fn run_periodic_reporter(
    stats: RuntimeStats,
    interval: Option<Duration>,
    shutdown: CancellationToken,
) {
    let Some(interval) = interval.filter(|value| !value.is_zero()) else {
        return;
    };

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(interval) => stats.log_snapshot("interval"),
        }
    }
}

fn add_duration(target: &AtomicU64, duration: Duration) {
    let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
    target.fetch_add(micros, Ordering::Relaxed);
}

fn update_max(target: &AtomicU64, duration: Duration) {
    let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
    let mut current = target.load(Ordering::Relaxed);
    while micros > current {
        match target.compare_exchange(current, micros, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

fn average_ms(total_micros: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        micros_to_ms(total_micros) / count as f64
    }
}

fn micros_to_ms(micros: u64) -> f64 {
    micros as f64 / 1_000.0
}

fn rate_per_sec(count: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= f64::EPSILON {
        0.0
    } else {
        count as f64 / seconds
    }
}
