use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    event::{Ecosystem, PackageReleaseEvent},
    priority::{PriorityBucket, PriorityCounts},
};

#[derive(Clone, Debug)]
pub struct PriorityViewTracker {
    inner: Arc<Mutex<PriorityViewState>>,
}

#[derive(Debug)]
struct PriorityViewState {
    recent_capacity: usize,
    entries: VecDeque<PriorityViewEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PriorityViewEntry {
    pub event_id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub observed_at: DateTime<Utc>,
    pub priority_bucket: String,
    pub direct_popularity: f64,
    pub propagated_impact: f64,
    pub hidden_leverage: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PriorityViewSnapshot {
    pub window_events: usize,
    pub priorities: PriorityCounts,
    pub top_releases: Vec<PriorityViewEntry>,
}

impl PriorityViewTracker {
    pub fn new(recent_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PriorityViewState {
                recent_capacity,
                entries: VecDeque::with_capacity(recent_capacity.max(1)),
            })),
        }
    }

    pub fn record(&self, event: &PackageReleaseEvent) {
        let priority = event.priority_snapshot();
        let entry = PriorityViewEntry {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            priority_bucket: bucket_label(priority.bucket()).to_string(),
            direct_popularity: priority.direct_popularity.unwrap_or_default(),
            propagated_impact: priority.propagated_impact.unwrap_or_default(),
            hidden_leverage: priority.hidden_leverage.unwrap_or_default(),
        };

        let mut state = self.inner.lock().expect("priority view mutex poisoned");
        if state.entries.len() == state.recent_capacity && state.recent_capacity > 0 {
            state.entries.pop_front();
        }
        if state.recent_capacity > 0 {
            state.entries.push_back(entry);
        }
    }

    pub fn snapshot(&self, top_limit: usize) -> PriorityViewSnapshot {
        let state = self.inner.lock().expect("priority view mutex poisoned");
        let mut priorities = PriorityCounts::default();
        for entry in &state.entries {
            match entry.priority_bucket.as_str() {
                "high" => priorities.high += 1,
                "medium" => priorities.medium += 1,
                "low" => priorities.low += 1,
                _ => priorities.unknown += 1,
            }
        }

        let mut top_releases = state.entries.iter().cloned().collect::<Vec<_>>();
        top_releases.sort_by(|left, right| {
            bucket_rank(&left.priority_bucket)
                .cmp(&bucket_rank(&right.priority_bucket))
                .then_with(|| right.propagated_impact.total_cmp(&left.propagated_impact))
                .then_with(|| right.hidden_leverage.total_cmp(&left.hidden_leverage))
                .then_with(|| right.observed_at.cmp(&left.observed_at))
                .then_with(|| left.package.cmp(&right.package))
        });
        top_releases.truncate(top_limit);

        PriorityViewSnapshot {
            window_events: state.entries.len(),
            priorities,
            top_releases,
        }
    }

    pub fn log_snapshot(&self, reason: &str, top_limit: usize) {
        let snapshot = self.snapshot(top_limit);
        let top_releases =
            serde_json::to_string(&snapshot.top_releases).unwrap_or_else(|_| "[]".to_string());
        info!(
            target: "supply_stream_core::priority_view",
            reason,
            window_events = snapshot.window_events,
            priority_high = snapshot.priorities.high,
            priority_medium = snapshot.priorities.medium,
            priority_low = snapshot.priorities.low,
            priority_unknown = snapshot.priorities.unknown,
            top_releases = %top_releases,
            "priority view snapshot"
        );
    }
}

pub async fn run_periodic_reporter(
    tracker: PriorityViewTracker,
    interval: Option<Duration>,
    top_limit: usize,
    shutdown: CancellationToken,
) {
    let Some(interval) = interval.filter(|value| !value.is_zero()) else {
        return;
    };

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(interval) => tracker.log_snapshot("interval", top_limit),
        }
    }
}

fn bucket_rank(bucket: &str) -> u8 {
    match bucket {
        "high" => 0,
        "medium" => 1,
        "unknown" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn bucket_label(bucket: PriorityBucket) -> &'static str {
    match bucket {
        PriorityBucket::High => "high",
        PriorityBucket::Medium => "medium",
        PriorityBucket::Low => "low",
        PriorityBucket::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::{
        event::PackageReleaseEvent,
        priority::{PrioritySnapshot, PrioritySource, PriorityTier},
    };

    #[test]
    fn priority_view_orders_highest_priority_recent_events_first() {
        let tracker = PriorityViewTracker::new(10);
        tracker.record(&sample_event(
            "pkg-low",
            "0.1.0",
            PrioritySnapshot {
                tier: PriorityTier::Low,
                source: PrioritySource::OfflineScoreFile,
                direct_popularity: Some(1.0),
                propagated_impact: Some(50.0),
                hidden_leverage: Some(2.0),
                computed_at: None,
                score_source_version: None,
            },
        ));
        tracker.record(&sample_event(
            "pkg-high",
            "1.0.0",
            PrioritySnapshot {
                tier: PriorityTier::High,
                source: PrioritySource::OfflineScoreFile,
                direct_popularity: Some(10.0),
                propagated_impact: Some(20.0),
                hidden_leverage: Some(1.0),
                computed_at: None,
                score_source_version: None,
            },
        ));

        let snapshot = tracker.snapshot(2);
        assert_eq!(snapshot.window_events, 2);
        assert_eq!(snapshot.priorities.high, 1);
        assert_eq!(snapshot.priorities.low, 1);
        assert_eq!(snapshot.top_releases[0].package, "pkg-high");
    }

    #[test]
    fn priority_view_respects_recent_capacity() {
        let tracker = PriorityViewTracker::new(1);
        tracker.record(&sample_event(
            "first",
            "0.1.0",
            PrioritySnapshot::default_unknown(),
        ));
        tracker.record(&sample_event(
            "second",
            "0.2.0",
            PrioritySnapshot::default_unknown(),
        ));
        let snapshot = tracker.snapshot(10);
        assert_eq!(snapshot.window_events, 1);
        assert_eq!(snapshot.top_releases[0].package, "second");
    }

    fn sample_event(
        package: &str,
        version: &str,
        priority: PrioritySnapshot,
    ) -> PackageReleaseEvent {
        PackageReleaseEvent {
            event_id: format!("pypi:{package}@{version}"),
            ecosystem: Ecosystem::Pypi,
            package: package.to_string(),
            version: version.to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(priority),
        }
    }
}
