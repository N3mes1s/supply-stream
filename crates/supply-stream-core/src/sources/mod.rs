pub mod crates_io;
pub mod npm;
pub mod pypi;

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::StatusCode;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    config::{AppConfig, SourceResilienceConfig},
    event::PackageReleaseEvent,
    state::FileStateStore,
};

const DEFAULT_OFFLINE_MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_OFFLINE_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const DEFAULT_OFFLINE_BACKOFF_MAX: Duration = Duration::from_secs(30);

#[async_trait]
pub trait PackageSource: Send {
    fn name(&self) -> &'static str;
    async fn run(self: Box<Self>) -> Result<()>;
}

pub fn build_sources(
    config: &AppConfig,
    http: &reqwest::Client,
    tx: mpsc::Sender<PackageReleaseEvent>,
    state_store: FileStateStore,
    shutdown: CancellationToken,
) -> Vec<Box<dyn PackageSource>> {
    let mut sources: Vec<Box<dyn PackageSource>> = Vec::new();

    for ecosystem in &config.ecosystems {
        match ecosystem {
            crate::event::Ecosystem::Npm => sources.push(Box::new(npm::NpmSource::new(
                http.clone(),
                tx.clone(),
                state_store.clone(),
                shutdown.clone(),
                config.npm.clone(),
                config.once,
            ))),
            crate::event::Ecosystem::Pypi => sources.push(Box::new(pypi::PypiSource::new(
                http.clone(),
                tx.clone(),
                state_store.clone(),
                shutdown.clone(),
                config.pypi.clone(),
                config.once,
            ))),
            crate::event::Ecosystem::CratesIo => {
                sources.push(Box::new(crates_io::CratesIoSource::new(
                    http.clone(),
                    tx.clone(),
                    state_store.clone(),
                    shutdown.clone(),
                    config.crates_io.clone(),
                    config.once,
                )))
            }
        }
    }

    sources
}

pub async fn sleep_or_shutdown(shutdown: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

#[derive(Clone, Debug)]
pub struct RequestThrottle {
    source: &'static str,
    min_request_interval: Duration,
    backoff_initial: Duration,
    backoff_max: Duration,
    state: Arc<Mutex<RequestThrottleState>>,
}

#[derive(Debug)]
struct RequestThrottleState {
    next_request_at: Instant,
    backoff_until: Option<Instant>,
    consecutive_failures: u32,
}

impl RequestThrottle {
    pub fn new(source: &'static str, config: &SourceResilienceConfig) -> Self {
        Self {
            source,
            min_request_interval: config.min_request_interval,
            backoff_initial: config.backoff_initial,
            backoff_max: config.backoff_max.max(config.backoff_initial),
            state: Arc::new(Mutex::new(RequestThrottleState {
                next_request_at: Instant::now(),
                backoff_until: None,
                consecutive_failures: 0,
            })),
        }
    }

    pub async fn send<F, Fut>(
        &self,
        shutdown: &CancellationToken,
        build_request: F,
    ) -> Result<reqwest::Response>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = reqwest::Result<reqwest::Response>>,
    {
        if self.wait_turn(shutdown).await {
            anyhow::bail!(
                "shutdown requested while waiting for {} request window",
                self.source
            );
        }

        match build_request().await {
            Ok(response) => {
                self.note_response(response.status());
                Ok(response)
            }
            Err(error) => {
                self.note_transport_error(&error);
                Err(error).with_context(|| format!("{} request failed", self.source))
            }
        }
    }

    pub async fn send_without_shutdown<F, Fut>(&self, build_request: F) -> Result<reqwest::Response>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = reqwest::Result<reqwest::Response>>,
    {
        self.send(&CancellationToken::new(), build_request).await
    }

    pub fn reset_failures(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.consecutive_failures = 0;
        state.backoff_until = None;
    }

    async fn wait_turn(&self, shutdown: &CancellationToken) -> bool {
        loop {
            let delay = {
                let now = Instant::now();
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let ready_at = state
                    .backoff_until
                    .map(|backoff_until| backoff_until.max(state.next_request_at))
                    .unwrap_or(state.next_request_at);
                if ready_at <= now {
                    state.next_request_at = now + self.min_request_interval;
                    None
                } else {
                    Some(ready_at - now)
                }
            };

            let Some(delay) = delay else {
                return false;
            };
            if sleep_or_shutdown(shutdown, delay).await {
                return true;
            }
        }
    }

    fn note_response(&self, status: StatusCode) {
        if is_backoff_status(status) {
            self.note_failure(Some(status.as_u16()), None);
            return;
        }
        self.reset_failures();
    }

    fn note_transport_error(&self, error: &reqwest::Error) {
        self.note_failure(None, Some(error.to_string()));
    }

    fn note_failure(&self, status: Option<u16>, error: Option<String>) {
        let (delay, consecutive_failures) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let multiplier = 1u32 << state.consecutive_failures.min(8);
            let delay = self
                .backoff_initial
                .saturating_mul(multiplier)
                .min(self.backoff_max);
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.backoff_until = Some(Instant::now() + delay);
            (delay, state.consecutive_failures)
        };

        warn!(
            source = self.source,
            status,
            error = error.as_deref(),
            consecutive_failures,
            backoff_ms = delay.as_millis() as u64,
            "source request backoff engaged"
        );
    }
}

pub fn default_offline_resilience_config() -> SourceResilienceConfig {
    SourceResilienceConfig {
        min_request_interval: DEFAULT_OFFLINE_MIN_REQUEST_INTERVAL,
        backoff_initial: DEFAULT_OFFLINE_BACKOFF_INITIAL,
        backoff_max: DEFAULT_OFFLINE_BACKOFF_MAX,
    }
}

#[derive(Debug, Clone)]
pub struct FailureBackoff {
    initial: Duration,
    max: Duration,
    consecutive_failures: u32,
}

impl FailureBackoff {
    pub fn new(config: &SourceResilienceConfig) -> Self {
        Self {
            initial: config.backoff_initial,
            max: config.backoff_max.max(config.backoff_initial),
            consecutive_failures: 0,
        }
    }

    pub fn reset(&mut self) {
        self.consecutive_failures = 0;
    }

    pub fn next_delay(&mut self) -> Duration {
        let multiplier = 1u32 << self.consecutive_failures.min(8);
        let delay = self.initial.saturating_mul(multiplier).min(self.max);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        delay
    }
}

fn is_backoff_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::SERVICE_UNAVAILABLE
        || status == StatusCode::GATEWAY_TIMEOUT
        || status.is_server_error()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use reqwest::StatusCode;

    use super::*;

    #[test]
    fn failure_backoff_grows_and_caps() {
        let mut backoff = FailureBackoff::new(&SourceResilienceConfig {
            min_request_interval: Duration::from_millis(0),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(8),
        });

        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
        assert_eq!(backoff.next_delay(), Duration::from_secs(4));
        assert_eq!(backoff.next_delay(), Duration::from_secs(8));
        assert_eq!(backoff.next_delay(), Duration::from_secs(8));

        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn request_throttle_resets_failures_after_success() {
        let throttle = RequestThrottle::new(
            "npm",
            &SourceResilienceConfig {
                min_request_interval: Duration::from_millis(0),
                backoff_initial: Duration::from_secs(1),
                backoff_max: Duration::from_secs(8),
            },
        );

        throttle.note_response(StatusCode::TOO_MANY_REQUESTS);
        throttle.note_response(StatusCode::OK);

        let state = throttle
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(state.consecutive_failures, 0);
        assert!(state.backoff_until.is_none());
    }
}
