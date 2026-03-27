use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    config::NpmConfig,
    event::{Ecosystem, PackageReleaseEvent},
    sources::{PackageSource, sleep_or_shutdown},
    state::{FileStateStore, RecentKeys, RecentKeysState},
};

const NPM_CHANGES_URL: &str = "https://replicate.npmjs.com/registry/_changes";
const NPM_ROOT_URL: &str = "https://replicate.npmjs.com/";
const NPM_PACKUMENT_BASE_URL: &str = "https://registry.npmjs.org/";
const STATE_KEY: &str = "npm";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NpmState {
    since: Option<String>,
    #[serde(default)]
    recent_release_keys: RecentKeysState,
}

#[derive(Debug, Deserialize)]
struct NpmRootResponse {
    update_seq: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct NpmChangesResponse {
    #[serde(default)]
    results: Vec<NpmChange>,
    #[serde(default)]
    last_seq: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NpmChange {
    id: String,
    seq: serde_json::Value,
    #[serde(default)]
    deleted: bool,
}

#[derive(Debug, Deserialize)]
struct NpmPackument {
    #[serde(default)]
    versions: HashMap<String, serde_json::Value>,
    #[serde(default)]
    time: HashMap<String, String>,
}

pub struct NpmSource {
    http: reqwest::Client,
    tx: mpsc::Sender<PackageReleaseEvent>,
    state_store: FileStateStore,
    shutdown: CancellationToken,
    config: NpmConfig,
    once: bool,
}

impl NpmSource {
    pub fn new(
        http: reqwest::Client,
        tx: mpsc::Sender<PackageReleaseEvent>,
        state_store: FileStateStore,
        shutdown: CancellationToken,
        config: NpmConfig,
        once: bool,
    ) -> Self {
        Self {
            http,
            tx,
            state_store,
            shutdown,
            config,
            once,
        }
    }

    async fn bootstrap_state(&self, state: &mut NpmState) -> Result<()> {
        let response = self
            .http
            .get(NPM_ROOT_URL)
            .send()
            .await
            .context("failed to fetch npm replication root")?
            .error_for_status()
            .context("npm replication root returned an error")?;
        let root: NpmRootResponse = response
            .json()
            .await
            .context("failed to decode npm replication root")?;
        state.since = Some(seq_to_string(&root.update_seq));
        self.state_store
            .save(STATE_KEY, state)
            .await
            .context("failed to persist npm bootstrap state")?;
        info!(cursor = ?state.since, "initialized npm cursor from current replication head");
        Ok(())
    }

    async fn fetch_changes(&self, since: &str) -> Result<NpmChangesResponse> {
        self.http
            .get(NPM_CHANGES_URL)
            .query(&[
                ("since", since.to_string()),
                ("limit", self.config.batch_size.to_string()),
            ])
            .send()
            .await
            .context("failed to fetch npm changes page")?
            .error_for_status()
            .context("npm changes endpoint returned an error")?
            .json()
            .await
            .context("failed to decode npm changes response")
    }
}

#[async_trait]
impl PackageSource for NpmSource {
    fn name(&self) -> &'static str {
        "npm"
    }

    async fn run(self: Box<Self>) -> Result<()> {
        let mut state = self
            .state_store
            .load::<NpmState>(STATE_KEY)
            .await?
            .unwrap_or_default();
        let mut recent_keys = RecentKeys::from_state(
            state.recent_release_keys.clone(),
            self.config.recent_key_capacity,
        );

        if state.since.is_none() {
            self.bootstrap_state(&mut state).await?;
            if self.once {
                return Ok(());
            }
        }

        loop {
            if self.shutdown.is_cancelled() {
                return Ok(());
            }

            let since = state
                .since
                .clone()
                .context("npm state cursor missing after bootstrap")?;
            let page = match self.fetch_changes(&since).await {
                Ok(page) => page,
                Err(error) => {
                    warn!(error = %error, "npm poll failed");
                    if self.once || sleep_or_shutdown(&self.shutdown, self.config.idle_delay).await
                    {
                        return Ok(());
                    }
                    continue;
                }
            };

            if page.results.is_empty() {
                debug!("npm changes page empty");
                if self.once || sleep_or_shutdown(&self.shutdown, self.config.idle_delay).await {
                    return Ok(());
                }
                continue;
            }

            let next_since = page
                .last_seq
                .as_ref()
                .map(seq_to_string)
                .or_else(|| page.results.last().map(|change| seq_to_string(&change.seq)))
                .context("npm changes page missing pagination cursor")?;

            let http = self.http.clone();
            let publish_window = self.config.recent_publish_window;
            let releases = futures::stream::iter(
                page.results
                    .into_iter()
                    .filter(|change| !change.deleted)
                    .collect::<Vec<_>>(),
            )
            .map(move |change| {
                let http = http.clone();
                async move {
                    let seq = seq_to_string(&change.seq);
                    let packument = fetch_packument(&http, &change.id).await?;
                    Ok::<_, anyhow::Error>(extract_recent_releases(
                        &change.id,
                        &seq,
                        &packument,
                        publish_window,
                    ))
                }
            })
            .buffer_unordered(self.config.packument_concurrency)
            .collect::<Vec<_>>()
            .await;

            let mut emitted = 0usize;
            for outcome in releases {
                match outcome {
                    Ok(events) => {
                        for event in events {
                            let release_key = event.release_key();
                            if recent_keys.insert(release_key) {
                                self.tx
                                    .send(event)
                                    .await
                                    .context("npm output channel closed")?;
                                emitted += 1;
                            }
                        }
                    }
                    Err(error) => warn!(error = %error, "npm packument processing failed"),
                }
            }

            state.since = Some(next_since);
            state.recent_release_keys = recent_keys.snapshot();
            self.state_store.save(STATE_KEY, &state).await?;

            info!(emitted, cursor = ?state.since, "processed npm changes page");

            if self.once {
                return Ok(());
            }
        }
    }
}

fn extract_recent_releases(
    package: &str,
    sequence: &str,
    packument: &NpmPackument,
    recent_publish_window: Duration,
) -> Vec<PackageReleaseEvent> {
    let Some(modified_at) = packument
        .time
        .get("modified")
        .and_then(|value| parse_rfc3339(value))
    else {
        return Vec::new();
    };

    let Some(window) = ChronoDuration::from_std(recent_publish_window).ok() else {
        return Vec::new();
    };
    let cutoff = modified_at - window;
    let encoded = urlencoding::encode(package);
    let mut events = Vec::new();

    for version in packument.versions.keys() {
        let Some(published_at) = packument
            .time
            .get(version)
            .and_then(|value| parse_rfc3339(value))
        else {
            continue;
        };

        if published_at < cutoff {
            continue;
        }

        events.push(PackageReleaseEvent {
            event_id: format!("npm:{package}@{version}"),
            ecosystem: Ecosystem::Npm,
            package: package.to_string(),
            version: version.clone(),
            published_at: Some(published_at),
            observed_at: Utc::now(),
            source: "npm.replication".to_string(),
            sequence: Some(sequence.to_string()),
            package_url: Some(format!("https://www.npmjs.com/package/{package}")),
            release_url: Some(format!(
                "https://www.npmjs.com/package/{package}/v/{version}"
            )),
            metadata_url: Some(format!("{NPM_PACKUMENT_BASE_URL}{encoded}")),
            priority: None,
        });
    }

    events.sort_by_key(|event| event.published_at);
    events
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

async fn fetch_packument(http: &reqwest::Client, package: &str) -> Result<NpmPackument> {
    let encoded = urlencoding::encode(package);
    http.get(format!("{NPM_PACKUMENT_BASE_URL}{encoded}"))
        .send()
        .await
        .with_context(|| format!("failed to fetch npm packument for {package}"))?
        .error_for_status()
        .with_context(|| format!("npm packument returned an error for {package}"))?
        .json()
        .await
        .with_context(|| format!("failed to decode npm packument for {package}"))
}

fn seq_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_recent_releases_filters_old_versions() {
        let packument = NpmPackument {
            versions: HashMap::from([
                ("1.0.0".to_string(), serde_json::json!({})),
                ("2.0.0".to_string(), serde_json::json!({})),
            ]),
            time: HashMap::from([
                (
                    "modified".to_string(),
                    "2026-03-25T10:10:00.000Z".to_string(),
                ),
                ("1.0.0".to_string(), "2026-03-01T10:00:00.000Z".to_string()),
                ("2.0.0".to_string(), "2026-03-25T10:00:00.000Z".to_string()),
            ]),
        };

        let releases =
            extract_recent_releases("demo", "42", &packument, Duration::from_secs(15 * 60));

        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, "2.0.0");
        assert_eq!(releases[0].sequence.as_deref(), Some("42"));
    }
}
