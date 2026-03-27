use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter},
    sync::Mutex,
};

use crate::event::PackageReleaseEvent;

pub const LEGACY_EVENTS_LOG: &str = "events.ndjson";
pub const OBSERVED_EVENTS_LOG: &str = "observed-events.ndjson";
pub const RECONSTRUCTED_EVENTS_LOG: &str = "reconstructed-events.ndjson";

pub struct EventLedger {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl EventLedger {
    pub async fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create event ledger dir {}", parent.display())
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open event ledger {}", path.display()))?;

        Ok(Self {
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub async fn append(&self, event: &PackageReleaseEvent) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let mut encoded = serde_json::to_vec(event).context("failed to encode event for ledger")?;
        encoded.push(b'\n');
        writer
            .write_all(&encoded)
            .await
            .with_context(|| format!("failed to append event to {}", self.path.display()))?;
        writer
            .flush()
            .await
            .with_context(|| format!("failed to flush event ledger {}", self.path.display()))?;
        Ok(())
    }
}

pub fn observed_ledger_path(data_dir: &Path) -> PathBuf {
    data_dir.join(OBSERVED_EVENTS_LOG)
}

pub fn reconstructed_ledger_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RECONSTRUCTED_EVENTS_LOG)
}

pub fn legacy_ledger_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LEGACY_EVENTS_LOG)
}

pub fn local_ledger_paths(data_dir: &Path) -> Vec<PathBuf> {
    let observed = observed_ledger_path(data_dir);
    let reconstructed = reconstructed_ledger_path(data_dir);
    let legacy = legacy_ledger_path(data_dir);

    let mut paths = vec![observed, reconstructed];
    if legacy.exists() {
        paths.push(legacy);
    }

    paths
}

pub async fn read_events(path: &Path) -> Result<Vec<PackageReleaseEvent>> {
    let file = match File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open event ledger {}", path.display()));
        }
    };

    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut events = Vec::new();

    while let Some(line) = lines
        .next_line()
        .await
        .with_context(|| format!("failed reading line from {}", path.display()))?
    {
        if line.trim().is_empty() {
            continue;
        }

        let event = serde_json::from_str::<PackageReleaseEvent>(&line)
            .with_context(|| format!("failed to decode ledger line from {}", path.display()))?;
        events.push(event);
    }

    Ok(events)
}

pub async fn read_events_from_paths(paths: &[PathBuf]) -> Result<Vec<PackageReleaseEvent>> {
    let mut events = Vec::new();
    let mut seen_event_ids = HashSet::new();

    for path in paths {
        for event in read_events(path).await? {
            if seen_event_ids.insert(event.event_id.clone()) {
                events.push(event);
            }
        }
    }

    Ok(events)
}

pub async fn read_local_events(data_dir: &Path) -> Result<Vec<PackageReleaseEvent>> {
    read_events_from_paths(&local_ledger_paths(data_dir)).await
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::event::Ecosystem;

    #[tokio::test]
    async fn ledger_round_trips_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("events.ndjson");
        let ledger = EventLedger::open(path.clone()).await.unwrap();

        ledger
            .append(&PackageReleaseEvent {
                event_id: "pypi:demo@1.0.0".to_string(),
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                version: "1.0.0".to_string(),
                published_at: Some(Utc::now()),
                observed_at: Utc::now(),
                source: "test".to_string(),
                sequence: None,
                package_url: None,
                release_url: None,
                metadata_url: None,
                priority: None,
            })
            .await
            .unwrap();

        let events = read_events(&path).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "pypi:demo@1.0.0");
    }
}
