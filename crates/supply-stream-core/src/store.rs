use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::task;

use crate::{
    capture::{
        CapturedRelease, graph_records_from_captured_release,
        package_repository_identity_from_captured_release,
    },
    diff::StoredReleaseDiff,
    event::{Ecosystem, PackageReleaseEvent},
    ledger,
    priority::{
        PriorityCounts, PriorityScoreRecord, PrioritySnapshot, PrioritySource, PriorityTier,
        normalize_package_name,
    },
    repo_provenance::{
        PackageRepositoryIdentity as RepoPackageRepositoryIdentity, RepositoryReleaseProvenance,
    },
    scoring::ScoreInputRecord,
};

const INDEX_DB: &str = "index.sqlite";
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS release_index (
    event_id TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    published_at TEXT,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    sequence TEXT,
    package_url TEXT,
    release_url TEXT,
    metadata_url TEXT,
    priority_tier TEXT,
    priority_source TEXT,
    direct_popularity REAL,
    propagated_impact REAL,
    hidden_leverage REAL,
    priority_computed_at TEXT,
    priority_score_source_version TEXT,
    origin TEXT NOT NULL,
    capture_state TEXT NOT NULL,
    capture_status TEXT,
    capture_artifact_count INTEGER,
    capture_dir TEXT,
    capture_reason TEXT,
    capture_updated_at TEXT,
    diff_state TEXT NOT NULL,
    diff_status TEXT,
    diff_baseline_version TEXT,
    diff_path TEXT,
    diff_reason TEXT,
    diff_updated_at TEXT
);

CREATE INDEX IF NOT EXISTS release_index_package_lookup
ON release_index (ecosystem, package, COALESCE(published_at, observed_at), observed_at, event_id);

CREATE INDEX IF NOT EXISTS release_index_recent_lookup
ON release_index (observed_at DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS release_index_origin_lookup
ON release_index (origin);

CREATE TABLE IF NOT EXISTS graph_package_index (
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    direct_popularity REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package)
);

CREATE TABLE IF NOT EXISTS package_repository_index (
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    repository_provider TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    normalized_repository_url TEXT NOT NULL,
    source TEXT NOT NULL,
    last_version TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package)
);

CREATE TABLE IF NOT EXISTS graph_edge_index (
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    dependency TEXT NOT NULL,
    weight REAL NOT NULL DEFAULT 1,
    confidence REAL,
    sources_json TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package, dependency)
);

CREATE INDEX IF NOT EXISTS graph_edge_dependency_lookup
ON graph_edge_index (ecosystem, dependency, package);

CREATE INDEX IF NOT EXISTS graph_edge_package_lookup
ON graph_edge_index (ecosystem, package, dependency);

CREATE TABLE IF NOT EXISTS priority_score_index (
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    priority_tier TEXT NOT NULL,
    priority_source TEXT,
    direct_popularity REAL,
    propagated_impact REAL,
    hidden_leverage REAL,
    computed_at TEXT,
    score_source_version TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package)
);

CREATE INDEX IF NOT EXISTS priority_score_tier_lookup
ON priority_score_index (ecosystem, priority_tier, package);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOrigin {
    Observed,
    Reconstructed,
}

impl EventOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Reconstructed => "reconstructed",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReconcileStats {
    pub events: usize,
    pub captures: usize,
    pub diffs: usize,
    pub graph_records: usize,
    pub repository_refs: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StoreStats {
    pub total_events: usize,
    pub observed_events: usize,
    pub reconstructed_events: usize,
    pub captures_ready: usize,
    pub diffs_ready: usize,
    pub capture_states: JobStateCounts,
    pub diff_states: JobStateCounts,
    pub priorities: PriorityCounts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ecosystems: Vec<EcosystemStoreStats>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EcosystemStoreStats {
    pub ecosystem: Ecosystem,
    pub total_events: usize,
    pub observed_events: usize,
    pub reconstructed_events: usize,
    pub captures_ready: usize,
    pub diffs_ready: usize,
    pub capture_states: JobStateCounts,
    pub diff_states: JobStateCounts,
    pub priorities: PriorityCounts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Pending,
    Ready,
    Skipped,
    Failed,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct JobStateCounts {
    pub pending: usize,
    pub ready: usize,
    pub skipped: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseRecordStatus {
    pub event: PackageReleaseEvent,
    pub origin: String,
    pub capture_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_reason: Option<String>,
    pub diff_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GraphEvidence {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub known: bool,
    pub direct_popularity: f64,
    pub direct_dependencies_seen: usize,
    pub reverse_dependents_seen: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<PackageRepositoryIdentity>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GraphNeighborhood {
    pub evidence: GraphEvidence,
    pub direct_dependencies: Vec<String>,
    pub reverse_dependents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PackageRepositoryIdentity {
    pub provider: String,
    pub repository_url: String,
    pub normalized_repository_url: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_version: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNeighborhoodRecords {
    pub roots: Vec<String>,
    pub records: Vec<ScoreInputRecord>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GraphStoreStats {
    pub packages: usize,
    pub dependencies: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ecosystems: Vec<GraphStoreEcosystemStats>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GraphStoreEcosystemStats {
    pub ecosystem: Ecosystem,
    pub packages: usize,
    pub dependencies: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PriorityScoreStoreStats {
    pub scored_packages: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ecosystems: Vec<PriorityScoreStoreEcosystemStats>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PriorityScoreStoreEcosystemStats {
    pub ecosystem: Ecosystem,
    pub packages: usize,
    pub priorities: PriorityCounts,
}

type AggregateCountsRow = (
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
);

#[derive(Debug, Clone)]
pub struct OperationalStore {
    path: PathBuf,
}

impl OperationalStore {
    pub async fn open(path: PathBuf) -> Result<Self> {
        let store = Self { path };
        store.init().await?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn init(&self) -> Result<()> {
        let path = self.path.clone();
        spawn_store_task(move || {
            let _conn = open_connection(&path)?;
            Ok(())
        })
        .await
    }

    pub async fn reconcile_local_data(&self, data_dir: &Path) -> Result<ReconcileStats> {
        let path = self.path.clone();
        let data_dir = data_dir.to_path_buf();
        spawn_store_task(move || reconcile_local_data_blocking(&path, &data_dir)).await
    }

    pub async fn record_event(
        &self,
        event: &PackageReleaseEvent,
        origin: EventOrigin,
    ) -> Result<()> {
        let path = self.path.clone();
        let event = event.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            upsert_event_row(&conn, &event, origin)?;
            Ok(())
        })
        .await
    }

    pub async fn record_capture(
        &self,
        event: &PackageReleaseEvent,
        origin: EventOrigin,
        capture_dir: &Path,
        capture: &CapturedRelease,
    ) -> Result<()> {
        let path = self.path.clone();
        let event = event.clone();
        let capture_dir = capture_dir.to_path_buf();
        let capture = capture.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            upsert_event_row(&conn, &event, origin)?;
            update_capture_row(&conn, &event.event_id, &capture_dir, &capture)?;
            if let Some(repository) = &capture.upstream_repository {
                upsert_package_repository_identity(
                    &conn,
                    event.ecosystem,
                    &event.package,
                    Some(&event.version),
                    repository,
                    "capture",
                )?;
            }
            Ok(())
        })
        .await
    }

    pub async fn record_diff(
        &self,
        event: &PackageReleaseEvent,
        origin: EventOrigin,
        capture_dir: &Path,
        diff: &StoredReleaseDiff,
    ) -> Result<()> {
        let path = self.path.clone();
        let event = event.clone();
        let capture_dir = capture_dir.to_path_buf();
        let diff = diff.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            upsert_event_row(&conn, &event, origin)?;
            update_diff_row(&conn, &event.event_id, &capture_dir, &diff)?;
            Ok(())
        })
        .await
    }

    pub async fn record_package_repository_identity(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: Option<&str>,
        repository: &RepositoryReleaseProvenance,
        source: &str,
    ) -> Result<()> {
        let path = self.path.clone();
        let package = normalize_package_name(ecosystem, package);
        let version = version.map(str::to_string);
        let repository = repository.clone();
        let source = source.to_string();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            upsert_package_repository_identity(
                &conn,
                ecosystem,
                &package,
                version.as_deref(),
                &repository,
                &source,
            )?;
            Ok(())
        })
        .await
    }

    pub async fn record_package_repository_ref(
        &self,
        repository: &RepoPackageRepositoryIdentity,
        version: Option<&str>,
    ) -> Result<()> {
        let path = self.path.clone();
        let mut repository = repository.clone();
        repository.package = normalize_package_name(repository.ecosystem, &repository.package);
        let version = version.map(str::to_string);
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            upsert_package_repository_ref(
                &conn,
                repository.ecosystem,
                &repository.package,
                version.as_deref(),
                &repository,
            )?;
            Ok(())
        })
        .await
    }

    pub async fn record_package_repository_refs(
        &self,
        repositories: &[RepoPackageRepositoryIdentity],
    ) -> Result<()> {
        let path = self.path.clone();
        let repositories = repositories
            .iter()
            .cloned()
            .map(|mut repository| {
                repository.package =
                    normalize_package_name(repository.ecosystem, &repository.package);
                repository
            })
            .collect::<Vec<_>>();
        spawn_store_task(move || {
            let mut conn = open_connection(&path)?;
            let tx = conn.transaction()?;
            for repository in &repositories {
                upsert_package_repository_ref(
                    &tx,
                    repository.ecosystem,
                    &repository.package,
                    None,
                    repository,
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn mark_capture_failed(&self, event_id: &str, reason: &str) -> Result<()> {
        let path = self.path.clone();
        let event_id = event_id.to_string();
        let reason = reason.to_string();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            conn.execute(
                "UPDATE release_index
                 SET capture_state = 'failed',
                     capture_reason = ?2,
                     capture_updated_at = ?3
                 WHERE event_id = ?1",
                params![event_id, reason, Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn mark_diff_failed(&self, event_id: &str, reason: &str) -> Result<()> {
        let path = self.path.clone();
        let event_id = event_id.to_string();
        let reason = reason.to_string();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            conn.execute(
                "UPDATE release_index
                 SET diff_state = 'failed',
                     diff_reason = ?2,
                     diff_updated_at = ?3
                 WHERE event_id = ?1",
                params![event_id, reason, Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn mark_diff_skipped(&self, event_id: &str, reason: &str) -> Result<()> {
        let path = self.path.clone();
        let event_id = event_id.to_string();
        let reason = reason.to_string();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            conn.execute(
                "UPDATE release_index
                 SET diff_state = 'skipped',
                     diff_reason = ?2,
                     diff_updated_at = ?3
                 WHERE event_id = ?1",
                params![event_id, reason, Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn event_count(&self) -> Result<usize> {
        let path = self.path.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM release_index", [], |row| row.get(0))?;
            usize::try_from(count).context("event count exceeds usize range")
        })
        .await
    }

    pub async fn load_package_events(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Vec<PackageReleaseEvent>> {
        let path = self.path.clone();
        let package = package.to_string();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            let mut stmt = conn.prepare(
                "SELECT event_id, ecosystem, package, version, published_at, observed_at, source, sequence, package_url, release_url, metadata_url, priority_tier, priority_source, direct_popularity, propagated_impact, hidden_leverage, priority_computed_at, priority_score_source_version
                 FROM release_index
                 WHERE ecosystem = ?1 AND package = ?2
                 ORDER BY COALESCE(published_at, observed_at), observed_at, event_id",
            )?;
            let rows = stmt.query_map(params![ecosystem.as_str(), package], event_from_row)?;
            let mut events = Vec::new();
            for row in rows {
                events.push(row?);
            }
            Ok(events)
        })
        .await
    }

    pub async fn load_event(&self, event_id: &str) -> Result<Option<PackageReleaseEvent>> {
        let path = self.path.clone();
        let event_id = event_id.to_string();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            conn.query_row(
                "SELECT event_id, ecosystem, package, version, published_at, observed_at, source, sequence, package_url, release_url, metadata_url, priority_tier, priority_source, direct_popularity, propagated_impact, hidden_leverage, priority_computed_at, priority_score_source_version
                 FROM release_index
                 WHERE event_id = ?1",
                params![event_id],
                event_from_row,
            )
            .optional()
            .map_err(anyhow::Error::from)
        })
        .await
    }

    pub async fn load_release_record(&self, event_id: &str) -> Result<Option<ReleaseRecordStatus>> {
        let path = self.path.clone();
        let event_id = event_id.to_string();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            conn.query_row(
                "SELECT event_id, ecosystem, package, version, published_at, observed_at, source, sequence, package_url, release_url, metadata_url, priority_tier, priority_source, direct_popularity, propagated_impact, hidden_leverage, priority_computed_at, priority_score_source_version, origin, capture_state, capture_status, capture_dir, capture_reason, diff_state, diff_status, diff_path, diff_reason
                 FROM release_index
                 WHERE event_id = ?1",
                params![event_id],
                release_record_from_row,
            )
            .optional()
            .map_err(anyhow::Error::from)
        })
        .await
    }

    pub async fn load_recent_events(
        &self,
        ecosystem: Option<Ecosystem>,
        limit: usize,
    ) -> Result<Vec<PackageReleaseEvent>> {
        let path = self.path.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            let limit = i64::try_from(limit).context("recent limit exceeds sqlite range")?;
            let mut events = Vec::new();

            if let Some(ecosystem) = ecosystem {
                let mut stmt = conn.prepare(
                    "SELECT event_id, ecosystem, package, version, published_at, observed_at, source, sequence, package_url, release_url, metadata_url, priority_tier, priority_source, direct_popularity, propagated_impact, hidden_leverage, priority_computed_at, priority_score_source_version
                     FROM release_index
                     WHERE ecosystem = ?1
                     ORDER BY observed_at DESC, event_id DESC
                     LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![ecosystem.as_str(), limit], event_from_row)?;
                for row in rows {
                    events.push(row?);
                }
            } else {
                let mut stmt = conn.prepare(
                    "SELECT event_id, ecosystem, package, version, published_at, observed_at, source, sequence, package_url, release_url, metadata_url, priority_tier, priority_source, direct_popularity, propagated_impact, hidden_leverage, priority_computed_at, priority_score_source_version
                     FROM release_index
                     ORDER BY observed_at DESC, event_id DESC
                     LIMIT ?1",
                )?;
                let rows = stmt.query_map(params![limit], event_from_row)?;
                for row in rows {
                    events.push(row?);
                }
            }

            Ok(events)
        })
        .await
    }

    pub async fn stats(&self) -> Result<StoreStats> {
        let path = self.path.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            let (
                total_events,
                observed_events,
                reconstructed_events,
                capture_pending,
                capture_ready,
                capture_skipped,
                capture_failed,
                diff_pending,
                diff_ready,
                diff_skipped,
                diff_failed,
                priority_high,
                priority_medium,
                priority_low,
                priority_unknown,
            ): AggregateCountsRow = conn.query_row(
                "SELECT
                    COUNT(*) AS total_events,
                    COALESCE(SUM(CASE WHEN origin = 'observed' THEN 1 ELSE 0 END), 0) AS observed_events,
                    COALESCE(SUM(CASE WHEN origin = 'reconstructed' THEN 1 ELSE 0 END), 0) AS reconstructed_events,
                    COALESCE(SUM(CASE WHEN capture_state = 'pending' THEN 1 ELSE 0 END), 0) AS capture_pending,
                    COALESCE(SUM(CASE WHEN capture_state = 'ready' THEN 1 ELSE 0 END), 0) AS capture_ready,
                    COALESCE(SUM(CASE WHEN capture_state = 'skipped' THEN 1 ELSE 0 END), 0) AS capture_skipped,
                    COALESCE(SUM(CASE WHEN capture_state = 'failed' THEN 1 ELSE 0 END), 0) AS capture_failed,
                    COALESCE(SUM(CASE WHEN diff_state = 'pending' THEN 1 ELSE 0 END), 0) AS diff_pending,
                    COALESCE(SUM(CASE WHEN diff_state = 'ready' THEN 1 ELSE 0 END), 0) AS diff_ready,
                    COALESCE(SUM(CASE WHEN diff_state = 'skipped' THEN 1 ELSE 0 END), 0) AS diff_skipped,
                    COALESCE(SUM(CASE WHEN diff_state = 'failed' THEN 1 ELSE 0 END), 0) AS diff_failed,
                    COALESCE(SUM(CASE WHEN priority_source IS NOT NULL AND priority_source != 'default_unknown' AND priority_tier = 'high' THEN 1 ELSE 0 END), 0) AS priority_high,
                    COALESCE(SUM(CASE WHEN priority_source IS NOT NULL AND priority_source != 'default_unknown' AND priority_tier = 'medium' THEN 1 ELSE 0 END), 0) AS priority_medium,
                    COALESCE(SUM(CASE WHEN priority_source IS NOT NULL AND priority_source != 'default_unknown' AND priority_tier = 'low' THEN 1 ELSE 0 END), 0) AS priority_low,
                    COALESCE(SUM(CASE WHEN priority_source IS NULL OR priority_source = 'default_unknown' THEN 1 ELSE 0 END), 0) AS priority_unknown
                 FROM release_index",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                        row.get(14)?,
                    ))
                },
            )?;

            let mut stmt = conn.prepare(
                "SELECT
                    ecosystem,
                    COUNT(*) AS total_events,
                    SUM(CASE WHEN origin = 'observed' THEN 1 ELSE 0 END) AS observed_events,
                    SUM(CASE WHEN origin = 'reconstructed' THEN 1 ELSE 0 END) AS reconstructed_events,
                    SUM(CASE WHEN capture_state = 'pending' THEN 1 ELSE 0 END) AS capture_pending,
                    SUM(CASE WHEN capture_state = 'ready' THEN 1 ELSE 0 END) AS capture_ready,
                    SUM(CASE WHEN capture_state = 'skipped' THEN 1 ELSE 0 END) AS capture_skipped,
                    SUM(CASE WHEN capture_state = 'failed' THEN 1 ELSE 0 END) AS capture_failed,
                    SUM(CASE WHEN diff_state = 'pending' THEN 1 ELSE 0 END) AS diff_pending,
                    SUM(CASE WHEN diff_state = 'ready' THEN 1 ELSE 0 END) AS diff_ready,
                    SUM(CASE WHEN diff_state = 'skipped' THEN 1 ELSE 0 END) AS diff_skipped,
                    SUM(CASE WHEN diff_state = 'failed' THEN 1 ELSE 0 END) AS diff_failed,
                    SUM(CASE WHEN priority_source IS NOT NULL AND priority_source != 'default_unknown' AND priority_tier = 'high' THEN 1 ELSE 0 END) AS priority_high,
                    SUM(CASE WHEN priority_source IS NOT NULL AND priority_source != 'default_unknown' AND priority_tier = 'medium' THEN 1 ELSE 0 END) AS priority_medium,
                    SUM(CASE WHEN priority_source IS NOT NULL AND priority_source != 'default_unknown' AND priority_tier = 'low' THEN 1 ELSE 0 END) AS priority_low,
                    SUM(CASE WHEN priority_source IS NULL OR priority_source = 'default_unknown' THEN 1 ELSE 0 END) AS priority_unknown
                 FROM release_index
                 GROUP BY ecosystem
                 ORDER BY ecosystem",
            )?;
            let rows = stmt.query_map([], |row| {
                let ecosystem: String = row.get(0)?;
                Ok(EcosystemStoreStats {
                    ecosystem: parse_ecosystem(&ecosystem).map_err(to_sql_error)?,
                    total_events: row.get::<_, i64>(1)? as usize,
                    observed_events: row.get::<_, i64>(2)? as usize,
                    reconstructed_events: row.get::<_, i64>(3)? as usize,
                    captures_ready: row.get::<_, i64>(5)? as usize,
                    diffs_ready: row.get::<_, i64>(9)? as usize,
                    capture_states: JobStateCounts {
                        pending: row.get::<_, i64>(4)? as usize,
                        ready: row.get::<_, i64>(5)? as usize,
                        skipped: row.get::<_, i64>(6)? as usize,
                        failed: row.get::<_, i64>(7)? as usize,
                    },
                    diff_states: JobStateCounts {
                        pending: row.get::<_, i64>(8)? as usize,
                        ready: row.get::<_, i64>(9)? as usize,
                        skipped: row.get::<_, i64>(10)? as usize,
                        failed: row.get::<_, i64>(11)? as usize,
                    },
                    priorities: PriorityCounts {
                        high: row.get::<_, i64>(12)? as usize,
                        medium: row.get::<_, i64>(13)? as usize,
                        low: row.get::<_, i64>(14)? as usize,
                        unknown: row.get::<_, i64>(15)? as usize,
                    },
                })
            })?;

            let mut ecosystems = Vec::new();
            for row in rows {
                ecosystems.push(row?);
            }

            Ok(StoreStats {
                total_events: total_events as usize,
                observed_events: observed_events as usize,
                reconstructed_events: reconstructed_events as usize,
                captures_ready: capture_ready as usize,
                diffs_ready: diff_ready as usize,
                capture_states: JobStateCounts {
                    pending: capture_pending as usize,
                    ready: capture_ready as usize,
                    skipped: capture_skipped as usize,
                    failed: capture_failed as usize,
                },
                diff_states: JobStateCounts {
                    pending: diff_pending as usize,
                    ready: diff_ready as usize,
                    skipped: diff_skipped as usize,
                    failed: diff_failed as usize,
                },
                priorities: PriorityCounts {
                    high: priority_high as usize,
                    medium: priority_medium as usize,
                    low: priority_low as usize,
                    unknown: priority_unknown as usize,
                },
                ecosystems,
            })
        })
        .await
    }

    pub async fn record_graph_records(&self, records: &[ScoreInputRecord]) -> Result<()> {
        let path = self.path.clone();
        let records = records.to_vec();
        spawn_store_task(move || {
            let mut conn = open_connection(&path)?;
            let tx = conn.transaction()?;
            for record in records {
                upsert_graph_record(&tx, &record)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn load_graph_evidence(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Option<GraphEvidence>> {
        let path = self.path.clone();
        let package = normalize_package_name(ecosystem, package);
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            let evidence = load_graph_evidence_blocking(&conn, ecosystem, &package)?;
            Ok(evidence)
        })
        .await
    }

    pub async fn load_graph_neighborhood(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        limit: usize,
    ) -> Result<Option<GraphNeighborhood>> {
        let path = self.path.clone();
        let package = normalize_package_name(ecosystem, package);
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            let neighborhood = load_graph_neighborhood_blocking(&conn, ecosystem, &package, limit)?;
            Ok(neighborhood)
        })
        .await
    }

    pub async fn load_package_repository_identity(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Option<PackageRepositoryIdentity>> {
        let path = self.path.clone();
        let package = normalize_package_name(ecosystem, package);
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            let repository = load_package_repository_identity_blocking(&conn, ecosystem, &package)?;
            Ok(repository)
        })
        .await
    }

    pub async fn load_graph_records_for_roots(
        &self,
        ecosystem: Ecosystem,
        roots: &[String],
        per_root_limit: usize,
    ) -> Result<GraphNeighborhoodRecords> {
        let path = self.path.clone();
        let roots = roots
            .iter()
            .map(|root| normalize_package_name(ecosystem, root))
            .collect::<Vec<_>>();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            let records =
                load_graph_records_for_roots_blocking(&conn, ecosystem, &roots, per_root_limit)?;
            Ok(records)
        })
        .await
    }

    pub async fn load_known_graph_packages(
        &self,
        ecosystems: &[Ecosystem],
    ) -> Result<BTreeSet<(Ecosystem, String)>> {
        let path = self.path.clone();
        let ecosystems = ecosystems.to_vec();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            load_known_graph_packages_blocking(&conn, &ecosystems)
        })
        .await
    }

    pub async fn graph_stats(&self) -> Result<GraphStoreStats> {
        let path = self.path.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            load_graph_store_stats_blocking(&conn)
        })
        .await
    }

    pub async fn record_priority_score_records(
        &self,
        records: &[PriorityScoreRecord],
    ) -> Result<()> {
        let path = self.path.clone();
        let records = records.to_vec();
        spawn_store_task(move || {
            let mut conn = open_connection(&path)?;
            let tx = conn.transaction()?;
            for record in &records {
                upsert_priority_score_record(&tx, record)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn load_priority_score_records(&self) -> Result<Vec<PriorityScoreRecord>> {
        let path = self.path.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            load_priority_score_records_blocking(&conn)
        })
        .await
    }

    pub async fn priority_score_stats(&self) -> Result<PriorityScoreStoreStats> {
        let path = self.path.clone();
        spawn_store_task(move || {
            let conn = open_connection(&path)?;
            load_priority_score_store_stats_blocking(&conn)
        })
        .await
    }
}

pub fn index_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join(INDEX_DB)
}

async fn spawn_store_task<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    task::spawn_blocking(f)
        .await
        .context("store task join failed")?
}

fn open_connection(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create store dir {}", parent.display()))?;
    }

    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite store {}", path.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(Duration::from_secs(5))?;
    ensure_schema(&conn)?;
    Ok(conn)
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    let existing_columns = table_columns(conn, "release_index")?;
    for (name, sql) in [
        (
            "priority_tier",
            "ALTER TABLE release_index ADD COLUMN priority_tier TEXT",
        ),
        (
            "priority_source",
            "ALTER TABLE release_index ADD COLUMN priority_source TEXT",
        ),
        (
            "direct_popularity",
            "ALTER TABLE release_index ADD COLUMN direct_popularity REAL",
        ),
        (
            "propagated_impact",
            "ALTER TABLE release_index ADD COLUMN propagated_impact REAL",
        ),
        (
            "hidden_leverage",
            "ALTER TABLE release_index ADD COLUMN hidden_leverage REAL",
        ),
        (
            "priority_computed_at",
            "ALTER TABLE release_index ADD COLUMN priority_computed_at TEXT",
        ),
        (
            "priority_score_source_version",
            "ALTER TABLE release_index ADD COLUMN priority_score_source_version TEXT",
        ),
        (
            "capture_reason",
            "ALTER TABLE release_index ADD COLUMN capture_reason TEXT",
        ),
    ] {
        if !existing_columns.contains_key(name) {
            conn.execute(sql, [])?;
        }
    }
    conn.execute(
        "UPDATE release_index SET diff_state = 'skipped' WHERE diff_state = 'not_requested'",
        [],
    )?;
    Ok(())
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashMap<String, String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    let mut columns = HashMap::new();
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        let ty: String = row.get(2)?;
        columns.insert(name, ty);
    }
    Ok(columns)
}

fn reconcile_local_data_blocking(path: &Path, data_dir: &Path) -> Result<ReconcileStats> {
    let mut records = HashMap::<String, (PackageReleaseEvent, EventOrigin)>::new();
    for event in read_event_ledger_blocking(&ledger::observed_ledger_path(data_dir))? {
        records.insert(event.event_id.clone(), (event, EventOrigin::Observed));
    }
    for event in read_event_ledger_blocking(&ledger::legacy_ledger_path(data_dir))? {
        records
            .entry(event.event_id.clone())
            .or_insert((event, EventOrigin::Observed));
    }
    for event in read_event_ledger_blocking(&ledger::reconstructed_ledger_path(data_dir))? {
        records
            .entry(event.event_id.clone())
            .or_insert((event, EventOrigin::Reconstructed));
    }

    if records.is_empty() {
        return Ok(ReconcileStats::default());
    }

    let conn = open_connection(path)?;
    let mut stats = ReconcileStats::default();

    let mut records = records.into_values().collect::<Vec<_>>();
    records.sort_by(|(left, _), (right, _)| left.event_id.cmp(&right.event_id));

    for (event, origin) in records {
        upsert_event_row(&conn, &event, origin)?;
        stats.events += 1;

        let capture_dir = capture_dir_for_event(data_dir, &event);
        let capture_path = capture_dir.join("capture.json");
        if capture_path.exists() {
            let capture = read_json_file::<CapturedRelease>(&capture_path)?;
            update_capture_row(&conn, &event.event_id, &capture_dir, &capture)?;
            for record in graph_records_from_captured_release(&capture) {
                upsert_graph_record(&conn, &record)?;
                stats.graph_records += 1;
            }
            if let Some(repository) =
                package_repository_identity_from_captured_release(event.ecosystem, &capture)
            {
                upsert_package_repository_ref(
                    &conn,
                    event.ecosystem,
                    &capture.package,
                    Some(&capture.version),
                    &repository,
                )?;
                stats.repository_refs += 1;
            }
            stats.captures += 1;
        }

        let diff_path = capture_dir.join("diff.json");
        if diff_path.exists() {
            let diff = read_json_file::<StoredReleaseDiffRecord>(&diff_path)?;
            update_diff_row_from_record(&conn, &event.event_id, &capture_dir, &diff)?;
            stats.diffs += 1;
        }
    }
    Ok(stats)
}

fn upsert_event_row(
    conn: &Connection,
    event: &PackageReleaseEvent,
    origin: EventOrigin,
) -> Result<()> {
    let origin = origin.as_str();
    let published_at = event.published_at.map(|value| value.to_rfc3339());
    let observed_at = event.observed_at.to_rfc3339();
    let priority = event.priority_snapshot();
    let default_capture_state = default_capture_state(origin, &priority).as_str();
    let default_diff_state = default_diff_state(origin, &priority).as_str();
    let priority_computed_at = priority.computed_at.map(|value| value.to_rfc3339());
    let diff_reason = diff_skip_reason(origin, &priority);
    let capture_reason = capture_skip_reason(origin, &priority);

    conn.execute(
        "INSERT INTO release_index (
            event_id,
            ecosystem,
            package,
            version,
            published_at,
            observed_at,
            source,
            sequence,
            package_url,
            release_url,
            metadata_url,
            priority_tier,
            priority_source,
            direct_popularity,
            propagated_impact,
            hidden_leverage,
            priority_computed_at,
            priority_score_source_version,
            origin,
            capture_state,
            capture_reason,
            diff_state,
            diff_reason
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)
        ON CONFLICT(event_id) DO UPDATE SET
            ecosystem = excluded.ecosystem,
            package = excluded.package,
            version = excluded.version,
            published_at = COALESCE(excluded.published_at, release_index.published_at),
            observed_at = excluded.observed_at,
            source = excluded.source,
            sequence = COALESCE(excluded.sequence, release_index.sequence),
            package_url = COALESCE(excluded.package_url, release_index.package_url),
            release_url = COALESCE(excluded.release_url, release_index.release_url),
            metadata_url = COALESCE(excluded.metadata_url, release_index.metadata_url),
            priority_tier = excluded.priority_tier,
            priority_source = excluded.priority_source,
            direct_popularity = excluded.direct_popularity,
            propagated_impact = excluded.propagated_impact,
            hidden_leverage = excluded.hidden_leverage,
            priority_computed_at = excluded.priority_computed_at,
            priority_score_source_version = excluded.priority_score_source_version,
            origin = CASE
                WHEN excluded.origin = 'observed' THEN 'observed'
                ELSE release_index.origin
            END,
            capture_state = CASE
                WHEN release_index.capture_state = 'ready' THEN release_index.capture_state
                WHEN release_index.capture_state = 'skipped' THEN release_index.capture_state
                WHEN release_index.capture_state = 'failed' THEN release_index.capture_state
                ELSE excluded.capture_state
            END,
            capture_reason = CASE
                WHEN release_index.capture_state = 'ready' THEN release_index.capture_reason
                WHEN release_index.capture_state = 'skipped' THEN release_index.capture_reason
                WHEN release_index.capture_state = 'failed' THEN release_index.capture_reason
                ELSE excluded.capture_reason
            END,
            diff_state = CASE
                WHEN release_index.diff_state = 'ready' THEN release_index.diff_state
                WHEN release_index.diff_state = 'skipped' THEN release_index.diff_state
                WHEN release_index.diff_state = 'failed' THEN release_index.diff_state
                ELSE excluded.diff_state
            END,
            diff_reason = CASE
                WHEN release_index.diff_state = 'ready' THEN release_index.diff_reason
                WHEN release_index.diff_state = 'skipped' THEN release_index.diff_reason
                WHEN release_index.diff_state = 'failed' THEN release_index.diff_reason
                ELSE excluded.diff_reason
            END",
        params![
            &event.event_id,
            event.ecosystem.as_str(),
            &event.package,
            &event.version,
            published_at,
            observed_at,
            &event.source,
            event.sequence.as_deref(),
            event.package_url.as_deref(),
            event.release_url.as_deref(),
            event.metadata_url.as_deref(),
            priority.tier.as_str(),
            priority.source.as_str(),
            priority.direct_popularity,
            priority.propagated_impact,
            priority.hidden_leverage,
            priority_computed_at,
            priority.score_source_version.as_deref(),
            origin,
            default_capture_state,
            capture_reason,
            default_diff_state,
            diff_reason,
        ],
    )?;

    Ok(())
}

fn update_capture_row(
    conn: &Connection,
    event_id: &str,
    capture_dir: &Path,
    capture: &CapturedRelease,
) -> Result<()> {
    conn.execute(
        "UPDATE release_index
         SET capture_state = 'ready',
             capture_status = ?2,
             capture_artifact_count = ?3,
             capture_dir = ?4,
             capture_reason = NULL,
             capture_updated_at = ?5
         WHERE event_id = ?1",
        params![
            event_id,
            capture.status.as_str(),
            i64::try_from(capture.artifacts.len())
                .context("artifact count exceeds sqlite range")?,
            capture_dir.display().to_string(),
            capture.captured_at.to_rfc3339(),
        ],
    )?;

    Ok(())
}

fn upsert_package_repository_identity(
    conn: &Connection,
    ecosystem: Ecosystem,
    package: &str,
    version: Option<&str>,
    repository: &RepositoryReleaseProvenance,
    source: &str,
) -> Result<()> {
    let package = normalize_package_name(ecosystem, package);
    conn.execute(
        "INSERT INTO package_repository_index (
            ecosystem,
            package,
            repository_provider,
            repository_url,
            normalized_repository_url,
            source,
            last_version,
            updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(ecosystem, package) DO UPDATE SET
            repository_provider = excluded.repository_provider,
            repository_url = excluded.repository_url,
            normalized_repository_url = excluded.normalized_repository_url,
            source = excluded.source,
            last_version = COALESCE(excluded.last_version, package_repository_index.last_version),
            updated_at = excluded.updated_at",
        params![
            ecosystem.as_str(),
            package,
            repository.provider.as_str(),
            &repository.repository_url,
            &repository.normalized_repository_url,
            source,
            version,
            repository.checked_at.to_rfc3339(),
        ],
    )?;

    Ok(())
}

fn upsert_package_repository_ref(
    conn: &Connection,
    ecosystem: Ecosystem,
    package: &str,
    version: Option<&str>,
    repository: &RepoPackageRepositoryIdentity,
) -> Result<()> {
    let package = normalize_package_name(ecosystem, package);
    conn.execute(
        "INSERT INTO package_repository_index (
            ecosystem,
            package,
            repository_provider,
            repository_url,
            normalized_repository_url,
            source,
            last_version,
            updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(ecosystem, package) DO UPDATE SET
            repository_provider = excluded.repository_provider,
            repository_url = excluded.repository_url,
            normalized_repository_url = excluded.normalized_repository_url,
            source = excluded.source,
            last_version = COALESCE(excluded.last_version, package_repository_index.last_version),
            updated_at = excluded.updated_at",
        params![
            ecosystem.as_str(),
            package,
            repository.provider.as_str(),
            &repository.repository_url,
            &repository.normalized_repository_url,
            &repository.source,
            version,
            repository.checked_at.to_rfc3339(),
        ],
    )?;

    Ok(())
}

fn update_diff_row(
    conn: &Connection,
    event_id: &str,
    capture_dir: &Path,
    diff: &StoredReleaseDiff,
) -> Result<()> {
    conn.execute(
        "UPDATE release_index
         SET diff_state = 'ready',
             diff_status = ?2,
             diff_baseline_version = ?3,
             diff_path = ?4,
             diff_reason = ?5,
             diff_updated_at = ?6
         WHERE event_id = ?1",
        params![
            event_id,
            diff.status.as_str(),
            diff.baseline_version.as_deref(),
            capture_dir.join("diff.json").display().to_string(),
            diff.reason.as_deref(),
            diff.generated_at.to_rfc3339(),
        ],
    )?;

    Ok(())
}

fn update_diff_row_from_record(
    conn: &Connection,
    event_id: &str,
    capture_dir: &Path,
    diff: &StoredReleaseDiffRecord,
) -> Result<()> {
    conn.execute(
        "UPDATE release_index
         SET diff_state = 'ready',
             diff_status = ?2,
             diff_baseline_version = ?3,
             diff_path = ?4,
             diff_reason = ?5,
             diff_updated_at = ?6
         WHERE event_id = ?1",
        params![
            event_id,
            diff.status.as_str(),
            diff.baseline_version.as_deref(),
            capture_dir.join("diff.json").display().to_string(),
            diff.reason.as_deref(),
            diff.generated_at.to_rfc3339(),
        ],
    )?;

    Ok(())
}

fn upsert_graph_record(conn: &Connection, record: &ScoreInputRecord) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    match record {
        ScoreInputRecord::Package {
            ecosystem,
            package,
            direct_popularity,
        } => {
            let package = package.to_string();
            conn.execute(
                "INSERT INTO graph_package_index (
                    ecosystem,
                    package,
                    direct_popularity,
                    updated_at
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(ecosystem, package) DO UPDATE SET
                    direct_popularity = MAX(graph_package_index.direct_popularity, excluded.direct_popularity),
                    updated_at = excluded.updated_at",
                params![ecosystem.as_str(), package, direct_popularity.max(0.0), now],
            )?;
        }
        ScoreInputRecord::Dependency {
            ecosystem,
            package,
            dependency,
            weight,
            sources,
            confidence,
        } => {
            let package = package.to_string();
            let dependency = dependency.to_string();
            let sources_json =
                serde_json::to_string(sources).context("failed to encode graph edge sources")?;

            for node in [&package, &dependency] {
                conn.execute(
                    "INSERT INTO graph_package_index (
                        ecosystem,
                        package,
                        direct_popularity,
                        updated_at
                     ) VALUES (?1, ?2, 0, ?3)
                     ON CONFLICT(ecosystem, package) DO UPDATE SET
                        updated_at = excluded.updated_at",
                    params![ecosystem.as_str(), node, now],
                )?;
            }

            conn.execute(
                "INSERT INTO graph_edge_index (
                    ecosystem,
                    package,
                    dependency,
                    weight,
                    confidence,
                    sources_json,
                    updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(ecosystem, package, dependency) DO UPDATE SET
                    weight = MAX(graph_edge_index.weight, excluded.weight),
                    confidence = CASE
                        WHEN graph_edge_index.confidence IS NULL THEN excluded.confidence
                        WHEN excluded.confidence IS NULL THEN graph_edge_index.confidence
                        ELSE MAX(graph_edge_index.confidence, excluded.confidence)
                    END,
                    sources_json = CASE
                        WHEN graph_edge_index.sources_json IS NULL OR graph_edge_index.sources_json = '[]'
                            THEN excluded.sources_json
                        ELSE graph_edge_index.sources_json
                    END,
                    updated_at = excluded.updated_at",
                params![
                    ecosystem.as_str(),
                    package,
                    dependency,
                    weight.max(0.0),
                    confidence,
                    sources_json,
                    now
                ],
            )?;
        }
    }

    Ok(())
}

fn upsert_priority_score_record(conn: &Connection, record: &PriorityScoreRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO priority_score_index (
            ecosystem,
            package,
            priority_tier,
            priority_source,
            direct_popularity,
            propagated_impact,
            hidden_leverage,
            computed_at,
            score_source_version,
            updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(ecosystem, package) DO UPDATE SET
            priority_tier = excluded.priority_tier,
            priority_source = excluded.priority_source,
            direct_popularity = excluded.direct_popularity,
            propagated_impact = excluded.propagated_impact,
            hidden_leverage = excluded.hidden_leverage,
            computed_at = excluded.computed_at,
            score_source_version = excluded.score_source_version,
            updated_at = excluded.updated_at",
        params![
            record.ecosystem.as_str(),
            record.package,
            record.priority_tier.as_str(),
            record
                .priority_source
                .map(|source| source.as_str().to_string()),
            record.direct_popularity,
            record.propagated_impact,
            record.hidden_leverage,
            record.computed_at.map(|value| value.to_rfc3339()),
            record.score_source_version,
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn load_graph_evidence_blocking(
    conn: &Connection,
    ecosystem: Ecosystem,
    package: &str,
) -> Result<Option<GraphEvidence>> {
    let direct_popularity: f64 = conn.query_row(
        "SELECT COALESCE(
            (SELECT direct_popularity
             FROM graph_package_index
             WHERE ecosystem = ?1 AND package = ?2),
            0
         )",
        params![ecosystem.as_str(), package],
        |row| row.get(0),
    )?;
    let direct_dependencies_seen: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM graph_edge_index
         WHERE ecosystem = ?1 AND package = ?2",
        params![ecosystem.as_str(), package],
        |row| row.get(0),
    )?;
    let reverse_dependents_seen: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM graph_edge_index
         WHERE ecosystem = ?1 AND dependency = ?2",
        params![ecosystem.as_str(), package],
        |row| row.get(0),
    )?;
    let known: i64 = conn.query_row(
        "SELECT CASE
            WHEN EXISTS(
                SELECT 1
                FROM graph_package_index
                WHERE ecosystem = ?1 AND package = ?2
            ) OR EXISTS(
                SELECT 1
                FROM graph_edge_index
                WHERE ecosystem = ?1 AND (package = ?2 OR dependency = ?2)
            )
            THEN 1 ELSE 0
         END",
        params![ecosystem.as_str(), package],
        |row| row.get(0),
    )?;
    let repository = load_package_repository_identity_blocking(conn, ecosystem, package)?;

    if known == 0 {
        return Ok(None);
    }

    Ok(Some(GraphEvidence {
        ecosystem,
        package: package.to_string(),
        known: true,
        direct_popularity,
        direct_dependencies_seen: usize::try_from(direct_dependencies_seen)
            .context("graph dependency count exceeds usize range")?,
        reverse_dependents_seen: usize::try_from(reverse_dependents_seen)
            .context("graph reverse dependent count exceeds usize range")?,
        repository,
    }))
}

fn load_graph_neighborhood_blocking(
    conn: &Connection,
    ecosystem: Ecosystem,
    package: &str,
    limit: usize,
) -> Result<Option<GraphNeighborhood>> {
    let Some(evidence) = load_graph_evidence_blocking(conn, ecosystem, package)? else {
        return Ok(None);
    };
    let limit = i64::try_from(limit).context("graph neighborhood limit exceeds i64 range")?;

    let mut direct_statement = conn.prepare(
        "SELECT dependency
         FROM graph_edge_index
         WHERE ecosystem = ?1 AND package = ?2
         ORDER BY dependency
         LIMIT ?3",
    )?;
    let direct_dependencies = direct_statement
        .query_map(params![ecosystem.as_str(), package, limit], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut reverse_statement = conn.prepare(
        "SELECT package
         FROM graph_edge_index
         WHERE ecosystem = ?1 AND dependency = ?2
         ORDER BY package
         LIMIT ?3",
    )?;
    let reverse_dependents = reverse_statement
        .query_map(params![ecosystem.as_str(), package, limit], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(Some(GraphNeighborhood {
        evidence,
        direct_dependencies,
        reverse_dependents,
    }))
}

fn load_known_graph_packages_blocking(
    conn: &Connection,
    ecosystems: &[Ecosystem],
) -> Result<BTreeSet<(Ecosystem, String)>> {
    let mut known = BTreeSet::new();
    if ecosystems.is_empty() {
        let mut stmt = conn.prepare(
            "SELECT ecosystem, package
             FROM graph_package_index
             ORDER BY ecosystem, package",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (ecosystem, package) = row?;
            known.insert((parse_ecosystem(&ecosystem)?, package));
        }
        return Ok(known);
    }

    let ecosystem_values = ecosystems
        .iter()
        .map(|ecosystem| rusqlite::types::Value::from(ecosystem.as_str().to_string()))
        .collect::<Vec<_>>();
    let sql = format!(
        "SELECT ecosystem, package
         FROM graph_package_index
         WHERE ecosystem IN ({})
         ORDER BY ecosystem, package",
        sqlite_placeholders(1, ecosystem_values.len())
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(ecosystem_values), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (ecosystem, package) = row?;
        known.insert((parse_ecosystem(&ecosystem)?, package));
    }
    Ok(known)
}

fn load_graph_store_stats_blocking(conn: &Connection) -> Result<GraphStoreStats> {
    let packages: i64 = conn.query_row("SELECT COUNT(*) FROM graph_package_index", [], |row| {
        row.get(0)
    })?;
    let dependencies: i64 = conn.query_row("SELECT COUNT(*) FROM graph_edge_index", [], |row| {
        row.get(0)
    })?;

    let mut stmt = conn.prepare(
        "SELECT
            ecosystems.ecosystem,
            COALESCE(packages.package_count, 0) AS package_count,
            COALESCE(edges.dependency_count, 0) AS dependency_count
         FROM (
             SELECT ecosystem FROM graph_package_index
             UNION
             SELECT ecosystem FROM graph_edge_index
         ) AS ecosystems
         LEFT JOIN (
             SELECT ecosystem, COUNT(*) AS package_count
             FROM graph_package_index
             GROUP BY ecosystem
         ) AS packages ON packages.ecosystem = ecosystems.ecosystem
         LEFT JOIN (
             SELECT ecosystem, COUNT(*) AS dependency_count
             FROM graph_edge_index
             GROUP BY ecosystem
         ) AS edges ON edges.ecosystem = ecosystems.ecosystem
         ORDER BY ecosystems.ecosystem",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(GraphStoreEcosystemStats {
            ecosystem: parse_ecosystem(&row.get::<_, String>(0)?).map_err(to_sql_error)?,
            packages: row.get::<_, i64>(1)? as usize,
            dependencies: row.get::<_, i64>(2)? as usize,
        })
    })?;
    let mut ecosystems = Vec::new();
    for row in rows {
        ecosystems.push(row?);
    }

    Ok(GraphStoreStats {
        packages: packages as usize,
        dependencies: dependencies as usize,
        ecosystems,
    })
}

fn load_priority_score_records_blocking(conn: &Connection) -> Result<Vec<PriorityScoreRecord>> {
    let mut stmt = conn.prepare(
        "SELECT
            ecosystem,
            package,
            priority_tier,
            priority_source,
            direct_popularity,
            propagated_impact,
            hidden_leverage,
            computed_at,
            score_source_version
         FROM priority_score_index
         ORDER BY ecosystem, package",
    )?;
    let rows = stmt.query_map([], priority_score_record_from_row)?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

fn load_priority_score_store_stats_blocking(conn: &Connection) -> Result<PriorityScoreStoreStats> {
    let scored_packages: i64 =
        conn.query_row("SELECT COUNT(*) FROM priority_score_index", [], |row| {
            row.get(0)
        })?;

    let mut stmt = conn.prepare(
        "SELECT
            ecosystem,
            COUNT(*) AS packages,
            COALESCE(SUM(CASE WHEN priority_tier = 'high' THEN 1 ELSE 0 END), 0) AS high_count,
            COALESCE(SUM(CASE WHEN priority_tier = 'medium' THEN 1 ELSE 0 END), 0) AS medium_count,
            COALESCE(SUM(CASE WHEN priority_tier = 'low' THEN 1 ELSE 0 END), 0) AS low_count
         FROM priority_score_index
         GROUP BY ecosystem
         ORDER BY ecosystem",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(PriorityScoreStoreEcosystemStats {
            ecosystem: parse_ecosystem(&row.get::<_, String>(0)?).map_err(to_sql_error)?,
            packages: row.get::<_, i64>(1)? as usize,
            priorities: PriorityCounts {
                high: row.get::<_, i64>(2)? as usize,
                medium: row.get::<_, i64>(3)? as usize,
                low: row.get::<_, i64>(4)? as usize,
                unknown: 0,
            },
        })
    })?;
    let mut ecosystems = Vec::new();
    for row in rows {
        ecosystems.push(row?);
    }

    Ok(PriorityScoreStoreStats {
        scored_packages: scored_packages as usize,
        ecosystems,
    })
}

fn load_package_repository_identity_blocking(
    conn: &Connection,
    ecosystem: Ecosystem,
    package: &str,
) -> Result<Option<PackageRepositoryIdentity>> {
    let mut statement = conn.prepare(
        "SELECT repository_provider, repository_url, normalized_repository_url, source, last_version, updated_at
         FROM package_repository_index
         WHERE ecosystem = ?1 AND package = ?2",
    )?;
    let identity = statement
        .query_row(params![ecosystem.as_str(), package], |row| {
            Ok(PackageRepositoryIdentity {
                provider: row.get(0)?,
                repository_url: row.get(1)?,
                normalized_repository_url: row.get(2)?,
                source: row.get(3)?,
                last_version: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })
        .optional()?;
    Ok(identity)
}

fn load_graph_records_for_roots_blocking(
    conn: &Connection,
    ecosystem: Ecosystem,
    roots: &[String],
    per_root_limit: usize,
) -> Result<GraphNeighborhoodRecords> {
    let normalized_roots = roots
        .iter()
        .map(|root| root.trim())
        .filter(|root| !root.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if normalized_roots.is_empty() {
        return Ok(GraphNeighborhoodRecords {
            roots: Vec::new(),
            records: Vec::new(),
        });
    }

    let root_values = normalized_roots
        .iter()
        .map(|value| rusqlite::types::Value::from(value.clone()))
        .collect::<Vec<_>>();
    let incoming_limit =
        i64::try_from(per_root_limit.saturating_mul(normalized_roots.len()).max(1))
            .context("graph records limit exceeds i64 range")?;
    let incoming_sql = format!(
        "SELECT DISTINCT package
         FROM graph_edge_index
         WHERE ecosystem = ?1 AND dependency IN ({})
         ORDER BY package
         LIMIT ?{}",
        sqlite_placeholders(2, root_values.len()),
        root_values.len() + 2
    );
    let mut incoming_params = Vec::with_capacity(2 + root_values.len());
    incoming_params.push(rusqlite::types::Value::from(ecosystem.as_str().to_string()));
    incoming_params.extend(root_values.iter().cloned());
    incoming_params.push(rusqlite::types::Value::from(incoming_limit));
    let mut incoming_statement = conn.prepare(&incoming_sql)?;
    let reverse_dependents = incoming_statement
        .query_map(rusqlite::params_from_iter(incoming_params), |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut frontier = BTreeSet::new();
    for root in &normalized_roots {
        if load_graph_evidence_blocking(conn, ecosystem, root)?.is_some() {
            frontier.insert(root.clone());
        }
    }
    frontier.extend(reverse_dependents);
    if frontier.is_empty() {
        return Ok(GraphNeighborhoodRecords {
            roots: normalized_roots,
            records: Vec::new(),
        });
    }
    let frontier_values = frontier
        .iter()
        .cloned()
        .map(rusqlite::types::Value::from)
        .collect::<Vec<_>>();
    let edge_limit = i64::try_from(per_root_limit.saturating_mul(frontier_values.len()).max(1))
        .context("graph edge limit exceeds i64 range")?;
    let edge_sql = format!(
        "SELECT package, dependency, weight, sources_json, confidence
         FROM graph_edge_index
         WHERE ecosystem = ?1 AND package IN ({})
         ORDER BY package, dependency
         LIMIT ?{}",
        sqlite_placeholders(2, frontier_values.len()),
        frontier_values.len() + 2
    );
    let mut edge_params = Vec::with_capacity(2 + frontier_values.len());
    edge_params.push(rusqlite::types::Value::from(ecosystem.as_str().to_string()));
    edge_params.extend(frontier_values.iter().cloned());
    edge_params.push(rusqlite::types::Value::from(edge_limit));
    let mut edge_statement = conn.prepare(&edge_sql)?;
    let edges = edge_statement
        .query_map(rusqlite::params_from_iter(edge_params), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<f64>>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut package_names = frontier.clone();
    for (package, dependency, _, _, _) in &edges {
        package_names.insert(package.clone());
        package_names.insert(dependency.clone());
    }

    let package_values = package_names
        .iter()
        .cloned()
        .map(rusqlite::types::Value::from)
        .collect::<Vec<_>>();
    let package_sql = format!(
        "SELECT package, direct_popularity
         FROM graph_package_index
         WHERE ecosystem = ?1 AND package IN ({})",
        sqlite_placeholders(2, package_values.len())
    );
    let mut package_params = Vec::with_capacity(1 + package_values.len());
    package_params.push(rusqlite::types::Value::from(ecosystem.as_str().to_string()));
    package_params.extend(package_values.iter().cloned());
    let mut package_statement = conn.prepare(&package_sql)?;
    let known_packages = package_statement
        .query_map(rusqlite::params_from_iter(package_params), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        })?
        .collect::<std::result::Result<HashMap<_, _>, _>>()?;

    let mut records = Vec::new();
    for package in &package_names {
        records.push(ScoreInputRecord::Package {
            ecosystem,
            package: package.clone(),
            direct_popularity: known_packages.get(package).copied().unwrap_or_default(),
        });
    }
    for (package, dependency, weight, sources_json, confidence) in edges {
        let sources = sources_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
            .unwrap_or_default();
        records.push(ScoreInputRecord::Dependency {
            ecosystem,
            package,
            dependency,
            weight,
            sources,
            confidence,
        });
    }

    Ok(GraphNeighborhoodRecords {
        roots: normalized_roots,
        records,
    })
}

fn sqlite_placeholders(start_index: usize, count: usize) -> String {
    (0..count)
        .map(|offset| format!("?{}", start_index + offset))
        .collect::<Vec<_>>()
        .join(", ")
}

fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PackageReleaseEvent> {
    let ecosystem: String = row.get(1)?;
    let published_at: Option<String> = row.get(4)?;
    let observed_at: String = row.get(5)?;
    let priority_tier: Option<String> = row.get(11)?;
    let priority_source: Option<String> = row.get(12)?;
    let priority_computed_at: Option<String> = row.get(16)?;

    Ok(PackageReleaseEvent {
        event_id: row.get(0)?,
        ecosystem: parse_ecosystem(&ecosystem).map_err(to_sql_error)?,
        package: row.get(2)?,
        version: row.get(3)?,
        published_at: published_at
            .as_deref()
            .map(parse_datetime)
            .transpose()
            .map_err(to_sql_error)?,
        observed_at: parse_datetime(&observed_at).map_err(to_sql_error)?,
        source: row.get(6)?,
        sequence: row.get(7)?,
        package_url: row.get(8)?,
        release_url: row.get(9)?,
        metadata_url: row.get(10)?,
        priority: Some(PrioritySnapshot {
            tier: priority_tier
                .as_deref()
                .map(parse_priority_tier)
                .transpose()
                .map_err(to_sql_error)?
                .unwrap_or(PriorityTier::Medium),
            source: priority_source
                .as_deref()
                .map(parse_priority_source)
                .transpose()
                .map_err(to_sql_error)?
                .unwrap_or(PrioritySource::DefaultUnknown),
            direct_popularity: row.get(13)?,
            propagated_impact: row.get(14)?,
            hidden_leverage: row.get(15)?,
            computed_at: priority_computed_at
                .as_deref()
                .map(parse_datetime)
                .transpose()
                .map_err(to_sql_error)?,
            score_source_version: row.get(17)?,
        }),
    })
}

fn release_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReleaseRecordStatus> {
    let event = event_from_row(row)?;
    Ok(ReleaseRecordStatus {
        event,
        origin: row.get(18)?,
        capture_state: row.get(19)?,
        capture_status: row.get(20)?,
        capture_dir: row.get(21)?,
        capture_reason: row.get(22)?,
        diff_state: row.get(23)?,
        diff_status: row.get(24)?,
        diff_path: row.get(25)?,
        diff_reason: row.get(26)?,
    })
}

fn priority_score_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PriorityScoreRecord> {
    let ecosystem: String = row.get(0)?;
    let priority_tier: String = row.get(2)?;
    let priority_source: Option<String> = row.get(3)?;
    let computed_at: Option<String> = row.get(7)?;
    Ok(PriorityScoreRecord {
        ecosystem: parse_ecosystem(&ecosystem).map_err(to_sql_error)?,
        package: row.get(1)?,
        priority_tier: parse_priority_tier(&priority_tier).map_err(to_sql_error)?,
        priority_source: priority_source
            .as_deref()
            .map(parse_priority_source)
            .transpose()
            .map_err(to_sql_error)?,
        direct_popularity: row.get(4)?,
        propagated_impact: row.get(5)?,
        hidden_leverage: row.get(6)?,
        computed_at: computed_at
            .as_deref()
            .map(parse_datetime)
            .transpose()
            .map_err(to_sql_error)?,
        score_source_version: row.get(8)?,
    })
}

fn read_event_ledger_blocking(path: &Path) -> Result<Vec<PackageReleaseEvent>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open event ledger {}", path.display()));
        }
    };

    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for line in reader.lines() {
        let line = line.with_context(|| format!("failed reading line from {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }

        let event = serde_json::from_str::<PackageReleaseEvent>(&line)
            .with_context(|| format!("failed to decode ledger line from {}", path.display()))?;
        events.push(event);
    }

    Ok(events)
}

fn read_json_file<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid rfc3339 timestamp: {value}"))?
        .with_timezone(&Utc))
}

fn parse_ecosystem(value: &str) -> Result<Ecosystem> {
    match value {
        "npm" => Ok(Ecosystem::Npm),
        "pypi" => Ok(Ecosystem::Pypi),
        "crates-io" => Ok(Ecosystem::CratesIo),
        _ => anyhow::bail!("unknown ecosystem {value}"),
    }
}

fn parse_priority_tier(value: &str) -> Result<PriorityTier> {
    match value {
        "high" => Ok(PriorityTier::High),
        "medium" => Ok(PriorityTier::Medium),
        "low" => Ok(PriorityTier::Low),
        _ => anyhow::bail!("unknown priority tier {value}"),
    }
}

fn parse_priority_source(value: &str) -> Result<PrioritySource> {
    match value {
        "offline_score_file" => Ok(PrioritySource::OfflineScoreFile),
        "package_census" => Ok(PrioritySource::PackageCensus),
        "known_package_stub" => Ok(PrioritySource::KnownPackageStub),
        "local_graph" => Ok(PrioritySource::LocalGraph),
        "deps_dev_dependents_api" => Ok(PrioritySource::DepsDevDependentsApi),
        "ecosyste_ms_counts_api" => Ok(PrioritySource::EcosysteMsCountsApi),
        "default_unknown" => Ok(PrioritySource::DefaultUnknown),
        _ => anyhow::bail!("unknown priority source {value}"),
    }
}

fn default_capture_state(origin: &str, priority: &PrioritySnapshot) -> JobState {
    if origin == EventOrigin::Observed.as_str() {
        if priority.capture_requested() {
            JobState::Pending
        } else {
            JobState::Skipped
        }
    } else {
        JobState::Pending
    }
}

fn default_diff_state(origin: &str, priority: &PrioritySnapshot) -> JobState {
    if origin == EventOrigin::Observed.as_str() && priority.diff_requested() {
        JobState::Pending
    } else {
        JobState::Skipped
    }
}

fn capture_skip_reason(origin: &str, priority: &PrioritySnapshot) -> Option<&'static str> {
    if origin == EventOrigin::Observed.as_str() && !priority.capture_requested() {
        Some("priority policy skipped capture")
    } else {
        None
    }
}

fn diff_skip_reason(origin: &str, priority: &PrioritySnapshot) -> Option<&'static str> {
    if origin == EventOrigin::Observed.as_str() && !priority.diff_requested() {
        Some("priority policy skipped diff")
    } else if origin != EventOrigin::Observed.as_str() {
        Some("reconstructed release skipped diff")
    } else {
        None
    }
}

fn capture_dir_for_event(data_dir: &Path, event: &PackageReleaseEvent) -> PathBuf {
    data_dir
        .join("captures")
        .join(event.ecosystem.as_str())
        .join(urlencoding::encode(&event.package).into_owned())
        .join(urlencoding::encode(&event.version).into_owned())
}

fn to_sql_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredReleaseDiffStatusRecord {
    Ready,
    NoBaseline,
}

impl StoredReleaseDiffStatusRecord {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NoBaseline => "no_baseline",
        }
    }
}

#[derive(Debug, Deserialize)]
struct StoredReleaseDiffRecord {
    generated_at: DateTime<Utc>,
    baseline_version: Option<String>,
    status: StoredReleaseDiffStatusRecord,
    reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        capture::{ArtifactHashes, CapturedArtifact, ReleaseStatus},
        diff::StoredReleaseDiffStatus,
        ledger::EventLedger,
        priority::{PrioritySnapshot, PrioritySource, PriorityTier},
    };

    #[tokio::test]
    async fn store_reconciles_ledgers_and_indexes_capture_and_diff() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let store = OperationalStore::open(index_db_path(&data_dir))
            .await
            .unwrap();

        let observed = sample_event("1.0.0");
        let reconstructed = sample_event("0.9.0");

        let observed_ledger = EventLedger::open(ledger::observed_ledger_path(&data_dir))
            .await
            .unwrap();
        observed_ledger.append(&observed).await.unwrap();

        let reconstructed_ledger = EventLedger::open(ledger::reconstructed_ledger_path(&data_dir))
            .await
            .unwrap();
        reconstructed_ledger.append(&reconstructed).await.unwrap();

        let observed_capture_dir = capture_dir_for_event(&data_dir, &observed);
        tokio::fs::create_dir_all(&observed_capture_dir)
            .await
            .unwrap();
        tokio::fs::write(
            observed_capture_dir.join("capture.json"),
            serde_json::to_vec_pretty(&sample_capture(&observed, ReleaseStatus::Active)).unwrap(),
        )
        .await
        .unwrap();
        tokio::fs::write(
            observed_capture_dir.join("diff.json"),
            serde_json::to_vec_pretty(&sample_diff(&observed, Some("0.9.0"))).unwrap(),
        )
        .await
        .unwrap();

        let reconstructed_capture_dir = capture_dir_for_event(&data_dir, &reconstructed);
        tokio::fs::create_dir_all(&reconstructed_capture_dir)
            .await
            .unwrap();
        tokio::fs::write(
            reconstructed_capture_dir.join("capture.json"),
            serde_json::to_vec_pretty(&sample_capture(&reconstructed, ReleaseStatus::Removed))
                .unwrap(),
        )
        .await
        .unwrap();

        let stats = store.reconcile_local_data(&data_dir).await.unwrap();
        assert_eq!(
            stats,
            ReconcileStats {
                events: 2,
                captures: 2,
                diffs: 1,
                graph_records: 1,
                repository_refs: 0,
            }
        );

        let package_events = store
            .load_package_events(Ecosystem::Pypi, "demo")
            .await
            .unwrap();
        assert_eq!(package_events.len(), 2);
        assert_eq!(package_events[0].version, "0.9.0");
        assert_eq!(package_events[1].version, "1.0.0");

        let recent = store.load_recent_events(None, 10).await.unwrap();
        assert_eq!(recent.len(), 2);

        let event = store.load_event(&observed.event_id).await.unwrap().unwrap();
        assert_eq!(event.version, "1.0.0");

        let graph = store
            .load_graph_evidence(Ecosystem::Pypi, "demo")
            .await
            .unwrap()
            .unwrap();
        assert!(graph.known);
        assert_eq!(graph.direct_dependencies_seen, 0);
    }

    #[tokio::test]
    async fn store_tracks_priority_tiers_and_job_states() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let store = OperationalStore::open(index_db_path(&data_dir))
            .await
            .unwrap();

        let high = sample_event_with_priority(
            "1.0.0",
            PrioritySnapshot {
                tier: PriorityTier::High,
                source: PrioritySource::OfflineScoreFile,
                direct_popularity: Some(100.0),
                propagated_impact: Some(10_000.0),
                hidden_leverage: Some(5.0),
                computed_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 13, 0, 0).unwrap()),
                score_source_version: Some("scores-v1".to_string()),
            },
        );
        let medium = sample_event_with_priority(
            "1.0.1",
            PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::OfflineScoreFile,
                direct_popularity: Some(10.0),
                propagated_impact: Some(500.0),
                hidden_leverage: Some(2.0),
                computed_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 13, 0, 0).unwrap()),
                score_source_version: Some("scores-v1".to_string()),
            },
        );
        let low = sample_event_with_priority(
            "1.0.2",
            PrioritySnapshot {
                tier: PriorityTier::Low,
                source: PrioritySource::OfflineScoreFile,
                direct_popularity: Some(1.0),
                propagated_impact: Some(5.0),
                hidden_leverage: Some(0.1),
                computed_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 13, 0, 0).unwrap()),
                score_source_version: Some("scores-v1".to_string()),
            },
        );

        store
            .record_event(&high, EventOrigin::Observed)
            .await
            .unwrap();
        store
            .record_event(&medium, EventOrigin::Observed)
            .await
            .unwrap();
        store
            .record_event(&low, EventOrigin::Observed)
            .await
            .unwrap();

        let high_capture_dir = capture_dir_for_event(&data_dir, &high);
        let medium_capture_dir = capture_dir_for_event(&data_dir, &medium);
        store
            .record_capture(
                &high,
                EventOrigin::Observed,
                &high_capture_dir,
                &sample_capture(&high, ReleaseStatus::Active),
            )
            .await
            .unwrap();
        store
            .record_diff(
                &high,
                EventOrigin::Observed,
                &high_capture_dir,
                &sample_diff(&high, Some("0.9.9")),
            )
            .await
            .unwrap();
        store
            .record_capture(
                &medium,
                EventOrigin::Observed,
                &medium_capture_dir,
                &sample_capture(&medium, ReleaseStatus::Active),
            )
            .await
            .unwrap();

        let stats = store.stats().await.unwrap();
        assert_eq!(stats.priorities.high, 1);
        assert_eq!(stats.priorities.medium, 1);
        assert_eq!(stats.priorities.low, 1);
        assert_eq!(stats.priorities.unknown, 0);
        assert_eq!(stats.capture_states.pending, 0);
        assert_eq!(stats.capture_states.ready, 2);
        assert_eq!(stats.capture_states.skipped, 1);
        assert_eq!(stats.capture_states.failed, 0);
        assert_eq!(stats.diff_states.pending, 0);
        assert_eq!(stats.diff_states.ready, 1);
        assert_eq!(stats.diff_states.skipped, 2);
        assert_eq!(stats.diff_states.failed, 0);
    }

    #[tokio::test]
    async fn store_records_graph_rows_and_loads_evidence() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let store = OperationalStore::open(index_db_path(&data_dir))
            .await
            .unwrap();

        store
            .record_graph_records(&[
                ScoreInputRecord::Package {
                    ecosystem: Ecosystem::Npm,
                    package: "pkg-a".to_string(),
                    direct_popularity: 3.0,
                },
                ScoreInputRecord::Dependency {
                    ecosystem: Ecosystem::Npm,
                    package: "pkg-a".to_string(),
                    dependency: "dep-b".to_string(),
                    weight: 1.0,
                    sources: vec!["capture_metadata".to_string()],
                    confidence: Some(1.0),
                },
                ScoreInputRecord::Dependency {
                    ecosystem: Ecosystem::Npm,
                    package: "pkg-c".to_string(),
                    dependency: "dep-b".to_string(),
                    weight: 1.0,
                    sources: vec!["capture_metadata".to_string()],
                    confidence: Some(0.8),
                },
            ])
            .await
            .unwrap();

        let package = store
            .load_graph_evidence(Ecosystem::Npm, "pkg-a")
            .await
            .unwrap()
            .unwrap();
        assert!(package.known);
        assert_eq!(package.direct_popularity, 3.0);
        assert_eq!(package.direct_dependencies_seen, 1);
        assert_eq!(package.reverse_dependents_seen, 0);

        let dependency = store
            .load_graph_evidence(Ecosystem::Npm, "dep-b")
            .await
            .unwrap()
            .unwrap();
        assert!(dependency.known);
        assert_eq!(dependency.direct_popularity, 0.0);
        assert_eq!(dependency.direct_dependencies_seen, 0);
        assert_eq!(dependency.reverse_dependents_seen, 2);

        let neighborhood = store
            .load_graph_neighborhood(Ecosystem::Npm, "dep-b", 10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(neighborhood.direct_dependencies, Vec::<String>::new());
        assert_eq!(
            neighborhood.reverse_dependents,
            vec!["pkg-a".to_string(), "pkg-c".to_string()]
        );
    }

    #[tokio::test]
    async fn store_preserves_failed_capture_state_across_event_reindex() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let store = OperationalStore::open(index_db_path(&data_dir))
            .await
            .unwrap();

        let event = PackageReleaseEvent {
            event_id: "npm:@mastra/deployer-cloudflare@0.0.0-satin-jumpsuit-20260327151201"
                .to_string(),
            ecosystem: Ecosystem::Npm,
            package: "@mastra/deployer-cloudflare".to_string(),
            version: "0.0.0-satin-jumpsuit-20260327151201".to_string(),
            published_at: Some(Utc.with_ymd_and_hms(2026, 3, 27, 15, 19, 0).unwrap()),
            observed_at: Utc.with_ymd_and_hms(2026, 3, 27, 15, 19, 30).unwrap(),
            source: "test".to_string(),
            sequence: Some("seq-1".to_string()),
            package_url: Some(
                "https://www.npmjs.com/package/@mastra/deployer-cloudflare".to_string(),
            ),
            release_url: Some(
                "https://www.npmjs.com/package/@mastra/deployer-cloudflare/v/0.0.0-satin-jumpsuit-20260327151201"
                    .to_string(),
            ),
            metadata_url: Some(
                "https://registry.npmjs.org/%40mastra%2Fdeployer-cloudflare".to_string(),
            ),
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: Some(0.0),
                propagated_impact: Some(0.0),
                hidden_leverage: Some(0.0),
                computed_at: Some(Utc.with_ymd_and_hms(2026, 3, 27, 15, 19, 30).unwrap()),
                score_source_version: Some("runtime_observed_v1".to_string()),
            }),
        };

        store
            .record_event(&event, EventOrigin::Observed)
            .await
            .unwrap();
        store
            .mark_capture_failed(&event.event_id, "failed to decode npm metadata")
            .await
            .unwrap();

        store
            .record_event(&event, EventOrigin::Observed)
            .await
            .unwrap();

        let record = store
            .load_release_record(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.capture_state, "failed");
        assert_eq!(
            record.capture_reason.as_deref(),
            Some("failed to decode npm metadata")
        );
    }

    #[tokio::test]
    async fn store_records_priority_scores_and_graph_stats() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let store = OperationalStore::open(index_db_path(&data_dir))
            .await
            .unwrap();

        store
            .record_graph_records(&[
                ScoreInputRecord::Package {
                    ecosystem: Ecosystem::Pypi,
                    package: "pkg-a".to_string(),
                    direct_popularity: 2.0,
                },
                ScoreInputRecord::Package {
                    ecosystem: Ecosystem::Pypi,
                    package: "pkg-b".to_string(),
                    direct_popularity: 1.0,
                },
                ScoreInputRecord::Dependency {
                    ecosystem: Ecosystem::Pypi,
                    package: "pkg-a".to_string(),
                    dependency: "pkg-b".to_string(),
                    weight: 1.0,
                    sources: vec!["capture_metadata".to_string()],
                    confidence: Some(1.0),
                },
            ])
            .await
            .unwrap();
        store
            .record_priority_score_records(&[
                PriorityScoreRecord {
                    ecosystem: Ecosystem::Pypi,
                    package: "pkg-a".to_string(),
                    priority_tier: PriorityTier::Low,
                    priority_source: Some(PrioritySource::LocalGraph),
                    direct_popularity: Some(2.0),
                    propagated_impact: Some(2.0),
                    hidden_leverage: Some(0.0),
                    computed_at: Some(Utc.with_ymd_and_hms(2026, 3, 27, 10, 0, 0).unwrap()),
                    score_source_version: Some("local_graph".to_string()),
                },
                PriorityScoreRecord {
                    ecosystem: Ecosystem::Pypi,
                    package: "pkg-b".to_string(),
                    priority_tier: PriorityTier::Medium,
                    priority_source: Some(PrioritySource::LocalGraph),
                    direct_popularity: Some(1.0),
                    propagated_impact: Some(3.0),
                    hidden_leverage: Some(1.0),
                    computed_at: Some(Utc.with_ymd_and_hms(2026, 3, 27, 10, 0, 0).unwrap()),
                    score_source_version: Some("local_graph".to_string()),
                },
            ])
            .await
            .unwrap();

        let known = store
            .load_known_graph_packages(&[Ecosystem::Pypi])
            .await
            .unwrap();
        assert!(known.contains(&(Ecosystem::Pypi, "pkg-a".to_string())));
        assert!(known.contains(&(Ecosystem::Pypi, "pkg-b".to_string())));

        let graph_stats = store.graph_stats().await.unwrap();
        assert_eq!(graph_stats.packages, 2);
        assert_eq!(graph_stats.dependencies, 1);
        assert_eq!(graph_stats.ecosystems.len(), 1);
        assert_eq!(graph_stats.ecosystems[0].packages, 2);
        assert_eq!(graph_stats.ecosystems[0].dependencies, 1);

        let scores = store.load_priority_score_records().await.unwrap();
        assert_eq!(scores.len(), 2);

        let score_stats = store.priority_score_stats().await.unwrap();
        assert_eq!(score_stats.scored_packages, 2);
        assert_eq!(score_stats.ecosystems.len(), 1);
        assert_eq!(score_stats.ecosystems[0].packages, 2);
        assert_eq!(score_stats.ecosystems[0].priorities.medium, 1);
        assert_eq!(score_stats.ecosystems[0].priorities.low, 1);
    }

    fn sample_event(version: &str) -> PackageReleaseEvent {
        sample_event_with_priority(version, PrioritySnapshot::default_unknown())
    }

    fn sample_event_with_priority(
        version: &str,
        priority: PrioritySnapshot,
    ) -> PackageReleaseEvent {
        PackageReleaseEvent {
            event_id: format!("pypi:demo@{version}"),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: version.to_string(),
            published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 14, 0, 0).unwrap()),
            observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 14, 1, 0).unwrap(),
            source: "test".to_string(),
            sequence: None,
            package_url: Some("https://example.test/demo".to_string()),
            release_url: Some(format!("https://example.test/demo/{version}")),
            metadata_url: Some(format!("https://example.test/demo/{version}/json")),
            priority: Some(priority),
        }
    }

    fn sample_capture(event: &PackageReleaseEvent, status: ReleaseStatus) -> CapturedRelease {
        CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc.with_ymd_and_hms(2026, 3, 25, 14, 2, 0).unwrap(),
            status,
            package_url: event.package_url.clone(),
            release_url: event.release_url.clone(),
            metadata_url: event.metadata_url.clone(),
            raw_metadata_path: Some("metadata.json".to_string()),
            artifacts: vec![CapturedArtifact {
                filename: format!("demo-{}.whl", event.version),
                kind: Some("bdist_wheel".to_string()),
                url: Some("https://example.test/artifact".to_string()),
                size_bytes: Some(42),
                uploaded_at: event.published_at,
                yanked: None,
                hashes: ArtifactHashes {
                    sha256: Some("abc".to_string()),
                    ..ArtifactHashes::default()
                },
                provenance_path: None,
            }],
            upstream_repository: None,
            details: serde_json::json!({"name": "demo"}),
        }
    }

    fn sample_diff(
        event: &PackageReleaseEvent,
        baseline_version: Option<&str>,
    ) -> StoredReleaseDiff {
        StoredReleaseDiff {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            generated_at: Utc.with_ymd_and_hms(2026, 3, 25, 14, 3, 0).unwrap(),
            baseline_event_id: baseline_version.map(|version| format!("pypi:demo@{version}")),
            baseline_version: baseline_version.map(str::to_string),
            status: StoredReleaseDiffStatus::Ready,
            reason: None,
            diff: None,
        }
    }
}
