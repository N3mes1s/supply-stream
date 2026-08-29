use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::{
    bounded_map::BoundedMap,
    capture::{
        CapturedRelease, captured_metadata_risk, graph_records_from_captured_release,
        hydrate_release_metadata_for_priority, package_repository_identity_from_captured_release,
    },
    collector::{self, SeedPackageRecord},
    config::PriorityConfig,
    deps_dev_bigquery::{self, LiveFocusConfig},
    event::{Ecosystem, EmittedGraphEvidence, PackageReleaseEvent},
    repo_provenance::PackageRepositoryIdentity as RepoPackageRepositoryIdentity,
    scoring,
    store::{
        GraphEvidence, GraphNeighborhood, GraphNeighborhoodRecords, OperationalStore,
        PackageRepositoryIdentity,
    },
};

const ECOSYSTE_MS_PACKAGES_BASE: &str = "https://packages.ecosyste.ms/api/v1";
const ECOSYSTE_MS_REPOS_USAGE_BASE: &str = "https://repos.ecosyste.ms/api/v1/usage";
const FALLBACK_MIN_MEDIUM_PROPAGATED_IMPACT: f64 = 10.0;
const FALLBACK_MIN_HIGH_PROPAGATED_IMPACT: f64 = 100.0;
const PACKAGE_CENSUS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const MAX_OBSERVATION_COUNT_ENTRIES: usize = 100_000;
const MAX_ONLINE_FALLBACK_CACHE_ENTRIES: usize = 50_000;
const MAX_EMITTED_GRAPH_EVIDENCE_CACHE_ENTRIES: usize = 50_000;

#[derive(Debug, Clone)]
pub struct PriorityResolver {
    inner: Arc<PriorityResolverInner>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PriorityUpdate {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub previous: Option<PrioritySnapshot>,
    pub current: PrioritySnapshot,
}

#[derive(Debug)]
struct PriorityResolverInner {
    scores: RwLock<HashMap<(Ecosystem, String), PrioritySnapshot>>,
    observed_package_recorder: ObservedPackageRecorder,
    package_census: PackageCensus,
    local_graph_fallback: Option<LocalGraphFallback>,
    inline_observed_hydrator: Option<InlineObservedHydrator>,
    online_fallback: Option<OnlinePriorityFallback>,
    online_expander: Option<OnlinePriorityExpander>,
    observation_counts: Mutex<BoundedMap<(Ecosystem, String), usize>>,
    emitted_graph_cache: Mutex<BoundedMap<(Ecosystem, String), CachedEmittedGraphEvidence>>,
}

#[derive(Debug, Clone)]
struct ObservedPackageRecorder {
    graph_file: PathBuf,
    score_file: PathBuf,
    census_file: PathBuf,
    graph_store_file: Option<PathBuf>,
    update_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone)]
struct InlineObservedHydrator {
    http: reqwest::Client,
    allowed_ecosystems: HashSet<Ecosystem>,
    concurrency_limit: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
struct PackageCensus {
    path: PathBuf,
    cache: Arc<Mutex<Option<PackageCensusCache>>>,
}

#[derive(Debug, Clone)]
struct PackageCensusCache {
    modified_at: Option<SystemTime>,
    packages: HashSet<(Ecosystem, String)>,
    checked_at: std::time::Instant,
}

#[derive(Debug)]
struct OnlinePriorityFallback {
    http: reqwest::Client,
    v3_base: String,
    v3alpha_base: String,
    thresholds: HashMap<Ecosystem, FallbackThresholds>,
    cache: Mutex<BoundedMap<(Ecosystem, String), PrioritySnapshot>>,
}

#[derive(Debug)]
struct LocalGraphFallback {
    graph_file: PathBuf,
    thresholds: HashMap<Ecosystem, FallbackThresholds>,
    score_build: scoring::ScoreBuildConfig,
    store: Option<OperationalStore>,
    cache: Mutex<Option<LocalGraphCache>>,
}

#[derive(Debug, Clone)]
struct LocalGraphCache {
    modified_at: Option<SystemTime>,
    direct_popularity: HashMap<(Ecosystem, String), f64>,
    reverse_dependents: HashMap<(Ecosystem, String), usize>,
    direct_dependencies: HashMap<(Ecosystem, String), usize>,
    direct_dependency_names: HashMap<(Ecosystem, String), BTreeSet<String>>,
    reverse_dependent_names: HashMap<(Ecosystem, String), BTreeSet<String>>,
    known_packages: HashSet<(Ecosystem, String)>,
}

#[derive(Debug, Clone, Default)]
struct LocalGraphEvidence {
    known: bool,
    direct_dependencies_seen: usize,
    reverse_dependents_seen: usize,
    repository: Option<PackageRepositoryIdentity>,
}

#[derive(Debug, Clone)]
struct CachedEmittedGraphEvidence {
    known_in_local_graph: bool,
    known_in_census: bool,
    direct_dependencies_seen: usize,
    reverse_dependents_seen: usize,
    repository: Option<PackageRepositoryIdentity>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LocalGraphInspection {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub known_in_local_graph: bool,
    pub known_in_census: bool,
    pub direct_popularity: f64,
    pub direct_dependencies_seen: usize,
    pub reverse_dependents_seen: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reverse_dependents: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<PackageRepositoryIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<PrioritySnapshot>,
}

#[derive(Debug, Clone, Default)]
struct LocalGraphInspectionData {
    known: bool,
    direct_popularity: f64,
    direct_dependencies_seen: usize,
    reverse_dependents_seen: usize,
    direct_dependencies: Vec<String>,
    reverse_dependents: Vec<String>,
    repository: Option<PackageRepositoryIdentity>,
}

#[derive(Debug)]
struct OnlinePriorityExpander {
    graph_file: std::path::PathBuf,
    score_file: std::path::PathBuf,
    census_file: std::path::PathBuf,
    focus: crate::deps_dev::FocusDependentsConfig,
    collect: crate::collector::CollectConfig,
    score_build: crate::scoring::ScoreBuildConfig,
    min_observations: usize,
    in_flight: Arc<Mutex<HashSet<(Ecosystem, String)>>>,
    update_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, Copy)]
struct FallbackThresholds {
    high: f64,
    medium: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityTier {
    High,
    Medium,
    Low,
}

impl PriorityTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrioritySource {
    OfflineScoreFile,
    PackageCensus,
    KnownPackageStub,
    LocalGraph,
    DepsDevDependentsApi,
    EcosysteMsCountsApi,
    DefaultUnknown,
}

impl PrioritySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OfflineScoreFile => "offline_score_file",
            Self::PackageCensus => "package_census",
            Self::KnownPackageStub => "known_package_stub",
            Self::LocalGraph => "local_graph",
            Self::DepsDevDependentsApi => "deps_dev_dependents_api",
            Self::EcosysteMsCountsApi => "ecosyste_ms_counts_api",
            Self::DefaultUnknown => "default_unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrioritySnapshot {
    pub tier: PriorityTier,
    pub source: PrioritySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_popularity: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagated_impact: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_leverage: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_source_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageCensusRecord {
    pub ecosystem: Ecosystem,
    pub package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl PrioritySnapshot {
    pub fn default_unknown() -> Self {
        Self {
            tier: PriorityTier::Medium,
            source: PrioritySource::DefaultUnknown,
            direct_popularity: None,
            propagated_impact: None,
            hidden_leverage: None,
            computed_at: None,
            score_source_version: None,
        }
    }

    pub fn known_package_stub() -> Self {
        Self {
            tier: PriorityTier::Medium,
            source: PrioritySource::KnownPackageStub,
            direct_popularity: Some(0.0),
            propagated_impact: Some(0.0),
            hidden_leverage: Some(0.0),
            computed_at: Some(Utc::now()),
            score_source_version: Some("runtime_observed_v1".to_string()),
        }
    }

    pub fn package_census() -> Self {
        Self {
            tier: PriorityTier::Medium,
            source: PrioritySource::PackageCensus,
            direct_popularity: Some(0.0),
            propagated_impact: Some(0.0),
            hidden_leverage: Some(0.0),
            computed_at: Some(Utc::now()),
            score_source_version: Some("package_census_v1".to_string()),
        }
    }

    pub fn capture_requested(&self) -> bool {
        !matches!(self.tier, PriorityTier::Low)
    }

    pub fn diff_requested(&self) -> bool {
        matches!(self.tier, PriorityTier::High)
    }

    pub fn bucket(&self) -> PriorityBucket {
        match self.source {
            PrioritySource::DefaultUnknown => PriorityBucket::Unknown,
            PrioritySource::OfflineScoreFile
            | PrioritySource::PackageCensus
            | PrioritySource::KnownPackageStub
            | PrioritySource::LocalGraph
            | PrioritySource::DepsDevDependentsApi
            | PrioritySource::EcosysteMsCountsApi => match self.tier {
                PriorityTier::High => PriorityBucket::High,
                PriorityTier::Medium => PriorityBucket::Medium,
                PriorityTier::Low => PriorityBucket::Low,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityBucket {
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct PriorityCounts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

impl PriorityCounts {
    pub fn record(&mut self, snapshot: &PrioritySnapshot) {
        match snapshot.bucket() {
            PriorityBucket::High => self.high += 1,
            PriorityBucket::Medium => self.medium += 1,
            PriorityBucket::Low => self.low += 1,
            PriorityBucket::Unknown => self.unknown += 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PriorityScoreRecord {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub priority_tier: PriorityTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_source: Option<PrioritySource>,
    #[serde(default)]
    pub direct_popularity: Option<f64>,
    #[serde(default)]
    pub propagated_impact: Option<f64>,
    #[serde(default)]
    pub hidden_leverage: Option<f64>,
    #[serde(default)]
    pub computed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub score_source_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PriorityScoreLookupResult {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub normalized_package: String,
    pub ecosystem_package_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem_rank_by_propagated_impact: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem_rank_by_hidden_leverage: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<PriorityScoreRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityScoreMetric {
    DirectPopularity,
    PropagatedImpact,
    HiddenLeverage,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PriorityTopEntry {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub priority_tier: PriorityTier,
    pub direct_popularity: f64,
    pub propagated_impact: f64,
    pub hidden_leverage: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PriorityScoreStatsSummary {
    pub scored_packages: usize,
    pub ecosystems: Vec<PriorityScoreEcosystemSummary>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct LocalGraphHydrationSummary {
    pub graph_packages: usize,
    pub existing_scores: usize,
    pub missing_graph_packages: usize,
    pub hydrated_scores: usize,
    pub batches: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PriorityScoreEcosystemSummary {
    pub ecosystem: Ecosystem,
    pub packages: usize,
    pub priorities: PriorityCounts,
    pub top_by_propagated_impact: Vec<PriorityTopEntry>,
    pub top_by_hidden_leverage: Vec<PriorityTopEntry>,
}

impl PriorityResolver {
    pub async fn load(config: &PriorityConfig) -> Result<Self> {
        let records = load_priority_score_records_with_store(
            &config.score_file,
            config.graph_store_file.as_deref(),
        )
        .await?;
        let thresholds = fallback_thresholds(&records);
        let update_lock = Arc::new(Mutex::new(()));
        let scores = records
            .into_iter()
            .map(|record| {
                (
                    (
                        record.ecosystem,
                        normalize_package_name(record.ecosystem, &record.package),
                    ),
                    snapshot_from_score_record(record),
                )
            })
            .collect();
        let online_fallback = if config.online_fallback {
            Some(OnlinePriorityFallback {
                http: reqwest::Client::builder()
                    .user_agent("supply-stream-priority/0.1.0")
                    .http2_adaptive_window(true)
                    .connect_timeout(config.online_request_timeout)
                    .timeout(config.online_request_timeout)
                    .build()
                    .context("failed to build priority fallback HTTP client")?,
                v3_base: config.deps_dev_v3_base.clone(),
                v3alpha_base: config.deps_dev_v3alpha_base.clone(),
                thresholds: thresholds.clone(),
                cache: Mutex::new(BoundedMap::new(MAX_ONLINE_FALLBACK_CACHE_ENTRIES)),
            })
        } else {
            None
        };
        let local_graph_store = if let Some(path) = &config.graph_store_file {
            Some(OperationalStore::open(path.clone()).await?)
        } else {
            None
        };
        let local_graph_fallback = Some(LocalGraphFallback {
            graph_file: config.graph_file.clone(),
            thresholds: thresholds.clone(),
            score_build: config.expand_score_build.clone(),
            store: local_graph_store,
            cache: Mutex::new(None),
        });
        let package_census = PackageCensus {
            path: config.census_file.clone(),
            cache: Arc::new(Mutex::new(None)),
        };
        let inline_observed_hydrator = Some(InlineObservedHydrator {
            http: reqwest::Client::builder()
                .user_agent("supply-stream-inline-priority/0.1.0")
                .http2_adaptive_window(true)
                .connect_timeout(config.online_request_timeout.min(Duration::from_secs(3)))
                .timeout(config.online_request_timeout.min(Duration::from_secs(5)))
                .build()
                .context("failed to build inline priority hydrate HTTP client")?,
            allowed_ecosystems: [Ecosystem::Pypi, Ecosystem::Npm, Ecosystem::CratesIo]
                .into_iter()
                .collect(),
            concurrency_limit: Arc::new(Semaphore::new(4)),
        });
        let online_expander = if config.online_expand_unknown {
            Some(OnlinePriorityExpander {
                graph_file: config.graph_file.clone(),
                score_file: config.score_file.clone(),
                census_file: config.census_file.clone(),
                focus: config.expand_focus.clone(),
                collect: config.expand_collect.clone(),
                score_build: config.expand_score_build.clone(),
                min_observations: config.online_expand_min_observations.max(1),
                in_flight: Arc::new(Mutex::new(HashSet::new())),
                update_lock: Arc::clone(&update_lock),
            })
        } else {
            None
        };
        Ok(Self {
            inner: Arc::new(PriorityResolverInner {
                scores: RwLock::new(scores),
                observed_package_recorder: ObservedPackageRecorder {
                    graph_file: config.graph_file.clone(),
                    score_file: config.score_file.clone(),
                    census_file: config.census_file.clone(),
                    graph_store_file: config.graph_store_file.clone(),
                    update_lock,
                },
                package_census,
                local_graph_fallback,
                inline_observed_hydrator,
                online_fallback,
                online_expander,
                observation_counts: Mutex::new(BoundedMap::new(MAX_OBSERVATION_COUNT_ENTRIES)),
                emitted_graph_cache: Mutex::new(BoundedMap::new(
                    MAX_EMITTED_GRAPH_EVIDENCE_CACHE_ENTRIES,
                )),
            }),
        })
    }

    pub async fn apply(&self, mut event: PackageReleaseEvent) -> PackageReleaseEvent {
        event.priority = Some(self.resolve_observed_event(&event).await);
        event
    }

    pub async fn seed_event_snapshot(
        &self,
        event: &PackageReleaseEvent,
    ) -> Option<PrioritySnapshot> {
        let snapshot = event.priority.clone()?;
        let normalized = normalize_package_name(event.ecosystem, &event.package);
        Some(
            self.inner
                .remember_snapshot(event.ecosystem, normalized, snapshot)
                .await,
        )
    }

    pub async fn resolve(&self, ecosystem: Ecosystem, package: &str) -> PrioritySnapshot {
        self.inner
            .scores
            .read()
            .await
            .get(&(ecosystem, normalize_package_name(ecosystem, package)))
            .cloned()
            .unwrap_or_else(PrioritySnapshot::default_unknown)
    }

    pub async fn record_captured_release(&self, capture: &CapturedRelease) -> Vec<PriorityUpdate> {
        let mut touched = Vec::new();
        touched.push(normalize_package_name(capture.ecosystem, &capture.package));
        for dependency in capture
            .details
            .get("dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let normalized = normalize_package_name(capture.ecosystem, dependency);
            if !touched.contains(&normalized) {
                touched.push(normalized);
            }
        }

        let mut updates = Vec::new();
        if let Some(local_graph) = &self.inner.local_graph_fallback {
            let rescored = local_graph
                .score_neighborhood(capture.ecosystem, &touched, 128)
                .await
                .unwrap_or_default();
            for (package, snapshot) in rescored {
                let package_name = package.clone();
                let previous = self
                    .inner
                    .scores
                    .read()
                    .await
                    .get(&(capture.ecosystem, package_name.clone()))
                    .cloned();
                let current = self
                    .inner
                    .remember_snapshot(capture.ecosystem, package, snapshot)
                    .await;
                if previous.as_ref() != Some(&current) {
                    updates.push(PriorityUpdate {
                        ecosystem: capture.ecosystem,
                        package: package_name,
                        previous,
                        current,
                    });
                }
            }
        }
        for package in &touched {
            self.inner
                .invalidate_emitted_graph_cache(capture.ecosystem, package)
                .await;
        }
        updates
    }

    pub async fn record_hydrated_release_metadata(
        &self,
        event: &PackageReleaseEvent,
        capture: &CapturedRelease,
    ) -> Result<Option<PrioritySnapshot>> {
        let normalized = normalize_package_name(event.ecosystem, &event.package);
        self.inner
            .apply_hydrated_release_metadata(event, &normalized, capture)
            .await
    }

    pub async fn resolve_observed_release(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> PrioritySnapshot {
        let normalized = normalize_package_name(ecosystem, package);
        let observation_count = self
            .inner
            .record_observation(ecosystem, normalized.clone())
            .await;
        if let Some(snapshot) = self
            .inner
            .scores
            .read()
            .await
            .get(&(ecosystem, normalized.clone()))
            .cloned()
        {
            return snapshot;
        }

        if let Some(local_graph) = &self.inner.local_graph_fallback
            && let Some(snapshot) = local_graph.resolve(ecosystem, &normalized).await
        {
            let snapshot = self
                .inner
                .remember_snapshot(ecosystem, normalized.clone(), snapshot)
                .await;
            if let Some(expander) = &self.inner.online_expander
                && expander.should_expand(&snapshot, observation_count)
            {
                expander
                    .spawn_expand(
                        Arc::clone(&self.inner),
                        ecosystem,
                        normalized.clone(),
                        snapshot.direct_popularity,
                    )
                    .await;
            }
            return snapshot;
        }

        if self
            .inner
            .package_census
            .contains(ecosystem, &normalized)
            .await
            .unwrap_or(false)
        {
            let snapshot = self
                .inner
                .remember_snapshot(
                    ecosystem,
                    normalized.clone(),
                    PrioritySnapshot::package_census(),
                )
                .await;
            if let Some(expander) = &self.inner.online_expander
                && expander.should_expand(&snapshot, observation_count)
            {
                expander
                    .spawn_expand(
                        Arc::clone(&self.inner),
                        ecosystem,
                        normalized.clone(),
                        snapshot.direct_popularity,
                    )
                    .await;
            }
            return snapshot;
        }

        let snapshot = self
            .inner
            .remember_snapshot(
                ecosystem,
                normalized.clone(),
                PrioritySnapshot::known_package_stub(),
            )
            .await;
        if let Some(expander) = &self.inner.online_expander
            && expander.should_expand(&snapshot, observation_count)
        {
            expander
                .spawn_expand(
                    Arc::clone(&self.inner),
                    ecosystem,
                    normalized,
                    snapshot.direct_popularity,
                )
                .await;
        }
        snapshot
    }

    pub async fn resolve_observed_event(&self, event: &PackageReleaseEvent) -> PrioritySnapshot {
        let normalized = normalize_package_name(event.ecosystem, &event.package);
        let observation_count = self
            .inner
            .record_observation(event.ecosystem, normalized.clone())
            .await;
        if let Some(snapshot) = self
            .inner
            .scores
            .read()
            .await
            .get(&(event.ecosystem, normalized.clone()))
            .cloned()
            && (snapshot.source != PrioritySource::KnownPackageStub || observation_count < 2)
        {
            return snapshot;
        }

        if let Some(local_graph) = &self.inner.local_graph_fallback
            && let Some(snapshot) = local_graph.resolve(event.ecosystem, &normalized).await
        {
            let snapshot = self
                .inner
                .remember_snapshot(event.ecosystem, normalized.clone(), snapshot)
                .await;
            if let Some(expander) = &self.inner.online_expander
                && expander.should_expand(&snapshot, observation_count)
            {
                expander
                    .spawn_expand(
                        Arc::clone(&self.inner),
                        event.ecosystem,
                        normalized.clone(),
                        snapshot.direct_popularity,
                    )
                    .await;
            }
            return snapshot;
        }

        if observation_count >= 2 {
            match self
                .inner
                .inline_hydrate_observed_release(event, &normalized)
                .await
            {
                Ok(Some(snapshot)) => {
                    if let Some(expander) = &self.inner.online_expander
                        && expander.should_expand(&snapshot, observation_count)
                    {
                        expander
                            .spawn_expand(
                                Arc::clone(&self.inner),
                                event.ecosystem,
                                normalized.clone(),
                                snapshot.direct_popularity,
                            )
                            .await;
                    }
                    return snapshot;
                }
                Ok(None) => {}
                Err(error) => {
                    debug!(
                        event_id = event.event_id,
                        ecosystem = %event.ecosystem,
                        package = event.package,
                        error = %error,
                        "inline priority metadata hydrate failed"
                    );
                }
            }
        }

        if self
            .inner
            .package_census
            .contains(event.ecosystem, &normalized)
            .await
            .unwrap_or(false)
        {
            let snapshot = self
                .inner
                .remember_snapshot(
                    event.ecosystem,
                    normalized.clone(),
                    PrioritySnapshot::package_census(),
                )
                .await;
            if let Some(expander) = &self.inner.online_expander
                && expander.should_expand(&snapshot, observation_count)
            {
                expander
                    .spawn_expand(
                        Arc::clone(&self.inner),
                        event.ecosystem,
                        normalized.clone(),
                        snapshot.direct_popularity,
                    )
                    .await;
            }
            return snapshot;
        }

        let snapshot = self
            .inner
            .remember_snapshot(
                event.ecosystem,
                normalized.clone(),
                PrioritySnapshot::known_package_stub(),
            )
            .await;
        if let Some(expander) = &self.inner.online_expander
            && expander.should_expand(&snapshot, observation_count)
        {
            expander
                .spawn_expand(
                    Arc::clone(&self.inner),
                    event.ecosystem,
                    normalized,
                    snapshot.direct_popularity,
                )
                .await;
        }
        snapshot
    }

    pub async fn resolve_for_event(&self, ecosystem: Ecosystem, package: &str) -> PrioritySnapshot {
        let normalized = normalize_package_name(ecosystem, package);
        let observation_count = self
            .inner
            .record_observation(ecosystem, normalized.clone())
            .await;
        if let Some(snapshot) = self
            .inner
            .scores
            .read()
            .await
            .get(&(ecosystem, normalized.clone()))
            .cloned()
        {
            return snapshot;
        }

        if let Some(local_graph) = &self.inner.local_graph_fallback
            && let Some(snapshot) = local_graph.resolve(ecosystem, &normalized).await
        {
            let snapshot = self
                .inner
                .remember_snapshot(ecosystem, normalized.clone(), snapshot)
                .await;
            if let Some(expander) = &self.inner.online_expander
                && expander.should_expand(&snapshot, observation_count)
            {
                expander
                    .spawn_expand(
                        Arc::clone(&self.inner),
                        ecosystem,
                        normalized.clone(),
                        snapshot.direct_popularity,
                    )
                    .await;
            }
            return snapshot;
        }

        if self
            .inner
            .package_census
            .contains(ecosystem, &normalized)
            .await
            .unwrap_or(false)
        {
            let snapshot = self
                .inner
                .remember_snapshot(
                    ecosystem,
                    normalized.clone(),
                    PrioritySnapshot::package_census(),
                )
                .await;
            if let Some(expander) = &self.inner.online_expander
                && expander.should_expand(&snapshot, observation_count)
            {
                expander
                    .spawn_expand(
                        Arc::clone(&self.inner),
                        ecosystem,
                        normalized.clone(),
                        snapshot.direct_popularity,
                    )
                    .await;
            }
            return snapshot;
        }

        let fallback_snapshot = if let Some(fallback) = &self.inner.online_fallback {
            fallback.resolve(ecosystem, &normalized).await
        } else {
            PrioritySnapshot::default_unknown()
        };
        let snapshot = if fallback_snapshot.source == PrioritySource::DefaultUnknown {
            self.inner
                .remember_snapshot(
                    ecosystem,
                    normalized.clone(),
                    PrioritySnapshot::known_package_stub(),
                )
                .await
        } else {
            self.inner
                .remember_snapshot(ecosystem, normalized.clone(), fallback_snapshot)
                .await
        };
        if let Some(expander) = &self.inner.online_expander
            && expander.should_expand(&snapshot, observation_count)
        {
            expander
                .spawn_expand(
                    Arc::clone(&self.inner),
                    ecosystem,
                    normalized.clone(),
                    snapshot.direct_popularity,
                )
                .await;
        }
        snapshot
    }

    pub async fn emitted_graph_evidence(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> EmittedGraphEvidence {
        let normalized = normalize_package_name(ecosystem, package);
        let key = (ecosystem, normalized.clone());
        let observed_count = self
            .inner
            .observation_counts
            .lock()
            .await
            .get(&key)
            .copied()
            .unwrap_or(0);
        if let Some(cached) = self
            .inner
            .emitted_graph_cache
            .lock()
            .await
            .get_cloned_refresh(&key)
        {
            return EmittedGraphEvidence {
                known_in_local_graph: cached.known_in_local_graph,
                known_in_census: cached.known_in_census,
                observed_count,
                direct_dependencies_seen: cached.direct_dependencies_seen,
                reverse_dependents_seen: cached.reverse_dependents_seen,
                repository: cached.repository,
            };
        }

        let known_in_census = self
            .inner
            .package_census
            .contains(ecosystem, &normalized)
            .await
            .unwrap_or(false);

        let local_graph = if let Some(local_graph) = &self.inner.local_graph_fallback {
            local_graph
                .evidence(ecosystem, &normalized)
                .await
                .unwrap_or_default()
        } else {
            LocalGraphEvidence::default()
        };
        let cached = CachedEmittedGraphEvidence {
            known_in_local_graph: local_graph.known,
            known_in_census,
            direct_dependencies_seen: local_graph.direct_dependencies_seen,
            reverse_dependents_seen: local_graph.reverse_dependents_seen,
            repository: local_graph.repository.clone(),
        };
        self.inner
            .emitted_graph_cache
            .lock()
            .await
            .insert(key, cached.clone());
        EmittedGraphEvidence {
            known_in_local_graph: cached.known_in_local_graph,
            known_in_census: cached.known_in_census,
            observed_count,
            direct_dependencies_seen: cached.direct_dependencies_seen,
            reverse_dependents_seen: cached.reverse_dependents_seen,
            repository: cached.repository,
        }
    }

    pub async fn inspect_local_graph(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        limit: usize,
    ) -> Result<LocalGraphInspection> {
        let normalized = normalize_package_name(ecosystem, package);
        let score = self
            .inner
            .scores
            .read()
            .await
            .get(&(ecosystem, normalized.clone()))
            .cloned();
        let known_in_census = self
            .inner
            .package_census
            .contains(ecosystem, &normalized)
            .await
            .unwrap_or(false);
        let local = if let Some(local_graph) = &self.inner.local_graph_fallback {
            local_graph.inspect(ecosystem, &normalized, limit).await?
        } else {
            LocalGraphInspectionData::default()
        };
        let repository = if let Some(local_graph) = &self.inner.local_graph_fallback {
            local_graph.repository(ecosystem, &normalized).await?
        } else {
            None
        };

        Ok(LocalGraphInspection {
            ecosystem,
            package: normalized,
            known_in_local_graph: local.known,
            known_in_census,
            direct_popularity: local.direct_popularity,
            direct_dependencies_seen: local.direct_dependencies_seen,
            reverse_dependents_seen: local.reverse_dependents_seen,
            direct_dependencies: local.direct_dependencies,
            reverse_dependents: local.reverse_dependents,
            repository: repository.or(local.repository),
            score,
        })
    }
}

impl PriorityResolverInner {
    async fn invalidate_emitted_graph_cache(&self, ecosystem: Ecosystem, package: &str) {
        self.emitted_graph_cache
            .lock()
            .await
            .remove(&(ecosystem, normalize_package_name(ecosystem, package)));
    }

    async fn record_observation(&self, ecosystem: Ecosystem, package: String) -> usize {
        let mut counts = self.observation_counts.lock().await;
        let key = (ecosystem, package);
        if let Some(entry) = counts.get_mut(&key) {
            *entry += 1;
            *entry
        } else {
            counts.insert(key, 1);
            1
        }
    }

    async fn remember_snapshot(
        &self,
        ecosystem: Ecosystem,
        package: String,
        snapshot: PrioritySnapshot,
    ) -> PrioritySnapshot {
        let key = (ecosystem, package.clone());
        let mut scores = self.scores.write().await;
        let persist = match scores.get(&key) {
            Some(existing) if !should_replace_snapshot(existing, &snapshot) => {
                return existing.clone();
            }
            _ => true,
        };
        scores.insert(key, snapshot.clone());
        drop(scores);

        if persist {
            self.invalidate_emitted_graph_cache(ecosystem, &package)
                .await;
            if snapshot_requires_runtime_persistence(&snapshot) {
                self.observed_package_recorder
                    .persist_snapshot(ecosystem, package.clone(), snapshot.clone())
                    .await;
            }
            self.package_census.remember(ecosystem, &package).await;
        }

        snapshot
    }

    async fn inline_hydrate_observed_release(
        &self,
        event: &PackageReleaseEvent,
        normalized: &str,
    ) -> Result<Option<PrioritySnapshot>> {
        let Some(hydrator) = &self.inline_observed_hydrator else {
            return Ok(None);
        };
        if self.local_graph_fallback.is_none() {
            return Ok(None);
        }

        let Some(capture) = hydrator.hydrate(event).await? else {
            return Ok(None);
        };
        self.apply_hydrated_release_metadata(event, normalized, &capture)
            .await
    }

    async fn apply_hydrated_release_metadata(
        &self,
        event: &PackageReleaseEvent,
        normalized: &str,
        capture: &CapturedRelease,
    ) -> Result<Option<PrioritySnapshot>> {
        let graph_records = graph_records_from_captured_release(capture);
        let repositories =
            package_repository_identity_from_captured_release(event.ecosystem, capture)
                .into_iter()
                .collect::<Vec<_>>();
        self.observed_package_recorder
            .persist_graph_material(&graph_records, &repositories)
            .await?;
        self.package_census
            .remember_from_score_input(&graph_records)
            .await;
        for package in touched_packages_from_score_input(&graph_records) {
            self.invalidate_emitted_graph_cache(event.ecosystem, &package)
                .await;
        }

        let Some(local_graph) = &self.local_graph_fallback else {
            return Ok(None);
        };

        let roots = vec![normalized.to_string()];
        let rescored = local_graph
            .score_neighborhood(event.ecosystem, &roots, 32)
            .await?;
        for (package, snapshot) in &rescored {
            let snapshot = if package == normalized {
                apply_metadata_risk_override(snapshot.clone(), capture)
            } else {
                snapshot.clone()
            };
            self.remember_snapshot(event.ecosystem, package.clone(), snapshot)
                .await;
        }

        if let Some(snapshot) = rescored.get(normalized).cloned() {
            return Ok(Some(apply_metadata_risk_override(snapshot, capture)));
        }

        Ok(local_graph
            .resolve(event.ecosystem, normalized)
            .await
            .map(|snapshot| apply_metadata_risk_override(snapshot, capture)))
    }
}

fn touched_packages_from_score_input(records: &[scoring::ScoreInputRecord]) -> BTreeSet<String> {
    let mut packages = BTreeSet::new();
    for record in records {
        match record {
            scoring::ScoreInputRecord::Package { package, .. } => {
                packages.insert(package.clone());
            }
            scoring::ScoreInputRecord::Dependency {
                package,
                dependency,
                ..
            } => {
                packages.insert(package.clone());
                packages.insert(dependency.clone());
            }
        }
    }
    packages
}

impl InlineObservedHydrator {
    async fn hydrate(&self, event: &PackageReleaseEvent) -> Result<Option<CapturedRelease>> {
        if !self.allowed_ecosystems.contains(&event.ecosystem) {
            return Ok(None);
        }
        let Ok(_permit) = Arc::clone(&self.concurrency_limit).try_acquire_owned() else {
            return Ok(None);
        };
        hydrate_release_metadata_for_priority(&self.http, event).await
    }
}

fn should_replace_snapshot(existing: &PrioritySnapshot, candidate: &PrioritySnapshot) -> bool {
    let existing_rank = priority_source_rank(existing.source);
    let candidate_rank = priority_source_rank(candidate.source);
    if candidate_rank != existing_rank {
        return candidate_rank > existing_rank;
    }

    if candidate.tier != existing.tier {
        return priority_tier_rank(candidate.tier) > priority_tier_rank(existing.tier);
    }

    metric_or_zero(candidate.propagated_impact) > metric_or_zero(existing.propagated_impact)
        || metric_or_zero(candidate.direct_popularity) > metric_or_zero(existing.direct_popularity)
        || metric_or_zero(candidate.hidden_leverage) > metric_or_zero(existing.hidden_leverage)
}

fn priority_source_rank(source: PrioritySource) -> u8 {
    match source {
        PrioritySource::DefaultUnknown => 0,
        PrioritySource::KnownPackageStub => 1,
        PrioritySource::PackageCensus => 2,
        PrioritySource::LocalGraph => 3,
        PrioritySource::DepsDevDependentsApi => 4,
        PrioritySource::EcosysteMsCountsApi => 4,
        PrioritySource::OfflineScoreFile => 5,
    }
}

fn priority_tier_rank(tier: PriorityTier) -> u8 {
    match tier {
        PriorityTier::Low => 0,
        PriorityTier::Medium => 1,
        PriorityTier::High => 2,
    }
}

fn apply_metadata_risk_override(
    mut snapshot: PrioritySnapshot,
    capture: &CapturedRelease,
) -> PrioritySnapshot {
    let metadata_risk = captured_metadata_risk(capture);
    if !metadata_risk.suspicious {
        return snapshot;
    }

    let override_tier = if metadata_risk.score >= 8 {
        PriorityTier::High
    } else {
        PriorityTier::Medium
    };
    if priority_tier_rank(override_tier) > priority_tier_rank(snapshot.tier) {
        snapshot.tier = override_tier;
        snapshot.score_source_version = Some("local_graph_metadata_risk_v1".to_string());
    }
    snapshot
}

fn metric_or_zero(value: Option<f64>) -> f64 {
    value.unwrap_or_default()
}

pub async fn load_priority_score_records(path: &Path) -> Result<Vec<PriorityScoreRecord>> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read priority score file {}", path.display()));
        }
    };

    let body = String::from_utf8(bytes)
        .with_context(|| format!("priority score file is not valid utf-8: {}", path.display()))?;
    let mut scores = Vec::new();
    for (line_number, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<PriorityScoreRecord>(line).with_context(|| {
            format!(
                "failed to parse priority score line {} from {}",
                line_number + 1,
                path.display()
            )
        })?;
        scores.push(record);
    }

    Ok(scores)
}

pub async fn write_priority_score_records(
    path: &Path,
    records: &[PriorityScoreRecord],
) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut body = String::new();
    for record in records {
        body.push_str(
            &serde_json::to_string(record).context("failed to encode priority score record")?,
        );
        body.push('\n');
    }

    tokio::fs::write(path, body)
        .await
        .with_context(|| format!("failed to write priority scores {}", path.display()))
}

pub async fn upsert_priority_score_records(
    path: &Path,
    updates: &[PriorityScoreRecord],
) -> Result<Vec<PriorityScoreRecord>> {
    let existing = load_priority_score_records(path).await?;
    let (merged, _) = merge_priority_score_records(existing, updates);
    write_priority_score_records(path, &merged).await?;
    Ok(merged)
}

pub async fn export_priority_score_records(
    path: &Path,
    graph_store_file: Option<&Path>,
) -> Result<Vec<PriorityScoreRecord>> {
    let records = load_priority_score_records_with_store(path, graph_store_file).await?;
    write_priority_score_records(path, &records).await?;
    Ok(records)
}

fn merge_priority_score_records(
    existing: Vec<PriorityScoreRecord>,
    updates: &[PriorityScoreRecord],
) -> (Vec<PriorityScoreRecord>, Vec<PriorityScoreRecord>) {
    let mut merged = existing;
    let mut effective_updates = Vec::new();
    let mut index = HashMap::<(Ecosystem, String), usize>::new();
    for (position, record) in merged.iter().enumerate() {
        index.insert(
            (
                record.ecosystem,
                normalize_package_name(record.ecosystem, &record.package),
            ),
            position,
        );
    }

    for update in updates {
        let key = (
            update.ecosystem,
            normalize_package_name(update.ecosystem, &update.package),
        );
        match index.get(&key).copied() {
            Some(position) => {
                let existing_snapshot = snapshot_from_score_record(merged[position].clone());
                let candidate_snapshot = snapshot_from_score_record(update.clone());
                if should_replace_snapshot(&existing_snapshot, &candidate_snapshot) {
                    merged[position] = update.clone();
                    effective_updates.push(update.clone());
                }
            }
            None => {
                index.insert(key, merged.len());
                merged.push(update.clone());
                effective_updates.push(update.clone());
            }
        }
    }

    merged.sort_by(|left, right| {
        (
            left.ecosystem,
            normalize_package_name(left.ecosystem, &left.package),
        )
            .cmp(&(
                right.ecosystem,
                normalize_package_name(right.ecosystem, &right.package),
            ))
    });
    (merged, effective_updates)
}

pub async fn load_package_census_records(path: &Path) -> Result<Vec<PackageCensusRecord>> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read package census {}", path.display()));
        }
    };

    let body = String::from_utf8(bytes)
        .with_context(|| format!("package census file is not valid utf-8: {}", path.display()))?;
    let mut records = Vec::new();
    for (line_number, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<PackageCensusRecord>(line).with_context(|| {
            format!(
                "failed to parse package census line {} from {}",
                line_number + 1,
                path.display()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

pub async fn write_package_census_records(
    path: &Path,
    records: &[PackageCensusRecord],
) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut body = String::new();
    for record in records {
        body.push_str(
            &serde_json::to_string(record).context("failed to encode package census record")?,
        );
        body.push('\n');
    }

    tokio::fs::write(path, body)
        .await
        .with_context(|| format!("failed to write package census {}", path.display()))
}

pub async fn rescore_local_graph_roots(
    config: &PriorityConfig,
    roots: &[(Ecosystem, String)],
    per_root_limit: usize,
) -> Result<Vec<PriorityScoreRecord>> {
    let records = load_priority_score_records_with_store(
        &config.score_file,
        config.graph_store_file.as_deref(),
    )
    .await?;
    let thresholds = fallback_thresholds(&records);
    let local_graph_store = if let Some(path) = &config.graph_store_file {
        Some(OperationalStore::open(path.clone()).await?)
    } else {
        None
    };
    let local_graph = LocalGraphFallback {
        graph_file: config.graph_file.clone(),
        thresholds,
        score_build: config.expand_score_build.clone(),
        store: local_graph_store,
        cache: Mutex::new(None),
    };

    let mut grouped = BTreeMap::<Ecosystem, Vec<String>>::new();
    for (ecosystem, package) in roots {
        grouped
            .entry(*ecosystem)
            .or_default()
            .push(normalize_package_name(*ecosystem, package));
    }

    let mut rescored = Vec::new();
    for (ecosystem, packages) in grouped {
        let snapshots = local_graph
            .score_neighborhood(ecosystem, &packages, per_root_limit)
            .await?;
        for (package, snapshot) in snapshots {
            rescored.push(PriorityScoreRecord {
                ecosystem,
                package,
                priority_tier: snapshot.tier,
                priority_source: Some(snapshot.source),
                direct_popularity: snapshot.direct_popularity,
                propagated_impact: snapshot.propagated_impact,
                hidden_leverage: snapshot.hidden_leverage,
                computed_at: snapshot.computed_at,
                score_source_version: snapshot.score_source_version.clone(),
            });
        }
    }

    rescored.sort_by(|left, right| {
        (
            left.ecosystem,
            normalize_package_name(left.ecosystem, &left.package),
        )
            .cmp(&(
                right.ecosystem,
                normalize_package_name(right.ecosystem, &right.package),
            ))
    });
    rescored.dedup_by(|left, right| {
        left.ecosystem == right.ecosystem
            && normalize_package_name(left.ecosystem, &left.package)
                == normalize_package_name(right.ecosystem, &right.package)
    });
    Ok(rescored)
}

pub async fn hydrate_local_graph_scores(
    config: &PriorityConfig,
    ecosystems: &[Ecosystem],
    batch_size: usize,
    per_root_limit: usize,
) -> Result<LocalGraphHydrationSummary> {
    let Some(graph_store_file) = config.graph_store_file.as_ref() else {
        return Ok(LocalGraphHydrationSummary::default());
    };

    let store = OperationalStore::open(graph_store_file.clone()).await?;
    let known_graph_packages = store.load_known_graph_packages(ecosystems).await?;
    if known_graph_packages.is_empty() {
        return Ok(LocalGraphHydrationSummary::default());
    }

    let existing_records =
        load_priority_score_records_union(&config.score_file, Some(&store)).await?;
    let existing_scored_packages = existing_records
        .iter()
        .map(|record| {
            (
                record.ecosystem,
                normalize_package_name(record.ecosystem, &record.package),
            )
        })
        .collect::<HashSet<_>>();
    let mut missing_roots = known_graph_packages
        .iter()
        .filter(|key| !existing_scored_packages.contains(*key))
        .cloned()
        .collect::<Vec<_>>();
    missing_roots.sort();

    if missing_roots.is_empty() {
        return Ok(LocalGraphHydrationSummary {
            graph_packages: known_graph_packages.len(),
            existing_scores: existing_scored_packages.len(),
            missing_graph_packages: 0,
            hydrated_scores: 0,
            batches: 0,
        });
    }

    let thresholds = fallback_thresholds(&existing_records);
    let local_graph = LocalGraphFallback {
        graph_file: config.graph_file.clone(),
        thresholds,
        score_build: config.expand_score_build.clone(),
        store: Some(store.clone()),
        cache: Mutex::new(None),
    };

    let mut updates = Vec::new();
    let mut batches = 0usize;
    for batch in missing_roots.chunks(batch_size.max(1)) {
        batches += 1;
        let mut grouped = BTreeMap::<Ecosystem, Vec<String>>::new();
        for (ecosystem, package) in batch {
            grouped.entry(*ecosystem).or_default().push(package.clone());
        }
        for (ecosystem, packages) in grouped {
            let snapshots = local_graph
                .score_neighborhood(ecosystem, &packages, per_root_limit.max(1))
                .await?;
            for (package, snapshot) in snapshots {
                updates.push(PriorityScoreRecord {
                    ecosystem,
                    package,
                    priority_tier: snapshot.tier,
                    priority_source: Some(snapshot.source),
                    direct_popularity: snapshot.direct_popularity,
                    propagated_impact: snapshot.propagated_impact,
                    hidden_leverage: snapshot.hidden_leverage,
                    computed_at: snapshot.computed_at,
                    score_source_version: snapshot.score_source_version.clone(),
                });
            }
        }
    }

    let (merged_scores, effective_updates) =
        merge_priority_score_records(existing_records, &updates);
    if !effective_updates.is_empty() {
        store
            .record_priority_score_records(&effective_updates)
            .await?;
        if config.graph_store_file.is_none() {
            write_priority_score_records(&config.score_file, &merged_scores).await?;
        }
    }

    Ok(LocalGraphHydrationSummary {
        graph_packages: known_graph_packages.len(),
        existing_scores: existing_scored_packages.len(),
        missing_graph_packages: missing_roots.len(),
        hydrated_scores: effective_updates.len(),
        batches,
    })
}

async fn load_priority_score_records_with_store(
    score_file: &Path,
    graph_store_file: Option<&Path>,
) -> Result<Vec<PriorityScoreRecord>> {
    let file_records = load_priority_score_records(score_file).await?;
    let Some(graph_store_file) = graph_store_file else {
        return Ok(file_records);
    };

    let store = OperationalStore::open(graph_store_file.to_path_buf()).await?;
    let store_records = store.load_priority_score_records().await?;
    if store_records.is_empty() {
        return Ok(file_records);
    }

    let (merged, _) = merge_priority_score_records(file_records, &store_records);
    Ok(merged)
}

async fn load_priority_score_records_union(
    score_file: &Path,
    store: Option<&OperationalStore>,
) -> Result<Vec<PriorityScoreRecord>> {
    let file_records = load_priority_score_records(score_file).await?;
    let Some(store) = store else {
        return Ok(file_records);
    };
    let store_records = store.load_priority_score_records().await?;
    let (merged, _) = merge_priority_score_records(file_records, &store_records);
    Ok(merged)
}

impl PackageCensus {
    async fn contains(&self, ecosystem: Ecosystem, package: &str) -> Result<bool> {
        let normalized = normalize_package_name(ecosystem, package);
        let key = (ecosystem, normalized);
        {
            let mut guard = self.cache.lock().await;
            if let Some(cache) = guard.as_mut()
                && cache.checked_at.elapsed() < PACKAGE_CENSUS_REFRESH_INTERVAL
            {
                return Ok(cache.packages.contains(&key));
            }
        }

        let modified_at = tokio::fs::metadata(&self.path)
            .await
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        {
            let mut guard = self.cache.lock().await;
            if let Some(cache) = guard.as_mut()
                && cache.modified_at == modified_at
            {
                cache.checked_at = Instant::now();
                return Ok(cache.packages.contains(&key));
            }
        }

        let records = load_package_census_records(&self.path).await?;
        let packages = records
            .into_iter()
            .map(|record| {
                (
                    record.ecosystem,
                    normalize_package_name(record.ecosystem, &record.package),
                )
            })
            .collect::<HashSet<_>>();
        let contains = packages.contains(&key);
        let cache = PackageCensusCache {
            modified_at,
            packages,
            checked_at: Instant::now(),
        };
        *self.cache.lock().await = Some(cache.clone());
        Ok(contains)
    }

    async fn remember(&self, ecosystem: Ecosystem, package: &str) {
        let normalized = normalize_package_name(ecosystem, package);
        let mut guard = self.cache.lock().await;
        if let Some(cache) = guard.as_mut() {
            cache.packages.insert((ecosystem, normalized));
            cache.checked_at = Instant::now();
        }
    }

    async fn remember_records(&self, records: &[PackageCensusRecord]) {
        if records.is_empty() {
            return;
        }

        let mut guard = self.cache.lock().await;
        if let Some(cache) = guard.as_mut() {
            for record in records {
                cache.packages.insert((
                    record.ecosystem,
                    normalize_package_name(record.ecosystem, &record.package),
                ));
            }
            cache.checked_at = Instant::now();
        }
    }

    async fn remember_from_score_input(&self, records: &[scoring::ScoreInputRecord]) {
        let census_records = package_census_from_score_input(records);
        self.remember_records(&census_records).await;
    }
}

impl ObservedPackageRecorder {
    async fn persist_snapshot(
        &self,
        ecosystem: Ecosystem,
        package: String,
        snapshot: PrioritySnapshot,
    ) {
        let graph_file = self.graph_file.clone();
        let score_file = self.score_file.clone();
        let census_file = self.census_file.clone();
        let graph_store_file = self.graph_store_file.clone();
        let update_lock = Arc::clone(&self.update_lock);
        let _guard = update_lock.lock().await;
        if let Err(error) = append_snapshot_records(
            &graph_file,
            &score_file,
            &census_file,
            graph_store_file.as_deref(),
            ecosystem,
            &package,
            &snapshot,
        )
        .await
        {
            warn!(
                ecosystem = %ecosystem,
                package,
                error = %error,
                "failed to persist runtime priority snapshot"
            );
        }
    }

    async fn persist_graph_material(
        &self,
        records: &[scoring::ScoreInputRecord],
        repositories: &[RepoPackageRepositoryIdentity],
    ) -> Result<()> {
        let _guard = self.update_lock.lock().await;
        append_graph_material_records(
            &self.graph_file,
            &self.census_file,
            self.graph_store_file.as_deref(),
            records,
            repositories,
        )
        .await
    }
}

async fn append_snapshot_records(
    graph_file: &Path,
    score_file: &Path,
    census_file: &Path,
    graph_store_file: Option<&Path>,
    ecosystem: Ecosystem,
    package: &str,
    snapshot: &PrioritySnapshot,
) -> Result<()> {
    append_ndjson_line(
        census_file,
        &PackageCensusRecord {
            ecosystem,
            package: package.to_string(),
            discovered_at: Some(Utc::now()),
            source: Some(snapshot.source.as_str().to_string()),
        },
    )
    .await?;

    if matches!(
        snapshot.source,
        PrioritySource::LocalGraph | PrioritySource::OfflineScoreFile
    ) {
        append_ndjson_line(
            graph_file,
            &scoring::ScoreInputRecord::Package {
                ecosystem,
                package: package.to_string(),
                direct_popularity: snapshot.direct_popularity.unwrap_or_default(),
            },
        )
        .await?;
    }

    if snapshot_persists_to_score_file(snapshot) {
        let record = PriorityScoreRecord {
            ecosystem,
            package: package.to_string(),
            priority_tier: snapshot.tier,
            priority_source: Some(snapshot.source),
            direct_popularity: snapshot.direct_popularity,
            propagated_impact: snapshot.propagated_impact,
            hidden_leverage: snapshot.hidden_leverage,
            computed_at: snapshot.computed_at,
            score_source_version: snapshot.score_source_version.clone(),
        };
        if let Some(graph_store_file) = graph_store_file {
            let store = OperationalStore::open(graph_store_file.to_path_buf()).await?;
            store.record_priority_score_records(&[record]).await?;
        } else {
            append_ndjson_line(score_file, &record).await?;
        }
    }

    Ok(())
}

async fn append_graph_material_records(
    graph_file: &Path,
    census_file: &Path,
    graph_store_file: Option<&Path>,
    records: &[scoring::ScoreInputRecord],
    repositories: &[RepoPackageRepositoryIdentity],
) -> Result<()> {
    if records.is_empty() && repositories.is_empty() {
        return Ok(());
    }

    if !records.is_empty() {
        append_ndjson_records(graph_file, records).await?;
        let census_records = package_census_from_score_input(records);
        append_ndjson_records(census_file, &census_records).await?;
    }

    if let Some(graph_store_file) = graph_store_file {
        let store = OperationalStore::open(graph_store_file.to_path_buf()).await?;
        if !records.is_empty() {
            store.record_graph_records(records).await?;
        }
        if !repositories.is_empty() {
            store.record_package_repository_refs(repositories).await?;
        }
    }

    Ok(())
}

pub fn merge_package_census_records(records: &[PackageCensusRecord]) -> Vec<PackageCensusRecord> {
    let mut merged = BTreeMap::<(Ecosystem, String), PackageCensusRecord>::new();
    for record in records {
        let key = (
            record.ecosystem,
            normalize_package_name(record.ecosystem, &record.package),
        );
        match merged.get_mut(&key) {
            Some(existing) => merge_package_census_record(existing, record),
            None => {
                let mut normalized = record.clone();
                normalized.package = key.1.clone();
                merged.insert(key, normalized);
            }
        }
    }
    merged.into_values().collect()
}

fn merge_package_census_record(target: &mut PackageCensusRecord, candidate: &PackageCensusRecord) {
    let candidate_discovered_at = match (target.discovered_at, candidate.discovered_at) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, Some(right)) => Some(right),
        (Some(left), None) => Some(left),
        (None, None) => None,
    };
    target.discovered_at = candidate_discovered_at;

    let target_rank = census_source_rank(target.source.as_deref());
    let candidate_rank = census_source_rank(candidate.source.as_deref());
    if candidate_rank > target_rank || (candidate_rank == target_rank && target.source.is_none()) {
        target.source = candidate.source.clone();
    }
}

fn census_source_rank(source: Option<&str>) -> u8 {
    match source {
        Some("pypi_simple_index") | Some("npm_all_docs") | Some("crates_io_native") => 5,
        Some("graph_input") => 4,
        Some("offline_score_file") | Some("local_graph") => 3,
        Some("package_census") => 2,
        Some("known_package_stub") | Some("runtime_observed_v1") => 1,
        Some(_) => 2,
        None => 0,
    }
}

fn snapshot_persists_to_score_file(snapshot: &PrioritySnapshot) -> bool {
    matches!(
        snapshot.source,
        PrioritySource::LocalGraph | PrioritySource::OfflineScoreFile
    )
}

fn snapshot_requires_runtime_persistence(snapshot: &PrioritySnapshot) -> bool {
    !matches!(
        snapshot.source,
        PrioritySource::KnownPackageStub | PrioritySource::PackageCensus
    )
}

async fn append_ndjson_line<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let encoded =
        serde_json::to_string(value).context("failed to encode runtime priority snapshot")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("failed to open {} for append", path.display()))?;
    file.write_all(encoded.as_bytes())
        .await
        .with_context(|| format!("failed to append {}", path.display()))?;
    file.write_all(b"\n")
        .await
        .with_context(|| format!("failed to append newline to {}", path.display()))
}

async fn append_ndjson_records<T: Serialize>(path: &Path, values: &[T]) -> Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut body = String::new();
    for value in values {
        body.push_str(
            &serde_json::to_string(value).with_context(|| {
                format!("failed to encode append record for {}", path.display())
            })?,
        );
        body.push('\n');
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("failed to open {} for append", path.display()))?;
    file.write_all(body.as_bytes())
        .await
        .with_context(|| format!("failed to append {}", path.display()))
}

fn roots_from_score_input(records: &[scoring::ScoreInputRecord]) -> Vec<(Ecosystem, String)> {
    let mut roots = BTreeSet::new();
    for record in records {
        match record {
            scoring::ScoreInputRecord::Package {
                ecosystem, package, ..
            } => {
                roots.insert((*ecosystem, normalize_package_name(*ecosystem, package)));
            }
            scoring::ScoreInputRecord::Dependency {
                ecosystem,
                package,
                dependency,
                ..
            } => {
                roots.insert((*ecosystem, normalize_package_name(*ecosystem, package)));
                roots.insert((*ecosystem, normalize_package_name(*ecosystem, dependency)));
            }
        }
    }
    roots.into_iter().collect()
}

impl OnlinePriorityFallback {
    async fn resolve(&self, ecosystem: Ecosystem, package: &str) -> PrioritySnapshot {
        let key = (ecosystem, package.to_string());
        if let Some(snapshot) = self.cache.lock().await.get_cloned_refresh(&key) {
            return snapshot;
        }

        let snapshot = match fetch_deps_dev_fallback_snapshot(
            &self.http,
            &self.v3_base,
            &self.v3alpha_base,
            ecosystem,
            package,
            self.thresholds.get(&ecosystem).copied(),
        )
        .await
        {
            Ok(snapshot) => snapshot,
            Err(deps_dev_error) => {
                match fetch_ecosyste_ms_fallback_snapshot(
                    &self.http,
                    ecosystem,
                    package,
                    self.thresholds.get(&ecosystem).copied(),
                )
                .await
                {
                    Ok(snapshot) => snapshot,
                    Err(ecosyste_ms_error) => {
                        debug!(
                            ecosystem = %ecosystem,
                            package,
                            deps_dev_error = %deps_dev_error,
                            ecosyste_ms_error = %ecosyste_ms_error,
                            "priority fallback lookup failed"
                        );
                        PrioritySnapshot::default_unknown()
                    }
                }
            }
        };

        self.cache.lock().await.insert(key, snapshot.clone());
        snapshot
    }
}

impl LocalGraphFallback {
    async fn resolve(&self, ecosystem: Ecosystem, package: &str) -> Option<PrioritySnapshot> {
        self.resolve_scored(ecosystem, package).await.ok().flatten()
    }

    async fn load_cache(&self) -> Result<LocalGraphCache> {
        let modified_at = tokio::fs::metadata(&self.graph_file)
            .await
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        {
            let guard = self.cache.lock().await;
            if let Some(cache) = guard.as_ref()
                && cache.modified_at == modified_at
            {
                return Ok(cache.clone());
            }
        }

        let records = scoring::load_score_input_records(&self.graph_file).await?;
        let mut direct_popularity = HashMap::new();
        let mut reverse_dependents = HashMap::<(Ecosystem, String), usize>::new();
        let mut direct_dependencies = HashMap::<(Ecosystem, String), usize>::new();
        let mut direct_dependency_names = HashMap::<(Ecosystem, String), BTreeSet<String>>::new();
        let mut reverse_dependent_names = HashMap::<(Ecosystem, String), BTreeSet<String>>::new();
        let mut known_packages = HashSet::new();
        let mut seen_edges = HashSet::<(Ecosystem, String, String)>::new();
        for record in records {
            match record {
                scoring::ScoreInputRecord::Package {
                    ecosystem,
                    package,
                    direct_popularity: popularity,
                } => {
                    let key = (ecosystem, normalize_package_name(ecosystem, &package));
                    known_packages.insert(key.clone());
                    direct_popularity
                        .entry(key)
                        .and_modify(|current: &mut f64| *current = current.max(popularity))
                        .or_insert(popularity);
                }
                scoring::ScoreInputRecord::Dependency {
                    ecosystem,
                    package,
                    dependency,
                    ..
                } => {
                    let package_key = (ecosystem, normalize_package_name(ecosystem, &package));
                    let dependency_key =
                        (ecosystem, normalize_package_name(ecosystem, &dependency));
                    known_packages.insert(package_key.clone());
                    known_packages.insert(dependency_key.clone());
                    if seen_edges.insert((
                        ecosystem,
                        package_key.1.clone(),
                        dependency_key.1.clone(),
                    )) {
                        *direct_dependencies.entry(package_key).or_default() += 1;
                        *reverse_dependents.entry(dependency_key).or_default() += 1;
                        direct_dependency_names
                            .entry((ecosystem, normalize_package_name(ecosystem, &package)))
                            .or_default()
                            .insert(normalize_package_name(ecosystem, &dependency));
                        reverse_dependent_names
                            .entry((ecosystem, normalize_package_name(ecosystem, &dependency)))
                            .or_default()
                            .insert(normalize_package_name(ecosystem, &package));
                    }
                }
            }
        }

        let cache = LocalGraphCache {
            modified_at,
            direct_popularity,
            reverse_dependents,
            direct_dependencies,
            direct_dependency_names,
            reverse_dependent_names,
            known_packages,
        };
        *self.cache.lock().await = Some(cache.clone());
        Ok(cache)
    }

    async fn evidence(&self, ecosystem: Ecosystem, package: &str) -> Result<LocalGraphEvidence> {
        if let Some(evidence) = self.load_store_evidence(ecosystem, package).await? {
            return Ok(LocalGraphEvidence {
                known: evidence.known,
                direct_dependencies_seen: evidence.direct_dependencies_seen,
                reverse_dependents_seen: evidence.reverse_dependents_seen,
                repository: evidence.repository,
            });
        }
        if self.store.is_some() {
            return Ok(LocalGraphEvidence::default());
        }

        let cache = self.load_cache().await?;
        let key = (ecosystem, package.to_string());
        Ok(LocalGraphEvidence {
            known: cache.known_packages.contains(&key),
            direct_dependencies_seen: cache.direct_dependencies.get(&key).copied().unwrap_or(0),
            reverse_dependents_seen: cache.reverse_dependents.get(&key).copied().unwrap_or(0),
            repository: None,
        })
    }

    async fn repository(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Option<PackageRepositoryIdentity>> {
        match &self.store {
            Some(store) => {
                store
                    .load_package_repository_identity(ecosystem, package)
                    .await
            }
            None => Ok(None),
        }
    }

    async fn resolve_scored(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Option<PrioritySnapshot>> {
        let rescored = self
            .score_neighborhood(ecosystem, &[package.to_string()], 256)
            .await?;
        if let Some(snapshot) = rescored.get(package).cloned() {
            return Ok(Some(snapshot));
        }

        if let Some(evidence) = self.load_store_evidence(ecosystem, package).await? {
            return Ok(Some(self.snapshot_from_evidence(ecosystem, evidence)));
        }
        if self.store.is_some() {
            return Ok(None);
        }

        let cache = self.load_cache().await?;
        let key = (ecosystem, package.to_string());
        if !cache.known_packages.contains(&key) {
            return Ok(None);
        }
        Ok(Some(
            self.snapshot_from_values(
                ecosystem,
                cache
                    .direct_popularity
                    .get(&key)
                    .copied()
                    .unwrap_or_default(),
                cache
                    .reverse_dependents
                    .get(&key)
                    .copied()
                    .unwrap_or_default(),
            ),
        ))
    }

    async fn score_neighborhood(
        &self,
        ecosystem: Ecosystem,
        roots: &[String],
        per_root_limit: usize,
    ) -> Result<HashMap<String, PrioritySnapshot>> {
        let mut records = match self
            .load_store_graph_records(ecosystem, roots, per_root_limit)
            .await?
        {
            Some(records) => records,
            None => {
                self.load_cache_graph_records(ecosystem, roots, per_root_limit)
                    .await?
            }
        };
        if records.records.is_empty() {
            return Ok(HashMap::new());
        }
        let root_set = roots
            .iter()
            .map(|root| normalize_package_name(ecosystem, root))
            .collect::<HashSet<_>>();
        for record in &mut records.records {
            if let scoring::ScoreInputRecord::Package {
                ecosystem: record_ecosystem,
                package,
                direct_popularity,
            } = record
                && *record_ecosystem == ecosystem
                && root_set.contains(package)
            {
                *direct_popularity = direct_popularity.max(1.0);
            }
        }

        let (scores, _) =
            scoring::build_priority_scores_from_records(&records.records, &self.score_build)?;
        let thresholds = self.thresholds.get(&ecosystem).copied();
        Ok(scores
            .into_iter()
            .filter(|record| record.ecosystem == ecosystem)
            .map(|record| {
                let package = normalize_package_name(ecosystem, &record.package);
                let propagated_impact = record.propagated_impact.unwrap_or_default();
                let tier = match thresholds {
                    Some(value) if propagated_impact >= value.high => PriorityTier::High,
                    Some(value) if propagated_impact >= value.medium => PriorityTier::Medium,
                    Some(_) => PriorityTier::Low,
                    None => record.priority_tier,
                };
                (
                    package,
                    PrioritySnapshot {
                        tier,
                        source: PrioritySource::LocalGraph,
                        direct_popularity: record.direct_popularity,
                        propagated_impact: record.propagated_impact,
                        hidden_leverage: record.hidden_leverage,
                        computed_at: record.computed_at,
                        score_source_version: Some("local_graph".to_string()),
                    },
                )
            })
            .collect())
    }

    async fn inspect(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        limit: usize,
    ) -> Result<LocalGraphInspectionData> {
        if let Some(neighborhood) = self
            .load_store_neighborhood(ecosystem, package, limit)
            .await?
        {
            return Ok(LocalGraphInspectionData {
                known: neighborhood.evidence.known,
                direct_popularity: neighborhood.evidence.direct_popularity,
                direct_dependencies_seen: neighborhood.evidence.direct_dependencies_seen,
                reverse_dependents_seen: neighborhood.evidence.reverse_dependents_seen,
                direct_dependencies: neighborhood.direct_dependencies,
                reverse_dependents: neighborhood.reverse_dependents,
                repository: neighborhood.evidence.repository,
            });
        }
        if self.store.is_some() {
            return Ok(LocalGraphInspectionData::default());
        }

        let cache = self.load_cache().await?;
        let key = (ecosystem, package.to_string());
        Ok(LocalGraphInspectionData {
            known: cache.known_packages.contains(&key),
            direct_popularity: cache.direct_popularity.get(&key).copied().unwrap_or(0.0),
            direct_dependencies_seen: cache.direct_dependencies.get(&key).copied().unwrap_or(0),
            reverse_dependents_seen: cache.reverse_dependents.get(&key).copied().unwrap_or(0),
            direct_dependencies: cache
                .direct_dependency_names
                .get(&key)
                .map(|names| names.iter().take(limit).cloned().collect())
                .unwrap_or_default(),
            reverse_dependents: cache
                .reverse_dependent_names
                .get(&key)
                .map(|names| names.iter().take(limit).cloned().collect())
                .unwrap_or_default(),
            repository: None,
        })
    }

    async fn load_store_evidence(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Option<GraphEvidence>> {
        match &self.store {
            Some(store) => store.load_graph_evidence(ecosystem, package).await,
            None => Ok(None),
        }
    }

    async fn load_store_neighborhood(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        limit: usize,
    ) -> Result<Option<GraphNeighborhood>> {
        match &self.store {
            Some(store) => {
                store
                    .load_graph_neighborhood(ecosystem, package, limit)
                    .await
            }
            None => Ok(None),
        }
    }

    async fn load_store_graph_records(
        &self,
        ecosystem: Ecosystem,
        roots: &[String],
        per_root_limit: usize,
    ) -> Result<Option<GraphNeighborhoodRecords>> {
        match &self.store {
            Some(store) => store
                .load_graph_records_for_roots(ecosystem, roots, per_root_limit)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn load_cache_graph_records(
        &self,
        ecosystem: Ecosystem,
        roots: &[String],
        _per_root_limit: usize,
    ) -> Result<GraphNeighborhoodRecords> {
        let cache = self.load_cache().await?;
        let normalized_roots = roots
            .iter()
            .map(|root| normalize_package_name(ecosystem, root))
            .collect::<Vec<_>>();
        let mut frontier = BTreeSet::new();
        for root in &normalized_roots {
            if cache.known_packages.contains(&(ecosystem, root.clone())) {
                frontier.insert(root.clone());
            }
        }
        for root in &normalized_roots {
            if let Some(reverse) = cache
                .reverse_dependent_names
                .get(&(ecosystem, root.clone()))
            {
                frontier.extend(reverse.iter().cloned());
            }
        }
        if frontier.is_empty() {
            return Ok(GraphNeighborhoodRecords {
                roots: normalized_roots,
                records: Vec::new(),
            });
        }

        let mut package_names = frontier.clone();
        let mut records = Vec::new();
        for package in &frontier {
            if let Some(dependencies) = cache
                .direct_dependency_names
                .get(&(ecosystem, package.clone()))
            {
                for dependency in dependencies {
                    package_names.insert(dependency.clone());
                    records.push(scoring::ScoreInputRecord::Dependency {
                        ecosystem,
                        package: package.clone(),
                        dependency: dependency.clone(),
                        weight: 1.0,
                        sources: vec!["local_graph_cache".to_string()],
                        confidence: None,
                    });
                }
            }
        }
        let mut package_records = package_names
            .into_iter()
            .map(|package| scoring::ScoreInputRecord::Package {
                ecosystem,
                direct_popularity: cache
                    .direct_popularity
                    .get(&(ecosystem, package.clone()))
                    .copied()
                    .unwrap_or_default(),
                package,
            })
            .collect::<Vec<_>>();
        package_records.append(&mut records);

        Ok(GraphNeighborhoodRecords {
            roots: normalized_roots,
            records: package_records,
        })
    }

    fn snapshot_from_evidence(
        &self,
        ecosystem: Ecosystem,
        evidence: GraphEvidence,
    ) -> PrioritySnapshot {
        self.snapshot_from_values(
            ecosystem,
            evidence.direct_popularity,
            evidence.reverse_dependents_seen,
        )
    }

    fn snapshot_from_values(
        &self,
        ecosystem: Ecosystem,
        direct_popularity: f64,
        reverse_dependents: usize,
    ) -> PrioritySnapshot {
        let propagated_impact = (reverse_dependents as f64).max(direct_popularity);
        let hidden_leverage = (propagated_impact + 1.0).ln() - (direct_popularity + 1.0).ln();
        let tier = match self.thresholds.get(&ecosystem).copied() {
            Some(thresholds) if propagated_impact >= thresholds.high => PriorityTier::High,
            Some(thresholds) if propagated_impact >= thresholds.medium => PriorityTier::Medium,
            Some(_) => PriorityTier::Low,
            None => PriorityTier::Medium,
        };

        PrioritySnapshot {
            tier,
            source: PrioritySource::LocalGraph,
            direct_popularity: Some(direct_popularity),
            propagated_impact: Some(propagated_impact),
            hidden_leverage: Some(hidden_leverage),
            computed_at: Some(Utc::now()),
            score_source_version: Some("local_graph".to_string()),
        }
    }
}

impl OnlinePriorityExpander {
    fn should_expand(&self, snapshot: &PrioritySnapshot, observation_count: usize) -> bool {
        match snapshot.source {
            PrioritySource::OfflineScoreFile => false,
            PrioritySource::LocalGraph => {
                snapshot.tier == PriorityTier::High && observation_count >= self.min_observations
            }
            PrioritySource::DepsDevDependentsApi | PrioritySource::EcosysteMsCountsApi => {
                snapshot.tier == PriorityTier::High || observation_count >= self.min_observations
            }
            PrioritySource::PackageCensus | PrioritySource::KnownPackageStub => {
                observation_count >= self.min_observations
            }
            PrioritySource::DefaultUnknown => false,
        }
    }

    async fn spawn_expand(
        &self,
        inner: Arc<PriorityResolverInner>,
        ecosystem: Ecosystem,
        package: String,
        direct_popularity_hint: Option<f64>,
    ) {
        let key = (ecosystem, package.clone());
        {
            let mut in_flight = self.in_flight.lock().await;
            if !in_flight.insert(key.clone()) {
                return;
            }
        }

        let graph_file = self.graph_file.clone();
        let score_file = self.score_file.clone();
        let census_file = self.census_file.clone();
        let focus = self.focus.clone();
        let collect = self.collect.clone();
        let score_build = self.score_build.clone();
        let in_flight = self.in_flight.clone();
        let update_lock = self.update_lock.clone();
        tokio::spawn(async move {
            let result = async {
                let _guard = update_lock.lock().await;
                expand_priority_graph(RuntimeExpandRequest {
                    graph_file: &graph_file,
                    score_file: &score_file,
                    census_file: &census_file,
                    inner: &inner,
                    ecosystem,
                    package: &package,
                    direct_popularity_hint,
                    focus_config: &focus,
                    collect_config: &collect,
                    score_build: &score_build,
                })
                .await
            }
            .await;

            match result {
                Ok(summary) => {
                    info!(
                        ecosystem = %ecosystem,
                        package,
                        merged_packages = summary.merged_packages,
                        merged_dependencies = summary.merged_dependencies,
                        scored_packages = summary.scored_packages,
                        "expanded priority graph for unknown package"
                    );
                }
                Err(error) => {
                    warn!(
                        ecosystem = %ecosystem,
                        package,
                        error = %error,
                        "failed to expand priority graph for unknown package"
                    );
                }
            }

            in_flight.lock().await.remove(&key);
        });
    }
}

#[derive(Debug)]
struct RuntimeExpandSummary {
    merged_packages: usize,
    merged_dependencies: usize,
    scored_packages: usize,
}

struct RuntimeExpandRequest<'a> {
    graph_file: &'a Path,
    score_file: &'a Path,
    census_file: &'a Path,
    inner: &'a PriorityResolverInner,
    ecosystem: Ecosystem,
    package: &'a str,
    direct_popularity_hint: Option<f64>,
    focus_config: &'a crate::deps_dev::FocusDependentsConfig,
    collect_config: &'a crate::collector::CollectConfig,
    score_build: &'a crate::scoring::ScoreBuildConfig,
}

async fn expand_priority_graph(request: RuntimeExpandRequest<'_>) -> Result<RuntimeExpandSummary> {
    let focus_result = deps_dev_bigquery::focus_dependents_subgraph_live(
        request.ecosystem,
        request.package,
        request.focus_config,
        &LiveFocusConfig,
    )
    .await;

    let (reverse_records, seeds) = match focus_result {
        Ok((records, seeds, _summary)) => (records, seeds),
        Err(error) => {
            debug!(
                ecosystem = %request.ecosystem,
                package = request.package,
                error = %error,
                "live reverse expansion unavailable; falling back to forward-only expansion"
            );
            let seed = SeedPackageRecord {
                ecosystem: request.ecosystem,
                package: request.package.to_string(),
                direct_popularity: request.direct_popularity_hint,
            };
            (Vec::new(), vec![seed])
        }
    };

    let popularity = seeds
        .iter()
        .filter_map(|seed| {
            seed.direct_popularity
                .map(|direct_popularity| SeedPackageRecord {
                    ecosystem: seed.ecosystem,
                    package: seed.package.clone(),
                    direct_popularity: Some(direct_popularity),
                })
        })
        .collect::<Vec<_>>();
    let material =
        collector::collect_graph_material_from_records(seeds, popularity, request.collect_config)
            .await?;
    let forward_records = material.records;
    let forward_repositories = material.repositories;

    let mut batch_inputs = Vec::new();
    if !reverse_records.is_empty() {
        batch_inputs.push(scoring::encode_score_input_ndjson(&reverse_records)?);
    }
    if !forward_records.is_empty() {
        batch_inputs.push(scoring::encode_score_input_ndjson(&forward_records)?);
    }
    if batch_inputs.is_empty() {
        return Ok(RuntimeExpandSummary {
            merged_packages: 0,
            merged_dependencies: 0,
            scored_packages: 0,
        });
    }

    let batch_refs = batch_inputs.iter().map(String::as_str).collect::<Vec<_>>();
    let (batch_records, batch_merge_summary) =
        scoring::merge_score_input_ndjson(&batch_refs, batch_refs.len())?;
    let census_records = package_census_from_score_input(&batch_records);
    let roots = roots_from_score_input(&batch_records);

    if let Some(local_graph) = &request.inner.local_graph_fallback
        && let Some(store) = &local_graph.store
    {
        if !batch_records.is_empty() {
            store.record_graph_records(&batch_records).await?;
            append_ndjson_records(request.graph_file, &batch_records).await?;
        }
        if !census_records.is_empty() {
            append_ndjson_records(request.census_file, &census_records).await?;
        }
        if !forward_repositories.is_empty() {
            store
                .record_package_repository_refs(&forward_repositories)
                .await?;
        }

        let mut grouped = BTreeMap::<Ecosystem, Vec<String>>::new();
        for (ecosystem, package) in roots {
            grouped.entry(ecosystem).or_default().push(package);
        }
        let mut updates = Vec::new();
        for (ecosystem, packages) in grouped {
            let snapshots = local_graph
                .score_neighborhood(ecosystem, &packages, 256)
                .await?;
            for (package, snapshot) in snapshots {
                updates.push(PriorityScoreRecord {
                    ecosystem,
                    package,
                    priority_tier: snapshot.tier,
                    priority_source: Some(snapshot.source),
                    direct_popularity: snapshot.direct_popularity,
                    propagated_impact: snapshot.propagated_impact,
                    hidden_leverage: snapshot.hidden_leverage,
                    computed_at: snapshot.computed_at,
                    score_source_version: snapshot.score_source_version.clone(),
                });
            }
        }

        let merged_scores = if let Some(graph_store_file) = request
            .inner
            .observed_package_recorder
            .graph_store_file
            .as_deref()
        {
            let store = OperationalStore::open(graph_store_file.to_path_buf()).await?;
            store.record_priority_score_records(&updates).await?;
            load_priority_score_records_with_store(request.score_file, Some(graph_store_file))
                .await?
        } else {
            upsert_priority_score_records(request.score_file, &updates).await?
        };
        let snapshots = merged_scores
            .into_iter()
            .map(|record| {
                (
                    (
                        record.ecosystem,
                        normalize_package_name(record.ecosystem, &record.package),
                    ),
                    snapshot_from_score_record(record),
                )
            })
            .collect::<HashMap<_, _>>();
        *request.inner.scores.write().await = snapshots;

        return Ok(RuntimeExpandSummary {
            merged_packages: batch_merge_summary.merged_packages,
            merged_dependencies: batch_merge_summary.merged_dependencies,
            scored_packages: updates.len(),
        });
    }

    let mut inputs = Vec::new();
    let existing_records = scoring::load_score_input_records(request.graph_file).await?;
    if !existing_records.is_empty() {
        inputs.push(scoring::encode_score_input_ndjson(&existing_records)?);
    }
    inputs.push(scoring::encode_score_input_ndjson(&batch_records)?);
    let input_refs = inputs.iter().map(String::as_str).collect::<Vec<_>>();
    let (merged_records, merge_summary) =
        scoring::merge_score_input_ndjson(&input_refs, input_refs.len())?;
    let (scores, build_summary) =
        scoring::build_priority_scores_from_records(&merged_records, request.score_build)?;
    let merged_census_records = package_census_from_score_input(&merged_records);
    scoring::write_score_input_records(request.graph_file, &merged_records).await?;
    write_package_census_records(request.census_file, &merged_census_records).await?;
    if let Some(graph_store_file) = request
        .inner
        .observed_package_recorder
        .graph_store_file
        .as_deref()
    {
        let store = OperationalStore::open(graph_store_file.to_path_buf()).await?;
        store.record_priority_score_records(&scores).await?;
    } else {
        write_priority_score_records(request.score_file, &scores).await?;
    }

    let snapshots = scores
        .into_iter()
        .map(|record| {
            (
                (
                    record.ecosystem,
                    normalize_package_name(record.ecosystem, &record.package),
                ),
                snapshot_from_score_record(record),
            )
        })
        .collect::<HashMap<_, _>>();
    *request.inner.scores.write().await = snapshots;

    Ok(RuntimeExpandSummary {
        merged_packages: merge_summary.merged_packages,
        merged_dependencies: merge_summary.merged_dependencies,
        scored_packages: build_summary.scored_packages,
    })
}

pub async fn lookup_priority_score(
    path: &Path,
    ecosystem: Ecosystem,
    package: &str,
) -> Result<PriorityScoreLookupResult> {
    let normalized_package = normalize_package_name(ecosystem, package);
    let mut records = load_priority_score_records(path)
        .await?
        .into_iter()
        .filter(|record| record.ecosystem == ecosystem)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        right
            .propagated_impact
            .unwrap_or_default()
            .total_cmp(&left.propagated_impact.unwrap_or_default())
            .then_with(|| left.package.cmp(&right.package))
    });

    let ecosystem_package_count = records.len();
    let record = records
        .iter()
        .find(|record| normalize_package_name(ecosystem, &record.package) == normalized_package)
        .cloned();

    let ecosystem_rank_by_propagated_impact = records
        .iter()
        .position(|record| normalize_package_name(ecosystem, &record.package) == normalized_package)
        .map(|index| index + 1);

    let mut hidden = records.clone();
    hidden.sort_by(|left, right| {
        right
            .hidden_leverage
            .unwrap_or_default()
            .total_cmp(&left.hidden_leverage.unwrap_or_default())
            .then_with(|| left.package.cmp(&right.package))
    });
    let ecosystem_rank_by_hidden_leverage = hidden
        .iter()
        .position(|record| normalize_package_name(ecosystem, &record.package) == normalized_package)
        .map(|index| index + 1);

    Ok(PriorityScoreLookupResult {
        ecosystem,
        package: package.to_string(),
        normalized_package,
        ecosystem_package_count,
        ecosystem_rank_by_propagated_impact,
        ecosystem_rank_by_hidden_leverage,
        record,
    })
}

pub async fn resolve_online_priority_snapshot(
    ecosystem: Ecosystem,
    package: &str,
    online_request_timeout: Duration,
    deps_dev_v3_base: &str,
    deps_dev_v3alpha_base: &str,
) -> Result<PrioritySnapshot> {
    let http = reqwest::Client::builder()
        .user_agent("supply-stream-priority/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(online_request_timeout)
        .timeout(online_request_timeout)
        .build()
        .context("failed to build priority fallback HTTP client")?;

    let normalized = normalize_package_name(ecosystem, package);
    match fetch_deps_dev_fallback_snapshot(
        &http,
        deps_dev_v3_base,
        deps_dev_v3alpha_base,
        ecosystem,
        &normalized,
        None,
    )
    .await
    {
        Ok(snapshot) => Ok(snapshot),
        Err(deps_dev_error) => {
            fetch_ecosyste_ms_fallback_snapshot(&http, ecosystem, &normalized, None)
                .await
                .with_context(|| format!("deps.dev fallback failed first: {deps_dev_error}"))
        }
    }
}

pub async fn summarize_priority_scores(
    path: &Path,
    top_limit: usize,
) -> Result<PriorityScoreStatsSummary> {
    let records = load_priority_score_records(path).await?;
    Ok(summarize_priority_score_records(&records, top_limit))
}

pub fn summarize_priority_score_records(
    records: &[PriorityScoreRecord],
    top_limit: usize,
) -> PriorityScoreStatsSummary {
    let mut by_ecosystem = BTreeMap::<Ecosystem, Vec<PriorityScoreRecord>>::new();
    for record in records {
        by_ecosystem
            .entry(record.ecosystem)
            .or_default()
            .push(record.clone());
    }

    let ecosystems = by_ecosystem
        .into_iter()
        .map(
            |(ecosystem, ecosystem_records)| PriorityScoreEcosystemSummary {
                ecosystem,
                packages: ecosystem_records.len(),
                priorities: count_record_priorities(&ecosystem_records),
                top_by_propagated_impact: top_priority_score_records(
                    &ecosystem_records,
                    PriorityScoreMetric::PropagatedImpact,
                    top_limit,
                ),
                top_by_hidden_leverage: top_priority_score_records(
                    &ecosystem_records,
                    PriorityScoreMetric::HiddenLeverage,
                    top_limit,
                ),
            },
        )
        .collect::<Vec<_>>();

    PriorityScoreStatsSummary {
        scored_packages: records.len(),
        ecosystems,
    }
}

pub async fn load_top_priority_scores(
    path: &Path,
    ecosystem: Option<Ecosystem>,
    metric: PriorityScoreMetric,
    limit: usize,
) -> Result<Vec<PriorityTopEntry>> {
    let records = load_priority_score_records(path).await?;
    Ok(top_priority_scores(&records, ecosystem, metric, limit))
}

pub fn top_priority_scores(
    records: &[PriorityScoreRecord],
    ecosystem: Option<Ecosystem>,
    metric: PriorityScoreMetric,
    limit: usize,
) -> Vec<PriorityTopEntry> {
    let filtered = records
        .iter()
        .filter(|record| ecosystem.is_none_or(|target| record.ecosystem == target))
        .cloned()
        .collect::<Vec<_>>();
    top_priority_score_records(&filtered, metric, limit)
}

fn top_priority_score_records(
    records: &[PriorityScoreRecord],
    metric: PriorityScoreMetric,
    limit: usize,
) -> Vec<PriorityTopEntry> {
    let mut entries = records.to_vec();
    entries.sort_by(|left, right| {
        metric_value(right, metric)
            .total_cmp(&metric_value(left, metric))
            .then_with(|| left.ecosystem.cmp(&right.ecosystem))
            .then_with(|| left.package.cmp(&right.package))
    });
    entries
        .into_iter()
        .take(limit)
        .map(|record| PriorityTopEntry {
            ecosystem: record.ecosystem,
            package: record.package,
            priority_tier: record.priority_tier,
            direct_popularity: record.direct_popularity.unwrap_or_default(),
            propagated_impact: record.propagated_impact.unwrap_or_default(),
            hidden_leverage: record.hidden_leverage.unwrap_or_default(),
        })
        .collect()
}

fn metric_value(record: &PriorityScoreRecord, metric: PriorityScoreMetric) -> f64 {
    match metric {
        PriorityScoreMetric::DirectPopularity => record.direct_popularity.unwrap_or_default(),
        PriorityScoreMetric::PropagatedImpact => record.propagated_impact.unwrap_or_default(),
        PriorityScoreMetric::HiddenLeverage => record.hidden_leverage.unwrap_or_default(),
    }
}

fn count_record_priorities(records: &[PriorityScoreRecord]) -> PriorityCounts {
    let mut counts = PriorityCounts::default();
    for record in records {
        match record.priority_tier {
            PriorityTier::High => counts.high += 1,
            PriorityTier::Medium => counts.medium += 1,
            PriorityTier::Low => counts.low += 1,
        }
    }
    counts
}

pub fn snapshot_from_score_record(record: PriorityScoreRecord) -> PrioritySnapshot {
    PrioritySnapshot {
        tier: record.priority_tier,
        source: record
            .priority_source
            .unwrap_or(PrioritySource::OfflineScoreFile),
        direct_popularity: record.direct_popularity,
        propagated_impact: record.propagated_impact,
        hidden_leverage: record.hidden_leverage,
        computed_at: record.computed_at,
        score_source_version: record.score_source_version,
    }
}

pub fn package_census_from_score_input(
    records: &[scoring::ScoreInputRecord],
) -> Vec<PackageCensusRecord> {
    let mut packages = BTreeMap::<(Ecosystem, String), PackageCensusRecord>::new();
    for record in records {
        match record {
            scoring::ScoreInputRecord::Package {
                ecosystem, package, ..
            } => {
                let normalized = normalize_package_name(*ecosystem, package);
                packages
                    .entry((*ecosystem, normalized.clone()))
                    .or_insert(PackageCensusRecord {
                        ecosystem: *ecosystem,
                        package: normalized,
                        discovered_at: None,
                        source: Some("graph_input".to_string()),
                    });
            }
            scoring::ScoreInputRecord::Dependency {
                ecosystem,
                package,
                dependency,
                ..
            } => {
                for name in [
                    normalize_package_name(*ecosystem, package),
                    normalize_package_name(*ecosystem, dependency),
                ] {
                    packages
                        .entry((*ecosystem, name.clone()))
                        .or_insert(PackageCensusRecord {
                            ecosystem: *ecosystem,
                            package: name,
                            discovered_at: None,
                            source: Some("graph_input".to_string()),
                        });
                }
            }
        }
    }
    packages.into_values().collect()
}

fn fallback_thresholds(records: &[PriorityScoreRecord]) -> HashMap<Ecosystem, FallbackThresholds> {
    let mut by_ecosystem = BTreeMap::<Ecosystem, Vec<f64>>::new();
    for record in records {
        let impact = record
            .propagated_impact
            .or(record.direct_popularity)
            .unwrap_or_default();
        if impact.is_finite() && impact > 0.0 {
            by_ecosystem
                .entry(record.ecosystem)
                .or_default()
                .push(impact);
        }
    }

    by_ecosystem
        .into_iter()
        .filter_map(|(ecosystem, mut values)| {
            if values.is_empty() {
                return None;
            }
            values.sort_by(|left, right| left.total_cmp(right));
            Some((
                ecosystem,
                FallbackThresholds {
                    high: quantile_threshold(&values, 0.99),
                    medium: quantile_threshold(&values, 0.90),
                },
            ))
        })
        .collect()
}

fn quantile_threshold(values: &[f64], quantile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let last_index = values.len().saturating_sub(1);
    let index = ((last_index as f64) * quantile.clamp(0.0, 1.0)).round() as usize;
    values[index.min(last_index)]
}

async fn fetch_deps_dev_fallback_snapshot(
    http: &reqwest::Client,
    v3_base: &str,
    v3alpha_base: &str,
    ecosystem: Ecosystem,
    package: &str,
    thresholds: Option<FallbackThresholds>,
) -> Result<PrioritySnapshot> {
    let encoded = urlencoding::encode(package);
    let package_url = format!(
        "{}/systems/{}/packages/{}",
        v3_base.trim_end_matches('/'),
        deps_dev_v3_system(ecosystem),
        encoded
    );
    let package_raw = http
        .get(&package_url)
        .send()
        .await
        .with_context(|| format!("failed to fetch deps.dev package for {ecosystem}:{package}"))?
        .error_for_status()
        .with_context(|| format!("deps.dev package lookup failed for {ecosystem}:{package}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("failed to decode deps.dev package for {ecosystem}:{package}"))?;

    let version = select_deps_dev_default_version(&package_raw)
        .with_context(|| format!("missing deps.dev default version for {ecosystem}:{package}"))?;
    let dependents_url = format!(
        "{}/systems/{}/packages/{}/versions/{}:dependents",
        v3alpha_base.trim_end_matches('/'),
        deps_dev_v3alpha_system(ecosystem),
        encoded,
        urlencoding::encode(&version)
    );
    let dependents_raw = http
        .get(&dependents_url)
        .send()
        .await
        .with_context(|| {
            format!("failed to fetch deps.dev dependents for {ecosystem}:{package}@{version}")
        })?
        .error_for_status()
        .with_context(|| {
            format!("deps.dev dependents lookup failed for {ecosystem}:{package}@{version}")
        })?
        .json::<Value>()
        .await
        .with_context(|| {
            format!("failed to decode deps.dev dependents for {ecosystem}:{package}@{version}")
        })?;

    let dependent_count = extract_u64(&dependents_raw, &["dependentCount", "dependentsCount"])
        .context("missing dependentCount")?;
    let direct_dependent_count = extract_u64(
        &dependents_raw,
        &["directDependentCount", "directDependentsCount"],
    )
    .unwrap_or(0);

    Ok(priority_snapshot_from_dependents_counts(
        dependent_count,
        direct_dependent_count,
        thresholds,
    ))
}

fn extract_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(key).and_then(Value::as_u64))
}

fn priority_snapshot_from_dependents_counts(
    dependent_count: u64,
    direct_dependent_count: u64,
    thresholds: Option<FallbackThresholds>,
) -> PrioritySnapshot {
    let propagated_impact = dependent_count as f64;
    let direct_popularity = direct_dependent_count as f64;
    let hidden_leverage = (propagated_impact + 1.0).ln() - (direct_popularity + 1.0).ln();
    let tier = fallback_priority_tier_from_counts(propagated_impact, thresholds);

    PrioritySnapshot {
        tier,
        source: PrioritySource::DepsDevDependentsApi,
        direct_popularity: Some(direct_popularity),
        propagated_impact: Some(propagated_impact),
        hidden_leverage: Some(hidden_leverage),
        computed_at: Some(Utc::now()),
        score_source_version: Some("deps_dev_dependents_api".to_string()),
    }
}

async fn fetch_ecosyste_ms_fallback_snapshot(
    http: &reqwest::Client,
    ecosystem: Ecosystem,
    package: &str,
    thresholds: Option<FallbackThresholds>,
) -> Result<PrioritySnapshot> {
    let encoded = urlencoding::encode(package);
    let package_url = format!(
        "{}/registries/{}/packages/{}",
        ECOSYSTE_MS_PACKAGES_BASE,
        ecosyste_ms_registry_name(ecosystem),
        encoded
    );
    let package_raw = http
        .get(&package_url)
        .send()
        .await
        .with_context(|| format!("failed to fetch ecosyste.ms package for {ecosystem}:{package}"))?
        .error_for_status()
        .with_context(|| format!("ecosyste.ms package lookup failed for {ecosystem}:{package}"))?
        .json::<Value>()
        .await
        .with_context(|| {
            format!("failed to decode ecosyste.ms package for {ecosystem}:{package}")
        })?;

    let dependent_packages_count = extract_u64(&package_raw, &["dependent_packages_count"])
        .context("missing dependent_packages_count")?;
    let dependent_repositories_count = extract_u64(&package_raw, &["dependent_repositories_count"]);
    let repo_dependents_count = match dependent_repositories_count {
        Some(value) => Some(value),
        None => {
            let usage_url = format!(
                "{}/{}/{}",
                ECOSYSTE_MS_REPOS_USAGE_BASE,
                ecosyste_ms_usage_system(ecosystem),
                encoded
            );
            let response = http.get(&usage_url).send().await.with_context(|| {
                format!("failed to fetch ecosyste.ms repo usage for {ecosystem}:{package}")
            })?;
            if !response.status().is_success() {
                None
            } else {
                let raw = response.json::<Value>().await.with_context(|| {
                    format!("failed to decode ecosyste.ms repo usage for {ecosystem}:{package}")
                })?;
                extract_u64(&raw, &["dependents_count"])
            }
        }
    };

    Ok(priority_snapshot_from_ecosyste_ms_counts(
        dependent_packages_count,
        repo_dependents_count,
        thresholds,
    ))
}

fn priority_snapshot_from_ecosyste_ms_counts(
    dependent_packages_count: u64,
    repo_dependents_count: Option<u64>,
    thresholds: Option<FallbackThresholds>,
) -> PrioritySnapshot {
    let direct_popularity = dependent_packages_count as f64;
    let propagated_impact = repo_dependents_count
        .map(|value| value as f64)
        .unwrap_or(direct_popularity)
        .max(direct_popularity);
    let hidden_leverage = (propagated_impact + 1.0).ln() - (direct_popularity + 1.0).ln();
    let tier = fallback_priority_tier_from_counts(propagated_impact, thresholds);

    PrioritySnapshot {
        tier,
        source: PrioritySource::EcosysteMsCountsApi,
        direct_popularity: Some(direct_popularity),
        propagated_impact: Some(propagated_impact),
        hidden_leverage: Some(hidden_leverage),
        computed_at: Some(Utc::now()),
        score_source_version: Some("ecosyste_ms_counts_api".to_string()),
    }
}

fn fallback_priority_tier_from_counts(
    propagated_impact: f64,
    thresholds: Option<FallbackThresholds>,
) -> PriorityTier {
    let (high_threshold, medium_threshold) = match thresholds {
        Some(thresholds) => (
            thresholds.high.max(FALLBACK_MIN_HIGH_PROPAGATED_IMPACT),
            thresholds.medium.max(FALLBACK_MIN_MEDIUM_PROPAGATED_IMPACT),
        ),
        None => (
            FALLBACK_MIN_HIGH_PROPAGATED_IMPACT,
            FALLBACK_MIN_MEDIUM_PROPAGATED_IMPACT,
        ),
    };

    if propagated_impact >= high_threshold {
        PriorityTier::High
    } else if propagated_impact >= medium_threshold {
        PriorityTier::Medium
    } else {
        PriorityTier::Low
    }
}

fn deps_dev_v3_system(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
        Ecosystem::CratesIo => "cargo",
    }
}

fn deps_dev_v3alpha_system(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "NPM",
        Ecosystem::Pypi => "PYPI",
        Ecosystem::CratesIo => "CARGO",
    }
}

fn ecosyste_ms_registry_name(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npmjs.org",
        Ecosystem::Pypi => "pypi.org",
        Ecosystem::CratesIo => "crates.io",
    }
}

fn ecosyste_ms_usage_system(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
        Ecosystem::CratesIo => "cargo",
    }
}

fn select_deps_dev_default_version(package_raw: &Value) -> Option<String> {
    let versions = package_raw.get("versions")?.as_array()?;
    let default = versions
        .iter()
        .find(|version| {
            version
                .get("isDefault")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .or_else(|| {
            versions.iter().max_by_key(|version| {
                version
                    .get("publishedAt")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            })
        })
        .or_else(|| versions.last())?;
    default
        .pointer("/versionKey/version")
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub fn normalize_package_name(ecosystem: Ecosystem, package: &str) -> String {
    match ecosystem {
        Ecosystem::Pypi => normalize_pypi_name(package),
        Ecosystem::Npm | Ecosystem::CratesIo => package.to_ascii_lowercase(),
    }
}

fn normalize_pypi_name(name: &str) -> String {
    let mut normalized = String::new();
    let mut previous_dash = false;
    for ch in name.chars() {
        let lower = ch.to_ascii_lowercase();
        if matches!(lower, '-' | '_' | '.') {
            if !previous_dash {
                normalized.push('-');
                previous_dash = true;
            }
        } else {
            normalized.push(lower);
            previous_dash = false;
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use chrono::Utc;
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn normalizes_package_names_by_ecosystem() {
        assert_eq!(
            normalize_package_name(Ecosystem::Pypi, "My_Package.Name"),
            "my-package-name"
        );
        assert_eq!(
            normalize_package_name(Ecosystem::Npm, "@Scope/Example"),
            "@scope/example"
        );
        assert_eq!(
            normalize_package_name(Ecosystem::CratesIo, "Serde"),
            "serde"
        );
    }

    #[test]
    fn default_unknown_priority_is_medium_capture_only() {
        let snapshot = PrioritySnapshot::default_unknown();
        assert!(snapshot.capture_requested());
        assert!(!snapshot.diff_requested());
        assert_eq!(snapshot.bucket(), PriorityBucket::Unknown);
    }

    #[test]
    fn known_package_stub_priority_is_medium_and_not_unknown() {
        let snapshot = PrioritySnapshot::known_package_stub();
        assert!(snapshot.capture_requested());
        assert!(!snapshot.diff_requested());
        assert_eq!(snapshot.bucket(), PriorityBucket::Medium);
        assert_eq!(snapshot.source, PrioritySource::KnownPackageStub);
    }

    #[tokio::test]
    async fn lookup_priority_score_normalizes_and_ranks_records() {
        let path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-lookup-{}.ndjson",
            std::process::id()
        ));
        let body = format!(
            concat!(
                "{{\"ecosystem\":\"pypi\",\"package\":\"My_Package.Name\",\"priority_tier\":\"high\",",
                "\"direct_popularity\":100.0,\"propagated_impact\":2000.0,\"hidden_leverage\":4.0,",
                "\"computed_at\":\"{}\"}}\n",
                "{{\"ecosystem\":\"pypi\",\"package\":\"consumer\",\"priority_tier\":\"medium\",",
                "\"direct_popularity\":1000.0,\"propagated_impact\":1500.0,\"hidden_leverage\":1.0}}\n"
            ),
            Utc::now().to_rfc3339()
        );
        tokio::fs::write(&path, body).await.unwrap();

        let lookup = lookup_priority_score(&path, Ecosystem::Pypi, "my-package-name")
            .await
            .unwrap();
        assert_eq!(lookup.normalized_package, "my-package-name");
        assert_eq!(lookup.ecosystem_package_count, 2);
        assert_eq!(lookup.ecosystem_rank_by_propagated_impact, Some(1));
        assert_eq!(lookup.ecosystem_rank_by_hidden_leverage, Some(1));
        assert_eq!(lookup.record.unwrap().package, "My_Package.Name");

        let _ = tokio::fs::remove_file(path).await;
    }

    #[test]
    fn summarize_and_rank_priority_scores() {
        let records = vec![
            PriorityScoreRecord {
                ecosystem: Ecosystem::Pypi,
                package: "litellm".to_string(),
                priority_tier: PriorityTier::Medium,
                priority_source: Some(PrioritySource::OfflineScoreFile),
                direct_popularity: Some(2.0),
                propagated_impact: Some(4.4),
                hidden_leverage: Some(0.59),
                computed_at: None,
                score_source_version: None,
            },
            PriorityScoreRecord {
                ecosystem: Ecosystem::Pypi,
                package: "urllib3".to_string(),
                priority_tier: PriorityTier::High,
                priority_source: Some(PrioritySource::OfflineScoreFile),
                direct_popularity: Some(1.0),
                propagated_impact: Some(4.75),
                hidden_leverage: Some(1.05),
                computed_at: None,
                score_source_version: None,
            },
            PriorityScoreRecord {
                ecosystem: Ecosystem::Npm,
                package: "react".to_string(),
                priority_tier: PriorityTier::High,
                priority_source: Some(PrioritySource::OfflineScoreFile),
                direct_popularity: Some(10.0),
                propagated_impact: Some(10.0),
                hidden_leverage: Some(0.0),
                computed_at: None,
                score_source_version: None,
            },
        ];

        let summary = summarize_priority_score_records(&records, 2);
        assert_eq!(summary.scored_packages, 3);
        assert_eq!(summary.ecosystems.len(), 2);
        let pypi = summary
            .ecosystems
            .iter()
            .find(|ecosystem| ecosystem.ecosystem == Ecosystem::Pypi)
            .unwrap();
        assert_eq!(pypi.packages, 2);
        assert_eq!(pypi.priorities.high, 1);
        assert_eq!(pypi.top_by_hidden_leverage[0].package, "urllib3");

        let top = top_priority_scores(
            &records,
            Some(Ecosystem::Pypi),
            PriorityScoreMetric::PropagatedImpact,
            1,
        );
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].package, "urllib3");
    }

    #[tokio::test]
    async fn resolver_uses_deps_dev_fallback_for_unknown_package() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 4096];
                let bytes = socket.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let body = if path == "/v3/systems/pypi/packages/litellm" {
                    serde_json::json!({
                        "versions": [
                            {"versionKey": {"version": "1.82.6"}, "isDefault": true}
                        ]
                    })
                } else if path
                    == "/v3alpha/systems/PYPI/packages/litellm/versions/1.82.6:dependents"
                {
                    serde_json::json!({
                        "dependentCount": 500,
                        "directDependentCount": 25
                    })
                } else {
                    serde_json::json!({"error": "not found"})
                };
                let status = if body.get("error").is_some() {
                    "404 Not Found"
                } else {
                    "200 OK"
                };
                let encoded = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    encoded.len(),
                    encoded
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-fallback-{}.ndjson",
            std::process::id()
        ));
        let graph_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-fallback-graph-{}.ndjson",
            std::process::id()
        ));
        let census_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-fallback-census-{}.ndjson",
            std::process::id()
        ));
        let body = concat!(
            "{\"ecosystem\":\"pypi\",\"package\":\"requests\",\"priority_tier\":\"medium\",",
            "\"direct_popularity\":10.0,\"propagated_impact\":100.0,\"hidden_leverage\":1.0}\n",
            "{\"ecosystem\":\"pypi\",\"package\":\"numpy\",\"priority_tier\":\"high\",",
            "\"direct_popularity\":20.0,\"propagated_impact\":400.0,\"hidden_leverage\":2.0}\n"
        );
        tokio::fs::write(&path, body).await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: path.clone(),
            graph_file: graph_path.clone(),
            graph_store_file: None,
            census_file: census_path.clone(),
            online_fallback: true,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: format!("http://{addr}/v3"),
            deps_dev_v3alpha_base: format!("http://{addr}/v3alpha"),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let snapshot = resolver.resolve_for_event(Ecosystem::Pypi, "litellm").await;
        assert_eq!(snapshot.source, PrioritySource::DepsDevDependentsApi);
        assert_eq!(snapshot.tier, PriorityTier::High);
        assert_eq!(snapshot.direct_popularity, Some(25.0));
        assert_eq!(snapshot.propagated_impact, Some(500.0));

        server.await.unwrap();
        let _ = tokio::fs::remove_file(path).await;
        let _ = tokio::fs::remove_file(graph_path).await;
        let _ = tokio::fs::remove_file(census_path).await;
    }

    #[tokio::test]
    async fn resolver_uses_local_graph_before_network_fallback() {
        let score_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-local-score-{}.ndjson",
            std::process::id()
        ));
        let graph_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-local-graph-{}.ndjson",
            std::process::id()
        ));
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(
            &graph_path,
            concat!(
                "{\"type\":\"package\",\"ecosystem\":\"pypi\",\"package\":\"litellm\",\"direct_popularity\":5}\n",
                "{\"type\":\"dependency\",\"ecosystem\":\"pypi\",\"package\":\"open-webui\",\"dependency\":\"litellm\",\"weight\":1.0}\n",
                "{\"type\":\"dependency\",\"ecosystem\":\"pypi\",\"package\":\"aider-chat\",\"dependency\":\"litellm\",\"weight\":1.0}\n"
            ),
        )
        .await
        .unwrap();

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path.clone(),
            graph_file: graph_path.clone(),
            graph_store_file: None,
            census_file: score_path.with_extension("census.ndjson"),
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let snapshot = resolver.resolve_for_event(Ecosystem::Pypi, "litellm").await;
        assert_eq!(snapshot.source, PrioritySource::LocalGraph);
        assert_eq!(snapshot.direct_popularity, Some(5.0));
        assert_eq!(snapshot.propagated_impact, Some(5.0));
        assert!(matches!(
            snapshot.tier,
            PriorityTier::Medium | PriorityTier::Low | PriorityTier::High
        ));

        let _ = tokio::fs::remove_file(score_path).await;
        let _ = tokio::fs::remove_file(graph_path).await;
    }

    #[tokio::test]
    async fn resolver_uses_graph_store_before_network_fallback() {
        let temp = tempdir().unwrap();
        let score_path = temp.path().join("priority-scores.ndjson");
        let graph_path = temp.path().join("graph-input.ndjson");
        let census_path = temp.path().join("package-census.ndjson");
        let store_path = temp.path().join("index.sqlite");
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let store = OperationalStore::open(store_path.clone()).await.unwrap();
        store
            .record_graph_records(&[
                scoring::ScoreInputRecord::Package {
                    ecosystem: Ecosystem::Pypi,
                    package: "litellm".to_string(),
                    direct_popularity: 7.0,
                },
                scoring::ScoreInputRecord::Dependency {
                    ecosystem: Ecosystem::Pypi,
                    package: "open-webui".to_string(),
                    dependency: "litellm".to_string(),
                    weight: 1.0,
                    sources: vec!["capture_metadata".to_string()],
                    confidence: Some(1.0),
                },
                scoring::ScoreInputRecord::Dependency {
                    ecosystem: Ecosystem::Pypi,
                    package: "aider-chat".to_string(),
                    dependency: "litellm".to_string(),
                    weight: 1.0,
                    sources: vec!["capture_metadata".to_string()],
                    confidence: Some(1.0),
                },
            ])
            .await
            .unwrap();

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path,
            graph_file: graph_path,
            graph_store_file: Some(store_path),
            census_file: census_path,
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let snapshot = resolver.resolve_for_event(Ecosystem::Pypi, "litellm").await;
        assert_eq!(snapshot.source, PrioritySource::LocalGraph);
        assert_eq!(snapshot.direct_popularity, Some(7.0));
        assert_eq!(snapshot.propagated_impact, Some(7.0));

        let evidence = resolver
            .emitted_graph_evidence(Ecosystem::Pypi, "litellm")
            .await;
        assert!(evidence.known_in_local_graph);
        assert_eq!(evidence.direct_dependencies_seen, 0);
        assert_eq!(evidence.reverse_dependents_seen, 2);

        let inspection = resolver
            .inspect_local_graph(Ecosystem::Pypi, "litellm", 10)
            .await
            .unwrap();
        assert!(inspection.known_in_local_graph);
        assert_eq!(inspection.direct_popularity, 7.0);
        assert_eq!(inspection.reverse_dependents_seen, 2);
        assert_eq!(
            inspection.reverse_dependents,
            vec!["aider-chat".to_string(), "open-webui".to_string()]
        );
    }

    #[tokio::test]
    async fn hydrates_local_graph_scores_from_store() {
        let temp = tempdir().unwrap();
        let score_path = temp.path().join("priority-scores.ndjson");
        let graph_path = temp.path().join("graph-input.ndjson");
        let census_path = temp.path().join("package-census.ndjson");
        let store_path = temp.path().join("index.sqlite");
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let store = OperationalStore::open(store_path.clone()).await.unwrap();
        store
            .record_graph_records(&[
                scoring::ScoreInputRecord::Package {
                    ecosystem: Ecosystem::Pypi,
                    package: "litellm".to_string(),
                    direct_popularity: 7.0,
                },
                scoring::ScoreInputRecord::Dependency {
                    ecosystem: Ecosystem::Pypi,
                    package: "open-webui".to_string(),
                    dependency: "litellm".to_string(),
                    weight: 1.0,
                    sources: vec!["capture_metadata".to_string()],
                    confidence: Some(1.0),
                },
            ])
            .await
            .unwrap();

        let config = PriorityConfig {
            score_file: score_path.clone(),
            graph_file: graph_path,
            graph_store_file: Some(store_path),
            census_file: census_path,
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        };

        let summary = hydrate_local_graph_scores(&config, &[Ecosystem::Pypi], 32, 64)
            .await
            .unwrap();
        assert_eq!(summary.graph_packages, 2);
        assert_eq!(summary.existing_scores, 0);
        assert_eq!(summary.missing_graph_packages, 2);
        assert!(summary.hydrated_scores >= 2);

        let score_body = tokio::fs::read_to_string(&score_path).await.unwrap();
        assert!(score_body.trim().is_empty());

        let stored_scores = store.load_priority_score_records().await.unwrap();
        assert!(
            stored_scores
                .iter()
                .any(|record| record.package == "litellm")
        );
        assert!(
            stored_scores
                .iter()
                .any(|record| record.priority_source == Some(PrioritySource::LocalGraph))
        );
    }

    #[tokio::test]
    async fn resolver_creates_known_package_stub_without_persisting_runtime_files() {
        let temp = tempdir().unwrap();
        let score_path = temp.path().join("priority-scores.ndjson");
        let graph_path = temp.path().join("graph-input.ndjson");
        let census_path = temp.path().join("package-census.ndjson");
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path.clone(),
            graph_file: graph_path.clone(),
            graph_store_file: None,
            census_file: census_path.clone(),
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let snapshot = resolver
            .resolve_for_event(Ecosystem::Npm, "@scope/new-package")
            .await;
        assert_eq!(snapshot.source, PrioritySource::KnownPackageStub);
        assert_eq!(snapshot.tier, PriorityTier::Medium);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let second = resolver
            .resolve_for_event(Ecosystem::Npm, "@scope/new-package")
            .await;
        assert_eq!(second.source, PrioritySource::KnownPackageStub);

        let emitted = resolver
            .emitted_graph_evidence(Ecosystem::Npm, "@scope/new-package")
            .await;
        assert!(emitted.known_in_census);

        let score_body = tokio::fs::read_to_string(&score_path).await.unwrap();
        assert!(score_body.trim().is_empty());

        let census_body = tokio::fs::read_to_string(&census_path).await.unwrap();
        assert!(census_body.trim().is_empty());
    }

    #[tokio::test]
    async fn captured_release_promotes_stub_to_local_graph_and_persists_score() {
        let score_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-promote-score-{}.ndjson",
            std::process::id()
        ));
        let graph_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-promote-graph-{}.ndjson",
            std::process::id()
        ));
        let census_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-promote-census-{}.ndjson",
            std::process::id()
        ));
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path.clone(),
            graph_file: graph_path.clone(),
            graph_store_file: None,
            census_file: census_path.clone(),
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let first = resolver
            .resolve_observed_release(Ecosystem::Npm, "pkg-a")
            .await;
        assert_eq!(first.source, PrioritySource::KnownPackageStub);

        let graph_records = vec![
            scoring::ScoreInputRecord::Package {
                ecosystem: Ecosystem::Npm,
                package: "pkg-a".to_string(),
                direct_popularity: 0.0,
            },
            scoring::ScoreInputRecord::Dependency {
                ecosystem: Ecosystem::Npm,
                package: "pkg-a".to_string(),
                dependency: "dep-b".to_string(),
                weight: 1.0,
                sources: vec!["capture_metadata".to_string()],
                confidence: Some(1.0),
            },
        ];
        scoring::write_score_input_records(&graph_path, &graph_records)
            .await
            .unwrap();

        resolver
            .record_captured_release(&crate::capture::CapturedRelease {
                event_id: "npm:pkg-a@1.0.0".to_string(),
                ecosystem: Ecosystem::Npm,
                package: "pkg-a".to_string(),
                version: "1.0.0".to_string(),
                observed_at: Utc::now(),
                published_at: None,
                captured_at: Utc::now(),
                status: crate::capture::ReleaseStatus::Active,
                package_url: None,
                release_url: None,
                metadata_url: None,
                raw_metadata_path: None,
                artifacts: Vec::new(),
                upstream_repository: None,
                details: serde_json::json!({
                    "dependencies": ["dep-b"]
                }),
            })
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let package_snapshot = resolver
            .resolve_observed_release(Ecosystem::Npm, "pkg-a")
            .await;
        assert_eq!(package_snapshot.source, PrioritySource::LocalGraph);

        let dependency_snapshot = resolver
            .resolve_observed_release(Ecosystem::Npm, "dep-b")
            .await;
        assert_eq!(dependency_snapshot.source, PrioritySource::LocalGraph);
        assert!(dependency_snapshot.propagated_impact.unwrap_or_default() > 1.0);

        let package_evidence = resolver
            .emitted_graph_evidence(Ecosystem::Npm, "pkg-a")
            .await;
        assert!(package_evidence.known_in_local_graph);
        assert_eq!(package_evidence.direct_dependencies_seen, 1);
        assert_eq!(package_evidence.reverse_dependents_seen, 0);

        let dependency_evidence = resolver
            .emitted_graph_evidence(Ecosystem::Npm, "dep-b")
            .await;
        assert!(dependency_evidence.known_in_local_graph);
        assert_eq!(dependency_evidence.direct_dependencies_seen, 0);
        assert_eq!(dependency_evidence.reverse_dependents_seen, 1);

        let score_body = tokio::fs::read_to_string(&score_path).await.unwrap();
        assert!(score_body.contains("\"priority_source\":\"local_graph\""));
        assert!(!score_body.contains("\"priority_source\":\"known_package_stub\""));

        let _ = tokio::fs::remove_file(score_path).await;
        let _ = tokio::fs::remove_file(graph_path).await;
        let _ = tokio::fs::remove_file(census_path).await;
    }

    #[tokio::test]
    async fn hydrated_metadata_drop_still_persists_graph_material() {
        let temp = tempdir().unwrap();
        let score_path = temp.path().join("priority-scores.ndjson");
        let graph_path = temp.path().join("graph-input.ndjson");
        let census_path = temp.path().join("package-census.ndjson");
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path.clone(),
            graph_file: graph_path.clone(),
            graph_store_file: None,
            census_file: census_path.clone(),
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let event = PackageReleaseEvent {
            event_id: "npm:pkg-drop@1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "pkg-drop".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot::known_package_stub()),
        };

        resolver
            .record_hydrated_release_metadata(
                &event,
                &crate::capture::CapturedRelease {
                    event_id: event.event_id.clone(),
                    ecosystem: Ecosystem::Npm,
                    package: "pkg-drop".to_string(),
                    version: "1.0.0".to_string(),
                    observed_at: Utc::now(),
                    published_at: None,
                    captured_at: Utc::now(),
                    status: crate::capture::ReleaseStatus::Active,
                    package_url: None,
                    release_url: None,
                    metadata_url: None,
                    raw_metadata_path: None,
                    artifacts: Vec::new(),
                    upstream_repository: None,
                    details: serde_json::json!({
                        "dependencies": ["dep-z"],
                        "repository": "https://github.com/example/pkg-drop",
                        "metadata_risk": {
                            "suspicious": false,
                            "score": 0,
                            "factors": [],
                            "reason": "clean"
                        }
                    }),
                },
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let package_evidence = resolver
            .emitted_graph_evidence(Ecosystem::Npm, "pkg-drop")
            .await;
        assert!(package_evidence.known_in_local_graph);
        assert_eq!(package_evidence.direct_dependencies_seen, 1);

        let dependency_evidence = resolver
            .emitted_graph_evidence(Ecosystem::Npm, "dep-z")
            .await;
        assert!(dependency_evidence.known_in_local_graph);
        assert_eq!(dependency_evidence.reverse_dependents_seen, 1);

        let graph_body = tokio::fs::read_to_string(&graph_path).await.unwrap();
        assert!(graph_body.contains("\"package\":\"pkg-drop\""));
        assert!(graph_body.contains("\"dependency\":\"dep-z\""));
    }

    #[tokio::test]
    async fn apply_inline_hydrates_observed_release_into_local_graph() {
        let temp = tempdir().unwrap();
        let score_path = temp.path().join("priority-scores.ndjson");
        let graph_path = temp.path().join("graph-input.ndjson");
        let census_path = temp.path().join("package-census.ndjson");
        let store_path = temp.path().join("index.sqlite");
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let metadata_url = serve_json_once(serde_json::json!({
            "info": {
                "requires_dist": ["dep-b>=1.0"],
                "home_page": "https://github.com/acme/demo",
                "project_urls": {
                    "Source": "https://github.com/acme/demo"
                }
            },
            "urls": [],
            "last_serial": 42
        }))
        .await;

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path.clone(),
            graph_file: graph_path.clone(),
            graph_store_file: Some(store_path.clone()),
            census_file: census_path.clone(),
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let event = PackageReleaseEvent {
            event_id: "pypi:demo@1.2.3".to_string(),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: "1.2.3".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: Some(metadata_url),
            priority: None,
        };

        let first = resolver.apply(event.clone()).await;
        assert_eq!(
            first.priority_snapshot().source,
            PrioritySource::KnownPackageStub
        );

        let resolved = resolver.apply(event).await;
        let snapshot = resolved.priority_snapshot();
        assert_eq!(snapshot.source, PrioritySource::LocalGraph);

        let inspection = resolver
            .inspect_local_graph(Ecosystem::Pypi, "demo", 10)
            .await
            .unwrap();
        assert!(inspection.known_in_local_graph);
        assert_eq!(inspection.direct_dependencies_seen, 1);
        assert_eq!(
            inspection
                .repository
                .as_ref()
                .map(|repository| repository.normalized_repository_url.as_str()),
            Some("https://github.com/acme/demo")
        );

        let store = OperationalStore::open(store_path).await.unwrap();
        let repository = store
            .load_package_repository_identity(Ecosystem::Pypi, "demo")
            .await
            .unwrap();
        assert!(repository.is_some());
    }

    #[tokio::test]
    async fn apply_inline_hydrate_supports_npm_event_time_local_graph() {
        let temp = tempdir().unwrap();
        let score_path = temp.path().join("priority-scores.ndjson");
        let graph_path = temp.path().join("graph-input.ndjson");
        let census_path = temp.path().join("package-census.ndjson");
        let store_path = temp.path().join("index.sqlite");
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let metadata_url = serve_json_once(serde_json::json!({
            "name": "demo",
            "version": "1.2.3",
            "repository": "https://github.com/acme/demo",
            "dependencies": {
                "dep-b": "^1.0.0"
            }
        }))
        .await;

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path,
            graph_file: graph_path,
            graph_store_file: Some(store_path.clone()),
            census_file: census_path,
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let event = PackageReleaseEvent {
            event_id: "npm:demo@1.2.3".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            version: "1.2.3".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: Some(metadata_url),
            priority: None,
        };

        let first = resolver.apply(event.clone()).await;
        assert_eq!(
            first.priority_snapshot().source,
            PrioritySource::KnownPackageStub
        );

        let resolved = resolver.apply(event).await;
        assert_eq!(
            resolved.priority_snapshot().source,
            PrioritySource::LocalGraph
        );

        let store = OperationalStore::open(store_path).await.unwrap();
        let inspection = store
            .load_graph_evidence(Ecosystem::Npm, "demo")
            .await
            .unwrap();
        assert!(inspection.is_some());
    }

    #[tokio::test]
    async fn apply_inline_hydrate_escalates_malware_shaped_npm_metadata() {
        let temp = tempdir().unwrap();
        let score_path = temp.path().join("priority-scores.ndjson");
        let graph_path = temp.path().join("graph-input.ndjson");
        let census_path = temp.path().join("package-census.ndjson");
        let store_path = temp.path().join("index.sqlite");
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let metadata_url = serve_json_once(serde_json::json!({
            "name": "undicy-http",
            "version": "2.0.0",
            "main": "index.js",
            "bin": "index.js",
            "pkg": {"targets": ["node20-win-x64"]},
            "dependencies": {
                "@primno/dpapi": "^2.0.1",
                "adm-zip": "^0.5.16",
                "archiver": "^7.0.1",
                "koffi": "^2.15.2",
                "rcedit": "^4.0.1",
                "screenshot-desktop": "^1.15.3",
                "sqlite3": "^5.1.7",
                "ws": "^8.18.2"
            }
        }))
        .await;

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path,
            graph_file: graph_path,
            graph_store_file: Some(store_path),
            census_file: census_path,
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let event = PackageReleaseEvent {
            event_id: "npm:undicy-http@2.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "undicy-http".to_string(),
            version: "2.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: Some(metadata_url),
            priority: None,
        };

        let first = resolver.apply(event.clone()).await;
        assert_eq!(
            first.priority_snapshot().source,
            PrioritySource::KnownPackageStub
        );

        let resolved = resolver.apply(event).await;
        let snapshot = resolved.priority_snapshot();
        assert_eq!(snapshot.source, PrioritySource::LocalGraph);
        assert_eq!(snapshot.tier, PriorityTier::High);
        assert!(snapshot.capture_requested());
        assert!(snapshot.diff_requested());
    }

    #[tokio::test]
    async fn resolver_uses_package_census_before_network_fallback() {
        let score_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-census-score-{}.ndjson",
            std::process::id()
        ));
        let graph_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-census-graph-{}.ndjson",
            std::process::id()
        ));
        let census_path = PathBuf::from(format!(
            "/tmp/supply-stream-priority-census-file-{}.ndjson",
            std::process::id()
        ));
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(&graph_path, "").await.unwrap();
        tokio::fs::write(
            &census_path,
            "{\"ecosystem\":\"pypi\",\"package\":\"litellm\",\"source\":\"test\"}\n",
        )
        .await
        .unwrap();

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path.clone(),
            graph_file: graph_path.clone(),
            graph_store_file: None,
            census_file: census_path.clone(),
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: std::time::Duration::from_secs(2),
            deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
            deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 1000,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 512,
                request_concurrency: 16,
                allow_external_fallback: true,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: Some("test_runtime_expand_v1".to_string()),
            },
        })
        .await
        .unwrap();

        let snapshot = resolver.resolve_for_event(Ecosystem::Pypi, "litellm").await;
        assert_eq!(snapshot.source, PrioritySource::PackageCensus);
        assert_eq!(snapshot.tier, PriorityTier::Medium);

        let _ = tokio::fs::remove_file(score_path).await;
        let _ = tokio::fs::remove_file(graph_path).await;
        let _ = tokio::fs::remove_file(census_path).await;
    }

    #[tokio::test]
    async fn emitted_graph_evidence_cache_keeps_observation_count_fresh() {
        let temp = tempdir().unwrap();
        let score_path = temp.path().join("priority-scores.ndjson");
        let graph_path = temp.path().join("graph-input.ndjson");
        let census_path = temp.path().join("package-census.ndjson");
        tokio::fs::write(&score_path, "").await.unwrap();
        tokio::fs::write(
            &graph_path,
            "{\"ecosystem\":\"npm\",\"package\":\"pkg-a\",\"direct_popularity\":1.0}\n",
        )
        .await
        .unwrap();
        tokio::fs::write(&census_path, "").await.unwrap();

        let resolver = PriorityResolver::load(&PriorityConfig {
            score_file: score_path.clone(),
            graph_file: graph_path.clone(),
            census_file: census_path.clone(),
            graph_store_file: None,
            online_fallback: false,
            online_expand_unknown: false,
            online_expand_min_observations: 2,
            online_request_timeout: Duration::from_secs(1),
            deps_dev_v3_base: "http://127.0.0.1".to_string(),
            deps_dev_v3alpha_base: "http://127.0.0.1".to_string(),
            expand_focus: crate::deps_dev::FocusDependentsConfig {
                reverse_depth: 1,
                max_frontier_packages: 64,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy:
                    crate::deps_dev::DirectPopularityStrategy::DirectDependentCount,
            },
            expand_collect: crate::collector::CollectConfig {
                max_depth: 1,
                max_packages: 64,
                request_concurrency: 4,
                allow_external_fallback: false,
            },
            expand_score_build: crate::scoring::ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 32,
                epsilon: 1e-6,
                high_quantile: 0.99,
                medium_quantile: 0.9,
                score_source_version: Some("test".to_string()),
            },
        })
        .await
        .unwrap();

        resolver
            .resolve_observed_release(Ecosystem::Npm, "pkg-a")
            .await;
        let first = resolver
            .emitted_graph_evidence(Ecosystem::Npm, "pkg-a")
            .await;
        assert_eq!(first.observed_count, 1);

        resolver
            .resolve_observed_release(Ecosystem::Npm, "pkg-a")
            .await;
        let second = resolver
            .emitted_graph_evidence(Ecosystem::Npm, "pkg-a")
            .await;
        assert_eq!(second.observed_count, 2);
        assert_eq!(second.known_in_local_graph, first.known_in_local_graph);
        assert_eq!(
            second.direct_dependencies_seen,
            first.direct_dependencies_seen
        );
    }

    #[test]
    fn ecosyste_ms_counts_snapshot_uses_repo_count_for_broader_impact() {
        let snapshot = priority_snapshot_from_ecosyste_ms_counts(116, Some(482), None);
        assert_eq!(snapshot.source, PrioritySource::EcosysteMsCountsApi);
        assert_eq!(snapshot.direct_popularity, Some(116.0));
        assert_eq!(snapshot.propagated_impact, Some(482.0));
        assert_eq!(snapshot.tier, PriorityTier::High);
        assert!(snapshot.hidden_leverage.unwrap_or_default() > 0.0);
    }

    #[test]
    fn fallback_count_snapshots_keep_tiny_unknowns_low() {
        let deps_dev = priority_snapshot_from_dependents_counts(2, 1, None);
        assert_eq!(deps_dev.source, PrioritySource::DepsDevDependentsApi);
        assert_eq!(deps_dev.tier, PriorityTier::Low);

        let ecosyste_ms = priority_snapshot_from_ecosyste_ms_counts(2, Some(3), None);
        assert_eq!(ecosyste_ms.source, PrioritySource::EcosysteMsCountsApi);
        assert_eq!(ecosyste_ms.tier, PriorityTier::Low);
    }

    #[test]
    fn merge_package_census_records_prefers_native_sources() {
        let merged = merge_package_census_records(&[
            PackageCensusRecord {
                ecosystem: Ecosystem::Npm,
                package: "@scope/pkg".to_string(),
                discovered_at: None,
                source: Some("graph_input".to_string()),
            },
            PackageCensusRecord {
                ecosystem: Ecosystem::Npm,
                package: "@scope/pkg".to_string(),
                discovered_at: None,
                source: Some("npm_all_docs".to_string()),
            },
            PackageCensusRecord {
                ecosystem: Ecosystem::Npm,
                package: "@scope/pkg".to_string(),
                discovered_at: Some(Utc::now()),
                source: Some("known_package_stub".to_string()),
            },
        ]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].package, "@scope/pkg");
        assert_eq!(merged[0].source.as_deref(), Some("npm_all_docs"));
    }

    async fn serve_json_once(body: Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = serde_json::to_string(&body).unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        format!("http://{addr}/metadata.json")
    }
}
