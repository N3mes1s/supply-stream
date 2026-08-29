use std::{net::SocketAddr, path::PathBuf, time::Duration};

use crate::{
    collector::CollectConfig, deps_dev::FocusDependentsConfig, event::Ecosystem,
    scoring::ScoreBuildConfig,
};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub ecosystems: Vec<Ecosystem>,
    pub state_dir: PathBuf,
    pub data_dir: PathBuf,
    pub health: HealthConfig,
    pub priority: PriorityConfig,
    pub priority_view: PriorityViewConfig,
    pub channel_capacity: usize,
    pub runtime_stats_interval: Option<Duration>,
    pub triage: TriageConfig,
    pub capture: CaptureConfig,
    pub autodiff: AutoDiffConfig,
    pub once: bool,
    pub npm: NpmConfig,
    pub pypi: PypiConfig,
    pub crates_io: CratesConfig,
}

#[derive(Debug, Clone)]
pub struct HealthConfig {
    pub bind: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct PriorityConfig {
    pub score_file: PathBuf,
    pub graph_file: PathBuf,
    pub census_file: PathBuf,
    pub graph_store_file: Option<PathBuf>,
    pub online_fallback: bool,
    pub online_expand_unknown: bool,
    pub online_expand_min_observations: usize,
    pub online_request_timeout: Duration,
    pub deps_dev_v3_base: String,
    pub deps_dev_v3alpha_base: String,
    pub expand_focus: FocusDependentsConfig,
    pub expand_collect: CollectConfig,
    pub expand_score_build: ScoreBuildConfig,
}

#[derive(Debug, Clone)]
pub struct PriorityViewConfig {
    pub interval: Option<Duration>,
    pub top_limit: usize,
    pub recent_capacity: usize,
}

#[derive(Debug, Clone)]
pub struct TriageConfig {
    pub queue_capacity: usize,
    pub worker_concurrency: usize,
    pub suspicious_small_artifact_max_bytes: u64,
    pub ephemeral_scan_max_artifact_bytes: u64,
    pub dropped_audit_interval: Option<Duration>,
    pub dropped_audit_window: Duration,
    pub dropped_audit_sample_size: usize,
    pub dropped_backfill_batch_size: usize,
    pub dropped_history_size: usize,
}

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub queue_capacity: usize,
    pub worker_concurrency: usize,
    pub data_dir: PathBuf,
    pub observed_event_log_path: PathBuf,
    pub capture_dir: PathBuf,
    pub staging_dir: PathBuf,
    pub staging_cache_ttl: Duration,
    pub staging_cache_max_bytes: u64,
    pub staging_cache_sweep_interval: Duration,
    pub graph_file: PathBuf,
    pub pypi_provenance: bool,
    pub github_api_base: String,
    pub gitlab_api_base: String,
}

#[derive(Debug, Clone)]
pub struct AutoDiffConfig {
    pub queue_capacity: usize,
    pub worker_concurrency: usize,
    pub data_dir: PathBuf,
    pub include_patches: bool,
    pub patch_context: usize,
    pub write_markdown: bool,
    pub backfill_lineage: bool,
}

#[derive(Debug, Clone)]
pub struct NpmConfig {
    pub batch_size: u32,
    pub packument_concurrency: usize,
    pub recent_publish_window: Duration,
    pub idle_delay: Duration,
    pub recent_key_capacity: usize,
    pub resilience: SourceResilienceConfig,
}

#[derive(Debug, Clone)]
pub struct PypiConfig {
    pub poll_interval: Duration,
    pub recent_key_capacity: usize,
    pub resilience: SourceResilienceConfig,
}

#[derive(Debug, Clone)]
pub struct CratesConfig {
    pub poll_interval: Duration,
    pub recent_key_capacity: usize,
    pub resilience: SourceResilienceConfig,
}

#[derive(Debug, Clone)]
pub struct SourceResilienceConfig {
    pub min_request_interval: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
}
