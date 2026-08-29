use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::{ArgAction, Args, Parser, Subcommand};
use supply_stream_core::{
    config::{
        AppConfig, AutoDiffConfig, CaptureConfig, CratesConfig, NpmConfig, PriorityConfig,
        PriorityViewConfig, PypiConfig, TriageConfig,
    },
    diff::DEFAULT_PATCH_CONTEXT,
    event::Ecosystem,
    ledger, store,
};

const DEFAULT_DIFF_QUEUE_CAPACITY: usize = 512;
const DEFAULT_RUNTIME_STATS_INTERVAL_SECS: u64 = 60;
const DEFAULT_PRIORITY_VIEW_INTERVAL_SECS: u64 = 0;
const DEFAULT_PRIORITY_REQUEST_CONCURRENCY: usize = 16;

#[derive(Debug, Clone, Parser)]
#[command(
    author,
    version,
    about = "Near-real-time package release stream fan-in service"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub run: RunArgs,
    #[arg(long, default_value = "info", global = true)]
    pub log_filter: String,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    History(HistoryArgs),
    Priority(PriorityArgs),
}

#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "npm,pypi,crates-io"
    )]
    pub ecosystems: Vec<Ecosystem>,
    #[arg(long, default_value = ".supply-stream-state")]
    pub state_dir: PathBuf,
    #[arg(long, default_value = ".supply-stream-data")]
    pub data_dir: PathBuf,
    #[arg(long)]
    pub health_bind: Option<SocketAddr>,
    #[arg(long)]
    pub priority_file: Option<PathBuf>,
    #[arg(long)]
    pub priority_graph_file: Option<PathBuf>,
    #[arg(long)]
    pub priority_census_file: Option<PathBuf>,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub priority_online_fallback: bool,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub priority_online_expand_unknown: bool,
    #[arg(long, default_value_t = 2)]
    pub priority_online_expand_min_observations: usize,
    #[arg(long, default_value_t = 3)]
    pub priority_online_timeout_secs: u64,
    #[arg(long, default_value_t = 2)]
    pub priority_expand_reverse_depth: usize,
    #[arg(long, default_value_t = 1)]
    pub priority_expand_forward_depth: usize,
    #[arg(long, default_value_t = 1000)]
    pub priority_expand_max_frontier_packages: usize,
    #[arg(long, default_value_t = 512)]
    pub priority_expand_max_packages: usize,
    #[arg(long, default_value_t = DEFAULT_PRIORITY_REQUEST_CONCURRENCY)]
    pub priority_expand_request_concurrency: usize,
    #[arg(long, default_value_t = 1024)]
    pub channel_capacity: usize,
    #[arg(long, default_value_t = DEFAULT_RUNTIME_STATS_INTERVAL_SECS)]
    pub runtime_stats_interval_secs: u64,
    #[arg(long, default_value_t = DEFAULT_PRIORITY_VIEW_INTERVAL_SECS)]
    pub priority_view_interval_secs: u64,
    #[arg(long, default_value_t = 10)]
    pub priority_view_limit: usize,
    #[arg(long, default_value_t = 1000)]
    pub priority_view_recent_capacity: usize,
    #[arg(long, default_value_t = 2048)]
    pub triage_queue_capacity: usize,
    #[arg(long, default_value_t = 8)]
    pub triage_workers: usize,
    #[arg(long, default_value_t = 32768u64)]
    pub triage_suspicious_small_artifact_max_bytes: u64,
    #[arg(long, default_value_t = 67108864u64)]
    pub triage_ephemeral_scan_max_artifact_bytes: u64,
    #[arg(long, default_value_t = 300)]
    pub triage_dropped_audit_interval_secs: u64,
    #[arg(long, default_value_t = 24)]
    pub triage_dropped_audit_window_hours: u64,
    #[arg(long, default_value_t = 3)]
    pub triage_dropped_audit_sample_size: usize,
    #[arg(long, default_value_t = 6)]
    pub triage_dropped_backfill_batch_size: usize,
    #[arg(long, default_value_t = 5000)]
    pub triage_dropped_history_size: usize,
    #[arg(long, default_value_t = 1024)]
    pub capture_queue_capacity: usize,
    #[arg(long, default_value_t = 2)]
    pub capture_workers: usize,
    #[arg(long, default_value_t = 21600)]
    pub artifact_cache_ttl_secs: u64,
    #[arg(long, default_value_t = 21474836480u64)]
    pub artifact_cache_max_bytes: u64,
    #[arg(long, default_value_t = 300)]
    pub artifact_cache_sweep_interval_secs: u64,
    #[arg(long, default_value_t = DEFAULT_DIFF_QUEUE_CAPACITY)]
    pub diff_queue_capacity: usize,
    #[arg(long, default_value_t = 1)]
    pub diff_workers: usize,
    #[arg(long, default_value_t = false, action = ArgAction::Set)]
    pub diff_include_patches: bool,
    #[arg(long, default_value_t = DEFAULT_PATCH_CONTEXT)]
    pub diff_patch_context: usize,
    #[arg(long, default_value_t = false, action = ArgAction::Set)]
    pub diff_write_markdown: bool,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub diff_backfill_lineage: bool,
    #[arg(long, default_value_t = 30)]
    pub poll_interval_secs: u64,
    #[arg(long, default_value_t = 200)]
    pub source_min_request_interval_ms: u64,
    #[arg(long, default_value_t = 1)]
    pub source_backoff_initial_secs: u64,
    #[arg(long, default_value_t = 60)]
    pub source_backoff_max_secs: u64,
    #[arg(long, default_value_t = 5000)]
    pub recent_key_capacity: usize,
    #[arg(long, default_value_t = 250)]
    pub npm_batch_size: u32,
    #[arg(long, default_value_t = 6)]
    pub npm_packument_concurrency: usize,
    #[arg(long, default_value_t = 900)]
    pub npm_recent_publish_window_secs: u64,
    #[arg(long, default_value_t = 5)]
    pub npm_idle_delay_secs: u64,
    #[arg(long, default_value_t = true)]
    pub capture_pypi_provenance: bool,
    #[arg(long)]
    pub once: bool,
}

impl RunArgs {
    pub fn into_config(self) -> AppConfig {
        let score_file = self
            .priority_file
            .unwrap_or_else(|| self.data_dir.join("priority-scores.ndjson"));
        let graph_file = self
            .priority_graph_file
            .unwrap_or_else(|| self.data_dir.join("graph-input.ndjson"));
        let census_file = self
            .priority_census_file
            .unwrap_or_else(|| self.data_dir.join("package-census.ndjson"));
        AppConfig {
            ecosystems: self.ecosystems,
            state_dir: self.state_dir,
            data_dir: self.data_dir.clone(),
            health: supply_stream_core::config::HealthConfig {
                bind: self.health_bind,
            },
            priority: PriorityConfig {
                score_file: score_file.clone(),
                graph_file: graph_file.clone(),
                census_file,
                graph_store_file: Some(store::index_db_path(&self.data_dir)),
                online_fallback: self.priority_online_fallback,
                online_expand_unknown: self.priority_online_expand_unknown,
                online_expand_min_observations: self.priority_online_expand_min_observations,
                online_request_timeout: Duration::from_secs(self.priority_online_timeout_secs),
                deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
                deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
                expand_focus: supply_stream_core::deps_dev::FocusDependentsConfig {
                    reverse_depth: self.priority_expand_reverse_depth,
                    max_frontier_packages: self.priority_expand_max_frontier_packages,
                    include_non_highest_dependent_releases: false,
                    default_direct_popularity: 1.0,
                    direct_popularity_strategy:
                        supply_stream_core::deps_dev::DirectPopularityStrategy::DirectDependentCount,
                },
                expand_collect: supply_stream_core::collector::CollectConfig {
                    max_depth: self.priority_expand_forward_depth,
                    max_packages: self.priority_expand_max_packages,
                    request_concurrency: self.priority_expand_request_concurrency,
                    allow_external_fallback: true,
                },
                expand_score_build: supply_stream_core::scoring::ScoreBuildConfig {
                    alpha: 0.85,
                    max_iterations: 64,
                    epsilon: 1e-6,
                    high_quantile: 0.99,
                    medium_quantile: 0.90,
                    score_source_version: Some("runtime_expand_v1".to_string()),
                },
            },
            priority_view: PriorityViewConfig {
                interval: (self.priority_view_interval_secs > 0)
                    .then(|| Duration::from_secs(self.priority_view_interval_secs)),
                top_limit: self.priority_view_limit,
                recent_capacity: self.priority_view_recent_capacity,
            },
            channel_capacity: self.channel_capacity,
            runtime_stats_interval: (self.runtime_stats_interval_secs > 0)
                .then(|| Duration::from_secs(self.runtime_stats_interval_secs)),
            triage: TriageConfig {
                queue_capacity: self.triage_queue_capacity,
                worker_concurrency: self.triage_workers,
                suspicious_small_artifact_max_bytes: self
                    .triage_suspicious_small_artifact_max_bytes,
                ephemeral_scan_max_artifact_bytes: self.triage_ephemeral_scan_max_artifact_bytes,
                dropped_audit_interval: (self.triage_dropped_audit_interval_secs > 0)
                    .then(|| Duration::from_secs(self.triage_dropped_audit_interval_secs)),
                dropped_audit_window: Duration::from_secs(
                    self.triage_dropped_audit_window_hours.saturating_mul(3600),
                ),
                dropped_audit_sample_size: self.triage_dropped_audit_sample_size,
                dropped_backfill_batch_size: self.triage_dropped_backfill_batch_size,
                dropped_history_size: self.triage_dropped_history_size,
            },
            capture: CaptureConfig {
                queue_capacity: self.capture_queue_capacity,
                worker_concurrency: self.capture_workers,
                data_dir: self.data_dir.clone(),
                observed_event_log_path: ledger::observed_ledger_path(&self.data_dir),
                capture_dir: self.data_dir.join("captures"),
                staging_dir: self.data_dir.join("staging-captures"),
                staging_cache_ttl: Duration::from_secs(self.artifact_cache_ttl_secs),
                staging_cache_max_bytes: self.artifact_cache_max_bytes,
                staging_cache_sweep_interval: Duration::from_secs(
                    self.artifact_cache_sweep_interval_secs,
                ),
                graph_file,
                pypi_provenance: self.capture_pypi_provenance,
                github_api_base: "https://api.github.com".to_string(),
                gitlab_api_base: "https://gitlab.com/api/v4".to_string(),
            },
            autodiff: AutoDiffConfig {
                queue_capacity: self.diff_queue_capacity,
                worker_concurrency: self.diff_workers,
                data_dir: self.data_dir.clone(),
                include_patches: self.diff_include_patches,
                patch_context: self.diff_patch_context,
                write_markdown: self.diff_write_markdown,
                backfill_lineage: self.diff_backfill_lineage,
            },
            once: self.once,
            npm: NpmConfig {
                batch_size: self.npm_batch_size,
                packument_concurrency: self.npm_packument_concurrency,
                recent_publish_window: Duration::from_secs(self.npm_recent_publish_window_secs),
                idle_delay: Duration::from_secs(self.npm_idle_delay_secs),
                recent_key_capacity: self.recent_key_capacity,
                resilience: supply_stream_core::config::SourceResilienceConfig {
                    min_request_interval: Duration::from_millis(
                        self.source_min_request_interval_ms,
                    ),
                    backoff_initial: Duration::from_secs(self.source_backoff_initial_secs),
                    backoff_max: Duration::from_secs(self.source_backoff_max_secs),
                },
            },
            pypi: PypiConfig {
                poll_interval: Duration::from_secs(self.poll_interval_secs),
                recent_key_capacity: self.recent_key_capacity,
                resilience: supply_stream_core::config::SourceResilienceConfig {
                    min_request_interval: Duration::from_millis(
                        self.source_min_request_interval_ms,
                    ),
                    backoff_initial: Duration::from_secs(self.source_backoff_initial_secs),
                    backoff_max: Duration::from_secs(self.source_backoff_max_secs),
                },
            },
            crates_io: CratesConfig {
                poll_interval: Duration::from_secs(self.poll_interval_secs),
                recent_key_capacity: self.recent_key_capacity,
                resilience: supply_stream_core::config::SourceResilienceConfig {
                    min_request_interval: Duration::from_millis(
                        self.source_min_request_interval_ms,
                    ),
                    backoff_initial: Duration::from_secs(self.source_backoff_initial_secs),
                    backoff_max: Duration::from_secs(self.source_backoff_max_secs),
                },
            },
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct HistoryArgs {
    #[arg(long, default_value = ".supply-stream-data")]
    pub data_dir: PathBuf,
    #[command(subcommand)]
    pub command: HistoryCommand,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DiffOutputFormat {
    Text,
    Markdown,
    Json,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DepsDevDirectPopularityMode {
    Constant,
    DirectDependentCount,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum PriorityScoreMetricArg {
    DirectPopularity,
    PropagatedImpact,
    HiddenLeverage,
}

#[derive(Debug, Clone, Subcommand)]
pub enum HistoryCommand {
    Sync {
        #[arg(long)]
        json: bool,
    },
    Stats {
        #[arg(long)]
        json: bool,
    },
    Report {
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long, default_value_t = 24)]
        since_hours: u64,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    Package {
        #[arg(value_enum)]
        ecosystem: Ecosystem,
        package: String,
        #[arg(long)]
        online: bool,
        #[arg(long)]
        json: bool,
    },
    Event {
        event_id: String,
        #[arg(long)]
        online: bool,
        #[arg(long)]
        json: bool,
    },
    Locate {
        #[arg(value_enum)]
        ecosystem: Ecosystem,
        package: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Provenance {
        #[arg(value_enum)]
        ecosystem: Ecosystem,
        package: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ProvenanceBackfill {
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        emit: bool,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    AssessmentBackfill {
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        emit: bool,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    RetryCaptures {
        #[arg(long, default_value_t = 8)]
        workers: usize,
        #[arg(long)]
        json: bool,
    },
    RetrySkippedCaptures {
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long, default_value_t = 72)]
        since_hours: u64,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, default_value_t = 8)]
        workers: usize,
        #[arg(long)]
        json: bool,
    },
    Bundle {
        event_id: String,
        #[arg(long)]
        write: bool,
        #[arg(long)]
        json: bool,
    },
    RepairBundles {
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long, default_value_t = 24)]
        since_hours: u64,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    Validate {
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        write_missing_bundles: bool,
        #[arg(long)]
        json: bool,
    },
    DetectionEval {
        #[arg(long, default_value = "fixtures/detection/corpus.json")]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Diff {
        #[arg(value_enum)]
        ecosystem: Ecosystem,
        package: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        baseline: Option<String>,
        #[arg(long)]
        artifact: Option<PathBuf>,
        #[arg(long)]
        baseline_artifact: Option<PathBuf>,
        #[arg(long)]
        patch: bool,
        #[arg(long, default_value_t = DEFAULT_PATCH_CONTEXT)]
        patch_context: usize,
        #[arg(long, value_enum)]
        format: Option<DiffOutputFormat>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        online: bool,
        #[arg(long)]
        #[arg(hide = true)]
        json: bool,
    },
    Recent {
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Args)]
pub struct PriorityArgs {
    #[command(subcommand)]
    pub command: PriorityCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum PriorityCommand {
    Expand {
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long)]
        package: Option<String>,
        #[arg(
            long,
            default_value = ".supply-stream-data/bootstrap/seed-packages.ndjson"
        )]
        seeds: PathBuf,
        #[arg(long)]
        deps_dev_input: Vec<PathBuf>,
        #[arg(long)]
        base_input: Vec<PathBuf>,
        #[arg(long)]
        popularity_file: Option<PathBuf>,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        skip_seed_collect: bool,
        #[arg(long, default_value = ".supply-stream-data/graph-input.ndjson")]
        graph_output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/index.sqlite")]
        graph_store_file: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/package-census.ndjson")]
        census_output: PathBuf,
        #[arg(long, default_value_t = 3)]
        depth: usize,
        #[arg(long, default_value_t = 2)]
        reverse_depth: usize,
        #[arg(long, default_value_t = 1000)]
        max_frontier_packages: usize,
        #[arg(long, default_value_t = 50_000)]
        max_packages: usize,
        #[arg(long, default_value_t = DEFAULT_PRIORITY_REQUEST_CONCURRENCY)]
        request_concurrency: usize,
        #[arg(long, default_value_t = 2000)]
        bigquery_baseline_package_limit: usize,
        #[arg(long, default_value_t = 0)]
        bigquery_census_package_limit: usize,
        #[arg(long, default_value_t = 0)]
        bigquery_baseline_package_offset: usize,
        #[arg(long, default_value_t = 50000)]
        bigquery_baseline_edge_limit: usize,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        bigquery_baseline_via_collector: bool,
        #[arg(long)]
        target_scored_packages: Option<usize>,
        #[arg(long, default_value_t = 1.0)]
        deps_dev_default_direct_popularity: f64,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        deps_dev_include_indirect: bool,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        deps_dev_include_non_highest_dependent_releases: bool,
        #[arg(long, value_enum, default_value = "direct-dependent-count")]
        deps_dev_direct_popularity_mode: DepsDevDirectPopularityMode,
        #[arg(long, default_value_t = 0.85)]
        alpha: f64,
        #[arg(long, default_value_t = 64)]
        max_iterations: usize,
        #[arg(long, default_value_t = 1e-6)]
        epsilon: f64,
        #[arg(long, default_value_t = 0.99)]
        high_quantile: f64,
        #[arg(long, default_value_t = 0.90)]
        medium_quantile: f64,
        #[arg(long)]
        score_source_version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Focus {
        #[arg(value_enum)]
        ecosystem: Ecosystem,
        package: String,
        #[arg(long)]
        deps_dev_input: Vec<PathBuf>,
        #[arg(long)]
        base_input: Vec<PathBuf>,
        #[arg(long)]
        popularity_file: Option<PathBuf>,
        #[arg(long, default_value = ".supply-stream-data/focus-graph.ndjson")]
        graph_output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/index.sqlite")]
        graph_store_file: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/focus-scores.ndjson")]
        output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/focus-census.ndjson")]
        census_output: PathBuf,
        #[arg(long, default_value_t = 2)]
        reverse_depth: usize,
        #[arg(long, default_value_t = 1000)]
        max_frontier_packages: usize,
        #[arg(long, default_value_t = 2)]
        forward_depth: usize,
        #[arg(long, default_value_t = 5000)]
        max_packages: usize,
        #[arg(long, default_value_t = DEFAULT_PRIORITY_REQUEST_CONCURRENCY)]
        request_concurrency: usize,
        #[arg(long, default_value_t = 1.0)]
        deps_dev_default_direct_popularity: f64,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        deps_dev_include_non_highest_dependent_releases: bool,
        #[arg(long, value_enum, default_value = "direct-dependent-count")]
        deps_dev_direct_popularity_mode: DepsDevDirectPopularityMode,
        #[arg(long, default_value_t = 0.85)]
        alpha: f64,
        #[arg(long, default_value_t = 64)]
        max_iterations: usize,
        #[arg(long, default_value_t = 1e-6)]
        epsilon: f64,
        #[arg(long, default_value_t = 0.99)]
        high_quantile: f64,
        #[arg(long, default_value_t = 0.90)]
        medium_quantile: f64,
        #[arg(long)]
        score_source_version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Bootstrap {
        #[arg(
            long,
            default_value = ".supply-stream-data/bootstrap/seed-packages.ndjson"
        )]
        seeds: PathBuf,
        #[arg(long)]
        popularity_file: Option<PathBuf>,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        skip_seed_collect: bool,
        #[arg(long)]
        deps_dev_input: Vec<PathBuf>,
        #[arg(long, default_value = ".supply-stream-data/graph-input.ndjson")]
        graph_output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/index.sqlite")]
        graph_store_file: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/package-census.ndjson")]
        census_output: PathBuf,
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        #[arg(long, default_value_t = 50_000)]
        max_packages: usize,
        #[arg(long, default_value_t = DEFAULT_PRIORITY_REQUEST_CONCURRENCY)]
        request_concurrency: usize,
        #[arg(long, default_value_t = 2000)]
        bigquery_baseline_package_limit: usize,
        #[arg(long, default_value_t = 0)]
        bigquery_census_package_limit: usize,
        #[arg(long, default_value_t = 0)]
        bigquery_baseline_package_offset: usize,
        #[arg(long, default_value_t = 50000)]
        bigquery_baseline_edge_limit: usize,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        bigquery_baseline_via_collector: bool,
        #[arg(long)]
        target_scored_packages: Option<usize>,
        #[arg(long, default_value_t = 1.0)]
        deps_dev_default_direct_popularity: f64,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        deps_dev_include_indirect: bool,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        deps_dev_include_non_highest_dependent_releases: bool,
        #[arg(long, value_enum, default_value = "direct-dependent-count")]
        deps_dev_direct_popularity_mode: DepsDevDirectPopularityMode,
        #[arg(long, default_value_t = 0.85)]
        alpha: f64,
        #[arg(long, default_value_t = 64)]
        max_iterations: usize,
        #[arg(long, default_value_t = 1e-6)]
        epsilon: f64,
        #[arg(long, default_value_t = 0.99)]
        high_quantile: f64,
        #[arg(long, default_value_t = 0.90)]
        medium_quantile: f64,
        #[arg(long)]
        score_source_version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    MergeGraph {
        #[arg(long, required = true)]
        input: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ImportDepsDev {
        #[arg(long, required = true)]
        input: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 1.0)]
        default_direct_popularity: f64,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        include_indirect: bool,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        include_non_highest_dependent_releases: bool,
        #[arg(long, value_enum, default_value = "direct-dependent-count")]
        direct_popularity_mode: DepsDevDirectPopularityMode,
        #[arg(long)]
        json: bool,
    },
    Collect {
        #[arg(long)]
        seeds: PathBuf,
        #[arg(long)]
        popularity_file: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        #[arg(long, default_value_t = 50_000)]
        max_packages: usize,
        #[arg(long, default_value_t = DEFAULT_PRIORITY_REQUEST_CONCURRENCY)]
        request_concurrency: usize,
        #[arg(long)]
        json: bool,
    },
    Build {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        output: PathBuf,
        #[arg(long, default_value_t = 0.85)]
        alpha: f64,
        #[arg(long, default_value_t = 64)]
        max_iterations: usize,
        #[arg(long, default_value_t = 1e-6)]
        epsilon: f64,
        #[arg(long, default_value_t = 0.99)]
        high_quantile: f64,
        #[arg(long, default_value_t = 0.90)]
        medium_quantile: f64,
        #[arg(long)]
        score_source_version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Census {
        #[arg(
            long,
            value_enum,
            value_delimiter = ',',
            default_value = "npm,pypi,crates-io"
        )]
        ecosystems: Vec<Ecosystem>,
        #[arg(long, default_value = ".supply-stream-data/package-census.ndjson")]
        output: PathBuf,
        #[arg(long)]
        base_input: Vec<PathBuf>,
        #[arg(long, default_value_t = 5000)]
        npm_page_size: usize,
        #[arg(long)]
        npm_start_key: Option<String>,
        #[arg(long, default_value_t = 10000)]
        npm_limit: usize,
        #[arg(long, default_value_t = 100000)]
        pypi_limit: usize,
        #[arg(long, default_value_t = 100)]
        crates_page_size: usize,
        #[arg(long, default_value_t = 1)]
        crates_start_page: usize,
        #[arg(long, default_value_t = 10000)]
        crates_limit: usize,
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        #[arg(long)]
        json: bool,
    },
    Broaden {
        #[arg(
            long,
            value_enum,
            value_delimiter = ',',
            default_value = "npm,pypi,crates-io"
        )]
        ecosystems: Vec<Ecosystem>,
        #[arg(long, default_value = ".supply-stream-data/package-census.ndjson")]
        census_file: PathBuf,
        #[arg(long)]
        base_input: Vec<PathBuf>,
        #[arg(long, default_value = ".supply-stream-data/graph-input.ndjson")]
        graph_output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/index.sqlite")]
        graph_store_file: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = ".supply-stream-data/broaden-progress.json")]
        progress_file: PathBuf,
        #[arg(long, default_value_t = 500)]
        batch_size: usize,
        #[arg(long, default_value_t = 6)]
        recent_stub_hours: u64,
        #[arg(long, default_value_t = 1000)]
        recent_stub_limit: usize,
        #[arg(long, default_value_t = 1)]
        iterations: usize,
        #[arg(long)]
        cursor: Option<usize>,
        #[arg(long, default_value_t = 0)]
        max_depth: usize,
        #[arg(long, default_value_t = 5000)]
        max_packages: usize,
        #[arg(long, default_value_t = DEFAULT_PRIORITY_REQUEST_CONCURRENCY)]
        request_concurrency: usize,
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        rebuild_scores: bool,
        #[arg(long, default_value_t = 0.85)]
        alpha: f64,
        #[arg(long, default_value_t = 64)]
        max_iterations: usize,
        #[arg(long, default_value_t = 1e-6)]
        epsilon: f64,
        #[arg(long, default_value_t = 0.99)]
        high_quantile: f64,
        #[arg(long, default_value_t = 0.90)]
        medium_quantile: f64,
        #[arg(long)]
        score_source_version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Score {
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        input: PathBuf,
        #[arg(value_enum)]
        ecosystem: Ecosystem,
        package: String,
        #[arg(long)]
        json: bool,
    },
    Resolve {
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        input: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/graph-input.ndjson")]
        graph_file: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/package-census.ndjson")]
        census_file: PathBuf,
        #[arg(long)]
        graph_store_file: Option<PathBuf>,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        online_fallback: bool,
        #[arg(long, default_value_t = 3)]
        online_timeout_secs: u64,
        #[arg(value_enum)]
        ecosystem: Ecosystem,
        package: String,
        #[arg(long)]
        json: bool,
    },
    Graph {
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        input: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/graph-input.ndjson")]
        graph_file: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/package-census.ndjson")]
        census_file: PathBuf,
        #[arg(long)]
        graph_store_file: Option<PathBuf>,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(value_enum)]
        ecosystem: Ecosystem,
        package: String,
        #[arg(long)]
        json: bool,
    },
    RepoBackfill {
        #[arg(long, default_value = ".supply-stream-data/graph-input.ndjson")]
        graph_file: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/index.sqlite")]
        graph_store_file: PathBuf,
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, default_value_t = DEFAULT_PRIORITY_REQUEST_CONCURRENCY)]
        request_concurrency: usize,
        #[arg(long)]
        json: bool,
    },
    GraphBackfill {
        #[arg(long, default_value = ".supply-stream-data")]
        data_dir: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/graph-input.ndjson")]
        graph_output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/index.sqlite")]
        graph_store_file: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        output: PathBuf,
        #[arg(long, default_value = ".supply-stream-data/package-census.ndjson")]
        census_output: PathBuf,
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, default_value_t = 0.85)]
        alpha: f64,
        #[arg(long, default_value_t = 64)]
        max_iterations: usize,
        #[arg(long, default_value_t = 1e-6)]
        epsilon: f64,
        #[arg(long, default_value_t = 0.99)]
        high_quantile: f64,
        #[arg(long, default_value_t = 0.90)]
        medium_quantile: f64,
        #[arg(long)]
        score_source_version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    ScoreStats {
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        input: PathBuf,
        #[arg(long, default_value_t = 10)]
        top_limit: usize,
        #[arg(long)]
        json: bool,
    },
    Top {
        #[arg(long, default_value = ".supply-stream-data/priority-scores.ndjson")]
        input: PathBuf,
        #[arg(long)]
        ecosystem: Option<Ecosystem>,
        #[arg(long, value_enum, default_value = "propagated-impact")]
        metric: PriorityScoreMetricArg,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}
