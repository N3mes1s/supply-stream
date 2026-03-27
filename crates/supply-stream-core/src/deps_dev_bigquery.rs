use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    collector::SeedPackageRecord,
    deps_dev::{DirectPopularityStrategy, FocusDependentsConfig, FocusDependentsSummary},
    event::Ecosystem,
    priority::normalize_package_name,
    scoring::ScoreInputRecord,
};

const BIGQUERY_BASE: &str = "https://bigquery.googleapis.com/bigquery/v2";
const OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DEPS_DEV_DATASET: &str = "bigquery-public-data.deps_dev_v1.DependenciesLatest";
const DEFAULT_LOCATION: &str = "US";
const DEFAULT_FRONTIER_QUERY_BATCH: usize = 200;
const DEFAULT_BASELINE_QUERY_BATCH: usize = 50;
const DEFAULT_BASELINE_PACKAGE_WINDOW: usize = 100;
const DEFAULT_TOP_PACKAGE_PAGE_SIZE: usize = 5_000;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 60;
const DEFAULT_BIGQUERY_TIMEOUT_MS: u64 = 120_000;

#[derive(Debug, Clone)]
pub struct LiveFocusConfig;

#[derive(Debug, Clone)]
pub struct LiveBaselineConfig {
    pub package_limit_per_ecosystem: usize,
    pub package_offset_per_ecosystem: usize,
    pub edge_limit_per_ecosystem: usize,
    pub default_direct_popularity: f64,
    pub direct_popularity_strategy: DirectPopularityStrategy,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LiveBaselineSummary {
    pub ecosystems: Vec<LiveBaselineEcosystemSummary>,
    pub emitted_package_records: usize,
    pub emitted_dependency_records: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LiveBaselineEcosystemSummary {
    pub ecosystem: Ecosystem,
    pub packages: usize,
    pub dependency_records: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LiveTopPackageSummary {
    pub ecosystems: Vec<LiveTopPackageEcosystemSummary>,
    pub emitted_seed_records: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LiveTopPackageEcosystemSummary {
    pub ecosystem: Ecosystem,
    pub packages: usize,
}

pub async fn import_dependencies_latest_live(
    ecosystems: &[Ecosystem],
    config: &LiveBaselineConfig,
) -> Result<(Vec<ScoreInputRecord>, LiveBaselineSummary)> {
    if config.package_limit_per_ecosystem == 0 {
        return Ok((
            Vec::new(),
            LiveBaselineSummary {
                ecosystems: Vec::new(),
                emitted_package_records: 0,
                emitted_dependency_records: 0,
            },
        ));
    }
    if config.default_direct_popularity < 0.0 {
        anyhow::bail!("default_direct_popularity must be >= 0.0");
    }

    let http = reqwest::Client::builder()
        .user_agent("supply-stream-priority/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .build()
        .context("failed to build deps.dev bigquery HTTP client")?;
    let auth = GoogleCloudAuth::discover()?;

    let mut package_keys = BTreeSet::<(Ecosystem, String)>::new();
    let mut edges = BTreeSet::<(Ecosystem, String, String)>::new();
    let mut ecosystem_summaries = Vec::new();

    for ecosystem in ecosystems {
        let mut ecosystem_packages = BTreeSet::<String>::new();
        let mut ecosystem_edges = 0usize;
        for window in baseline_package_windows(config) {
            let chunk_config = LiveBaselineConfig {
                package_limit_per_ecosystem: window.package_limit,
                package_offset_per_ecosystem: window.package_offset,
                edge_limit_per_ecosystem: window.edge_limit,
                default_direct_popularity: config.default_direct_popularity,
                direct_popularity_strategy: config.direct_popularity_strategy,
            };
            let rows = query_global_baseline_edges(&http, &auth, *ecosystem, &chunk_config).await?;
            for row in rows {
                let package = normalize_package_name(*ecosystem, &row.package_name);
                let dependency = normalize_package_name(*ecosystem, &row.dependency_name);
                if package == dependency {
                    continue;
                }
                package_keys.insert((*ecosystem, package.clone()));
                package_keys.insert((*ecosystem, dependency.clone()));
                ecosystem_packages.insert(package.clone());
                ecosystem_packages.insert(dependency.clone());
                if edges.insert((*ecosystem, package, dependency)) {
                    ecosystem_edges += 1;
                }
            }
            if config.edge_limit_per_ecosystem > 0
                && ecosystem_edges >= config.edge_limit_per_ecosystem
            {
                break;
            }
        }
        ecosystem_summaries.push(LiveBaselineEcosystemSummary {
            ecosystem: *ecosystem,
            packages: ecosystem_packages.len(),
            dependency_records: ecosystem_edges,
        });
    }

    let mut dependent_counts = BTreeMap::<(Ecosystem, String), usize>::new();
    for (ecosystem, _, dependency) in &edges {
        *dependent_counts
            .entry((*ecosystem, dependency.clone()))
            .or_default() += 1;
    }

    let mut records = Vec::with_capacity(package_keys.len() + edges.len());
    for (ecosystem, package) in &package_keys {
        let direct_popularity = match config.direct_popularity_strategy {
            DirectPopularityStrategy::Constant => config.default_direct_popularity,
            DirectPopularityStrategy::DirectDependentCount => (*dependent_counts
                .get(&(*ecosystem, package.clone()))
                .unwrap_or(&0)
                as f64)
                .max(config.default_direct_popularity),
        };
        records.push(ScoreInputRecord::Package {
            ecosystem: *ecosystem,
            package: package.clone(),
            direct_popularity,
        });
    }
    for (ecosystem, package, dependency) in &edges {
        records.push(ScoreInputRecord::Dependency {
            ecosystem: *ecosystem,
            package: package.clone(),
            dependency: dependency.clone(),
            weight: 1.0,
            sources: vec!["deps_dev_bigquery".to_string()],
            confidence: Some(0.8),
        });
    }

    Ok((
        records,
        LiveBaselineSummary {
            ecosystems: ecosystem_summaries,
            emitted_package_records: package_keys.len(),
            emitted_dependency_records: edges.len(),
        },
    ))
}

pub async fn import_top_package_seeds_live(
    ecosystems: &[Ecosystem],
    config: &LiveBaselineConfig,
) -> Result<(Vec<SeedPackageRecord>, LiveTopPackageSummary)> {
    if config.package_limit_per_ecosystem == 0 {
        return Ok((
            Vec::new(),
            LiveTopPackageSummary {
                ecosystems: Vec::new(),
                emitted_seed_records: 0,
            },
        ));
    }
    if config.default_direct_popularity < 0.0 {
        anyhow::bail!("default_direct_popularity must be >= 0.0");
    }

    let http = reqwest::Client::builder()
        .user_agent("supply-stream-priority/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .build()
        .context("failed to build deps.dev bigquery HTTP client")?;
    let auth = GoogleCloudAuth::discover()?;

    let mut seeds = Vec::new();
    let mut ecosystems_summary = Vec::new();
    for ecosystem in ecosystems {
        let mut rows = Vec::new();
        let mut seen = BTreeSet::new();
        for window in baseline_package_windows(config) {
            let window_rows = query_top_packages(
                &http,
                &auth,
                *ecosystem,
                window.package_limit,
                window.package_offset,
            )
            .await?;
            for row in window_rows {
                if seen.insert(row.package_name.clone()) {
                    rows.push(row);
                }
            }
        }
        ecosystems_summary.push(LiveTopPackageEcosystemSummary {
            ecosystem: *ecosystem,
            packages: rows.len(),
        });
        for row in rows {
            let direct_popularity = match config.direct_popularity_strategy {
                DirectPopularityStrategy::Constant => config.default_direct_popularity,
                DirectPopularityStrategy::DirectDependentCount => {
                    (row.dependent_count as f64).max(config.default_direct_popularity)
                }
            };
            seeds.push(SeedPackageRecord {
                ecosystem: *ecosystem,
                package: normalize_package_name(*ecosystem, &row.package_name),
                direct_popularity: Some(direct_popularity),
            });
        }
    }

    Ok((
        seeds.clone(),
        LiveTopPackageSummary {
            ecosystems: ecosystems_summary,
            emitted_seed_records: seeds.len(),
        },
    ))
}

pub async fn focus_dependents_subgraph_live(
    ecosystem: Ecosystem,
    package: &str,
    config: &FocusDependentsConfig,
    _live: &LiveFocusConfig,
) -> Result<(
    Vec<ScoreInputRecord>,
    Vec<SeedPackageRecord>,
    FocusDependentsSummary,
)> {
    let http = reqwest::Client::builder()
        .user_agent("supply-stream-priority/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .build()
        .context("failed to build deps.dev bigquery HTTP client")?;
    let auth = GoogleCloudAuth::discover()?;
    let target = normalize_package_name(ecosystem, package);
    focus_dependents_subgraph_live_with_auth(&http, &auth, ecosystem, &target, config).await
}

async fn focus_dependents_subgraph_live_with_auth(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    ecosystem: Ecosystem,
    package: &str,
    config: &FocusDependentsConfig,
) -> Result<(
    Vec<ScoreInputRecord>,
    Vec<SeedPackageRecord>,
    FocusDependentsSummary,
)> {
    if config.default_direct_popularity < 0.0 {
        anyhow::bail!("default_direct_popularity must be >= 0.0");
    }
    if config.max_frontier_packages == 0 {
        anyhow::bail!("max_frontier_packages must be greater than zero");
    }

    let target = normalize_package_name(ecosystem, package);
    let mut visited_packages = BTreeSet::from([target.clone()]);
    let mut reverse_edges = BTreeSet::<(String, String)>::new();
    let mut frontier = VecDeque::from([(target.clone(), 0usize)]);
    let mut summary = FocusDependentsSummary {
        input_files: 0,
        input_rows: 0,
        matched_rows: 0,
        reverse_depth: config.reverse_depth,
        frontier_packages: 1,
        frontier_truncated: false,
        emitted_package_records: 0,
        emitted_dependency_records: 0,
    };

    while let Some((_, depth)) = frontier.front() {
        if *depth >= config.reverse_depth {
            break;
        }
        let current_depth = *depth;
        let mut depth_frontier = Vec::new();
        while let Some((name, depth)) = frontier.front().cloned() {
            if depth != current_depth {
                break;
            }
            frontier.pop_front();
            depth_frontier.push(name);
        }

        for batch in depth_frontier.chunks(DEFAULT_FRONTIER_QUERY_BATCH) {
            let rows = query_dependents_batch(http, auth, ecosystem, batch).await?;
            summary.input_rows += batch.len();
            summary.matched_rows += rows.len();
            for row in rows {
                let dependency = normalize_package_name(ecosystem, &row.name);
                let dependent = normalize_package_name(ecosystem, &row.dependent_name);
                if dependency == dependent {
                    continue;
                }
                reverse_edges.insert((dependent.clone(), dependency.clone()));
                let was_new_package = visited_packages.insert(dependent.clone());
                if was_new_package && visited_packages.len() > config.max_frontier_packages {
                    visited_packages.remove(&dependent);
                    summary.frontier_truncated = true;
                    continue;
                }
                if was_new_package {
                    summary.frontier_packages = visited_packages.len();
                }
                if current_depth < config.reverse_depth && visited_packages.contains(&dependent) {
                    frontier.push_back((dependent.clone(), current_depth + 1));
                }
            }
            if summary.frontier_truncated {
                frontier.retain(|(name, _)| visited_packages.contains(name));
            }
        }
    }

    let mut dependent_counts = BTreeMap::<String, usize>::new();
    for (_, dependency) in &reverse_edges {
        *dependent_counts.entry(dependency.clone()).or_default() += 1;
    }

    let mut records = Vec::new();
    let mut seeds = Vec::new();
    for package in &visited_packages {
        let direct_popularity = match config.direct_popularity_strategy {
            DirectPopularityStrategy::Constant => config.default_direct_popularity,
            DirectPopularityStrategy::DirectDependentCount => {
                (*dependent_counts.get(package).unwrap_or(&0) as f64)
                    .max(config.default_direct_popularity)
            }
        };
        records.push(ScoreInputRecord::Package {
            ecosystem,
            package: package.clone(),
            direct_popularity,
        });
        seeds.push(SeedPackageRecord {
            ecosystem,
            package: package.clone(),
            direct_popularity: Some(direct_popularity),
        });
    }
    for (dependent, dependency) in &reverse_edges {
        records.push(ScoreInputRecord::Dependency {
            ecosystem,
            package: dependent.clone(),
            dependency: dependency.clone(),
            weight: 1.0,
            sources: vec!["deps_dev_bigquery".to_string()],
            confidence: Some(0.8),
        });
    }

    summary.emitted_package_records = visited_packages.len();
    summary.emitted_dependency_records = reverse_edges.len();
    Ok((records, seeds, summary))
}

async fn query_dependents_batch(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    ecosystem: Ecosystem,
    frontier: &[String],
) -> Result<Vec<DependentRow>> {
    if frontier.is_empty() {
        return Ok(Vec::new());
    }
    let query = build_dependents_query(ecosystem, frontier);
    let token = auth.access_token(http, false).await?;
    match execute_bigquery_query(http, auth, &token, &query).await {
        Ok(rows) => Ok(rows),
        Err(error) if is_unauthorized(&error) => {
            let token = auth.access_token(http, true).await?;
            execute_bigquery_query(http, auth, &token, &query).await
        }
        Err(error) => Err(error),
    }
}

async fn query_global_baseline_edges(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    ecosystem: Ecosystem,
    config: &LiveBaselineConfig,
) -> Result<Vec<DependencyEdgeRow>> {
    let frontier = query_top_packages(
        http,
        auth,
        ecosystem,
        config.package_limit_per_ecosystem,
        config.package_offset_per_ecosystem,
    )
    .await?
    .into_iter()
    .map(|row| row.package_name)
    .collect::<Vec<_>>();
    if frontier.is_empty() {
        return Ok(Vec::new());
    }

    let mut edges = Vec::new();
    let mut seen = BTreeSet::<(String, String)>::new();
    let frontier_batches = frontier
        .chunks(DEFAULT_BASELINE_QUERY_BATCH)
        .collect::<Vec<_>>();
    for (batch_index, batch) in frontier_batches.iter().enumerate() {
        let remaining = if config.edge_limit_per_ecosystem > 0 {
            config.edge_limit_per_ecosystem.saturating_sub(edges.len())
        } else {
            usize::MAX
        };
        if remaining == 0 {
            break;
        }
        let per_batch_limit = if config.edge_limit_per_ecosystem > 0 {
            let batches_remaining = frontier_batches.len().saturating_sub(batch_index);
            remaining.div_ceil(batches_remaining.max(1))
        } else {
            usize::MAX
        };
        let batch_rows =
            query_edges_for_frontier_batch(http, auth, ecosystem, batch, per_batch_limit).await?;
        for row in batch_rows {
            if seen.insert((row.package_name.clone(), row.dependency_name.clone())) {
                edges.push(row);
                if config.edge_limit_per_ecosystem > 0
                    && edges.len() >= config.edge_limit_per_ecosystem
                {
                    break;
                }
            }
        }
        if config.edge_limit_per_ecosystem > 0 && edges.len() >= config.edge_limit_per_ecosystem {
            break;
        }
    }
    Ok(edges)
}

#[derive(Debug, Clone, Copy)]
struct BaselinePackageWindow {
    package_limit: usize,
    package_offset: usize,
    edge_limit: usize,
}

fn baseline_package_windows(config: &LiveBaselineConfig) -> Vec<BaselinePackageWindow> {
    if config.package_limit_per_ecosystem == 0 {
        return Vec::new();
    }

    let total_windows = config
        .package_limit_per_ecosystem
        .div_ceil(DEFAULT_BASELINE_PACKAGE_WINDOW);
    let mut windows = Vec::with_capacity(total_windows);
    let mut remaining_packages = config.package_limit_per_ecosystem;
    let mut remaining_edges = config.edge_limit_per_ecosystem;
    let mut offset = config.package_offset_per_ecosystem;

    for window_index in 0..total_windows {
        let package_limit = remaining_packages.min(DEFAULT_BASELINE_PACKAGE_WINDOW);
        let windows_remaining = total_windows.saturating_sub(window_index);
        let edge_limit = if config.edge_limit_per_ecosystem > 0 {
            remaining_edges.div_ceil(windows_remaining.max(1))
        } else {
            0
        };
        windows.push(BaselinePackageWindow {
            package_limit,
            package_offset: offset,
            edge_limit,
        });
        remaining_packages = remaining_packages.saturating_sub(package_limit);
        remaining_edges = remaining_edges.saturating_sub(edge_limit);
        offset += package_limit;
    }

    windows
}

async fn query_top_packages(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    ecosystem: Ecosystem,
    package_limit: usize,
    package_offset: usize,
) -> Result<Vec<TopPackageRow>> {
    if package_limit == 0 {
        return Ok(Vec::new());
    }

    let mut packages = Vec::with_capacity(package_limit.min(DEFAULT_TOP_PACKAGE_PAGE_SIZE));
    let mut seen = BTreeSet::new();
    let mut offset = package_offset;

    while packages.len() < package_limit {
        let page_size = (package_limit - packages.len()).min(DEFAULT_TOP_PACKAGE_PAGE_SIZE);
        let query = build_top_packages_query_page(ecosystem, page_size, offset);
        let token = auth.access_token(http, false).await?;
        let rows = match execute_bigquery_top_package_query(http, auth, &token, &query).await {
            Ok(rows) => rows,
            Err(error) if is_unauthorized(&error) => {
                let token = auth.access_token(http, true).await?;
                execute_bigquery_top_package_query(http, auth, &token, &query).await?
            }
            Err(error) => return Err(error),
        };

        if rows.is_empty() {
            break;
        }

        let row_count = rows.len();
        for row in rows {
            if seen.insert(row.package_name.clone()) {
                packages.push(row);
                if packages.len() >= package_limit {
                    break;
                }
            }
        }

        if row_count < page_size {
            break;
        }
        offset += row_count;
    }

    Ok(packages)
}

async fn query_edges_for_frontier_batch(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    ecosystem: Ecosystem,
    frontier: &[String],
    edge_limit: usize,
) -> Result<Vec<DependencyEdgeRow>> {
    let query = build_edges_for_frontier_query(ecosystem, frontier, edge_limit);
    let token = auth.access_token(http, false).await?;
    match execute_bigquery_edge_query(http, auth, &token, &query).await {
        Ok(rows) => Ok(rows),
        Err(error) if is_unauthorized(&error) => {
            let token = auth.access_token(http, true).await?;
            execute_bigquery_edge_query(http, auth, &token, &query).await
        }
        Err(error) => Err(error),
    }
}

async fn execute_bigquery_query(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    token: &str,
    query: &str,
) -> Result<Vec<DependentRow>> {
    let url = format!(
        "{}/projects/{}/queries",
        BIGQUERY_BASE,
        urlencoding::encode(&auth.project_id)
    );
    let mut response = send_bigquery_query_request(http, &url, token, query)
        .await
        .context("failed to execute BigQuery query")?;

    if response.status() == StatusCode::UNAUTHORIZED {
        anyhow::bail!("bigquery unauthorized");
    }
    response = ensure_bigquery_success(response, "BigQuery query request failed").await?;
    let mut payload = response
        .json::<BigQueryQueryResponse>()
        .await
        .context("failed to decode BigQuery query response")?;
    let job_id = payload
        .job_reference
        .as_ref()
        .and_then(|reference| reference.job_id.clone());
    let mut rows = extract_query_rows(payload.rows.take())?;

    while !payload.job_complete.unwrap_or(true) {
        let Some(job_id) = job_id.as_deref() else {
            anyhow::bail!("BigQuery query did not provide a job id");
        };
        tokio::time::sleep(Duration::from_millis(250)).await;
        payload = fetch_bigquery_results(http, auth, token, job_id, None).await?;
        rows.extend(extract_query_rows(payload.rows.take())?);
    }

    let mut page_token = payload.page_token.take();
    while let Some(token_page) = page_token {
        let Some(job_id) = job_id.as_deref() else {
            anyhow::bail!("BigQuery query did not provide a job id");
        };
        payload = fetch_bigquery_results(http, auth, token, job_id, Some(&token_page)).await?;
        rows.extend(extract_query_rows(payload.rows.take())?);
        page_token = payload.page_token.take();
    }

    Ok(rows)
}

async fn execute_bigquery_edge_query(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    token: &str,
    query: &str,
) -> Result<Vec<DependencyEdgeRow>> {
    let url = format!(
        "{}/projects/{}/queries",
        BIGQUERY_BASE,
        urlencoding::encode(&auth.project_id)
    );
    let mut response = send_bigquery_query_request(http, &url, token, query)
        .await
        .context("failed to execute BigQuery edge query")?;

    if response.status() == StatusCode::UNAUTHORIZED {
        anyhow::bail!("bigquery unauthorized");
    }
    response = ensure_bigquery_success(response, "BigQuery edge query request failed").await?;
    let mut payload = response
        .json::<BigQueryQueryResponse>()
        .await
        .context("failed to decode BigQuery edge query response")?;
    let job_id = payload
        .job_reference
        .as_ref()
        .and_then(|reference| reference.job_id.clone());
    let mut rows = extract_edge_rows(payload.rows.take())?;

    while !payload.job_complete.unwrap_or(true) {
        let Some(job_id) = job_id.as_deref() else {
            anyhow::bail!("BigQuery edge query did not provide a job id");
        };
        tokio::time::sleep(Duration::from_millis(250)).await;
        payload = fetch_bigquery_results(http, auth, token, job_id, None).await?;
        rows.extend(extract_edge_rows(payload.rows.take())?);
    }

    let mut page_token = payload.page_token.take();
    while let Some(token_page) = page_token {
        let Some(job_id) = job_id.as_deref() else {
            anyhow::bail!("BigQuery edge query did not provide a job id");
        };
        payload = fetch_bigquery_results(http, auth, token, job_id, Some(&token_page)).await?;
        rows.extend(extract_edge_rows(payload.rows.take())?);
        page_token = payload.page_token.take();
    }

    Ok(rows)
}

async fn execute_bigquery_top_package_query(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    token: &str,
    query: &str,
) -> Result<Vec<TopPackageRow>> {
    let url = format!(
        "{}/projects/{}/queries",
        BIGQUERY_BASE,
        urlencoding::encode(&auth.project_id)
    );
    let mut response = send_bigquery_query_request(http, &url, token, query)
        .await
        .context("failed to execute BigQuery top package query")?;

    if response.status() == StatusCode::UNAUTHORIZED {
        anyhow::bail!("bigquery unauthorized");
    }
    response =
        ensure_bigquery_success(response, "BigQuery top package query request failed").await?;
    let mut payload = response
        .json::<BigQueryQueryResponse>()
        .await
        .context("failed to decode BigQuery top package query response")?;
    let job_id = payload
        .job_reference
        .as_ref()
        .and_then(|reference| reference.job_id.clone());
    let mut rows = extract_top_package_rows(payload.rows.take())?;

    while !payload.job_complete.unwrap_or(true) {
        let Some(job_id) = job_id.as_deref() else {
            anyhow::bail!("BigQuery top package query did not provide a job id");
        };
        tokio::time::sleep(Duration::from_millis(250)).await;
        payload = fetch_bigquery_results(http, auth, token, job_id, None).await?;
        rows.extend(extract_top_package_rows(payload.rows.take())?);
    }

    let mut page_token = payload.page_token.take();
    while let Some(token_page) = page_token {
        let Some(job_id) = job_id.as_deref() else {
            anyhow::bail!("BigQuery top package query did not provide a job id");
        };
        payload = fetch_bigquery_results(http, auth, token, job_id, Some(&token_page)).await?;
        rows.extend(extract_top_package_rows(payload.rows.take())?);
        page_token = payload.page_token.take();
    }

    Ok(rows)
}

async fn fetch_bigquery_results(
    http: &reqwest::Client,
    auth: &GoogleCloudAuth,
    token: &str,
    job_id: &str,
    page_token: Option<&str>,
) -> Result<BigQueryQueryResponse> {
    let url = format!(
        "{}/projects/{}/queries/{}",
        BIGQUERY_BASE,
        urlencoding::encode(&auth.project_id),
        urlencoding::encode(job_id)
    );

    let mut attempts = 0usize;
    loop {
        attempts += 1;
        let mut request = http
            .get(&url)
            .bearer_auth(token)
            .query(&[("location", DEFAULT_LOCATION), ("maxResults", "1000")]);
        if let Some(page_token) = page_token {
            request = request.query(&[("pageToken", page_token)]);
        }
        match request.send().await {
            Ok(response) => {
                if response.status() == StatusCode::UNAUTHORIZED {
                    anyhow::bail!("bigquery unauthorized");
                }
                return ensure_bigquery_success(response, "BigQuery query results request failed")
                    .await?
                    .json::<BigQueryQueryResponse>()
                    .await
                    .context("failed to decode BigQuery query results");
            }
            Err(error) if attempts < 3 && should_retry_transport_error(&error) => {
                tokio::time::sleep(Duration::from_millis(250 * attempts as u64)).await;
            }
            Err(error) => {
                return Err(error).context("failed to fetch BigQuery query results");
            }
        }
    }
}

async fn send_bigquery_query_request(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    query: &str,
) -> Result<reqwest::Response> {
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        let request = http.post(url).bearer_auth(token).json(&json!({
            "query": query,
            "useLegacySql": false,
            "location": DEFAULT_LOCATION,
            "timeoutMs": DEFAULT_BIGQUERY_TIMEOUT_MS,
            "maxResults": 1000u64,
        }));
        match request.send().await {
            Ok(response) => return Ok(response),
            Err(error) if attempts < 3 && should_retry_transport_error(&error) => {
                tokio::time::sleep(Duration::from_millis(250 * attempts as u64)).await;
            }
            Err(error) => return Err(error).context("failed to send BigQuery query request"),
        }
    }
}

async fn ensure_bigquery_success(
    response: reqwest::Response,
    context_message: &str,
) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    anyhow::bail!("{context_message}: status={status} body={body}");
}

fn extract_query_rows(rows: Option<Vec<BigQueryRow>>) -> Result<Vec<DependentRow>> {
    let mut extracted = Vec::new();
    for row in rows.unwrap_or_default() {
        let values = row
            .f
            .into_iter()
            .map(|cell| match cell.v {
                Some(Value::String(value)) => Some(value),
                Some(Value::Bool(value)) => Some(value.to_string()),
                Some(Value::Number(value)) => Some(value.to_string()),
                Some(Value::Null) | None => None,
                Some(other) => Some(other.to_string()),
            })
            .collect::<Vec<_>>();
        let name = values
            .first()
            .and_then(|value| value.clone())
            .context("BigQuery row missing dependency name")?;
        let dependent_name = values
            .get(1)
            .and_then(|value| value.clone())
            .context("BigQuery row missing dependent name")?;
        extracted.push(DependentRow {
            name,
            dependent_name,
        });
    }
    Ok(extracted)
}

fn extract_edge_rows(rows: Option<Vec<BigQueryRow>>) -> Result<Vec<DependencyEdgeRow>> {
    let mut extracted = Vec::new();
    for row in rows.unwrap_or_default() {
        let values = row
            .f
            .into_iter()
            .map(|cell| match cell.v {
                Some(Value::String(value)) => Some(value),
                Some(Value::Bool(value)) => Some(value.to_string()),
                Some(Value::Number(value)) => Some(value.to_string()),
                Some(Value::Null) | None => None,
                Some(other) => Some(other.to_string()),
            })
            .collect::<Vec<_>>();
        let package_name = values
            .first()
            .and_then(|value| value.clone())
            .context("BigQuery row missing package name")?;
        let dependency_name = values
            .get(1)
            .and_then(|value| value.clone())
            .context("BigQuery row missing dependency name")?;
        extracted.push(DependencyEdgeRow {
            package_name,
            dependency_name,
        });
    }
    Ok(extracted)
}

fn extract_top_package_rows(rows: Option<Vec<BigQueryRow>>) -> Result<Vec<TopPackageRow>> {
    let mut extracted = Vec::new();
    for row in rows.unwrap_or_default() {
        let values = row
            .f
            .into_iter()
            .map(|cell| match cell.v {
                Some(Value::String(value)) => Some(value),
                Some(Value::Bool(value)) => Some(value.to_string()),
                Some(Value::Number(value)) => Some(value.to_string()),
                Some(Value::Null) | None => None,
                Some(other) => Some(other.to_string()),
            })
            .collect::<Vec<_>>();
        let package_name = values
            .first()
            .and_then(|value| value.clone())
            .context("BigQuery row missing package name")?;
        let dependent_count = values
            .get(1)
            .and_then(|value| value.clone())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        extracted.push(TopPackageRow {
            package_name,
            dependent_count,
        });
    }
    Ok(extracted)
}

fn build_dependents_query(ecosystem: Ecosystem, frontier: &[String]) -> String {
    let rows = frontier
        .iter()
        .map(|name| format!("SELECT '{}' AS Name", escape_sql_string(name)))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    format!(
        "WITH frontier AS ({rows}) \
         SELECT DISTINCT d.Dependency.Name AS DependencyName, d.Name AS DependentName \
         FROM `{DEPS_DEV_DATASET}` AS d \
         JOIN frontier AS f ON d.Dependency.Name = f.Name \
         WHERE d.System = '{}' AND d.MinimumDepth = 1",
        deps_dev_system(ecosystem)
    )
}

#[cfg(test)]
fn build_top_packages_query(ecosystem: Ecosystem, package_limit: usize) -> String {
    build_top_packages_query_page(ecosystem, package_limit, 0)
}

fn build_top_packages_query_page(
    ecosystem: Ecosystem,
    package_limit: usize,
    offset: usize,
) -> String {
    format!(
        "WITH counts AS ( \
           SELECT d.Dependency.Name AS PackageName, COUNT(DISTINCT d.Name) AS DependentCount \
           FROM `{DEPS_DEV_DATASET}` AS d \
           WHERE d.System = '{system}' AND d.MinimumDepth = 1 \
           GROUP BY d.Dependency.Name \
         ) \
         SELECT PackageName, DependentCount \
         FROM counts \
         ORDER BY DependentCount DESC, PackageName ASC \
         LIMIT {package_limit} OFFSET {offset}",
        system = deps_dev_system(ecosystem),
        package_limit = package_limit,
        offset = offset,
    )
}

fn build_edges_for_frontier_query(
    ecosystem: Ecosystem,
    frontier: &[String],
    edge_limit: usize,
) -> String {
    let rows = frontier
        .iter()
        .map(|name| format!("SELECT '{}' AS Name", escape_sql_string(name)))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let mut query = format!(
        "WITH frontier AS ({rows}) \
         SELECT DISTINCT d.Name AS PackageName, d.Dependency.Name AS DependencyName \
         FROM `{DEPS_DEV_DATASET}` AS d \
         WHERE d.System = '{system}' AND d.MinimumDepth = 1 \
           AND d.Name IN (SELECT Name FROM frontier)",
        system = deps_dev_system(ecosystem),
    );
    if edge_limit > 0 {
        query.push_str(&format!(" LIMIT {edge_limit}"));
    }
    query
}

fn escape_sql_string(value: &str) -> String {
    value.replace('\'', "''")
}

fn deps_dev_system(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "NPM",
        Ecosystem::Pypi => "PYPI",
        Ecosystem::CratesIo => "CARGO",
    }
}

fn is_unauthorized(error: &anyhow::Error) -> bool {
    error.to_string().contains("unauthorized")
}

fn should_retry_transport_error(error: &reqwest::Error) -> bool {
    error.is_timeout()
        || error.is_connect()
        || error
            .to_string()
            .to_ascii_lowercase()
            .contains("address not available")
}

#[derive(Debug, Clone)]
struct GoogleCloudAuth {
    project_id: String,
    access_token: Option<String>,
    refresh_credentials: Option<RefreshCredentials>,
}

impl GoogleCloudAuth {
    fn discover() -> Result<Self> {
        let gcloud_dir = gcloud_dir();
        let project_id = detect_project_id(gcloud_dir.as_deref())?.context(
            "missing Google Cloud project; set GOOGLE_CLOUD_PROJECT or gcloud core/project",
        )?;
        let active_account = detect_active_account(gcloud_dir.as_deref())?;

        let mut refresh_credentials = None;
        if let Some(path) = application_default_credentials_path(gcloud_dir.as_deref())
            && path.exists()
        {
            refresh_credentials = load_authorized_user_credentials(&path).ok();
        }
        if refresh_credentials.is_none()
            && let (Some(gcloud_dir), Some(account)) =
                (gcloud_dir.as_deref(), active_account.as_deref())
        {
            refresh_credentials = load_gcloud_refresh_credentials(gcloud_dir, account).ok();
        }

        let access_token = if let (Some(gcloud_dir), Some(account)) =
            (gcloud_dir.as_deref(), active_account.as_deref())
        {
            load_gcloud_access_token(gcloud_dir, account).ok()
        } else {
            None
        };

        Ok(Self {
            project_id,
            access_token,
            refresh_credentials,
        })
    }

    async fn access_token(&self, http: &reqwest::Client, _force_refresh: bool) -> Result<String> {
        if let Some(credentials) = self.refresh_credentials.as_ref() {
            return refresh_access_token(http, credentials).await;
        }
        if let Some(token) = self.access_token.clone() {
            return Ok(token);
        }
        anyhow::bail!("no Google Cloud credentials available for BigQuery")
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RefreshCredentials {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

fn gcloud_dir() -> Option<PathBuf> {
    env::var_os("CLOUDSDK_CONFIG")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/gcloud")))
}

fn application_default_credentials_path(gcloud_dir: Option<&Path>) -> Option<PathBuf> {
    env::var_os("GOOGLE_APPLICATION_CREDENTIALS")
        .map(PathBuf::from)
        .or_else(|| gcloud_dir.map(|dir| dir.join("application_default_credentials.json")))
}

fn detect_project_id(gcloud_dir: Option<&Path>) -> Result<Option<String>> {
    if let Some(value) = env::var_os("GOOGLE_CLOUD_PROJECT")
        .or_else(|| env::var_os("GCLOUD_PROJECT"))
        .or_else(|| env::var_os("CLOUDSDK_CORE_PROJECT"))
    {
        let value = value.to_string_lossy().trim().to_string();
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    let Some(gcloud_dir) = gcloud_dir else {
        return Ok(None);
    };
    let active_name = std::fs::read_to_string(gcloud_dir.join("active_config"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "default".to_string());
    let config_path = gcloud_dir
        .join("configurations")
        .join(format!("config_{active_name}"));
    let body = match std::fs::read_to_string(&config_path) {
        Ok(body) => body,
        Err(_) => return Ok(None),
    };
    Ok(parse_gcloud_ini_value(&body, "core", "project"))
}

fn detect_active_account(gcloud_dir: Option<&Path>) -> Result<Option<String>> {
    if let Some(value) = env::var_os("CLOUDSDK_CORE_ACCOUNT") {
        let value = value.to_string_lossy().trim().to_string();
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    let Some(gcloud_dir) = gcloud_dir else {
        return Ok(None);
    };
    let active_name = std::fs::read_to_string(gcloud_dir.join("active_config"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "default".to_string());
    let config_path = gcloud_dir
        .join("configurations")
        .join(format!("config_{active_name}"));
    if let Ok(body) = std::fs::read_to_string(&config_path)
        && let Some(account) = parse_gcloud_ini_value(&body, "core", "account")
    {
        return Ok(Some(account));
    }
    let db_path = gcloud_dir.join("access_tokens.db");
    if !db_path.exists() {
        return Ok(None);
    }
    let connection = Connection::open(db_path).context("failed to open gcloud access token db")?;
    let mut statement = connection
        .prepare("SELECT account_id FROM access_tokens LIMIT 1")
        .context("failed to prepare gcloud account query")?;
    let mut rows = statement
        .query([])
        .context("failed to query gcloud access token db")?;
    if let Some(row) = rows
        .next()
        .context("failed to read gcloud access token row")?
    {
        return row
            .get::<_, String>(0)
            .map(Some)
            .context("failed to decode gcloud account id");
    }
    Ok(None)
}

fn parse_gcloud_ini_value(body: &str, section: &str, key: &str) -> Option<String> {
    let mut current_section = None::<String>;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(stripped) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            current_section = Some(stripped.trim().to_string());
            continue;
        }
        if current_section.as_deref() != Some(section) {
            continue;
        }
        let Some((left, right)) = line.split_once('=') else {
            continue;
        };
        if left.trim() == key {
            return Some(right.trim().to_string());
        }
    }
    None
}

fn load_authorized_user_credentials(path: &Path) -> Result<RefreshCredentials> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let credentials = serde_json::from_str::<RefreshCredentials>(&body)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(credentials)
}

fn load_gcloud_refresh_credentials(gcloud_dir: &Path, account: &str) -> Result<RefreshCredentials> {
    let connection = Connection::open(gcloud_dir.join("credentials.db"))
        .context("failed to open gcloud credentials db")?;
    let mut statement = connection
        .prepare("SELECT value FROM credentials WHERE account_id = ?1")
        .context("failed to prepare gcloud credential query")?;
    let payload = statement
        .query_row([account], |row| row.get::<_, String>(0))
        .with_context(|| format!("failed to load gcloud credentials for {account}"))?;
    serde_json::from_str::<RefreshCredentials>(&payload)
        .context("failed to parse gcloud refresh credentials")
}

fn load_gcloud_access_token(gcloud_dir: &Path, account: &str) -> Result<String> {
    let connection = Connection::open(gcloud_dir.join("access_tokens.db"))
        .context("failed to open gcloud access token db")?;
    let mut statement = connection
        .prepare("SELECT access_token, token_expiry FROM access_tokens WHERE account_id = ?1")
        .context("failed to prepare gcloud access token query")?;
    let (token, expiry) = statement
        .query_row([account], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .with_context(|| format!("failed to load gcloud access token for {account}"))?;

    let expiry = DateTime::parse_from_str(&expiry, "%Y-%m-%d %H:%M:%S%.f")
        .map(|value| value.with_timezone(&Utc))
        .ok();
    if expiry.is_some_and(|expiry| expiry <= Utc::now() + chrono::TimeDelta::seconds(30)) {
        anyhow::bail!("cached gcloud access token is expired");
    }
    Ok(token)
}

async fn refresh_access_token(
    http: &reqwest::Client,
    credentials: &RefreshCredentials,
) -> Result<String> {
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
    }

    let response = http
        .post(OAUTH_TOKEN_URL)
        .form(&[
            ("client_id", credentials.client_id.as_str()),
            ("client_secret", credentials.client_secret.as_str()),
            ("refresh_token", credentials.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .context("failed to refresh Google Cloud access token")?;
    let response =
        ensure_http_success(response, "Google Cloud access token refresh failed").await?;
    let response = response
        .json::<TokenResponse>()
        .await
        .context("failed to decode Google Cloud access token refresh response")?;
    Ok(response.access_token)
}

async fn ensure_http_success(
    response: reqwest::Response,
    context_message: &str,
) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    anyhow::bail!("{context_message}: status={status} body={body}");
}

#[derive(Debug, Deserialize)]
struct BigQueryQueryResponse {
    #[serde(rename = "jobComplete")]
    job_complete: Option<bool>,
    #[serde(rename = "pageToken")]
    page_token: Option<String>,
    rows: Option<Vec<BigQueryRow>>,
    #[serde(rename = "jobReference")]
    job_reference: Option<BigQueryJobReference>,
}

#[derive(Debug, Deserialize)]
struct BigQueryJobReference {
    #[serde(rename = "jobId")]
    job_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BigQueryRow {
    f: Vec<BigQueryCell>,
}

#[derive(Debug, Deserialize)]
struct BigQueryCell {
    v: Option<Value>,
}

#[derive(Debug)]
struct DependentRow {
    name: String,
    dependent_name: String,
}

#[derive(Debug)]
struct DependencyEdgeRow {
    package_name: String,
    dependency_name: String,
}

#[derive(Debug)]
struct TopPackageRow {
    package_name: String,
    dependent_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_dependents_query_for_frontier_batch() {
        let query = build_dependents_query(
            Ecosystem::Pypi,
            &["litellm".to_string(), "open-webui".to_string()],
        );
        assert!(query.contains("`bigquery-public-data.deps_dev_v1.DependenciesLatest`"));
        assert!(query.contains("SELECT 'litellm' AS Name"));
        assert!(query.contains("SELECT 'open-webui' AS Name"));
        assert!(query.contains("d.System = 'PYPI'"));
    }

    #[test]
    fn builds_top_packages_query_for_ecosystem() {
        let query = build_top_packages_query(Ecosystem::Pypi, 500);
        assert!(query.contains("`bigquery-public-data.deps_dev_v1.DependenciesLatest`"));
        assert!(query.contains("WITH counts AS"));
        assert!(query.contains("GROUP BY d.Dependency.Name"));
        assert!(query.contains("d.System = 'PYPI'"));
        assert!(query.contains("LIMIT 500"));
        assert!(query.contains("OFFSET 0"));
    }

    #[test]
    fn builds_top_packages_query_page_for_ecosystem() {
        let query = build_top_packages_query_page(Ecosystem::Npm, 250, 1000);
        assert!(query.contains("d.System = 'NPM'"));
        assert!(query.contains("LIMIT 250 OFFSET 1000"));
        assert!(query.contains("ORDER BY DependentCount DESC, PackageName ASC"));
        assert!(query.contains("SELECT PackageName, DependentCount"));
    }

    #[test]
    fn builds_edge_query_for_frontier_batch() {
        let query = build_edges_for_frontier_query(
            Ecosystem::Npm,
            &["react".to_string(), "next".to_string()],
            1000,
        );
        assert!(query.contains("SELECT 'react' AS Name"));
        assert!(query.contains("SELECT 'next' AS Name"));
        assert!(query.contains("d.System = 'NPM'"));
        assert!(query.contains("LIMIT 1000"));
    }

    #[test]
    fn parses_ini_value_from_gcloud_config() {
        let body = "[core]\naccount = person@example.com\nproject = sample-project\n";
        assert_eq!(
            parse_gcloud_ini_value(body, "core", "project").as_deref(),
            Some("sample-project")
        );
        assert_eq!(
            parse_gcloud_ini_value(body, "core", "account").as_deref(),
            Some("person@example.com")
        );
    }

    #[test]
    fn extracts_bigquery_rows() {
        let rows = vec![BigQueryRow {
            f: vec![
                BigQueryCell {
                    v: Some(Value::String("litellm".to_string())),
                },
                BigQueryCell {
                    v: Some(Value::String("open-webui".to_string())),
                },
            ],
        }];
        let extracted = extract_query_rows(Some(rows)).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, "litellm");
        assert_eq!(extracted[0].dependent_name, "open-webui");
    }

    #[test]
    fn extracts_top_package_rows() {
        let rows = vec![BigQueryRow {
            f: vec![BigQueryCell {
                v: Some(Value::String("litellm".to_string())),
            }],
        }];
        let extracted = extract_top_package_rows(Some(rows)).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].package_name, "litellm");
    }
}
