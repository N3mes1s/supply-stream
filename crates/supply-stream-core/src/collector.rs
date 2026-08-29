use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::repo_provenance::{self, PackageRepositoryIdentity};
use crate::{
    event::Ecosystem,
    priority::normalize_package_name,
    scoring::ScoreInputRecord,
    sources::{RequestThrottle, default_offline_resilience_config},
};

#[derive(Debug, Clone)]
pub struct CollectConfig {
    pub max_depth: usize,
    pub max_packages: usize,
    pub request_concurrency: usize,
    pub allow_external_fallback: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CollectSummary {
    pub seed_packages: usize,
    pub discovered_packages: usize,
    pub emitted_package_records: usize,
    pub emitted_dependency_records: usize,
    pub fetch_failures: usize,
    pub external_fallback_fetches: usize,
    pub ecosystems: Vec<CollectEcosystemSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CollectEcosystemSummary {
    pub ecosystem: Ecosystem,
    pub packages: usize,
    pub dependencies: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeedPackageRecord {
    pub ecosystem: Ecosystem,
    pub package: String,
    #[serde(default)]
    pub direct_popularity: Option<f64>,
}

#[derive(Debug, Clone)]
struct CollectedNode {
    direct_popularity: Option<f64>,
    dependencies: Vec<String>,
    repository: Option<PackageRepositoryIdentity>,
    used_external_fallback: bool,
}

#[derive(Debug, Clone)]
pub struct CollectedGraphMaterial {
    pub records: Vec<ScoreInputRecord>,
    pub repositories: Vec<PackageRepositoryIdentity>,
    pub summary: CollectSummary,
}

#[derive(Debug, Clone)]
struct CollectContext {
    http: reqwest::Client,
    endpoints: CollectorEndpoints,
    npm_throttle: RequestThrottle,
    pypi_throttle: RequestThrottle,
    crates_throttle: RequestThrottle,
    deps_dev_throttle: RequestThrottle,
}

#[derive(Debug, Clone)]
struct CollectorEndpoints {
    npm_registry_base: String,
    pypi_project_base: String,
    crates_base: String,
    crates_index_base: String,
    deps_dev_base: String,
}

#[derive(Debug, Deserialize)]
struct NpmPackument {
    #[serde(rename = "dist-tags")]
    dist_tags: NpmDistTags,
    versions: HashMap<String, NpmVersionMeta>,
}

#[derive(Debug, Deserialize)]
struct NpmLatestManifest {
    #[serde(default)]
    dependencies: Option<HashMap<String, String>>,
    #[serde(default)]
    repository: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct NpmDistTags {
    latest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NpmVersionMeta {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default)]
    repository: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct PypiProjectResponse {
    info: PypiInfo,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    #[serde(default)]
    requires_dist: Vec<String>,
    #[serde(default)]
    home_page: Option<String>,
    #[serde(default)]
    project_urls: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct CratesMetadataResponse {
    #[serde(rename = "crate")]
    krate: CratesMetadataCrate,
}

#[derive(Debug, Deserialize)]
struct CratesMetadataCrate {
    #[serde(default)]
    downloads: Option<f64>,
    #[serde(default)]
    max_stable_version: Option<String>,
    #[serde(default)]
    max_version: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CratesDependenciesResponse {
    #[serde(default)]
    dependencies: Vec<CratesDependency>,
}

#[derive(Debug, Deserialize)]
struct CratesDependency {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    optional: bool,
    crate_id: String,
}

#[derive(Debug, Deserialize)]
struct CratesIndexEntry {
    #[serde(default)]
    deps: Vec<CratesIndexDependency>,
    #[serde(default)]
    yanked: bool,
}

#[derive(Debug, Deserialize)]
struct CratesIndexDependency {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    optional: bool,
}

impl Default for CollectorEndpoints {
    fn default() -> Self {
        Self {
            npm_registry_base: "https://registry.npmjs.org".to_string(),
            pypi_project_base: "https://pypi.org/pypi".to_string(),
            crates_base: "https://crates.io/api/v1".to_string(),
            crates_index_base: "https://index.crates.io".to_string(),
            deps_dev_base: "https://api.deps.dev/v3".to_string(),
        }
    }
}

pub async fn collect_score_input_from_files(
    seeds_path: &Path,
    popularity_path: Option<&Path>,
    config: &CollectConfig,
) -> Result<(Vec<ScoreInputRecord>, CollectSummary)> {
    let material = collect_graph_material_from_files(seeds_path, popularity_path, config).await?;
    Ok((material.records, material.summary))
}

pub async fn collect_graph_material_from_files(
    seeds_path: &Path,
    popularity_path: Option<&Path>,
    config: &CollectConfig,
) -> Result<CollectedGraphMaterial> {
    let seeds = load_seed_records(seeds_path).await?;
    let popularity = match popularity_path {
        Some(path) => load_seed_records(path).await?,
        None => Vec::new(),
    };
    collect_graph_material_from_records(seeds, popularity, config).await
}

pub async fn collect_score_input_from_records(
    seeds: Vec<SeedPackageRecord>,
    popularity: Vec<SeedPackageRecord>,
    config: &CollectConfig,
) -> Result<(Vec<ScoreInputRecord>, CollectSummary)> {
    let material = collect_graph_material_from_records(seeds, popularity, config).await?;
    Ok((material.records, material.summary))
}

pub async fn collect_graph_material_from_records(
    seeds: Vec<SeedPackageRecord>,
    popularity: Vec<SeedPackageRecord>,
    config: &CollectConfig,
) -> Result<CollectedGraphMaterial> {
    let http = reqwest::Client::builder()
        .user_agent("supply-stream-collector/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("failed to build collector HTTP client")?;
    let resilience = default_offline_resilience_config();
    collect_graph_material_with_context(
        CollectContext {
            http,
            endpoints: CollectorEndpoints::default(),
            npm_throttle: RequestThrottle::new("collector-npm", &resilience),
            pypi_throttle: RequestThrottle::new("collector-pypi", &resilience),
            crates_throttle: RequestThrottle::new("collector-crates-io", &resilience),
            deps_dev_throttle: RequestThrottle::new("collector-deps-dev", &resilience),
        },
        seeds,
        popularity,
        config,
    )
    .await
}

async fn collect_graph_material_with_context(
    context: CollectContext,
    seeds: Vec<SeedPackageRecord>,
    popularity: Vec<SeedPackageRecord>,
    config: &CollectConfig,
) -> Result<CollectedGraphMaterial> {
    if config.max_packages == 0 {
        anyhow::bail!("max_packages must be greater than zero");
    }
    if config.request_concurrency == 0 {
        anyhow::bail!("request_concurrency must be greater than zero");
    }

    let mut popularity_map = HashMap::<(Ecosystem, String), f64>::new();
    for record in seeds.iter().chain(popularity.iter()) {
        let normalized = normalize_package_name(record.ecosystem, &record.package);
        let popularity = record.direct_popularity.unwrap_or(0.0).max(0.0);
        popularity_map
            .entry((record.ecosystem, normalized))
            .and_modify(|current| *current = current.max(popularity))
            .or_insert(popularity);
    }

    let seed_packages = seeds.len();
    let mut seen = BTreeSet::new();
    let mut packages = BTreeMap::<(Ecosystem, String), Option<f64>>::new();
    let mut edges = BTreeSet::<(Ecosystem, String, String)>::new();
    let mut repositories = BTreeMap::<(Ecosystem, String), PackageRepositoryIdentity>::new();
    let mut fetch_failures = 0usize;
    let mut external_fallback_fetches = 0usize;
    let mut frontier = seeds
        .into_iter()
        .map(|seed| {
            (
                seed.ecosystem,
                normalize_package_name(seed.ecosystem, &seed.package),
            )
        })
        .collect::<Vec<_>>();

    for depth in 0..=config.max_depth {
        if frontier.is_empty() || seen.len() >= config.max_packages {
            break;
        }

        let remaining_capacity = config.max_packages.saturating_sub(seen.len());
        let mut scheduled = Vec::new();
        let mut scheduled_set = BTreeSet::new();
        for (ecosystem, package) in frontier.drain(..) {
            if seen.contains(&(ecosystem, package.clone()))
                || !scheduled_set.insert((ecosystem, package.clone()))
            {
                continue;
            }
            if scheduled.len() >= remaining_capacity {
                break;
            }
            seen.insert((ecosystem, package.clone()));
            scheduled.push((ecosystem, package));
        }

        if scheduled.is_empty() {
            break;
        }

        let fetches = stream::iter(scheduled.into_iter().map(|(ecosystem, package)| {
            let context = context.clone();
            async move {
                let result = fetch_node(
                    &context,
                    ecosystem,
                    &package,
                    config.allow_external_fallback,
                )
                .await;
                (ecosystem, package, result)
            }
        }))
        .buffer_unordered(config.request_concurrency)
        .collect::<Vec<_>>()
        .await;

        let mut next_frontier = Vec::new();
        for (ecosystem, package, result) in fetches {
            match result {
                Ok(node) => {
                    if node.used_external_fallback {
                        external_fallback_fetches += 1;
                    }
                    let override_popularity =
                        popularity_map.get(&(ecosystem, package.clone())).copied();
                    let direct_popularity = override_popularity.or(node.direct_popularity);
                    packages
                        .entry((ecosystem, package.clone()))
                        .and_modify(|current| {
                            *current =
                                Some(current.unwrap_or(0.0).max(direct_popularity.unwrap_or(0.0)))
                        })
                        .or_insert(direct_popularity);
                    if let Some(repository) = node.repository {
                        repositories.insert((ecosystem, package.clone()), repository);
                    }

                    for dependency in node.dependencies {
                        edges.insert((ecosystem, package.clone(), dependency.clone()));
                        if depth < config.max_depth
                            && !seen.contains(&(ecosystem, dependency.clone()))
                        {
                            next_frontier.push((ecosystem, dependency));
                        }
                    }
                }
                Err(_) => {
                    fetch_failures += 1;
                    packages
                        .entry((ecosystem, package.clone()))
                        .or_insert_with(|| {
                            popularity_map.get(&(ecosystem, package.clone())).copied()
                        });
                }
            }
        }
        frontier = next_frontier;
    }

    let mut records = Vec::new();
    let mut ecosystem_package_counts = HashMap::<Ecosystem, usize>::new();
    let mut ecosystem_dependency_counts = HashMap::<Ecosystem, usize>::new();
    for ((ecosystem, package), direct_popularity) in &packages {
        *ecosystem_package_counts.entry(*ecosystem).or_default() += 1;
        records.push(ScoreInputRecord::Package {
            ecosystem: *ecosystem,
            package: package.clone(),
            direct_popularity: direct_popularity.unwrap_or(0.0),
        });
    }
    for (ecosystem, package, dependency) in &edges {
        *ecosystem_dependency_counts.entry(*ecosystem).or_default() += 1;
        records.push(ScoreInputRecord::Dependency {
            ecosystem: *ecosystem,
            package: package.clone(),
            dependency: dependency.clone(),
            weight: 1.0,
            sources: vec!["registry_metadata".to_string()],
            confidence: Some(1.0),
        });
    }

    let mut ecosystems = Vec::new();
    for ecosystem in [Ecosystem::Npm, Ecosystem::Pypi, Ecosystem::CratesIo] {
        let packages = ecosystem_package_counts
            .get(&ecosystem)
            .copied()
            .unwrap_or(0);
        let dependencies = ecosystem_dependency_counts
            .get(&ecosystem)
            .copied()
            .unwrap_or(0);
        if packages > 0 || dependencies > 0 {
            ecosystems.push(CollectEcosystemSummary {
                ecosystem,
                packages,
                dependencies,
            });
        }
    }

    Ok(CollectedGraphMaterial {
        records,
        repositories: repositories.into_values().collect(),
        summary: CollectSummary {
            seed_packages,
            discovered_packages: packages.len(),
            emitted_package_records: packages.len(),
            emitted_dependency_records: edges.len(),
            fetch_failures,
            external_fallback_fetches,
            ecosystems,
        },
    })
}

pub async fn load_seed_records(path: &Path) -> Result<Vec<SeedPackageRecord>> {
    let body = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut records = Vec::new();
    for (line_number, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut record = serde_json::from_str::<SeedPackageRecord>(line).with_context(|| {
            format!(
                "failed to parse seed record line {} from {}",
                line_number + 1,
                path.display()
            )
        })?;
        record.package = normalize_package_name(record.ecosystem, &record.package);
        records.push(record);
    }
    Ok(records)
}

pub async fn fetch_package_repository_identity(
    ecosystem: Ecosystem,
    package: &str,
) -> Result<Option<PackageRepositoryIdentity>> {
    let http = reqwest::Client::builder()
        .user_agent("supply-stream-collector/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("failed to build collector HTTP client")?;
    let resilience = default_offline_resilience_config();
    let context = CollectContext {
        http,
        endpoints: CollectorEndpoints::default(),
        npm_throttle: RequestThrottle::new("collector-npm", &resilience),
        pypi_throttle: RequestThrottle::new("collector-pypi", &resilience),
        crates_throttle: RequestThrottle::new("collector-crates-io", &resilience),
        deps_dev_throttle: RequestThrottle::new("collector-deps-dev", &resilience),
    };
    Ok(fetch_node(&context, ecosystem, package, false)
        .await?
        .repository)
}

async fn fetch_node(
    context: &CollectContext,
    ecosystem: Ecosystem,
    package: &str,
    allow_external_fallback: bool,
) -> Result<CollectedNode> {
    let registry_result = match ecosystem {
        Ecosystem::Npm => fetch_npm_node(context, package).await,
        Ecosystem::Pypi => fetch_pypi_node(context, package).await,
        Ecosystem::CratesIo => fetch_crates_node(context, package).await,
    };

    match registry_result {
        Ok(node) => Ok(node),
        Err(error) if allow_external_fallback => fetch_deps_dev_node(context, ecosystem, package)
            .await
            .with_context(|| {
                format!(
                    "registry fetch failed and deps.dev fallback also failed for {ecosystem}:{package}: {error}"
                )
            }),
        Err(error) => Err(error),
    }
}

async fn fetch_deps_dev_node(
    context: &CollectContext,
    ecosystem: Ecosystem,
    package: &str,
) -> Result<CollectedNode> {
    let system = deps_dev_system(ecosystem);
    let encoded = urlencoding::encode(package);
    let package_url = format!(
        "{}/systems/{}/packages/{}",
        context.endpoints.deps_dev_base, system, encoded
    );
    let package_raw = context
        .deps_dev_throttle
        .send_without_shutdown(|| context.http.get(&package_url).send())
        .await
        .with_context(|| format!("failed to fetch deps.dev package for {ecosystem}:{package}"))?
        .error_for_status()
        .with_context(|| format!("deps.dev returned an error for {ecosystem}:{package}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("failed to decode deps.dev package for {ecosystem}:{package}"))?;

    let version = select_deps_dev_default_version(&package_raw)
        .with_context(|| format!("missing deps.dev default version for {ecosystem}:{package}"))?;
    let dependencies_url = format!(
        "{}/systems/{}/packages/{}/versions/{}:dependencies",
        context.endpoints.deps_dev_base,
        system,
        encoded,
        urlencoding::encode(&version)
    );
    let dependencies_raw = context
        .deps_dev_throttle
        .send_without_shutdown(|| context.http.get(&dependencies_url).send())
        .await
        .with_context(|| {
            format!("failed to fetch deps.dev dependencies for {ecosystem}:{package}@{version}")
        })?
        .error_for_status()
        .with_context(|| {
            format!("deps.dev dependencies returned an error for {ecosystem}:{package}@{version}")
        })?
        .json::<Value>()
        .await
        .with_context(|| {
            format!("failed to decode deps.dev dependencies for {ecosystem}:{package}@{version}")
        })?;

    let dependencies = extract_deps_dev_direct_dependencies(ecosystem, &dependencies_raw)?;

    Ok(CollectedNode {
        direct_popularity: None,
        dependencies,
        repository: None,
        used_external_fallback: true,
    })
}

async fn fetch_npm_node(context: &CollectContext, package: &str) -> Result<CollectedNode> {
    let encoded = urlencoding::encode(package);
    match fetch_npm_latest_node(context, package, &encoded).await {
        Ok(node) => Ok(node),
        Err(_) => fetch_npm_packument_node(context, package, &encoded).await,
    }
}

async fn fetch_npm_latest_node(
    context: &CollectContext,
    package: &str,
    encoded: &str,
) -> Result<CollectedNode> {
    let url = format!("{}/{}/latest", context.endpoints.npm_registry_base, encoded);
    let raw = context
        .npm_throttle
        .send_without_shutdown(|| context.http.get(&url).send())
        .await
        .with_context(|| format!("failed to fetch npm latest manifest for {package}"))?
        .error_for_status()
        .with_context(|| format!("npm latest manifest returned an error for {package}"))?
        .json::<NpmLatestManifest>()
        .await
        .with_context(|| format!("failed to decode npm latest manifest for {package}"))?;

    Ok(CollectedNode {
        direct_popularity: None,
        dependencies: raw
            .dependencies
            .unwrap_or_default()
            .keys()
            .map(|name| normalize_package_name(Ecosystem::Npm, name))
            .collect(),
        repository: raw.repository.as_ref().and_then(|repository| {
            repo_provenance::extract_package_repository_identity(
                Ecosystem::Npm,
                package,
                &serde_json::json!({ "repository": repository }),
                "collector_registry_metadata",
                Some(1.0),
            )
        }),
        used_external_fallback: false,
    })
}

async fn fetch_npm_packument_node(
    context: &CollectContext,
    package: &str,
    encoded: &str,
) -> Result<CollectedNode> {
    let url = format!("{}/{}", context.endpoints.npm_registry_base, encoded);
    let raw = context
        .npm_throttle
        .send_without_shutdown(|| context.http.get(&url).send())
        .await
        .with_context(|| format!("failed to fetch npm packument for {package}"))?
        .error_for_status()
        .with_context(|| format!("npm returned an error for {package}"))?
        .json::<NpmPackument>()
        .await
        .with_context(|| format!("failed to decode npm packument for {package}"))?;

    let latest = raw.dist_tags.latest.context("missing dist-tags.latest")?;
    let version_meta = raw
        .versions
        .get(&latest)
        .with_context(|| format!("missing latest npm version metadata for {package}"))?;

    Ok(CollectedNode {
        direct_popularity: None,
        dependencies: version_meta
            .dependencies
            .keys()
            .map(|name| normalize_package_name(Ecosystem::Npm, name))
            .collect(),
        repository: version_meta.repository.as_ref().and_then(|repository| {
            repo_provenance::extract_package_repository_identity(
                Ecosystem::Npm,
                package,
                &serde_json::json!({ "repository": repository }),
                "collector_registry_metadata",
                Some(1.0),
            )
        }),
        used_external_fallback: false,
    })
}

async fn fetch_pypi_node(context: &CollectContext, package: &str) -> Result<CollectedNode> {
    let encoded = urlencoding::encode(package);
    let url = format!("{}/{}/json", context.endpoints.pypi_project_base, encoded);
    let raw = context
        .pypi_throttle
        .send_without_shutdown(|| context.http.get(&url).send())
        .await
        .with_context(|| format!("failed to fetch PyPI metadata for {package}"))?
        .error_for_status()
        .with_context(|| format!("PyPI returned an error for {package}"))?
        .json::<PypiProjectResponse>()
        .await
        .with_context(|| format!("failed to decode PyPI metadata for {package}"))?;

    let dependencies = raw
        .info
        .requires_dist
        .iter()
        .map(String::as_str)
        .filter_map(parse_pypi_requirement_name)
        .map(|name| normalize_package_name(Ecosystem::Pypi, &name))
        .collect();

    Ok(CollectedNode {
        direct_popularity: None,
        dependencies,
        repository: repo_provenance::extract_package_repository_identity(
            Ecosystem::Pypi,
            package,
            &serde_json::json!({
                "home_page": raw.info.home_page,
                "project_urls": raw.info.project_urls
            }),
            "collector_registry_metadata",
            Some(1.0),
        ),
        used_external_fallback: false,
    })
}

async fn fetch_crates_node(context: &CollectContext, package: &str) -> Result<CollectedNode> {
    match fetch_crates_index_node(context, package).await {
        Ok(node) => Ok(node),
        Err(_) => fetch_crates_api_node(context, package).await,
    }
}

async fn fetch_crates_index_node(context: &CollectContext, package: &str) -> Result<CollectedNode> {
    let index_path = crates_index_path(package);
    let url = format!("{}/{}", context.endpoints.crates_index_base, index_path);
    let body = context
        .crates_throttle
        .send_without_shutdown(|| context.http.get(&url).send())
        .await
        .with_context(|| format!("failed to fetch crates.io sparse index for {package}"))?
        .error_for_status()
        .with_context(|| format!("crates.io sparse index returned an error for {package}"))?
        .text()
        .await
        .with_context(|| format!("failed to read crates.io sparse index for {package}"))?;

    let entry = select_latest_crates_index_entry(&body)
        .with_context(|| format!("missing latest crates.io sparse index entry for {package}"))?;
    let dependencies = entry
        .deps
        .iter()
        .filter(|dependency| {
            dependency
                .kind
                .as_deref()
                .is_none_or(|kind| kind == "normal")
                && !dependency.optional
        })
        .map(|dependency| normalize_package_name(Ecosystem::CratesIo, &dependency.name))
        .collect();

    Ok(CollectedNode {
        direct_popularity: None,
        dependencies,
        repository: None,
        used_external_fallback: false,
    })
}

async fn fetch_crates_api_node(context: &CollectContext, package: &str) -> Result<CollectedNode> {
    let encoded = urlencoding::encode(package);
    let metadata_url = format!("{}/crates/{}", context.endpoints.crates_base, encoded);
    let raw = context
        .crates_throttle
        .send_without_shutdown(|| context.http.get(&metadata_url).send())
        .await
        .with_context(|| format!("failed to fetch crates.io metadata for {package}"))?
        .error_for_status()
        .with_context(|| format!("crates.io returned an error for {package}"))?
        .json::<CratesMetadataResponse>()
        .await
        .with_context(|| format!("failed to decode crates.io metadata for {package}"))?;

    let latest_version = raw
        .krate
        .max_stable_version
        .as_deref()
        .or(raw.krate.max_version.as_deref())
        .context("missing crates.io latest version")?;
    let dependency_url = format!(
        "{}/crates/{}/{}/dependencies",
        context.endpoints.crates_base, encoded, latest_version
    );
    let dependencies_raw = context
        .crates_throttle
        .send_without_shutdown(|| context.http.get(&dependency_url).send())
        .await
        .with_context(|| format!("failed to fetch crates.io dependencies for {package}"))?
        .error_for_status()
        .with_context(|| format!("crates.io dependency endpoint returned an error for {package}"))?
        .json::<CratesDependenciesResponse>()
        .await
        .with_context(|| format!("failed to decode crates.io dependencies for {package}"))?;

    let dependencies = dependencies_raw
        .dependencies
        .iter()
        .filter(|dependency| {
            dependency
                .kind
                .as_deref()
                .is_none_or(|kind| kind == "normal")
                && !dependency.optional
        })
        .map(|dependency| normalize_package_name(Ecosystem::CratesIo, &dependency.crate_id))
        .collect();

    Ok(CollectedNode {
        direct_popularity: raw.krate.downloads,
        dependencies,
        repository: repo_provenance::extract_package_repository_identity(
            Ecosystem::CratesIo,
            package,
            &serde_json::json!({
                "crate": {
                    "repository": raw.krate.repository,
                    "homepage": raw.krate.homepage
                }
            }),
            "collector_registry_metadata",
            Some(1.0),
        ),
        used_external_fallback: false,
    })
}

fn select_latest_crates_index_entry(body: &str) -> Result<CratesIndexEntry> {
    let mut latest_yanked = None;
    for line in body.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<CratesIndexEntry>(line)
            .context("failed to parse crates.io sparse index row")?;
        if !entry.yanked {
            return Ok(entry);
        }
        latest_yanked.get_or_insert(entry);
    }

    latest_yanked.context("crates.io sparse index body did not contain any version rows")
}

fn parse_pypi_requirement_name(requirement: &str) -> Option<String> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return None;
    }

    let mut name = String::new();
    for ch in requirement.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            name.push(ch);
        } else {
            break;
        }
    }

    (!name.is_empty()).then_some(name)
}

fn deps_dev_system(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
        Ecosystem::CratesIo => "cargo",
    }
}

fn crates_index_path(package: &str) -> String {
    let package = package.to_ascii_lowercase();
    match package.len() {
        1 => format!("1/{package}"),
        2 => format!("2/{package}"),
        3 => format!("3/{}/{}", &package[..1], package),
        _ => format!("{}/{}/{}", &package[..2], &package[2..4], package),
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

fn extract_deps_dev_direct_dependencies(
    ecosystem: Ecosystem,
    dependencies_raw: &Value,
) -> Result<Vec<String>> {
    let nodes = dependencies_raw
        .get("nodes")
        .and_then(Value::as_array)
        .context("deps.dev dependency graph missing nodes")?;
    let edges = dependencies_raw
        .get("edges")
        .and_then(Value::as_array)
        .context("deps.dev dependency graph missing edges")?;

    let mut dependencies = BTreeSet::new();
    for edge in edges {
        let from_node = edge
            .get("fromNode")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if from_node != 0 {
            continue;
        }
        let Some(to_node) = edge.get("toNode").and_then(Value::as_u64) else {
            continue;
        };
        let Some(node) = nodes.get(to_node as usize) else {
            continue;
        };
        let Some(name) = node.pointer("/versionKey/name").and_then(Value::as_str) else {
            continue;
        };
        dependencies.insert(normalize_package_name(ecosystem, name));
    }

    Ok(dependencies.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pypi_requirement_names() {
        assert_eq!(
            parse_pypi_requirement_name("requests>=2.0; python_version>'3.11'"),
            Some("requests".to_string())
        );
        assert_eq!(
            parse_pypi_requirement_name("foo-bar[baz]>=1.0"),
            Some("foo-bar".to_string())
        );
        assert_eq!(parse_pypi_requirement_name(""), None);
    }

    #[test]
    fn deps_dev_helpers_select_default_version_and_root_dependencies() {
        let package_raw = serde_json::json!({
            "versions": [
                {"versionKey": {"version": "1.0.0"}},
                {"versionKey": {"version": "1.2.0"}, "isDefault": true}
            ]
        });
        assert_eq!(
            select_deps_dev_default_version(&package_raw),
            Some("1.2.0".to_string())
        );

        let dependencies_raw = serde_json::json!({
            "nodes": [
                {"versionKey": {"name": "root"}},
                {"versionKey": {"name": "dep-a"}},
                {"versionKey": {"name": "dep-b"}},
                {"versionKey": {"name": "dep-c"}}
            ],
            "edges": [
                {"fromNode": 0, "toNode": 1},
                {"fromNode": 0, "toNode": 2},
                {"fromNode": 1, "toNode": 3}
            ]
        });
        assert_eq!(
            extract_deps_dev_direct_dependencies(Ecosystem::Pypi, &dependencies_raw).unwrap(),
            vec!["dep-a".to_string(), "dep-b".to_string()]
        );
    }

    #[test]
    fn computes_crates_index_paths() {
        assert_eq!(crates_index_path("a"), "1/a");
        assert_eq!(crates_index_path("ab"), "2/ab");
        assert_eq!(crates_index_path("abc"), "3/a/abc");
        assert_eq!(crates_index_path("serde"), "se/rd/serde");
    }

    #[test]
    fn selects_latest_non_yanked_crates_index_entry() {
        let body = r#"{"vers":"1.0.0","deps":[],"yanked":false}
{"vers":"1.1.0","deps":[{"name":"dep-a","kind":"normal","optional":false}],"yanked":true}
{"vers":"1.0.9","deps":[{"name":"dep-b","kind":"normal","optional":false}],"yanked":false}"#;

        let entry = select_latest_crates_index_entry(body).unwrap();
        assert_eq!(entry.deps.len(), 1);
        assert_eq!(entry.deps[0].name, "dep-b");
    }

    #[tokio::test]
    async fn collection_merges_seed_popularity_and_edges() {
        let seeds = vec![SeedPackageRecord {
            ecosystem: Ecosystem::Npm,
            package: "consumer-app".to_string(),
            direct_popularity: Some(1000.0),
        }];
        let popularity = vec![SeedPackageRecord {
            ecosystem: Ecosystem::Npm,
            package: "shared-lib".to_string(),
            direct_popularity: Some(50.0),
        }];
        let (records, summary) = collect_score_input_with_fetcher(
            seeds,
            popularity,
            &CollectConfig {
                max_depth: 2,
                max_packages: 10,
                request_concurrency: 4,
                allow_external_fallback: false,
            },
        )
        .unwrap();

        assert_eq!(summary.seed_packages, 1);
        assert_eq!(summary.discovered_packages, 3);
        assert_eq!(summary.emitted_dependency_records, 2);

        let package_records = records
            .iter()
            .filter_map(|record| match record {
                ScoreInputRecord::Package {
                    ecosystem,
                    package,
                    direct_popularity,
                } => Some((*ecosystem, package.clone(), *direct_popularity)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(package_records.contains(&(Ecosystem::Npm, "consumer-app".to_string(), 1000.0)));
        assert!(package_records.contains(&(Ecosystem::Npm, "shared-lib".to_string(), 50.0)));
    }

    fn collect_score_input_with_fetcher(
        seeds: Vec<SeedPackageRecord>,
        popularity: Vec<SeedPackageRecord>,
        config: &CollectConfig,
    ) -> Result<(Vec<ScoreInputRecord>, CollectSummary)> {
        if config.max_packages == 0 {
            anyhow::bail!("max_packages must be greater than zero");
        }

        let mut popularity_map = HashMap::<(Ecosystem, String), f64>::new();
        for record in seeds.iter().chain(popularity.iter()) {
            let normalized = normalize_package_name(record.ecosystem, &record.package);
            let popularity = record.direct_popularity.unwrap_or(0.0).max(0.0);
            popularity_map
                .entry((record.ecosystem, normalized))
                .and_modify(|current| *current = current.max(popularity))
                .or_insert(popularity);
        }

        let seed_packages = seeds.len();
        let mut seen = BTreeSet::new();
        let mut packages = BTreeMap::<(Ecosystem, String), Option<f64>>::new();
        let mut edges = BTreeSet::<(Ecosystem, String, String)>::new();
        let mut fetch_failures = 0usize;
        let external_fallback_fetches = 0usize;
        let mut frontier = seeds
            .into_iter()
            .map(|seed| {
                (
                    seed.ecosystem,
                    normalize_package_name(seed.ecosystem, &seed.package),
                )
            })
            .collect::<Vec<_>>();

        for depth in 0..=config.max_depth {
            if frontier.is_empty() || seen.len() >= config.max_packages {
                break;
            }

            let remaining_capacity = config.max_packages.saturating_sub(seen.len());
            let mut scheduled = Vec::new();
            let mut scheduled_set = BTreeSet::new();
            for (ecosystem, package) in frontier.drain(..) {
                if seen.contains(&(ecosystem, package.clone()))
                    || !scheduled_set.insert((ecosystem, package.clone()))
                {
                    continue;
                }
                if scheduled.len() >= remaining_capacity {
                    break;
                }
                seen.insert((ecosystem, package.clone()));
                scheduled.push((ecosystem, package));
            }

            let mut next_frontier = Vec::new();
            for (ecosystem, package) in scheduled {
                match fetch_node_for_test(ecosystem, &package) {
                    Ok(node) => {
                        let override_popularity =
                            popularity_map.get(&(ecosystem, package.clone())).copied();
                        let direct_popularity = override_popularity.or(node.direct_popularity);
                        packages.insert((ecosystem, package.clone()), direct_popularity);
                        for dependency in node.dependencies {
                            edges.insert((ecosystem, package.clone(), dependency.clone()));
                            if depth < config.max_depth
                                && !seen.contains(&(ecosystem, dependency.clone()))
                            {
                                next_frontier.push((ecosystem, dependency));
                            }
                        }
                    }
                    Err(_) => {
                        fetch_failures += 1;
                    }
                }
            }

            frontier = next_frontier;
        }

        let mut records = Vec::new();
        for ((ecosystem, package), direct_popularity) in &packages {
            records.push(ScoreInputRecord::Package {
                ecosystem: *ecosystem,
                package: package.clone(),
                direct_popularity: direct_popularity.unwrap_or(0.0),
            });
        }
        for (ecosystem, package, dependency) in &edges {
            records.push(ScoreInputRecord::Dependency {
                ecosystem: *ecosystem,
                package: package.clone(),
                dependency: dependency.clone(),
                weight: 1.0,
                sources: vec!["registry_metadata".to_string()],
                confidence: Some(1.0),
            });
        }

        Ok((
            records,
            CollectSummary {
                seed_packages,
                discovered_packages: packages.len(),
                emitted_package_records: packages.len(),
                emitted_dependency_records: edges.len(),
                fetch_failures,
                external_fallback_fetches,
                ecosystems: vec![CollectEcosystemSummary {
                    ecosystem: Ecosystem::Npm,
                    packages: packages.len(),
                    dependencies: edges.len(),
                }],
            },
        ))
    }

    fn fetch_node_for_test(_ecosystem: Ecosystem, package: &str) -> Result<CollectedNode> {
        let node = match package {
            "consumer-app" => CollectedNode {
                direct_popularity: None,
                dependencies: vec!["shared-lib".to_string()],
                repository: None,
                used_external_fallback: false,
            },
            "shared-lib" => CollectedNode {
                direct_popularity: None,
                dependencies: vec!["leaf-lib".to_string()],
                repository: None,
                used_external_fallback: false,
            },
            "leaf-lib" => CollectedNode {
                direct_popularity: None,
                dependencies: Vec::new(),
                repository: None,
                used_external_fallback: false,
            },
            other => anyhow::bail!("unexpected package {other}"),
        };
        Ok(node)
    }
}
