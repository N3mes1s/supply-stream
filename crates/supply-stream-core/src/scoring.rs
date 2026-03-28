use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    event::Ecosystem,
    priority::{
        PriorityCounts, PriorityScoreRecord, PrioritySource, PriorityTier, normalize_package_name,
    },
};

const DEFAULT_EDGE_WEIGHT: f64 = 1.0;
const NPM_NAMESPACE_FARM_MIN_REVERSE_DEPENDENTS: usize = 25;
const NPM_NAMESPACE_FARM_MAX_DIRECT_POPULARITY: f64 = 200.0;
const NPM_NAMESPACE_FARM_MIN_DOMINANT_RATIO: f64 = 0.70;
const NPM_NAMESPACE_FARM_MIN_PENALTY: f64 = 0.02;

#[derive(Debug, Clone)]
pub struct ScoreBuildConfig {
    pub alpha: f64,
    pub max_iterations: usize,
    pub epsilon: f64,
    pub high_quantile: f64,
    pub medium_quantile: f64,
    pub score_source_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScoreBuildSummary {
    pub input_packages: usize,
    pub input_dependencies: usize,
    pub scored_packages: usize,
    pub ecosystems: Vec<EcosystemScoreSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EcosystemScoreSummary {
    pub ecosystem: Ecosystem,
    pub packages: usize,
    pub dependencies: usize,
    pub priorities: PriorityCounts,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScoreInputMergeSummary {
    pub input_files: usize,
    pub input_packages: usize,
    pub input_dependencies: usize,
    pub merged_packages: usize,
    pub merged_dependencies: usize,
    pub ecosystems: Vec<EcosystemInputSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EcosystemInputSummary {
    pub ecosystem: Ecosystem,
    pub packages: usize,
    pub dependencies: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScoreInputRecord {
    Package {
        ecosystem: Ecosystem,
        package: String,
        direct_popularity: f64,
    },
    Dependency {
        ecosystem: Ecosystem,
        package: String,
        dependency: String,
        #[serde(default = "default_edge_weight")]
        weight: f64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sources: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<f64>,
    },
}

#[derive(Debug, Clone, Default)]
struct PackageNode {
    direct_popularity: f64,
}

#[derive(Debug, Clone, Default)]
struct EdgeRecord {
    weight: f64,
    sources: BTreeSet<String>,
    confidence: Option<f64>,
}

#[derive(Debug, Clone, Default)]
struct EcosystemGraph {
    packages: BTreeMap<String, PackageNode>,
    dependency_weights: BTreeMap<String, BTreeMap<String, EdgeRecord>>,
    input_package_records: usize,
    input_dependency_records: usize,
}

pub async fn merge_score_input_files(
    inputs: &[PathBuf],
) -> Result<(Vec<ScoreInputRecord>, ScoreInputMergeSummary)> {
    let mut bodies = Vec::with_capacity(inputs.len());
    for input in inputs {
        bodies.push(
            tokio::fs::read_to_string(input)
                .await
                .with_context(|| format!("failed to read scoring input {}", input.display()))?,
        );
    }
    merge_score_input_ndjson(
        &bodies.iter().map(String::as_str).collect::<Vec<_>>(),
        inputs.len(),
    )
}

pub async fn load_score_input_records(path: &Path) -> Result<Vec<ScoreInputRecord>> {
    let body = match tokio::fs::read_to_string(path).await {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read scoring input {}", path.display()));
        }
    };

    let mut records = Vec::new();
    for (line_number, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<ScoreInputRecord>(line).with_context(|| {
            format!(
                "failed to parse scoring input line {} from {}",
                line_number + 1,
                path.display()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

pub fn encode_score_input_ndjson(records: &[ScoreInputRecord]) -> Result<String> {
    let mut body = String::new();
    for record in records {
        body.push_str(
            &serde_json::to_string(record).context("failed to encode scoring input record")?,
        );
        body.push('\n');
    }
    Ok(body)
}

pub async fn write_score_input_records(path: &Path, records: &[ScoreInputRecord]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let body = encode_score_input_ndjson(records)?;
    tokio::fs::write(path, body)
        .await
        .with_context(|| format!("failed to write scoring input {}", path.display()))
}

pub fn merge_score_input_ndjson(
    inputs: &[&str],
    input_files: usize,
) -> Result<(Vec<ScoreInputRecord>, ScoreInputMergeSummary)> {
    let mut graphs: HashMap<Ecosystem, EcosystemGraph> = HashMap::new();
    let mut input_packages = 0usize;
    let mut input_dependencies = 0usize;

    for body in inputs {
        for (line_number, line) in body.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let record = serde_json::from_str::<ScoreInputRecord>(line).with_context(|| {
                format!("failed to parse scoring input line {}", line_number + 1)
            })?;
            match record {
                ScoreInputRecord::Package {
                    ecosystem,
                    package,
                    direct_popularity,
                } => {
                    let graph = graphs.entry(ecosystem).or_default();
                    let package = normalize_package_name(ecosystem, &package);
                    let popularity = direct_popularity.max(0.0);
                    let node = graph.packages.entry(package).or_default();
                    node.direct_popularity = node.direct_popularity.max(popularity);
                    graph.input_package_records += 1;
                    input_packages += 1;
                }
                ScoreInputRecord::Dependency {
                    ecosystem,
                    package,
                    dependency,
                    weight,
                    sources,
                    confidence,
                } => {
                    let graph = graphs.entry(ecosystem).or_default();
                    let package = normalize_package_name(ecosystem, &package);
                    let dependency = normalize_package_name(ecosystem, &dependency);
                    graph.packages.entry(package.clone()).or_default();
                    graph.packages.entry(dependency.clone()).or_default();
                    let edge = graph
                        .dependency_weights
                        .entry(package)
                        .or_default()
                        .entry(dependency)
                        .or_default();
                    edge.weight = edge.weight.max(weight.max(0.0));
                    merge_edge_sources(&mut edge.sources, sources);
                    edge.confidence = max_confidence(edge.confidence, confidence);
                    graph.input_dependency_records += 1;
                    input_dependencies += 1;
                }
            }
        }
    }

    let mut records = Vec::new();
    let mut ecosystems = Vec::new();

    for ecosystem in [Ecosystem::Npm, Ecosystem::Pypi, Ecosystem::CratesIo] {
        let Some(graph) = graphs.get(&ecosystem) else {
            continue;
        };
        ecosystems.push(EcosystemInputSummary {
            ecosystem,
            packages: graph.packages.len(),
            dependencies: graph
                .dependency_weights
                .values()
                .map(BTreeMap::len)
                .sum::<usize>(),
        });
        for (package, node) in &graph.packages {
            records.push(ScoreInputRecord::Package {
                ecosystem,
                package: package.clone(),
                direct_popularity: node.direct_popularity,
            });
        }
        for (package, dependencies) in &graph.dependency_weights {
            for (dependency, edge) in dependencies {
                records.push(ScoreInputRecord::Dependency {
                    ecosystem,
                    package: package.clone(),
                    dependency: dependency.clone(),
                    weight: edge.weight,
                    sources: edge.sources.iter().cloned().collect(),
                    confidence: edge.confidence,
                });
            }
        }
    }

    Ok((
        records,
        ScoreInputMergeSummary {
            input_files,
            input_packages,
            input_dependencies,
            merged_packages: ecosystems.iter().map(|ecosystem| ecosystem.packages).sum(),
            merged_dependencies: ecosystems
                .iter()
                .map(|ecosystem| ecosystem.dependencies)
                .sum(),
            ecosystems,
        },
    ))
}

pub async fn build_priority_scores_from_file(
    input: &Path,
    config: &ScoreBuildConfig,
) -> Result<(Vec<PriorityScoreRecord>, ScoreBuildSummary)> {
    validate_config(config)?;
    let body = tokio::fs::read_to_string(input)
        .await
        .with_context(|| format!("failed to read scoring input {}", input.display()))?;
    build_priority_scores_from_ndjson(&body, config)
}

pub fn build_priority_scores_from_ndjson(
    input: &str,
    config: &ScoreBuildConfig,
) -> Result<(Vec<PriorityScoreRecord>, ScoreBuildSummary)> {
    validate_config(config)?;
    let mut graphs: HashMap<Ecosystem, EcosystemGraph> = HashMap::new();
    let mut input_packages = 0usize;
    let mut input_dependencies = 0usize;

    for (line_number, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<ScoreInputRecord>(line)
            .with_context(|| format!("failed to parse scoring input line {}", line_number + 1))?;
        match record {
            ScoreInputRecord::Package {
                ecosystem,
                package,
                direct_popularity,
            } => {
                let graph = graphs.entry(ecosystem).or_default();
                let package = normalize_package_name(ecosystem, &package);
                graph.packages.entry(package).or_default().direct_popularity +=
                    direct_popularity.max(0.0);
                graph.input_package_records += 1;
                input_packages += 1;
            }
            ScoreInputRecord::Dependency {
                ecosystem,
                package,
                dependency,
                weight,
                sources,
                confidence,
            } => {
                let weight = weight.max(0.0);
                let graph = graphs.entry(ecosystem).or_default();
                let package = normalize_package_name(ecosystem, &package);
                let dependency = normalize_package_name(ecosystem, &dependency);
                graph.packages.entry(package.clone()).or_default();
                graph.packages.entry(dependency.clone()).or_default();
                let edge = graph
                    .dependency_weights
                    .entry(package)
                    .or_default()
                    .entry(dependency)
                    .or_default();
                edge.weight += weight;
                merge_edge_sources(&mut edge.sources, sources);
                edge.confidence = max_confidence(edge.confidence, confidence);
                graph.input_dependency_records += 1;
                input_dependencies += 1;
            }
        }
    }

    let computed_at = Utc::now();
    let mut scores = Vec::new();
    let mut ecosystems = Vec::new();

    for ecosystem in [Ecosystem::Npm, Ecosystem::Pypi, Ecosystem::CratesIo] {
        let Some(graph) = graphs.get(&ecosystem) else {
            continue;
        };
        let ecosystem_scores = score_ecosystem(ecosystem, graph, config, computed_at);
        ecosystems.push(EcosystemScoreSummary {
            ecosystem,
            packages: ecosystem_scores.len(),
            dependencies: graph.input_dependency_records,
            priorities: count_priorities(&ecosystem_scores),
        });
        scores.extend(ecosystem_scores);
    }

    scores.sort_by(|left, right| {
        left.ecosystem
            .cmp(&right.ecosystem)
            .then_with(|| {
                right
                    .propagated_impact
                    .unwrap_or_default()
                    .total_cmp(&left.propagated_impact.unwrap_or_default())
            })
            .then_with(|| left.package.cmp(&right.package))
    });

    Ok((
        scores.clone(),
        ScoreBuildSummary {
            input_packages,
            input_dependencies,
            scored_packages: scores.len(),
            ecosystems,
        },
    ))
}

pub fn build_priority_scores_from_records(
    records: &[ScoreInputRecord],
    config: &ScoreBuildConfig,
) -> Result<(Vec<PriorityScoreRecord>, ScoreBuildSummary)> {
    let body = encode_score_input_ndjson(records)?;
    build_priority_scores_from_ndjson(&body, config)
}

fn score_ecosystem(
    ecosystem: Ecosystem,
    graph: &EcosystemGraph,
    config: &ScoreBuildConfig,
    computed_at: chrono::DateTime<Utc>,
) -> Vec<PriorityScoreRecord> {
    let direct = graph
        .packages
        .iter()
        .map(|(package, node)| (package.clone(), node.direct_popularity))
        .collect::<HashMap<_, _>>();
    let mut impact = direct.clone();

    for _ in 0..config.max_iterations {
        let mut next = direct.clone();
        for (package, dependencies) in &graph.dependency_weights {
            let package_impact = impact.get(package).copied().unwrap_or_default();
            if package_impact <= 0.0 {
                continue;
            }
            let total_weight = dependencies.values().map(|edge| edge.weight).sum::<f64>();
            if total_weight <= 0.0 {
                continue;
            }
            for (dependency, edge) in dependencies {
                let contribution = config.alpha * package_impact * (edge.weight / total_weight);
                *next.entry(dependency.clone()).or_insert(0.0) += contribution;
            }
        }

        let max_delta = next
            .iter()
            .map(|(package, next_value)| {
                let current = impact.get(package).copied().unwrap_or_default();
                (next_value - current).abs()
            })
            .fold(0.0, f64::max);
        impact = next;
        if max_delta <= config.epsilon {
            break;
        }
    }

    apply_structural_guardrails(ecosystem, graph, &direct, &mut impact);

    let hidden = graph
        .packages
        .keys()
        .map(|package| {
            let direct_value = direct.get(package).copied().unwrap_or_default();
            let impact_value = impact.get(package).copied().unwrap_or_default();
            (
                package.clone(),
                ((impact_value + 1.0).ln() - (direct_value + 1.0).ln()).max(0.0),
            )
        })
        .collect::<HashMap<_, _>>();

    let high_rank_limit = top_bucket_size(graph.packages.len(), config.high_quantile);
    let medium_rank_limit = top_bucket_size(graph.packages.len(), config.medium_quantile);
    let impact_ranks = descending_rank_map(&impact);
    let hidden_ranks = descending_rank_map(&hidden);

    graph
        .packages
        .keys()
        .map(|package| {
            let direct_popularity = direct.get(package).copied().unwrap_or_default();
            let propagated_impact = impact.get(package).copied().unwrap_or_default();
            let hidden_leverage = hidden.get(package).copied().unwrap_or_default();
            let impact_rank = impact_ranks.get(package).copied().unwrap_or(usize::MAX);
            let hidden_rank = hidden_ranks.get(package).copied().unwrap_or(usize::MAX);
            let priority_tier = if impact_rank < high_rank_limit || hidden_rank < high_rank_limit {
                PriorityTier::High
            } else if impact_rank < medium_rank_limit || hidden_rank < medium_rank_limit {
                PriorityTier::Medium
            } else {
                PriorityTier::Low
            };

            PriorityScoreRecord {
                ecosystem,
                package: package.clone(),
                priority_tier,
                priority_source: Some(PrioritySource::OfflineScoreFile),
                direct_popularity: Some(direct_popularity),
                propagated_impact: Some(propagated_impact),
                hidden_leverage: Some(hidden_leverage),
                computed_at: Some(computed_at),
                score_source_version: config.score_source_version.clone(),
            }
        })
        .collect()
}

fn apply_structural_guardrails(
    ecosystem: Ecosystem,
    graph: &EcosystemGraph,
    direct: &HashMap<String, f64>,
    impact: &mut HashMap<String, f64>,
) {
    if ecosystem != Ecosystem::Npm {
        return;
    }

    let reverse_dependents = build_reverse_dependents(graph);
    for (package, dependents) in reverse_dependents {
        let direct_popularity = direct.get(&package).copied().unwrap_or_default();
        if direct_popularity > NPM_NAMESPACE_FARM_MAX_DIRECT_POPULARITY
            || dependents.len() < NPM_NAMESPACE_FARM_MIN_REVERSE_DEPENDENTS
        {
            continue;
        }

        let Some(dominant_ratio) = dominant_npm_namespace_ratio(&dependents) else {
            continue;
        };
        if dominant_ratio < NPM_NAMESPACE_FARM_MIN_DOMINANT_RATIO {
            continue;
        }

        let popularity_factor =
            (direct_popularity / NPM_NAMESPACE_FARM_MAX_DIRECT_POPULARITY).clamp(0.0, 1.0);
        let concentration_factor = (1.0
            - (dominant_ratio - NPM_NAMESPACE_FARM_MIN_DOMINANT_RATIO)
                / (1.0 - NPM_NAMESPACE_FARM_MIN_DOMINANT_RATIO))
            .clamp(0.0, 1.0);
        let penalty =
            (popularity_factor * concentration_factor).clamp(NPM_NAMESPACE_FARM_MIN_PENALTY, 1.0);
        if penalty >= 1.0 {
            continue;
        }

        if let Some(current) = impact.get_mut(&package) {
            *current *= penalty;
        }
    }
}

fn build_reverse_dependents(graph: &EcosystemGraph) -> HashMap<String, Vec<String>> {
    let mut reverse = HashMap::<String, Vec<String>>::new();
    for (package, dependencies) in &graph.dependency_weights {
        for dependency in dependencies.keys() {
            reverse
                .entry(dependency.clone())
                .or_default()
                .push(package.clone());
        }
    }
    reverse
}

fn dominant_npm_namespace_ratio(dependents: &[String]) -> Option<f64> {
    let mut namespaces = HashMap::<String, usize>::new();
    for dependent in dependents {
        let Some(namespace) = npm_namespace(dependent) else {
            continue;
        };
        *namespaces.entry(namespace).or_default() += 1;
    }
    let dominant = namespaces.into_values().max()?;
    Some(dominant as f64 / dependents.len() as f64)
}

fn npm_namespace(package: &str) -> Option<String> {
    let base = package.split('>').next().unwrap_or(package).trim();
    if !base.starts_with('@') {
        return None;
    }
    let mut segments = base.split('/');
    let scope = segments.next()?;
    Some(scope.to_string())
}

fn count_priorities(scores: &[PriorityScoreRecord]) -> PriorityCounts {
    let mut counts = PriorityCounts::default();
    for score in scores {
        match score.priority_tier {
            PriorityTier::High => counts.high += 1,
            PriorityTier::Medium => counts.medium += 1,
            PriorityTier::Low => counts.low += 1,
        }
    }
    counts
}

fn top_bucket_size(total: usize, quantile: f64) -> usize {
    if total == 0 {
        return 0;
    }

    let quantile = quantile.clamp(0.0, 1.0);
    if quantile >= 1.0 {
        return 1;
    }

    total.saturating_sub(((total as f64) * quantile).floor() as usize)
}

fn descending_rank_map(values: &HashMap<String, f64>) -> HashMap<String, usize> {
    let mut ranked = values
        .iter()
        .map(|(package, value)| (package.clone(), *value))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });

    ranked
        .into_iter()
        .enumerate()
        .map(|(index, (package, _))| (package, index))
        .collect()
}

fn validate_config(config: &ScoreBuildConfig) -> Result<()> {
    if !(0.0..1.0).contains(&config.alpha) {
        anyhow::bail!("alpha must be >= 0.0 and < 1.0");
    }
    if config.max_iterations == 0 {
        anyhow::bail!("max_iterations must be greater than zero");
    }
    if config.epsilon < 0.0 {
        anyhow::bail!("epsilon must be >= 0.0");
    }
    if !(0.0..=1.0).contains(&config.high_quantile) {
        anyhow::bail!("high_quantile must be between 0.0 and 1.0");
    }
    if !(0.0..=1.0).contains(&config.medium_quantile) {
        anyhow::bail!("medium_quantile must be between 0.0 and 1.0");
    }
    if config.medium_quantile > config.high_quantile {
        anyhow::bail!("medium_quantile must be <= high_quantile");
    }
    Ok(())
}

fn default_edge_weight() -> f64 {
    DEFAULT_EDGE_WEIGHT
}

fn merge_edge_sources(target: &mut BTreeSet<String>, sources: Vec<String>) {
    target.extend(
        sources
            .into_iter()
            .map(|source| source.trim().to_string())
            .filter(|source| !source.is_empty()),
    );
}

fn max_confidence(current: Option<f64>, next: Option<f64>) -> Option<f64> {
    match (current, next) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoring_builds_hidden_leverage_from_reverse_dependencies() {
        let input = r#"
{"type":"package","ecosystem":"npm","package":"app","direct_popularity":1000}
{"type":"package","ecosystem":"npm","package":"shared-lib","direct_popularity":10}
{"type":"package","ecosystem":"npm","package":"leaf-lib","direct_popularity":1}
{"type":"dependency","ecosystem":"npm","package":"app","dependency":"shared-lib","weight":1.0}
{"type":"dependency","ecosystem":"npm","package":"shared-lib","dependency":"leaf-lib","weight":1.0}
"#;
        let (scores, summary) = build_priority_scores_from_ndjson(
            input,
            &ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-9,
                high_quantile: 0.99,
                medium_quantile: 0.5,
                score_source_version: Some("test".to_string()),
            },
        )
        .unwrap();

        assert_eq!(summary.input_packages, 3);
        assert_eq!(summary.input_dependencies, 2);
        assert_eq!(summary.scored_packages, 3);

        let by_name = scores
            .into_iter()
            .map(|score| (score.package.clone(), score))
            .collect::<HashMap<_, _>>();

        let app = by_name.get("app").unwrap();
        let shared = by_name.get("shared-lib").unwrap();
        let leaf = by_name.get("leaf-lib").unwrap();

        assert_eq!(app.direct_popularity, Some(1000.0));
        assert_eq!(app.propagated_impact, Some(1000.0));
        assert!(shared.propagated_impact.unwrap() > shared.direct_popularity.unwrap());
        assert!(leaf.propagated_impact.unwrap() > leaf.direct_popularity.unwrap());
        assert!(shared.hidden_leverage.unwrap() > 0.0);
        assert!(leaf.hidden_leverage.unwrap() > 0.0);
    }

    #[test]
    fn scoring_normalizes_package_names_and_emits_tiers() {
        let input = r#"
{"type":"package","ecosystem":"pypi","package":"My_Package.Name","direct_popularity":100}
{"type":"package","ecosystem":"pypi","package":"consumer","direct_popularity":10000}
{"type":"dependency","ecosystem":"pypi","package":"consumer","dependency":"my-package-name","weight":1.0}
"#;
        let (scores, summary) = build_priority_scores_from_ndjson(
            input,
            &ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-9,
                high_quantile: 0.5,
                medium_quantile: 0.0,
                score_source_version: None,
            },
        )
        .unwrap();

        assert_eq!(summary.ecosystems.len(), 1);
        let package = scores
            .iter()
            .find(|score| score.package == "my-package-name")
            .unwrap();
        assert!(matches!(
            package.priority_tier,
            PriorityTier::High | PriorityTier::Medium
        ));
    }

    #[test]
    fn scoring_uses_rank_buckets_when_quantiles_collapse() {
        let mut input = String::new();
        for index in 0..100 {
            input.push_str(&format!(
                "{{\"type\":\"package\",\"ecosystem\":\"pypi\",\"package\":\"pkg-{index}\",\"direct_popularity\":1}}\n"
            ));
        }

        let (scores, summary) = build_priority_scores_from_ndjson(
            &input,
            &ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-9,
                high_quantile: 0.99,
                medium_quantile: 0.90,
                score_source_version: None,
            },
        )
        .unwrap();

        assert_eq!(summary.scored_packages, 100);
        assert_eq!(summary.ecosystems.len(), 1);
        assert_eq!(summary.ecosystems[0].priorities.high, 1);
        assert_eq!(summary.ecosystems[0].priorities.medium, 9);
        assert_eq!(summary.ecosystems[0].priorities.low, 90);

        let first = scores
            .iter()
            .find(|score| score.package == "pkg-0")
            .unwrap();
        assert_eq!(first.priority_tier, PriorityTier::High);
    }

    #[test]
    fn merge_score_input_keeps_strongest_popularity_and_dedupes_edges() {
        let input_a = r#"
{"type":"package","ecosystem":"npm","package":"shared-lib","direct_popularity":10}
{"type":"dependency","ecosystem":"npm","package":"app","dependency":"shared-lib","weight":1.0,"sources":["capture_metadata"],"confidence":1.0}
"#;
        let input_b = r#"
{"type":"package","ecosystem":"npm","package":"shared-lib","direct_popularity":100}
{"type":"dependency","ecosystem":"npm","package":"app","dependency":"shared-lib","weight":0.5,"sources":["deps_dev_export"],"confidence":0.8}
{"type":"dependency","ecosystem":"npm","package":"app","dependency":"shared-lib","weight":2.0,"sources":["registry_metadata"],"confidence":0.9}
"#;

        let (records, summary) = merge_score_input_ndjson(&[input_a, input_b], 2).unwrap();
        assert_eq!(summary.input_files, 2);
        assert_eq!(summary.input_packages, 2);
        assert_eq!(summary.input_dependencies, 3);
        assert_eq!(summary.merged_packages, 2);
        assert_eq!(summary.merged_dependencies, 1);

        let shared = records.iter().find_map(|record| match record {
            ScoreInputRecord::Package {
                ecosystem,
                package,
                direct_popularity,
            } if *ecosystem == Ecosystem::Npm && package == "shared-lib" => {
                Some(*direct_popularity)
            }
            _ => None,
        });
        assert_eq!(shared, Some(100.0));

        let edge = records.iter().find_map(|record| match record {
            ScoreInputRecord::Dependency {
                ecosystem,
                package,
                dependency,
                weight,
                sources,
                confidence,
            } if *ecosystem == Ecosystem::Npm && package == "app" && dependency == "shared-lib" => {
                Some((*weight, sources.clone(), *confidence))
            }
            _ => None,
        });
        assert_eq!(edge.as_ref().map(|value| value.0), Some(2.0));
        let (_, sources, confidence) = edge.unwrap();
        assert_eq!(
            sources,
            vec![
                "capture_metadata".to_string(),
                "deps_dev_export".to_string(),
                "registry_metadata".to_string()
            ]
        );
        assert_eq!(confidence, Some(1.0));
    }

    #[test]
    fn scoring_penalizes_low_popularity_npm_namespace_farms() {
        let mut input = String::from(
            r#"
{"type":"package","ecosystem":"npm","package":"legit-core","direct_popularity":1000}
{"type":"package","ecosystem":"npm","package":"farm-core","direct_popularity":80}
"#,
        );
        for index in 0..40 {
            input.push_str(&format!(
                "{{\"type\":\"package\",\"ecosystem\":\"npm\",\"package\":\"@farm/pkg-{index}\",\"direct_popularity\":82}}\n"
            ));
            input.push_str(&format!(
                "{{\"type\":\"dependency\",\"ecosystem\":\"npm\",\"package\":\"@farm/pkg-{index}\",\"dependency\":\"farm-core\",\"weight\":1.0}}\n"
            ));
        }

        let (scores, _) = build_priority_scores_from_ndjson(
            &input,
            &ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-9,
                high_quantile: 0.99,
                medium_quantile: 0.9,
                score_source_version: None,
            },
        )
        .unwrap();

        let by_name = scores
            .into_iter()
            .map(|score| (score.package.clone(), score))
            .collect::<HashMap<_, _>>();

        let legit = by_name.get("legit-core").unwrap();
        let farm = by_name.get("farm-core").unwrap();
        assert!(legit.propagated_impact.unwrap() > farm.propagated_impact.unwrap());
    }

    #[test]
    fn scoring_preserves_diversified_high_popularity_npm_hubs() {
        let mut input = String::from(
            r#"
{"type":"package","ecosystem":"npm","package":"hub-core","direct_popularity":1000}
"#,
        );
        for index in 0..30 {
            input.push_str(&format!(
                "{{\"type\":\"package\",\"ecosystem\":\"npm\",\"package\":\"@scope-{index}/pkg\",\"direct_popularity\":90}}\n"
            ));
            input.push_str(&format!(
                "{{\"type\":\"dependency\",\"ecosystem\":\"npm\",\"package\":\"@scope-{index}/pkg\",\"dependency\":\"hub-core\",\"weight\":1.0}}\n"
            ));
        }

        let (scores, _) = build_priority_scores_from_ndjson(
            &input,
            &ScoreBuildConfig {
                alpha: 0.85,
                max_iterations: 64,
                epsilon: 1e-9,
                high_quantile: 0.99,
                medium_quantile: 0.9,
                score_source_version: None,
            },
        )
        .unwrap();

        let by_name = scores
            .into_iter()
            .map(|score| (score.package.clone(), score))
            .collect::<HashMap<_, _>>();

        let hub = by_name.get("hub-core").unwrap();
        assert!(hub.propagated_impact.unwrap() > 1000.0);
        assert!(hub.hidden_leverage.unwrap() > 0.0);
    }
}
