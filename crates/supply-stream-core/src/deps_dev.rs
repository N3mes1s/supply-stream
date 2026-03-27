use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::{
    collector::SeedPackageRecord, event::Ecosystem, priority::normalize_package_name,
    scoring::ScoreInputRecord,
};

#[derive(Debug, Clone)]
pub struct ImportDependentsConfig {
    pub default_direct_popularity: f64,
    pub include_indirect: bool,
    pub include_non_highest_dependent_releases: bool,
    pub direct_popularity_strategy: DirectPopularityStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPopularityStrategy {
    Constant,
    DirectDependentCount,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportDependentsSummary {
    pub input_files: usize,
    pub input_rows: usize,
    pub imported_rows: usize,
    pub skipped_unsupported_system_rows: usize,
    pub skipped_indirect_rows: usize,
    pub skipped_non_highest_rows: usize,
    pub emitted_package_records: usize,
    pub emitted_dependency_records: usize,
}

#[derive(Debug, Clone)]
pub struct FocusDependentsConfig {
    pub reverse_depth: usize,
    pub max_frontier_packages: usize,
    pub include_non_highest_dependent_releases: bool,
    pub default_direct_popularity: f64,
    pub direct_popularity_strategy: DirectPopularityStrategy,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FocusDependentsSummary {
    pub input_files: usize,
    pub input_rows: usize,
    pub matched_rows: usize,
    pub reverse_depth: usize,
    pub frontier_packages: usize,
    pub frontier_truncated: bool,
    pub emitted_package_records: usize,
    pub emitted_dependency_records: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct DependentsLatestRow {
    #[serde(alias = "System", alias = "system")]
    system: String,
    #[serde(alias = "Name", alias = "name")]
    name: String,
    #[serde(alias = "Version", alias = "version")]
    _version: Option<String>,
    #[serde(alias = "Dependent", alias = "dependent")]
    dependent: DependentsVersionKey,
    #[serde(alias = "MinimumDepth", alias = "minimum_depth")]
    minimum_depth: Option<u64>,
    #[serde(
        alias = "DependentIsHighestReleaseWithResolution",
        alias = "dependent_is_highest_release_with_resolution"
    )]
    dependent_is_highest_release_with_resolution: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct DependentsVersionKey {
    #[serde(alias = "System", alias = "system")]
    system: String,
    #[serde(alias = "Name", alias = "name")]
    name: String,
    #[serde(alias = "Version", alias = "version")]
    _version: Option<String>,
}

pub async fn import_dependents_latest_from_file(
    input: &Path,
    config: &ImportDependentsConfig,
) -> Result<(Vec<ScoreInputRecord>, ImportDependentsSummary)> {
    import_dependents_latest_from_paths(&[input.to_path_buf()], config).await
}

pub async fn import_dependents_latest_from_paths(
    inputs: &[std::path::PathBuf],
    config: &ImportDependentsConfig,
) -> Result<(Vec<ScoreInputRecord>, ImportDependentsSummary)> {
    let files = collect_input_files(inputs).await?;
    let mut bodies = Vec::with_capacity(files.len());
    for input in &files {
        bodies.push(read_input_body(input).await?);
    }
    import_dependents_latest_from_inputs(
        &bodies.iter().map(String::as_str).collect::<Vec<_>>(),
        files.len(),
        config,
    )
}

pub fn import_dependents_latest_from_ndjson(
    input: &str,
    config: &ImportDependentsConfig,
) -> Result<(Vec<ScoreInputRecord>, ImportDependentsSummary)> {
    import_dependents_latest_from_inputs(&[input], 1, config)
}

pub fn import_dependents_latest_from_inputs(
    inputs: &[&str],
    input_files: usize,
    config: &ImportDependentsConfig,
) -> Result<(Vec<ScoreInputRecord>, ImportDependentsSummary)> {
    if config.default_direct_popularity < 0.0 {
        anyhow::bail!("default_direct_popularity must be >= 0.0");
    }

    let mut packages = BTreeSet::<(Ecosystem, String)>::new();
    let mut edges = BTreeSet::<(Ecosystem, String, String)>::new();
    let mut summary = ImportDependentsSummary {
        input_files,
        input_rows: 0,
        imported_rows: 0,
        skipped_unsupported_system_rows: 0,
        skipped_indirect_rows: 0,
        skipped_non_highest_rows: 0,
        emitted_package_records: 0,
        emitted_dependency_records: 0,
    };

    for input in inputs {
        for (line_number, line) in input.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            summary.input_rows += 1;
            let row = serde_json::from_str::<DependentsLatestRow>(line).with_context(|| {
                format!(
                    "failed to parse deps.dev dependents row {}",
                    line_number + 1
                )
            })?;

            let Some(ecosystem) = parse_deps_dev_system(&row.system) else {
                summary.skipped_unsupported_system_rows += 1;
                continue;
            };
            let Some(dependent_ecosystem) = parse_deps_dev_system(&row.dependent.system) else {
                summary.skipped_unsupported_system_rows += 1;
                continue;
            };
            if dependent_ecosystem != ecosystem {
                summary.skipped_unsupported_system_rows += 1;
                continue;
            }
            if !config.include_indirect && row.minimum_depth.unwrap_or(0) != 1 {
                summary.skipped_indirect_rows += 1;
                continue;
            }
            if !config.include_non_highest_dependent_releases
                && row
                    .dependent_is_highest_release_with_resolution
                    .is_some_and(|value| !value)
            {
                summary.skipped_non_highest_rows += 1;
                continue;
            }

            summary.imported_rows += 1;
            let package = normalize_package_name(ecosystem, &row.name);
            let dependent = normalize_package_name(ecosystem, &row.dependent.name);
            packages.insert((ecosystem, package.clone()));
            packages.insert((ecosystem, dependent.clone()));
            if dependent != package {
                edges.insert((ecosystem, dependent, package));
            }
        }
    }

    let mut dependent_counts = BTreeMap::<(Ecosystem, String), usize>::new();
    for (ecosystem, _, dependency) in &edges {
        *dependent_counts
            .entry((*ecosystem, dependency.clone()))
            .or_default() += 1;
    }

    let mut records = Vec::with_capacity(packages.len() + edges.len());
    for (ecosystem, package) in &packages {
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
            sources: vec!["deps_dev_export".to_string()],
            confidence: Some(0.8),
        });
    }

    summary.emitted_package_records = packages.len();
    summary.emitted_dependency_records = edges.len();
    Ok((records, summary))
}

pub async fn focus_dependents_subgraph_from_paths(
    inputs: &[std::path::PathBuf],
    ecosystem: Ecosystem,
    package: &str,
    config: &FocusDependentsConfig,
) -> Result<(
    Vec<ScoreInputRecord>,
    Vec<SeedPackageRecord>,
    FocusDependentsSummary,
)> {
    let files = collect_input_files(inputs).await?;
    let mut bodies = Vec::with_capacity(files.len());
    for input in &files {
        bodies.push(read_input_body(input).await?);
    }
    focus_dependents_subgraph_from_inputs(
        &bodies.iter().map(String::as_str).collect::<Vec<_>>(),
        files.len(),
        ecosystem,
        package,
        config,
    )
}

pub fn focus_dependents_subgraph_from_inputs(
    inputs: &[&str],
    input_files: usize,
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
    let mut reverse_edges = BTreeMap::<String, BTreeSet<String>>::new();
    let mut dependent_counts = BTreeMap::<String, usize>::new();
    let mut summary = FocusDependentsSummary {
        input_files,
        input_rows: 0,
        matched_rows: 0,
        reverse_depth: config.reverse_depth,
        frontier_packages: 0,
        frontier_truncated: false,
        emitted_package_records: 0,
        emitted_dependency_records: 0,
    };

    for input in inputs {
        for (line_number, line) in input.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            summary.input_rows += 1;
            let row = serde_json::from_str::<DependentsLatestRow>(line).with_context(|| {
                format!(
                    "failed to parse deps.dev dependents row {}",
                    line_number + 1
                )
            })?;

            let Some(row_ecosystem) = parse_deps_dev_system(&row.system) else {
                continue;
            };
            let Some(dependent_ecosystem) = parse_deps_dev_system(&row.dependent.system) else {
                continue;
            };
            if row_ecosystem != ecosystem || dependent_ecosystem != ecosystem {
                continue;
            }
            if row.minimum_depth.unwrap_or(0) != 1 {
                continue;
            }
            if !config.include_non_highest_dependent_releases
                && row
                    .dependent_is_highest_release_with_resolution
                    .is_some_and(|value| !value)
            {
                continue;
            }

            summary.matched_rows += 1;
            let dependency = normalize_package_name(ecosystem, &row.name);
            let dependent = normalize_package_name(ecosystem, &row.dependent.name);
            if dependency == dependent {
                continue;
            }
            reverse_edges
                .entry(dependency.clone())
                .or_default()
                .insert(dependent.clone());
            *dependent_counts.entry(dependency).or_default() += 1;
        }
    }

    let mut visited = BTreeSet::new();
    visited.insert(target.clone());
    let mut queue = VecDeque::from([(target.clone(), 0usize)]);

    while let Some((dependency, depth)) = queue.pop_front() {
        if depth >= config.reverse_depth {
            continue;
        }
        let Some(dependents) = reverse_edges.get(&dependency) else {
            continue;
        };
        for dependent in dependents {
            if visited.len() >= config.max_frontier_packages && !visited.contains(dependent) {
                summary.frontier_truncated = true;
                break;
            }
            if visited.insert(dependent.clone()) {
                queue.push_back((dependent.clone(), depth + 1));
            }
        }
        if summary.frontier_truncated {
            break;
        }
    }

    let mut records = Vec::new();
    let mut seeds = Vec::new();
    for package in &visited {
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

    let mut edge_count = 0usize;
    for dependency in &visited {
        if let Some(dependents) = reverse_edges.get(dependency) {
            for dependent in dependents {
                if visited.contains(dependent) {
                    records.push(ScoreInputRecord::Dependency {
                        ecosystem,
                        package: dependent.clone(),
                        dependency: dependency.clone(),
                        weight: 1.0,
                        sources: vec!["deps_dev_export".to_string()],
                        confidence: Some(0.8),
                    });
                    edge_count += 1;
                }
            }
        }
    }

    summary.frontier_packages = visited.len();
    summary.emitted_package_records = visited.len();
    summary.emitted_dependency_records = edge_count;
    Ok((records, seeds, summary))
}

async fn collect_input_files(inputs: &[std::path::PathBuf]) -> Result<Vec<std::path::PathBuf>> {
    let mut files = BTreeSet::new();
    for input in inputs {
        if input.is_dir() {
            let mut entries = tokio::fs::read_dir(input)
                .await
                .with_context(|| format!("failed to read directory {}", input.display()))?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .with_context(|| format!("failed to read directory entry in {}", input.display()))?
            {
                let path = entry.path();
                if path.is_file() && is_supported_input_file(&path) {
                    files.insert(path);
                }
            }
        } else if input.is_file() {
            if is_supported_input_file(input) {
                files.insert(input.clone());
            }
        } else {
            anyhow::bail!("deps.dev input path not found: {}", input.display());
        }
    }
    if files.is_empty() {
        anyhow::bail!("no supported deps.dev input files found");
    }
    Ok(files.into_iter().collect())
}

async fn read_input_body(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("failed to read deps.dev input {}", path.display()))?;
    if path.extension().and_then(|ext| ext.to_str()) == Some("gz") {
        let mut decoder = GzDecoder::new(bytes.as_slice());
        let mut body = String::new();
        decoder
            .read_to_string(&mut body)
            .with_context(|| format!("failed to decode gzip deps.dev input {}", path.display()))?;
        Ok(body)
    } else {
        String::from_utf8(bytes)
            .with_context(|| format!("deps.dev input is not valid utf-8: {}", path.display()))
    }
}

fn is_supported_input_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".ndjson")
        || name.ends_with(".jsonl")
        || name.ends_with(".json")
        || name.ends_with(".ndjson.gz")
        || name.ends_with(".jsonl.gz")
        || name.ends_with(".json.gz")
}

fn parse_deps_dev_system(value: &str) -> Option<Ecosystem> {
    match value {
        "NPM" | "npm" => Some(Ecosystem::Npm),
        "PYPI" | "pypi" => Some(Ecosystem::Pypi),
        "CARGO" | "cargo" => Some(Ecosystem::CratesIo),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn import_dependents_latest_emits_package_level_graph_input() {
        let input = r#"
{"System":"PYPI","Name":"litellm","Version":"1.82.6","Dependent":{"System":"PYPI","Name":"open-webui","Version":"0.6.0"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
{"System":"PYPI","Name":"litellm","Version":"1.82.6","Dependent":{"System":"PYPI","Name":"crewai","Version":"1.0.0"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
{"System":"PYPI","Name":"urllib3","Version":"2.2.0","Dependent":{"System":"PYPI","Name":"litellm","Version":"1.82.6"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
"#;

        let (records, summary) = import_dependents_latest_from_ndjson(
            input,
            &ImportDependentsConfig {
                default_direct_popularity: 1.0,
                include_indirect: false,
                include_non_highest_dependent_releases: false,
                direct_popularity_strategy: DirectPopularityStrategy::Constant,
            },
        )
        .unwrap();

        assert_eq!(summary.input_files, 1);
        assert_eq!(summary.input_rows, 3);
        assert_eq!(summary.imported_rows, 3);
        assert_eq!(summary.emitted_package_records, 4);
        assert_eq!(summary.emitted_dependency_records, 3);
        assert!(records.iter().any(|record| matches!(
            record,
            ScoreInputRecord::Dependency {
                ecosystem: Ecosystem::Pypi,
                package,
                dependency,
                ..
            } if package == "open-webui" && dependency == "litellm"
        )));
        assert!(records.iter().any(|record| matches!(
            record,
            ScoreInputRecord::Dependency {
                ecosystem: Ecosystem::Pypi,
                package,
                dependency,
                ..
            } if package == "litellm" && dependency == "urllib3"
        )));
    }

    #[test]
    fn import_dependents_latest_skips_indirect_and_non_highest_rows() {
        let input = r#"
{"System":"NPM","Name":"react","Version":"18.2.0","Dependent":{"System":"NPM","Name":"pkg-a","Version":"1.0.0"},"MinimumDepth":2,"DependentIsHighestReleaseWithResolution":true}
{"System":"NPM","Name":"react","Version":"18.2.0","Dependent":{"System":"NPM","Name":"pkg-b","Version":"1.0.0"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":false}
{"System":"NPM","Name":"react","Version":"18.2.0","Dependent":{"System":"NPM","Name":"pkg-c","Version":"1.0.0"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
"#;

        let (records, summary) = import_dependents_latest_from_ndjson(
            input,
            &ImportDependentsConfig {
                default_direct_popularity: 1.0,
                include_indirect: false,
                include_non_highest_dependent_releases: false,
                direct_popularity_strategy: DirectPopularityStrategy::Constant,
            },
        )
        .unwrap();

        assert_eq!(summary.imported_rows, 1);
        assert_eq!(summary.skipped_indirect_rows, 1);
        assert_eq!(summary.skipped_non_highest_rows, 1);
        assert_eq!(summary.emitted_dependency_records, 1);
        assert!(records.iter().any(|record| matches!(
            record,
            ScoreInputRecord::Dependency { package, dependency, .. }
            if package == "pkg-c" && dependency == "react"
        )));
    }

    #[test]
    fn import_dependents_can_derive_direct_popularity_from_dependent_counts() {
        let input = r#"
{"System":"PYPI","Name":"litellm","Version":"1.82.6","Dependent":{"System":"PYPI","Name":"open-webui","Version":"0.6.0"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
{"System":"PYPI","Name":"litellm","Version":"1.82.6","Dependent":{"System":"PYPI","Name":"crewai","Version":"1.0.0"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
"#;

        let (records, _) = import_dependents_latest_from_ndjson(
            input,
            &ImportDependentsConfig {
                default_direct_popularity: 1.0,
                include_indirect: false,
                include_non_highest_dependent_releases: false,
                direct_popularity_strategy: DirectPopularityStrategy::DirectDependentCount,
            },
        )
        .unwrap();

        let litellm = records.iter().find_map(|record| match record {
            ScoreInputRecord::Package {
                ecosystem: Ecosystem::Pypi,
                package,
                direct_popularity,
            } if package == "litellm" => Some(*direct_popularity),
            _ => None,
        });
        assert_eq!(litellm, Some(2.0));
    }

    #[test]
    fn focus_dependents_subgraph_builds_reverse_frontier_and_edges() {
        let input = r#"
{"System":"PYPI","Name":"litellm","Dependent":{"System":"PYPI","Name":"open-webui"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
{"System":"PYPI","Name":"open-webui","Dependent":{"System":"PYPI","Name":"ops-console"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
{"System":"PYPI","Name":"litellm","Dependent":{"System":"PYPI","Name":"crewai"},"MinimumDepth":1,"DependentIsHighestReleaseWithResolution":true}
"#;

        let (records, seeds, summary) = focus_dependents_subgraph_from_inputs(
            &[input],
            1,
            Ecosystem::Pypi,
            "litellm",
            &FocusDependentsConfig {
                reverse_depth: 2,
                max_frontier_packages: 10,
                include_non_highest_dependent_releases: false,
                default_direct_popularity: 1.0,
                direct_popularity_strategy: DirectPopularityStrategy::DirectDependentCount,
            },
        )
        .unwrap();

        assert_eq!(summary.frontier_packages, 4);
        assert_eq!(summary.emitted_dependency_records, 3);
        assert!(seeds.iter().any(|seed| seed.package == "litellm"));
        assert!(records.iter().any(|record| matches!(
            record,
            ScoreInputRecord::Dependency { package, dependency, .. }
            if package == "open-webui" && dependency == "litellm"
        )));
        assert!(records.iter().any(|record| matches!(
            record,
            ScoreInputRecord::Dependency { package, dependency, .. }
            if package == "ops-console" && dependency == "open-webui"
        )));
    }

    #[tokio::test]
    async fn import_dependents_supports_directory_and_gzip_inputs() {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("part-0000.ndjson");
        let gz = dir.path().join("part-0001.ndjson.gz");
        tokio::fs::write(
            &plain,
            "{\"System\":\"PYPI\",\"Name\":\"litellm\",\"Dependent\":{\"System\":\"PYPI\",\"Name\":\"open-webui\"},\"MinimumDepth\":1,\"DependentIsHighestReleaseWithResolution\":true}\n",
        )
        .await
        .unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(
                "{\"System\":\"PYPI\",\"Name\":\"litellm\",\"Dependent\":{\"System\":\"PYPI\",\"Name\":\"crewai\"},\"MinimumDepth\":1,\"DependentIsHighestReleaseWithResolution\":true}\n"
                    .as_bytes(),
            )
            .unwrap();
        tokio::fs::write(&gz, encoder.finish().unwrap())
            .await
            .unwrap();

        let (records, summary) = import_dependents_latest_from_paths(
            &[dir.path().to_path_buf()],
            &ImportDependentsConfig {
                default_direct_popularity: 1.0,
                include_indirect: false,
                include_non_highest_dependent_releases: false,
                direct_popularity_strategy: DirectPopularityStrategy::DirectDependentCount,
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.input_files, 2);
        assert_eq!(summary.imported_rows, 2);
        let litellm = records.iter().find_map(|record| match record {
            ScoreInputRecord::Package {
                ecosystem: Ecosystem::Pypi,
                package,
                direct_popularity,
            } if package == "litellm" => Some(*direct_popularity),
            _ => None,
        });
        assert_eq!(litellm, Some(2.0));
    }
}
