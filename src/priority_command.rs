use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use supply_stream_core::{
    capture, census,
    collector::{self, CollectConfig},
    config::PriorityConfig,
    deps_dev::{self, DirectPopularityStrategy, FocusDependentsConfig, ImportDependentsConfig},
    deps_dev_bigquery,
    priority::{self, PackageCensusRecord, PriorityScoreMetric},
    scoring::{self, ScoreBuildConfig},
};
use tokio::fs;

use crate::config::{
    DepsDevDirectPopularityMode, PriorityArgs, PriorityCommand, PriorityScoreMetricArg,
};

pub async fn run(args: PriorityArgs) -> Result<()> {
    match args.command {
        PriorityCommand::Expand {
            ecosystem,
            package,
            seeds,
            deps_dev_input,
            base_input,
            popularity_file,
            skip_seed_collect,
            graph_output,
            graph_store_file,
            output,
            census_output,
            depth,
            reverse_depth,
            max_frontier_packages,
            max_packages,
            request_concurrency,
            bigquery_baseline_package_limit,
            bigquery_census_package_limit,
            bigquery_baseline_package_offset,
            bigquery_baseline_edge_limit,
            bigquery_baseline_via_collector,
            target_scored_packages,
            deps_dev_default_direct_popularity,
            deps_dev_include_indirect,
            deps_dev_include_non_highest_dependent_releases,
            deps_dev_direct_popularity_mode,
            alpha,
            max_iterations,
            epsilon,
            high_quantile,
            medium_quantile,
            score_source_version,
            json,
        } => match (ecosystem, package) {
            (Some(ecosystem), Some(package)) => {
                run_focus_command(FocusCommand {
                    ecosystem,
                    package,
                    deps_dev_input,
                    base_input,
                    popularity_file,
                    graph_output,
                    graph_store_file,
                    output,
                    census_output,
                    reverse_depth,
                    max_frontier_packages,
                    forward_depth: depth,
                    max_packages,
                    request_concurrency,
                    deps_dev_default_direct_popularity,
                    deps_dev_include_non_highest_dependent_releases,
                    deps_dev_direct_popularity_mode,
                    alpha,
                    max_iterations,
                    epsilon,
                    high_quantile,
                    medium_quantile,
                    score_source_version,
                    json,
                })
                .await
            }
            (None, None) => {
                run_bootstrap_command(BootstrapCommand {
                    seeds,
                    base_input,
                    popularity_file,
                    skip_seed_collect,
                    deps_dev_input,
                    graph_output,
                    graph_store_file,
                    output,
                    census_output,
                    max_depth: depth,
                    max_packages,
                    request_concurrency,
                    bigquery_baseline_package_limit,
                    bigquery_census_package_limit,
                    bigquery_baseline_package_offset,
                    bigquery_baseline_edge_limit,
                    bigquery_baseline_via_collector,
                    target_scored_packages,
                    deps_dev_default_direct_popularity,
                    deps_dev_include_indirect,
                    deps_dev_include_non_highest_dependent_releases,
                    deps_dev_direct_popularity_mode,
                    alpha,
                    max_iterations,
                    epsilon,
                    high_quantile,
                    medium_quantile,
                    score_source_version,
                    json,
                })
                .await
            }
            _ => anyhow::bail!("--ecosystem and --package must be provided together"),
        },
        PriorityCommand::Focus {
            ecosystem,
            package,
            deps_dev_input,
            base_input,
            popularity_file,
            graph_output,
            graph_store_file,
            output,
            census_output,
            reverse_depth,
            max_frontier_packages,
            forward_depth,
            max_packages,
            request_concurrency,
            deps_dev_default_direct_popularity,
            deps_dev_include_non_highest_dependent_releases,
            deps_dev_direct_popularity_mode,
            alpha,
            max_iterations,
            epsilon,
            high_quantile,
            medium_quantile,
            score_source_version,
            json,
        } => {
            run_focus_command(FocusCommand {
                ecosystem,
                package,
                deps_dev_input,
                base_input,
                popularity_file,
                graph_output,
                graph_store_file,
                output,
                census_output,
                reverse_depth,
                max_frontier_packages,
                forward_depth,
                max_packages,
                request_concurrency,
                deps_dev_default_direct_popularity,
                deps_dev_include_non_highest_dependent_releases,
                deps_dev_direct_popularity_mode,
                alpha,
                max_iterations,
                epsilon,
                high_quantile,
                medium_quantile,
                score_source_version,
                json,
            })
            .await
        }
        PriorityCommand::Bootstrap {
            seeds,
            popularity_file,
            skip_seed_collect,
            deps_dev_input,
            graph_output,
            graph_store_file,
            output,
            census_output,
            max_depth,
            max_packages,
            request_concurrency,
            bigquery_baseline_package_limit,
            bigquery_census_package_limit,
            bigquery_baseline_package_offset,
            bigquery_baseline_edge_limit,
            bigquery_baseline_via_collector,
            target_scored_packages,
            deps_dev_default_direct_popularity,
            deps_dev_include_indirect,
            deps_dev_include_non_highest_dependent_releases,
            deps_dev_direct_popularity_mode,
            alpha,
            max_iterations,
            epsilon,
            high_quantile,
            medium_quantile,
            score_source_version,
            json,
        } => {
            run_bootstrap_command(BootstrapCommand {
                seeds,
                base_input: Vec::new(),
                popularity_file,
                skip_seed_collect,
                deps_dev_input,
                graph_output,
                graph_store_file,
                output,
                census_output,
                max_depth,
                max_packages,
                request_concurrency,
                bigquery_baseline_package_limit,
                bigquery_census_package_limit,
                bigquery_baseline_package_offset,
                bigquery_baseline_edge_limit,
                bigquery_baseline_via_collector,
                target_scored_packages,
                deps_dev_default_direct_popularity,
                deps_dev_include_indirect,
                deps_dev_include_non_highest_dependent_releases,
                deps_dev_direct_popularity_mode,
                alpha,
                max_iterations,
                epsilon,
                high_quantile,
                medium_quantile,
                score_source_version,
                json,
            })
            .await
        }
        PriorityCommand::MergeGraph {
            input,
            output,
            json,
        } => {
            let (records, summary) = scoring::merge_score_input_files(&input).await?;

            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("failed to create output dir {}", parent.display()))?;
            }

            let mut encoded = Vec::new();
            for record in &records {
                encoded.extend(
                    serde_json::to_vec(record)
                        .with_context(|| format!("failed to encode {}", output.display()))?,
                );
                encoded.push(b'\n');
            }
            fs::write(&output, encoded)
                .await
                .with_context(|| format!("failed to write {}", output.display()))?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "output": output.display().to_string(),
                        "summary": summary,
                    }))?
                );
            } else {
                println!("wrote {}", output.display());
                println!("input_files: {}", summary.input_files);
                println!("input_packages: {}", summary.input_packages);
                println!("input_dependencies: {}", summary.input_dependencies);
                println!("merged_packages: {}", summary.merged_packages);
                println!("merged_dependencies: {}", summary.merged_dependencies);
                for ecosystem in summary.ecosystems {
                    println!(
                        "{}: packages={} dependencies={}",
                        ecosystem.ecosystem, ecosystem.packages, ecosystem.dependencies
                    );
                }
            }
            Ok(())
        }
        PriorityCommand::ImportDepsDev {
            input,
            output,
            default_direct_popularity,
            include_indirect,
            include_non_highest_dependent_releases,
            direct_popularity_mode,
            json,
        } => {
            let (records, summary) = deps_dev::import_dependents_latest_from_paths(
                &input,
                &ImportDependentsConfig {
                    default_direct_popularity,
                    include_indirect,
                    include_non_highest_dependent_releases,
                    direct_popularity_strategy: map_deps_dev_direct_popularity_mode(
                        direct_popularity_mode,
                    ),
                },
            )
            .await?;

            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("failed to create output dir {}", parent.display()))?;
            }

            let mut encoded = Vec::new();
            for record in &records {
                encoded.extend(
                    serde_json::to_vec(record)
                        .with_context(|| format!("failed to encode {}", output.display()))?,
                );
                encoded.push(b'\n');
            }
            fs::write(&output, encoded)
                .await
                .with_context(|| format!("failed to write {}", output.display()))?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "output": output.display().to_string(),
                        "summary": summary,
                    }))?
                );
            } else {
                println!("wrote {}", output.display());
                println!("input_rows: {}", summary.input_rows);
                println!("imported_rows: {}", summary.imported_rows);
                println!(
                    "skipped_unsupported_system_rows: {}",
                    summary.skipped_unsupported_system_rows
                );
                println!("skipped_indirect_rows: {}", summary.skipped_indirect_rows);
                println!(
                    "skipped_non_highest_rows: {}",
                    summary.skipped_non_highest_rows
                );
                println!(
                    "emitted_package_records: {}",
                    summary.emitted_package_records
                );
                println!(
                    "emitted_dependency_records: {}",
                    summary.emitted_dependency_records
                );
            }
            Ok(())
        }
        PriorityCommand::Collect {
            seeds,
            popularity_file,
            output,
            max_depth,
            max_packages,
            request_concurrency,
            json,
        } => {
            let (records, summary) = collector::collect_score_input_from_files(
                &seeds,
                popularity_file.as_deref(),
                &CollectConfig {
                    max_depth,
                    max_packages,
                    request_concurrency,
                    allow_external_fallback: true,
                },
            )
            .await?;

            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("failed to create output dir {}", parent.display()))?;
            }

            let mut encoded = Vec::new();
            for record in &records {
                encoded.extend(
                    serde_json::to_vec(record)
                        .with_context(|| format!("failed to encode {}", output.display()))?,
                );
                encoded.push(b'\n');
            }
            fs::write(&output, encoded)
                .await
                .with_context(|| format!("failed to write {}", output.display()))?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "output": output.display().to_string(),
                        "summary": summary,
                    }))?
                );
            } else {
                println!("wrote {}", output.display());
                println!("seed_packages: {}", summary.seed_packages);
                println!("discovered_packages: {}", summary.discovered_packages);
                println!(
                    "emitted_package_records: {}",
                    summary.emitted_package_records
                );
                println!(
                    "emitted_dependency_records: {}",
                    summary.emitted_dependency_records
                );
                println!("fetch_failures: {}", summary.fetch_failures);
                for ecosystem in summary.ecosystems {
                    println!(
                        "{}: packages={} dependencies={}",
                        ecosystem.ecosystem, ecosystem.packages, ecosystem.dependencies
                    );
                }
            }
            Ok(())
        }
        PriorityCommand::Build {
            input,
            output,
            alpha,
            max_iterations,
            epsilon,
            high_quantile,
            medium_quantile,
            score_source_version,
            json,
        } => {
            let (scores, summary) = scoring::build_priority_scores_from_file(
                &input,
                &ScoreBuildConfig {
                    alpha,
                    max_iterations,
                    epsilon,
                    high_quantile,
                    medium_quantile,
                    score_source_version,
                },
            )
            .await?;

            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("failed to create output dir {}", parent.display()))?;
            }

            let mut encoded = Vec::new();
            for score in &scores {
                encoded.extend(
                    serde_json::to_vec(score)
                        .with_context(|| format!("failed to encode {}", output.display()))?,
                );
                encoded.push(b'\n');
            }
            fs::write(&output, encoded)
                .await
                .with_context(|| format!("failed to write {}", output.display()))?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "output": output.display().to_string(),
                        "summary": summary,
                    }))?
                );
            } else {
                println!("wrote {}", output.display());
                println!("input_packages: {}", summary.input_packages);
                println!("input_dependencies: {}", summary.input_dependencies);
                println!("scored_packages: {}", summary.scored_packages);
                for ecosystem in summary.ecosystems {
                    println!(
                        "{}: packages={} dependencies={} priority(high/medium/low/unknown)={}/{}/{}/{}",
                        ecosystem.ecosystem,
                        ecosystem.packages,
                        ecosystem.dependencies,
                        ecosystem.priorities.high,
                        ecosystem.priorities.medium,
                        ecosystem.priorities.low,
                        ecosystem.priorities.unknown
                    );
                }
            }
            Ok(())
        }
        PriorityCommand::Census {
            ecosystems,
            output,
            base_input,
            npm_page_size,
            npm_limit,
            pypi_limit,
            crates_page_size,
            crates_limit,
            timeout_secs,
            json,
        } => {
            let mut records = Vec::<PackageCensusRecord>::new();
            for input in base_input {
                let score_input = scoring::load_score_input_records(&input).await?;
                records.extend(priority::package_census_from_score_input(&score_input));
            }
            let (live_records, summary) = census::import_native_package_census_live(
                &ecosystems,
                &census::NativeCensusConfig {
                    pypi_base: "https://pypi.org".to_string(),
                    npm_all_docs_base: "https://replicate.npmjs.com/registry/_all_docs".to_string(),
                    crates_io_base: "https://crates.io".to_string(),
                    request_timeout: Duration::from_secs(timeout_secs),
                    npm_page_size,
                    npm_limit,
                    pypi_limit,
                    crates_page_size,
                    crates_limit,
                },
            )
            .await?;
            records.extend(live_records);
            records.sort();
            records.dedup_by(|left, right| {
                left.ecosystem == right.ecosystem && left.package == right.package
            });
            priority::write_package_census_records(&output, &records).await?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "output": output.display().to_string(),
                        "summary": summary,
                        "emitted_records": records.len(),
                    }))?
                );
            } else {
                println!("wrote {}", output.display());
                println!("emitted_records: {}", records.len());
                for ecosystem in summary.ecosystems {
                    println!("{}: packages={}", ecosystem.ecosystem, ecosystem.packages);
                }
            }
            Ok(())
        }
        PriorityCommand::Broaden {
            ecosystems,
            census_file,
            base_input,
            graph_output,
            graph_store_file,
            output,
            progress_file,
            batch_size,
            iterations,
            cursor,
            max_depth,
            max_packages,
            request_concurrency,
            rebuild_scores,
            alpha,
            max_iterations,
            epsilon,
            high_quantile,
            medium_quantile,
            score_source_version,
            json,
        } => {
            run_broaden_command(BroadenCommand {
                ecosystems,
                census_file,
                base_input,
                graph_output,
                graph_store_file,
                output,
                progress_file,
                batch_size,
                iterations,
                cursor,
                max_depth,
                max_packages,
                request_concurrency,
                rebuild_scores,
                alpha,
                max_iterations,
                epsilon,
                high_quantile,
                medium_quantile,
                score_source_version,
                json,
            })
            .await
        }
        PriorityCommand::Score {
            input,
            ecosystem,
            package,
            json,
        } => {
            let lookup = priority::lookup_priority_score(&input, ecosystem, &package).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&lookup)?);
            } else if let Some(record) = &lookup.record {
                println!("{}:{}", ecosystem, lookup.normalized_package);
                println!("tier: {}", record.priority_tier.as_str());
                if let Some(value) = record.direct_popularity {
                    println!("direct_popularity: {value:.6}");
                }
                if let Some(value) = record.propagated_impact {
                    println!("propagated_impact: {value:.6}");
                }
                if let Some(value) = record.hidden_leverage {
                    println!("hidden_leverage: {value:.6}");
                }
                if let Some(rank) = lookup.ecosystem_rank_by_propagated_impact {
                    println!("impact_rank: {}/{}", rank, lookup.ecosystem_package_count);
                }
                if let Some(rank) = lookup.ecosystem_rank_by_hidden_leverage {
                    println!(
                        "hidden_leverage_rank: {}/{}",
                        rank, lookup.ecosystem_package_count
                    );
                }
                if let Some(computed_at) = record.computed_at {
                    println!("computed_at: {}", computed_at.to_rfc3339());
                }
                if let Some(version) = &record.score_source_version {
                    println!("score_source_version: {version}");
                }
            } else {
                println!(
                    "{}:{} not found in {}",
                    ecosystem,
                    lookup.normalized_package,
                    input.display()
                );
                println!("ecosystem_packages: {}", lookup.ecosystem_package_count);
            }
            Ok(())
        }
        PriorityCommand::Resolve {
            input,
            graph_file,
            census_file,
            graph_store_file,
            online_fallback,
            online_timeout_secs,
            ecosystem,
            package,
            json,
        } => {
            let normalized_package = priority::normalize_package_name(ecosystem, &package);
            let resolver = load_priority_resolver(
                input.clone(),
                graph_file,
                census_file,
                graph_store_file,
                online_fallback,
                online_timeout_secs,
            )
            .await?;
            let snapshot = resolver.resolve_for_event(ecosystem, &package).await;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ecosystem": ecosystem,
                        "package": package,
                        "normalized_package": normalized_package,
                        "priority": snapshot,
                    }))?
                );
            } else {
                println!("{}:{}", ecosystem, normalized_package);
                println!("tier: {}", snapshot.tier.as_str());
                println!("source: {}", snapshot.source.as_str());
                if let Some(value) = snapshot.direct_popularity {
                    println!("direct_popularity: {value:.6}");
                }
                if let Some(value) = snapshot.propagated_impact {
                    println!("propagated_impact: {value:.6}");
                }
                if let Some(value) = snapshot.hidden_leverage {
                    println!("hidden_leverage: {value:.6}");
                }
                if let Some(computed_at) = snapshot.computed_at {
                    println!("computed_at: {}", computed_at.to_rfc3339());
                }
                if let Some(version) = &snapshot.score_source_version {
                    println!("score_source_version: {version}");
                }
            }
            Ok(())
        }
        PriorityCommand::Graph {
            input,
            graph_file,
            census_file,
            graph_store_file,
            limit,
            ecosystem,
            package,
            json,
        } => {
            let resolver =
                load_priority_resolver(input, graph_file, census_file, graph_store_file, false, 3)
                    .await?;
            let inspection = resolver
                .inspect_local_graph(ecosystem, &package, limit)
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&inspection)?);
            } else {
                println!("{}:{}", ecosystem, inspection.package);
                println!("known_in_local_graph: {}", inspection.known_in_local_graph);
                println!("known_in_census: {}", inspection.known_in_census);
                println!("direct_popularity: {:.6}", inspection.direct_popularity);
                println!(
                    "direct_dependencies_seen: {}",
                    inspection.direct_dependencies_seen
                );
                println!(
                    "reverse_dependents_seen: {}",
                    inspection.reverse_dependents_seen
                );
                if let Some(repository) = &inspection.repository {
                    println!(
                        "repository: {} ({})",
                        repository.normalized_repository_url, repository.provider
                    );
                    println!("repository_source: {}", repository.source);
                    if let Some(version) = &repository.last_version {
                        println!("repository_last_version: {version}");
                    }
                }
                if let Some(score) = &inspection.score {
                    println!("score_source: {}", score.source.as_str());
                    println!("score_tier: {}", score.tier.as_str());
                    if let Some(value) = score.propagated_impact {
                        println!("score_propagated_impact: {value:.6}");
                    }
                    if let Some(value) = score.hidden_leverage {
                        println!("score_hidden_leverage: {value:.6}");
                    }
                }
                println!("direct_dependencies:");
                for dependency in inspection.direct_dependencies {
                    println!("  {dependency}");
                }
                println!("reverse_dependents:");
                for dependent in inspection.reverse_dependents {
                    println!("  {dependent}");
                }
            }
            Ok(())
        }
        PriorityCommand::RepoBackfill {
            graph_file,
            graph_store_file,
            ecosystem,
            package,
            force,
            limit,
            request_concurrency,
            json,
        } => {
            let summary = run_repo_backfill_command(
                graph_file,
                graph_store_file,
                ecosystem,
                package,
                force,
                limit,
                request_concurrency,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("packages_scanned: {}", summary.packages_scanned);
                println!("fetched: {}", summary.fetched);
                println!("stored: {}", summary.stored);
                println!("already_known: {}", summary.already_known);
                println!("resolved: {}", summary.resolved);
                println!("missing_repository: {}", summary.missing_repository);
                println!("fetch_failures: {}", summary.fetch_failures);
            }
            Ok(())
        }
        PriorityCommand::GraphBackfill {
            data_dir,
            graph_output,
            graph_store_file,
            output,
            census_output,
            ecosystem,
            package,
            limit,
            alpha,
            max_iterations,
            epsilon,
            high_quantile,
            medium_quantile,
            score_source_version,
            json,
        } => {
            let summary = run_graph_backfill_command(GraphBackfillCommand {
                data_dir,
                graph_output,
                graph_store_file,
                output,
                census_output,
                ecosystem,
                package,
                limit,
                scoring_config: IncrementalScoringConfig {
                    score_source_version,
                    alpha,
                    max_iterations,
                    epsilon,
                    high_quantile,
                    medium_quantile,
                    max_packages: 0,
                    request_concurrency: 1,
                },
            })
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("data_dir: {}", summary.data_dir);
                println!("graph_output: {}", summary.graph_output);
                println!("graph_store: {}", summary.graph_store_file);
                println!("output: {}", summary.output);
                println!("census_output: {}", summary.census_output);
                println!("captures_scanned: {}", summary.captures_scanned);
                println!(
                    "captures_with_graph_records: {}",
                    summary.captures_with_graph_records
                );
                println!("repository_refs: {}", summary.repository_refs);
                println!(
                    "merge: packages={} dependencies={}",
                    summary.merge_summary.merged_packages,
                    summary.merge_summary.merged_dependencies
                );
                println!(
                    "build: scored_packages={} incremental_updates={}",
                    summary.build_summary.scored_packages, summary.incremental_score_updates
                );
            }
            Ok(())
        }
        PriorityCommand::ScoreStats {
            input,
            top_limit,
            json,
        } => {
            let summary = priority::summarize_priority_scores(&input, top_limit).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("scored_packages: {}", summary.scored_packages);
                for ecosystem in summary.ecosystems {
                    println!(
                        "{}: packages={} priority(high/medium/low/unknown)={}/{}/{}/{}",
                        ecosystem.ecosystem,
                        ecosystem.packages,
                        ecosystem.priorities.high,
                        ecosystem.priorities.medium,
                        ecosystem.priorities.low,
                        ecosystem.priorities.unknown
                    );
                    println!("  top_by_propagated_impact:");
                    for entry in ecosystem.top_by_propagated_impact {
                        println!(
                            "    {} tier={} impact={:.6} hidden={:.6} direct={:.6}",
                            entry.package,
                            entry.priority_tier.as_str(),
                            entry.propagated_impact,
                            entry.hidden_leverage,
                            entry.direct_popularity
                        );
                    }
                    println!("  top_by_hidden_leverage:");
                    for entry in ecosystem.top_by_hidden_leverage {
                        println!(
                            "    {} tier={} hidden={:.6} impact={:.6} direct={:.6}",
                            entry.package,
                            entry.priority_tier.as_str(),
                            entry.hidden_leverage,
                            entry.propagated_impact,
                            entry.direct_popularity
                        );
                    }
                }
            }
            Ok(())
        }
        PriorityCommand::Top {
            input,
            ecosystem,
            metric,
            limit,
            json,
        } => {
            let entries = priority::load_top_priority_scores(
                &input,
                ecosystem,
                map_priority_score_metric(metric),
                limit,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                for entry in entries {
                    println!(
                        "{}:{} tier={} direct={:.6} impact={:.6} hidden={:.6}",
                        entry.ecosystem,
                        entry.package,
                        entry.priority_tier.as_str(),
                        entry.direct_popularity,
                        entry.propagated_impact,
                        entry.hidden_leverage
                    );
                }
            }
            Ok(())
        }
    }
}

async fn load_priority_resolver(
    input: std::path::PathBuf,
    graph_file: std::path::PathBuf,
    census_file: std::path::PathBuf,
    graph_store_file: Option<std::path::PathBuf>,
    online_fallback: bool,
    online_timeout_secs: u64,
) -> Result<priority::PriorityResolver> {
    priority::PriorityResolver::load(&PriorityConfig {
        score_file: input,
        graph_file,
        census_file,
        graph_store_file,
        online_fallback,
        online_expand_unknown: false,
        online_expand_min_observations: 2,
        online_request_timeout: Duration::from_secs(online_timeout_secs),
        deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
        deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
        expand_focus: supply_stream_core::deps_dev::FocusDependentsConfig {
            reverse_depth: 2,
            max_frontier_packages: 1000,
            include_non_highest_dependent_releases: false,
            default_direct_popularity: 1.0,
            direct_popularity_strategy:
                supply_stream_core::deps_dev::DirectPopularityStrategy::DirectDependentCount,
        },
        expand_collect: supply_stream_core::collector::CollectConfig {
            max_depth: 1,
            max_packages: 512,
            request_concurrency: 16,
            allow_external_fallback: true,
        },
        expand_score_build: supply_stream_core::scoring::ScoreBuildConfig {
            alpha: 0.85,
            max_iterations: 64,
            epsilon: 1e-6,
            high_quantile: 0.99,
            medium_quantile: 0.90,
            score_source_version: Some("resolve_runtime_expand_v1".to_string()),
        },
    })
    .await
}

struct FocusCommand {
    ecosystem: supply_stream_core::event::Ecosystem,
    package: String,
    deps_dev_input: Vec<std::path::PathBuf>,
    base_input: Vec<std::path::PathBuf>,
    popularity_file: Option<std::path::PathBuf>,
    graph_output: std::path::PathBuf,
    graph_store_file: std::path::PathBuf,
    output: std::path::PathBuf,
    census_output: std::path::PathBuf,
    reverse_depth: usize,
    max_frontier_packages: usize,
    forward_depth: usize,
    max_packages: usize,
    request_concurrency: usize,
    deps_dev_default_direct_popularity: f64,
    deps_dev_include_non_highest_dependent_releases: bool,
    deps_dev_direct_popularity_mode: DepsDevDirectPopularityMode,
    alpha: f64,
    max_iterations: usize,
    epsilon: f64,
    high_quantile: f64,
    medium_quantile: f64,
    score_source_version: Option<String>,
    json: bool,
}

#[derive(Debug, Clone, Serialize)]
struct LocalFocusSummary {
    frontier_packages: usize,
    frontier_truncated: bool,
    emitted_dependency_records: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
struct FirstPartyReverseScanSummary {
    scanned_packages: usize,
    batches: usize,
    matched_dependents: usize,
    emitted_package_records: usize,
    emitted_dependency_records: usize,
    fetch_failures: usize,
}

#[derive(Debug, Clone, Copy)]
struct FirstPartyReverseScanConfig {
    ecosystem: supply_stream_core::event::Ecosystem,
    max_frontier_packages: usize,
    max_packages: usize,
    request_concurrency: usize,
    default_direct_popularity: f64,
}

struct BootstrapCommand {
    seeds: std::path::PathBuf,
    base_input: Vec<std::path::PathBuf>,
    popularity_file: Option<std::path::PathBuf>,
    skip_seed_collect: bool,
    deps_dev_input: Vec<std::path::PathBuf>,
    graph_output: std::path::PathBuf,
    graph_store_file: std::path::PathBuf,
    output: std::path::PathBuf,
    census_output: std::path::PathBuf,
    max_depth: usize,
    max_packages: usize,
    request_concurrency: usize,
    bigquery_baseline_package_limit: usize,
    bigquery_census_package_limit: usize,
    bigquery_baseline_package_offset: usize,
    bigquery_baseline_edge_limit: usize,
    bigquery_baseline_via_collector: bool,
    target_scored_packages: Option<usize>,
    deps_dev_default_direct_popularity: f64,
    deps_dev_include_indirect: bool,
    deps_dev_include_non_highest_dependent_releases: bool,
    deps_dev_direct_popularity_mode: DepsDevDirectPopularityMode,
    alpha: f64,
    max_iterations: usize,
    epsilon: f64,
    high_quantile: f64,
    medium_quantile: f64,
    score_source_version: Option<String>,
    json: bool,
}

#[derive(Debug, Clone)]
struct BroadenCommand {
    ecosystems: Vec<supply_stream_core::event::Ecosystem>,
    census_file: std::path::PathBuf,
    base_input: Vec<std::path::PathBuf>,
    graph_output: std::path::PathBuf,
    graph_store_file: std::path::PathBuf,
    output: Option<std::path::PathBuf>,
    progress_file: std::path::PathBuf,
    batch_size: usize,
    iterations: usize,
    cursor: Option<usize>,
    max_depth: usize,
    max_packages: usize,
    request_concurrency: usize,
    rebuild_scores: bool,
    alpha: f64,
    max_iterations: usize,
    epsilon: f64,
    high_quantile: f64,
    medium_quantile: f64,
    score_source_version: Option<String>,
    json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BroadenProgress {
    cursor: usize,
}

#[derive(Debug, Clone, Serialize)]
struct BroadenSummary {
    graph_output: String,
    graph_store_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    progress_file: String,
    iterations_requested: usize,
    iterations_completed: usize,
    cursor_before: usize,
    cursor_after: usize,
    census_size: usize,
    known_packages_source: &'static str,
    known_packages_count: usize,
    scanned: usize,
    selected: usize,
    exhausted: bool,
    collect_summary: collector::CollectSummary,
    merge_summary: scoring::ScoreInputMergeSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_summary: Option<scoring::ScoreBuildSummary>,
    incremental_score_updates: usize,
    total_selected: usize,
    total_scanned: usize,
    total_incremental_score_updates: usize,
    graph_persist_mode: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct RepoBackfillSummary {
    packages_scanned: usize,
    fetched: usize,
    stored: usize,
    already_known: usize,
    resolved: usize,
    missing_repository: usize,
    fetch_failures: usize,
}

#[derive(Debug, Clone, Serialize)]
struct GraphBackfillSummary {
    data_dir: String,
    graph_output: String,
    graph_store_file: String,
    output: String,
    census_output: String,
    captures_scanned: usize,
    captures_with_graph_records: usize,
    repository_refs: usize,
    merge_summary: scoring::ScoreInputMergeSummary,
    build_summary: scoring::ScoreBuildSummary,
    incremental_score_updates: usize,
}

struct GraphBackfillCommand {
    data_dir: std::path::PathBuf,
    graph_output: std::path::PathBuf,
    graph_store_file: std::path::PathBuf,
    output: std::path::PathBuf,
    census_output: std::path::PathBuf,
    ecosystem: Option<supply_stream_core::event::Ecosystem>,
    package: Option<String>,
    limit: Option<usize>,
    scoring_config: IncrementalScoringConfig,
}

async fn run_focus_command(command: FocusCommand) -> Result<()> {
    let normalized_package = priority::normalize_package_name(command.ecosystem, &command.package);
    let base_inputs = resolve_focus_base_inputs(&command.base_input, &command.graph_output).await;
    let base_records = load_score_input_from_paths(&base_inputs).await?;
    let (local_focus_seeds, local_focus_summary) = build_local_focus_frontier(
        &base_records,
        command.ecosystem,
        &command.package,
        command.reverse_depth,
        command.max_frontier_packages,
        command.deps_dev_default_direct_popularity,
        command.deps_dev_direct_popularity_mode,
    );
    let (first_party_reverse_records, first_party_reverse_seeds, first_party_reverse_summary) =
        discover_reverse_dependents_from_census(
            &command.census_output,
            &base_records,
            &command.package,
            FirstPartyReverseScanConfig {
                ecosystem: command.ecosystem,
                max_frontier_packages: command.max_frontier_packages,
                max_packages: command.max_packages,
                request_concurrency: command.request_concurrency,
                default_direct_popularity: command.deps_dev_default_direct_popularity,
            },
        )
        .await?;
    let (reverse_records, focus_seeds, focus_summary) = if command.deps_dev_input.is_empty() {
        match deps_dev_bigquery::focus_dependents_subgraph_live(
            command.ecosystem,
            &command.package,
            &FocusDependentsConfig {
                reverse_depth: command.reverse_depth,
                max_frontier_packages: command.max_frontier_packages,
                include_non_highest_dependent_releases: command
                    .deps_dev_include_non_highest_dependent_releases,
                default_direct_popularity: command.deps_dev_default_direct_popularity,
                direct_popularity_strategy: map_deps_dev_direct_popularity_mode(
                    command.deps_dev_direct_popularity_mode,
                ),
            },
            &deps_dev_bigquery::LiveFocusConfig,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                let snapshot = priority::resolve_online_priority_snapshot(
                    command.ecosystem,
                    &command.package,
                    Duration::from_secs(5),
                    "https://api.deps.dev/v3",
                    "https://api.deps.dev/v3alpha",
                )
                .await
                .unwrap_or_else(|_| priority::PrioritySnapshot::default_unknown());
                (
                    Vec::new(),
                    vec![collector::SeedPackageRecord {
                        ecosystem: command.ecosystem,
                        package: normalized_package,
                        direct_popularity: Some(
                            snapshot
                                .propagated_impact
                                .or(snapshot.direct_popularity)
                                .unwrap_or(command.deps_dev_default_direct_popularity),
                        ),
                    }],
                    deps_dev::FocusDependentsSummary {
                        input_files: 0,
                        input_rows: 0,
                        matched_rows: 0,
                        reverse_depth: command.reverse_depth,
                        frontier_packages: 1,
                        frontier_truncated: false,
                        emitted_package_records: 1,
                        emitted_dependency_records: 0,
                    },
                )
            }
        }
    } else {
        deps_dev::focus_dependents_subgraph_from_paths(
            &command.deps_dev_input,
            command.ecosystem,
            &command.package,
            &FocusDependentsConfig {
                reverse_depth: command.reverse_depth,
                max_frontier_packages: command.max_frontier_packages,
                include_non_highest_dependent_releases: command
                    .deps_dev_include_non_highest_dependent_releases,
                default_direct_popularity: command.deps_dev_default_direct_popularity,
                direct_popularity_strategy: map_deps_dev_direct_popularity_mode(
                    command.deps_dev_direct_popularity_mode,
                ),
            },
        )
        .await?
    };

    let focus_seeds = merge_seed_records(
        merge_seed_records(focus_seeds, local_focus_seeds),
        first_party_reverse_seeds,
    );

    let popularity = match command.popularity_file.as_deref() {
        Some(path) => collector::load_seed_records(path).await?,
        None => Vec::new(),
    };
    let forward_material = collector::collect_graph_material_from_records(
        focus_seeds,
        popularity,
        &CollectConfig {
            max_depth: command.forward_depth,
            max_packages: command.max_packages,
            request_concurrency: command.request_concurrency,
            allow_external_fallback: true,
        },
    )
    .await?;
    let forward_records = forward_material.records;
    let forward_repositories = forward_material.repositories;
    let collect_summary = forward_material.summary;

    let mut batch_records = Vec::new();
    if !reverse_records.is_empty() {
        batch_records.extend(reverse_records.clone());
    }
    if !first_party_reverse_records.is_empty() {
        batch_records.extend(first_party_reverse_records.clone());
    }
    if !forward_records.is_empty() {
        batch_records.extend(forward_records.clone());
    }

    if can_incrementally_persist_graph(&base_inputs, &command.graph_output)
        && !batch_records.is_empty()
    {
        let batch_summary = persist_incremental_graph_update(IncrementalPersistRequest {
            graph_output: &command.graph_output,
            graph_store_file: &command.graph_store_file,
            census_output: &command.census_output,
            output: &command.output,
            records: &batch_records,
            repositories: &forward_repositories,
            extra_census_records: &[],
            scoring_config: IncrementalScoringConfig {
                score_source_version: command.score_source_version.clone(),
                alpha: command.alpha,
                max_iterations: command.max_iterations,
                epsilon: command.epsilon,
                high_quantile: command.high_quantile,
                medium_quantile: command.medium_quantile,
                max_packages: command.max_packages,
                request_concurrency: command.request_concurrency,
            },
        })
        .await?;

        if command.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "graph_output": command.graph_output.display().to_string(),
                    "graph_store_file": command.graph_store_file.display().to_string(),
                    "output": command.output.display().to_string(),
                    "census_output": command.census_output.display().to_string(),
                    "focus_summary": focus_summary,
                    "local_focus_summary": local_focus_summary,
                    "first_party_reverse_summary": first_party_reverse_summary,
                    "collect_summary": collect_summary,
                    "merge_summary": batch_summary.merge_summary,
                    "build_summary": batch_summary.build_summary,
                    "incremental_score_updates": batch_summary.incremental_score_updates,
                    "graph_persist_mode": "append_store_incremental",
                }))?
            );
        } else {
            println!("wrote {}", command.graph_output.display());
            println!("graph_store: {}", command.graph_store_file.display());
            println!("wrote {}", command.output.display());
            println!("wrote {}", command.census_output.display());
            println!(
                "focus: frontier_packages={} reverse_edges={} reverse_depth={} truncated={}",
                focus_summary.frontier_packages,
                focus_summary.emitted_dependency_records,
                focus_summary.reverse_depth,
                focus_summary.frontier_truncated
            );
            println!(
                "local_focus: frontier_packages={} reverse_edges={} truncated={}",
                local_focus_summary.frontier_packages,
                local_focus_summary.emitted_dependency_records,
                local_focus_summary.frontier_truncated
            );
            println!(
                "first_party_reverse: scanned_packages={} matched_dependents={} dependency_records={} fetch_failures={}",
                first_party_reverse_summary.scanned_packages,
                first_party_reverse_summary.matched_dependents,
                first_party_reverse_summary.emitted_dependency_records,
                first_party_reverse_summary.fetch_failures
            );
            println!(
                "collect: seeds={} discovered={} dependency_records={} fetch_failures={} external_fallback_fetches={}",
                collect_summary.seed_packages,
                collect_summary.discovered_packages,
                collect_summary.emitted_dependency_records,
                collect_summary.fetch_failures,
                collect_summary.external_fallback_fetches
            );
            println!(
                "merge: packages={} dependencies={}",
                batch_summary.merge_summary.merged_packages,
                batch_summary.merge_summary.merged_dependencies
            );
            println!(
                "build: scored_packages={} incremental_updates={}",
                batch_summary.build_summary.scored_packages,
                batch_summary.incremental_score_updates
            );
        }
        return Ok(());
    }

    let mut merge_bodies = read_input_bodies(&base_inputs).await?;
    if !reverse_records.is_empty() {
        merge_bodies.push(encode_ndjson(&reverse_records, &command.graph_output)?);
    }
    if !first_party_reverse_records.is_empty() {
        merge_bodies.push(encode_ndjson(
            &first_party_reverse_records,
            &command.graph_output,
        )?);
    }
    if !forward_records.is_empty() {
        merge_bodies.push(encode_ndjson(&forward_records, &command.graph_output)?);
    }
    let merge_inputs = merge_bodies.iter().map(String::as_str).collect::<Vec<_>>();

    let (merged_records, merge_summary) =
        scoring::merge_score_input_ndjson(&merge_inputs, merge_inputs.len())?;
    write_ndjson_file(&command.graph_output, &merged_records).await?;
    let census_records = priority::package_census_from_score_input(&merged_records);
    write_ndjson_file(&command.census_output, &census_records).await?;
    let merged_body = encode_ndjson(&merged_records, &command.graph_output)?;
    let (scores, build_summary) = scoring::build_priority_scores_from_ndjson(
        &merged_body,
        &ScoreBuildConfig {
            alpha: command.alpha,
            max_iterations: command.max_iterations,
            epsilon: command.epsilon,
            high_quantile: command.high_quantile,
            medium_quantile: command.medium_quantile,
            score_source_version: command.score_source_version,
        },
    )?;
    write_ndjson_file(&command.output, &scores).await?;
    let store =
        supply_stream_core::store::OperationalStore::open(command.graph_store_file.clone()).await?;
    store.record_graph_records(&merged_records).await?;
    store.record_priority_score_records(&scores).await?;

    if command.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "graph_output": command.graph_output.display().to_string(),
                "output": command.output.display().to_string(),
                "census_output": command.census_output.display().to_string(),
                "focus_summary": focus_summary,
                "local_focus_summary": local_focus_summary,
                "first_party_reverse_summary": first_party_reverse_summary,
                "collect_summary": collect_summary,
                "merge_summary": merge_summary,
                "build_summary": build_summary,
            }))?
        );
    } else {
        println!("wrote {}", command.graph_output.display());
        println!("wrote {}", command.output.display());
        println!("wrote {}", command.census_output.display());
        println!(
            "focus: frontier_packages={} reverse_edges={} reverse_depth={} truncated={}",
            focus_summary.frontier_packages,
            focus_summary.emitted_dependency_records,
            focus_summary.reverse_depth,
            focus_summary.frontier_truncated
        );
        println!(
            "local_focus: frontier_packages={} reverse_edges={} truncated={}",
            local_focus_summary.frontier_packages,
            local_focus_summary.emitted_dependency_records,
            local_focus_summary.frontier_truncated
        );
        println!(
            "first_party_reverse: scanned_packages={} matched_dependents={} dependency_records={} fetch_failures={}",
            first_party_reverse_summary.scanned_packages,
            first_party_reverse_summary.matched_dependents,
            first_party_reverse_summary.emitted_dependency_records,
            first_party_reverse_summary.fetch_failures
        );
        println!(
            "collect: seeds={} discovered={} dependency_records={} fetch_failures={} external_fallback_fetches={}",
            collect_summary.seed_packages,
            collect_summary.discovered_packages,
            collect_summary.emitted_dependency_records,
            collect_summary.fetch_failures,
            collect_summary.external_fallback_fetches
        );
        println!(
            "merge: packages={} dependencies={}",
            merge_summary.merged_packages, merge_summary.merged_dependencies
        );
        println!("build: scored_packages={}", build_summary.scored_packages);
    }
    Ok(())
}

async fn run_bootstrap_command(command: BootstrapCommand) -> Result<()> {
    let (collected_records, collected_repositories, collect_summary) = if command.skip_seed_collect
    {
        (
            Vec::new(),
            Vec::new(),
            collector::CollectSummary {
                seed_packages: 0,
                discovered_packages: 0,
                emitted_package_records: 0,
                emitted_dependency_records: 0,
                fetch_failures: 0,
                external_fallback_fetches: 0,
                ecosystems: Vec::new(),
            },
        )
    } else {
        let material = collector::collect_graph_material_from_files(
            &command.seeds,
            command.popularity_file.as_deref(),
            &CollectConfig {
                max_depth: command.max_depth,
                max_packages: command.max_packages,
                request_concurrency: command.request_concurrency,
                allow_external_fallback: true,
            },
        )
        .await?;
        (material.records, material.repositories, material.summary)
    };

    let collected_body = encode_ndjson(&collected_records, &command.graph_output)?;
    let mut merge_bodies = read_input_bodies(&command.base_input).await?;
    let mut imported_body = None;
    let mut deps_dev_summary_json = None;
    if !command.deps_dev_input.is_empty() {
        let (records, summary) = deps_dev::import_dependents_latest_from_paths(
            &command.deps_dev_input,
            &ImportDependentsConfig {
                default_direct_popularity: command.deps_dev_default_direct_popularity,
                include_indirect: command.deps_dev_include_indirect,
                include_non_highest_dependent_releases: command
                    .deps_dev_include_non_highest_dependent_releases,
                direct_popularity_strategy: map_deps_dev_direct_popularity_mode(
                    command.deps_dev_direct_popularity_mode,
                ),
            },
        )
        .await?;
        imported_body = Some(encode_ndjson(&records, &command.graph_output)?);
        deps_dev_summary_json = Some(serde_json::to_value(&summary)?);
    }
    let mut census_records = Vec::<PackageCensusRecord>::new();
    if command.bigquery_census_package_limit > 0 {
        let ecosystems = [
            supply_stream_core::event::Ecosystem::Npm,
            supply_stream_core::event::Ecosystem::Pypi,
            supply_stream_core::event::Ecosystem::CratesIo,
        ];
        let (seeds, _summary) = deps_dev_bigquery::import_top_package_seeds_live(
            &ecosystems,
            &deps_dev_bigquery::LiveBaselineConfig {
                package_limit_per_ecosystem: command.bigquery_census_package_limit,
                package_offset_per_ecosystem: 0,
                edge_limit_per_ecosystem: 0,
                default_direct_popularity: command.deps_dev_default_direct_popularity,
                direct_popularity_strategy: map_deps_dev_direct_popularity_mode(
                    command.deps_dev_direct_popularity_mode,
                ),
            },
        )
        .await?;
        census_records.extend(seeds.into_iter().map(|seed| PackageCensusRecord {
            ecosystem: seed.ecosystem,
            package: priority::normalize_package_name(seed.ecosystem, &seed.package),
            discovered_at: None,
            source: Some("bigquery_top_packages".to_string()),
        }));
    }

    let mut growth_iterations = Vec::new();
    let mut next_bigquery_offset = command.bigquery_baseline_package_offset;
    let mut previous_merged_packages = 0usize;
    let mut pending_collected_records = Some(collected_records.clone());
    let mut pending_collected_repositories = Some(collected_repositories.clone());
    let mut pending_imported_records = match imported_body.as_deref() {
        Some(body) => Some(decode_score_input_ndjson(body)?),
        None => None,
    };
    let mut pending_census_records = Some(census_records.clone());

    loop {
        let bigquery_outcome = load_bigquery_step(&command, next_bigquery_offset).await?;
        let BootstrapBigqueryOutcome {
            body: bigquery_body,
            records: bigquery_records,
            summary_json: bigquery_summary_json,
            seed_collect_summary_json: bigquery_seed_collect_summary_json,
            error: bigquery_error,
        } = bigquery_outcome;

        let mut batch_records = pending_collected_records.take().unwrap_or_default();
        if let Some(records) = &bigquery_records {
            batch_records.extend(records.clone());
        }
        if let Some(imported_records) = pending_imported_records.take() {
            batch_records.extend(imported_records);
        }

        if command.base_input.is_empty() && !batch_records.is_empty() {
            let repositories = pending_collected_repositories.take().unwrap_or_default();
            let extra_census_records = pending_census_records.take().unwrap_or_default();
            let batch_summary = persist_incremental_graph_update(IncrementalPersistRequest {
                graph_output: &command.graph_output,
                graph_store_file: &command.graph_store_file,
                census_output: &command.census_output,
                output: &command.output,
                records: &batch_records,
                repositories: &repositories,
                extra_census_records: &extra_census_records,
                scoring_config: IncrementalScoringConfig {
                    score_source_version: command.score_source_version.clone(),
                    alpha: command.alpha,
                    max_iterations: command.max_iterations,
                    epsilon: command.epsilon,
                    high_quantile: command.high_quantile,
                    medium_quantile: command.medium_quantile,
                    max_packages: command.max_packages,
                    request_concurrency: command.request_concurrency,
                },
            })
            .await?;

            let merge_summary = batch_summary.merge_summary.clone();
            let build_summary = batch_summary.build_summary.clone();

            if command.target_scored_packages.is_some() {
                growth_iterations.push(serde_json::json!({
                    "iteration": growth_iterations.len() + 1,
                    "bigquery_offset": next_bigquery_offset,
                    "merge_summary": merge_summary,
                    "build_summary": build_summary,
                    "bigquery_baseline_summary": bigquery_summary_json,
                    "bigquery_seed_collect_summary": bigquery_seed_collect_summary_json,
                    "bigquery_baseline_error": bigquery_error,
                    "incremental_score_updates": batch_summary.incremental_score_updates,
                    "graph_persist_mode": "append_store_incremental",
                }));
            }

            let reached_target = command
                .target_scored_packages
                .is_some_and(|target| build_summary.scored_packages >= target);
            let no_more_bigquery_rows = bigquery_error.is_some()
                || bigquery_summary_json
                    .as_ref()
                    .is_some_and(bigquery_summary_is_empty);
            let no_growth = merge_summary.merged_packages <= previous_merged_packages;
            previous_merged_packages = merge_summary.merged_packages;

            if command.target_scored_packages.is_none()
                || reached_target
                || no_more_bigquery_rows
                || (no_growth && command.bigquery_baseline_package_limit > 0)
            {
                if command.json {
                    let mut payload = serde_json::json!({
                        "graph_output": command.graph_output.display().to_string(),
                        "graph_store_file": command.graph_store_file.display().to_string(),
                        "output": command.output.display().to_string(),
                        "census_output": command.census_output.display().to_string(),
                        "collect_summary": collect_summary,
                        "merge_summary": merge_summary,
                        "build_summary": build_summary,
                        "incremental_score_updates": batch_summary.incremental_score_updates,
                        "graph_persist_mode": "append_store_incremental",
                    });
                    if let Some(summary) = deps_dev_summary_json.clone() {
                        payload["deps_dev_import_summary"] = summary;
                    }
                    if let Some(summary) = bigquery_summary_json.clone() {
                        payload["bigquery_baseline_summary"] = summary;
                    }
                    if let Some(summary) = bigquery_seed_collect_summary_json.clone() {
                        payload["bigquery_seed_collect_summary"] = summary;
                    }
                    if let Some(error) = bigquery_error.clone() {
                        payload["bigquery_baseline_error"] = serde_json::Value::String(error);
                    }
                    if !growth_iterations.is_empty() {
                        payload["growth_iterations"] = serde_json::Value::Array(growth_iterations);
                    }
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                } else {
                    println!("wrote {}", command.graph_output.display());
                    println!("graph_store: {}", command.graph_store_file.display());
                    println!("wrote {}", command.output.display());
                    println!("wrote {}", command.census_output.display());
                    println!(
                        "collect: seeds={} discovered={} dependency_records={} fetch_failures={} external_fallback_fetches={}",
                        collect_summary.seed_packages,
                        collect_summary.discovered_packages,
                        collect_summary.emitted_dependency_records,
                        collect_summary.fetch_failures,
                        collect_summary.external_fallback_fetches
                    );
                    if let Some(summary) = deps_dev_summary_json {
                        println!(
                            "deps_dev: imported_rows={} emitted_dependency_records={}",
                            summary["imported_rows"].as_u64().unwrap_or(0),
                            summary["emitted_dependency_records"].as_u64().unwrap_or(0)
                        );
                    }
                    if let Some(summary) = bigquery_summary_json {
                        println!(
                            "bigquery: packages={} dependency_records={}",
                            summary["emitted_package_records"].as_u64().unwrap_or(0),
                            summary["emitted_dependency_records"].as_u64().unwrap_or(0)
                        );
                    }
                    if let Some(error) = bigquery_error {
                        println!("bigquery_error: {error}");
                    }
                    println!(
                        "merge: packages={} dependencies={}",
                        merge_summary.merged_packages, merge_summary.merged_dependencies
                    );
                    println!(
                        "build: scored_packages={} incremental_updates={}",
                        build_summary.scored_packages, batch_summary.incremental_score_updates
                    );
                }
                break;
            }

            next_bigquery_offset =
                next_bigquery_offset.saturating_add(command.bigquery_baseline_package_limit);
            continue;
        }

        let mut iteration_merge_bodies = merge_bodies.clone();
        iteration_merge_bodies.push(collected_body.clone());
        if let Some(bigquery_body) = bigquery_body.as_deref() {
            iteration_merge_bodies.push(bigquery_body.to_string());
        }
        if let Some(imported_body) = imported_body.as_deref() {
            iteration_merge_bodies.push(imported_body.to_string());
        }

        let (merged_body, merge_summary, build_summary) =
            merge_build_and_write_outputs(&command, &iteration_merge_bodies, &census_records)
                .await?;
        merge_bodies = vec![merged_body];

        if command.target_scored_packages.is_some() {
            growth_iterations.push(serde_json::json!({
                "iteration": growth_iterations.len() + 1,
                "bigquery_offset": next_bigquery_offset,
                "merge_summary": merge_summary,
                "build_summary": build_summary,
                "bigquery_baseline_summary": bigquery_summary_json,
                "bigquery_seed_collect_summary": bigquery_seed_collect_summary_json,
                "bigquery_baseline_error": bigquery_error,
            }));
        }

        let reached_target = command
            .target_scored_packages
            .is_some_and(|target| build_summary.scored_packages >= target);
        let no_more_bigquery_rows = bigquery_error.is_some()
            || bigquery_summary_json
                .as_ref()
                .is_some_and(bigquery_summary_is_empty);
        let no_growth = merge_summary.merged_packages <= previous_merged_packages;
        previous_merged_packages = merge_summary.merged_packages;

        if command.target_scored_packages.is_none()
            || reached_target
            || no_more_bigquery_rows
            || (no_growth && command.bigquery_baseline_package_limit > 0)
        {
            if command.json {
                let mut payload = serde_json::json!({
                    "graph_output": command.graph_output.display().to_string(),
                    "output": command.output.display().to_string(),
                    "census_output": command.census_output.display().to_string(),
                    "collect_summary": collect_summary,
                    "merge_summary": merge_summary,
                    "build_summary": build_summary,
                });
                if let Some(summary) = deps_dev_summary_json.clone() {
                    payload["deps_dev_import_summary"] = summary;
                }
                if let Some(summary) = bigquery_summary_json.clone() {
                    payload["bigquery_baseline_summary"] = summary;
                }
                if let Some(summary) = bigquery_seed_collect_summary_json.clone() {
                    payload["bigquery_seed_collect_summary"] = summary;
                }
                if let Some(error) = bigquery_error.clone() {
                    payload["bigquery_baseline_error"] = serde_json::Value::String(error);
                }
                if !growth_iterations.is_empty() {
                    payload["growth_iterations"] = serde_json::Value::Array(growth_iterations);
                }
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                println!("wrote {}", command.graph_output.display());
                println!("wrote {}", command.output.display());
                println!("wrote {}", command.census_output.display());
                println!(
                    "collect: seeds={} discovered={} dependency_records={} fetch_failures={} external_fallback_fetches={}",
                    collect_summary.seed_packages,
                    collect_summary.discovered_packages,
                    collect_summary.emitted_dependency_records,
                    collect_summary.fetch_failures,
                    collect_summary.external_fallback_fetches
                );
                if let Some(summary) = deps_dev_summary_json {
                    println!(
                        "deps_dev: imported_rows={} emitted_dependency_records={}",
                        summary["imported_rows"].as_u64().unwrap_or(0),
                        summary["emitted_dependency_records"].as_u64().unwrap_or(0)
                    );
                }
                if let Some(summary) = bigquery_summary_json {
                    println!(
                        "bigquery: packages={} dependency_records={}",
                        summary["emitted_package_records"].as_u64().unwrap_or(0),
                        summary["emitted_dependency_records"].as_u64().unwrap_or(0)
                    );
                }
                if let Some(error) = bigquery_error {
                    println!("bigquery_error: {error}");
                }
                println!(
                    "merge: packages={} dependencies={}",
                    merge_summary.merged_packages, merge_summary.merged_dependencies
                );
                println!("build: scored_packages={}", build_summary.scored_packages);
            }
            break;
        }

        next_bigquery_offset =
            next_bigquery_offset.saturating_add(command.bigquery_baseline_package_limit);
    }
    Ok(())
}

async fn run_broaden_command(command: BroadenCommand) -> Result<()> {
    if command.batch_size == 0 {
        anyhow::bail!("batch_size must be greater than zero");
    }

    let allowed_ecosystems = command
        .ecosystems
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    ensure_graph_store_seeded_if_needed(&command.graph_store_file, &command.graph_output).await?;
    let store =
        supply_stream_core::store::OperationalStore::open(command.graph_store_file.clone()).await?;
    let census = priority::load_package_census_records(&command.census_file).await?;
    let ordered_census = census
        .into_iter()
        .filter(|record| allowed_ecosystems.contains(&record.ecosystem))
        .map(|record| collector::SeedPackageRecord {
            ecosystem: record.ecosystem,
            package: priority::normalize_package_name(record.ecosystem, &record.package),
            direct_popularity: None,
        })
        .collect::<Vec<_>>();

    let cursor_before = match command.cursor {
        Some(cursor) => cursor,
        None => load_broaden_progress(&command.progress_file)
            .await?
            .map(|progress| progress.cursor)
            .unwrap_or(0),
    };
    let mut graph_persist_mode = "append_only";
    let mut build_summary: Option<scoring::ScoreBuildSummary> = None;
    let mut last_collect_summary = collector::CollectSummary {
        seed_packages: 0,
        discovered_packages: 0,
        emitted_package_records: 0,
        emitted_dependency_records: 0,
        fetch_failures: 0,
        external_fallback_fetches: 0,
        ecosystems: Vec::new(),
    };
    let mut last_merge_summary = scoring::ScoreInputMergeSummary {
        input_files: 0,
        input_packages: 0,
        input_dependencies: 0,
        merged_packages: 0,
        merged_dependencies: 0,
        ecosystems: Vec::new(),
    };
    let mut incremental_score_updates = 0usize;
    let mut total_incremental_score_updates = 0usize;
    let mut total_selected = 0usize;
    let mut total_scanned = 0usize;
    let mut exhausted = false;
    let mut iterations_completed = 0usize;
    let mut current_cursor = cursor_before;

    for _ in 0..command.iterations.max(1) {
        let known_packages = store
            .load_known_graph_packages(&allowed_ecosystems.iter().copied().collect::<Vec<_>>())
            .await?;
        let selection = select_broaden_batch(
            &ordered_census,
            &known_packages,
            current_cursor,
            command.batch_size,
        );
        current_cursor = selection.cursor_after;
        total_selected += selection.selected.len();
        total_scanned += selection.scanned;
        exhausted = selection.exhausted;
        iterations_completed += 1;

        let (collected_records, collected_repositories, collect_summary) =
            if selection.selected.is_empty() {
                (
                    Vec::new(),
                    Vec::new(),
                    collector::CollectSummary {
                        seed_packages: 0,
                        discovered_packages: 0,
                        emitted_package_records: 0,
                        emitted_dependency_records: 0,
                        fetch_failures: 0,
                        external_fallback_fetches: 0,
                        ecosystems: Vec::new(),
                    },
                )
            } else {
                let material = collector::collect_graph_material_from_records(
                    selection.selected.clone(),
                    Vec::new(),
                    &CollectConfig {
                        max_depth: command.max_depth,
                        max_packages: command.max_packages,
                        request_concurrency: command.request_concurrency,
                        allow_external_fallback: false,
                    },
                )
                .await?;
                (material.records, material.repositories, material.summary)
            };

        let batch_merge_summary = if collected_records.is_empty() {
            scoring::ScoreInputMergeSummary {
                input_files: 0,
                input_packages: 0,
                input_dependencies: 0,
                merged_packages: 0,
                merged_dependencies: 0,
                ecosystems: Vec::new(),
            }
        } else {
            let batch_body = encode_ndjson(&collected_records, &command.graph_output)?;
            let (_, summary) = scoring::merge_score_input_ndjson(&[batch_body.as_str()], 1)?;
            summary
        };

        incremental_score_updates = 0;
        if !collected_records.is_empty() {
            append_ndjson_file(&command.graph_output, &collected_records).await?;
            store.record_graph_records(&collected_records).await?;
            if !collected_repositories.is_empty() {
                store
                    .record_package_repository_refs(&collected_repositories)
                    .await?;
            }

            if let Some(output) = &command.output
                && !command.rebuild_scores
            {
                let roots = priority_roots_from_score_input(&collected_records);
                let config = PriorityConfig {
                    score_file: output.clone(),
                    graph_file: command.graph_output.clone(),
                    census_file: command.census_file.clone(),
                    graph_store_file: Some(command.graph_store_file.clone()),
                    online_fallback: false,
                    online_request_timeout: Duration::from_secs(10),
                    deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
                    deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
                    online_expand_unknown: false,
                    online_expand_min_observations: 3,
                    expand_focus: supply_stream_core::deps_dev::FocusDependentsConfig {
                        reverse_depth: 1,
                        max_frontier_packages: 256,
                        include_non_highest_dependent_releases: false,
                        default_direct_popularity: 1.0,
                        direct_popularity_strategy:
                            supply_stream_core::deps_dev::DirectPopularityStrategy::DirectDependentCount,
                    },
                    expand_collect: supply_stream_core::collector::CollectConfig {
                        max_depth: 0,
                        max_packages: command.max_packages,
                        request_concurrency: command.request_concurrency,
                        allow_external_fallback: false,
                    },
                    expand_score_build: supply_stream_core::scoring::ScoreBuildConfig {
                        alpha: command.alpha,
                        max_iterations: command.max_iterations,
                        epsilon: command.epsilon,
                        high_quantile: command.high_quantile,
                        medium_quantile: command.medium_quantile,
                        score_source_version: command.score_source_version.clone(),
                    },
                };
                let updates = priority::rescore_local_graph_roots(&config, &roots, 128).await?;
                incremental_score_updates = updates.len();
                total_incremental_score_updates += updates.len();
                if !updates.is_empty() {
                    store.record_priority_score_records(&updates).await?;
                    priority::export_priority_score_records(
                        output,
                        Some(&command.graph_store_file),
                    )
                    .await?;
                }
            }
        }

        save_broaden_progress(
            &command.progress_file,
            &BroadenProgress {
                cursor: current_cursor,
            },
        )
        .await?;

        last_collect_summary = collect_summary;
        last_merge_summary = batch_merge_summary;
        if exhausted {
            break;
        }
    }

    if command.rebuild_scores {
        graph_persist_mode = "rewrite_merged";
        let base_inputs =
            resolve_broaden_base_inputs(&command.base_input, &command.graph_output).await;
        let merge_bodies = read_input_bodies(&base_inputs).await?;
        let merge_inputs = merge_bodies.iter().map(String::as_str).collect::<Vec<_>>();
        let (merged_records, _) =
            scoring::merge_score_input_ndjson(&merge_inputs, merge_inputs.len())?;
        write_ndjson_file(&command.graph_output, &merged_records).await?;

        let output = command
            .output
            .as_ref()
            .context("--output is required when --rebuild-scores true")?;
        let merged_body = encode_ndjson(&merged_records, &command.graph_output)?;
        let (scores, rebuilt_summary) = scoring::build_priority_scores_from_ndjson(
            &merged_body,
            &ScoreBuildConfig {
                alpha: command.alpha,
                max_iterations: command.max_iterations,
                epsilon: command.epsilon,
                high_quantile: command.high_quantile,
                medium_quantile: command.medium_quantile,
                score_source_version: command.score_source_version.clone(),
            },
        )?;
        write_ndjson_file(output, &scores).await?;
        store.record_priority_score_records(&scores).await?;
        build_summary = Some(rebuilt_summary);
    }
    let final_known_packages = store
        .load_known_graph_packages(&allowed_ecosystems.iter().copied().collect::<Vec<_>>())
        .await?;

    let summary = BroadenSummary {
        graph_output: command.graph_output.display().to_string(),
        graph_store_file: command.graph_store_file.display().to_string(),
        output: command
            .output
            .as_ref()
            .map(|path| path.display().to_string()),
        progress_file: command.progress_file.display().to_string(),
        iterations_requested: command.iterations.max(1),
        iterations_completed,
        cursor_before,
        cursor_after: current_cursor,
        census_size: ordered_census.len(),
        known_packages_source: "graph_store",
        known_packages_count: final_known_packages.len(),
        scanned: total_scanned,
        selected: total_selected,
        exhausted,
        collect_summary: last_collect_summary,
        merge_summary: last_merge_summary,
        build_summary,
        incremental_score_updates,
        total_selected,
        total_scanned,
        total_incremental_score_updates,
        graph_persist_mode,
    };

    if command.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("wrote {}", command.graph_output.display());
        println!("graph_store: {}", command.graph_store_file.display());
        println!("progress: {}", command.progress_file.display());
        println!(
            "broadened: iterations={}/{} selected={} scanned={} cursor={} exhausted={} known_packages={} known_source={}",
            summary.iterations_completed,
            summary.iterations_requested,
            summary.total_selected,
            summary.total_scanned,
            summary.cursor_after,
            summary.exhausted,
            summary.known_packages_count,
            summary.known_packages_source
        );
        println!(
            "persist: mode={} incremental_score_updates={} total_incremental_score_updates={}",
            summary.graph_persist_mode,
            summary.incremental_score_updates,
            summary.total_incremental_score_updates
        );
        println!(
            "collect: discovered={} dependency_records={} fetch_failures={} external_fallback_fetches={}",
            summary.collect_summary.discovered_packages,
            summary.collect_summary.emitted_dependency_records,
            summary.collect_summary.fetch_failures,
            summary.collect_summary.external_fallback_fetches
        );
        println!(
            "merge: packages={} dependencies={}",
            summary.merge_summary.merged_packages, summary.merge_summary.merged_dependencies
        );
        if let Some(build_summary) = &summary.build_summary {
            println!("build: scored_packages={}", build_summary.scored_packages);
        }
    }

    Ok(())
}

async fn run_repo_backfill_command(
    graph_file: std::path::PathBuf,
    graph_store_file: std::path::PathBuf,
    ecosystem: Option<supply_stream_core::event::Ecosystem>,
    package: Option<String>,
    force: bool,
    limit: Option<usize>,
    request_concurrency: usize,
) -> Result<RepoBackfillSummary> {
    if request_concurrency == 0 {
        anyhow::bail!("request_concurrency must be greater than zero");
    }
    if package.is_some() && ecosystem.is_none() {
        anyhow::bail!("--package requires --ecosystem");
    }

    let graph_records = scoring::load_score_input_records(&graph_file).await?;
    let mut packages = known_packages_from_records(&graph_records)
        .into_iter()
        .collect::<Vec<_>>();
    packages.sort();

    let store = supply_stream_core::store::OperationalStore::open(graph_store_file).await?;
    let normalized_package = package
        .as_deref()
        .zip(ecosystem)
        .map(|(package, ecosystem)| priority::normalize_package_name(ecosystem, package));

    let mut summary = RepoBackfillSummary {
        packages_scanned: 0,
        fetched: 0,
        stored: 0,
        already_known: 0,
        resolved: 0,
        missing_repository: 0,
        fetch_failures: 0,
    };
    let mut targets = Vec::new();

    for (record_ecosystem, record_package) in packages {
        if let Some(filter_ecosystem) = ecosystem
            && record_ecosystem != filter_ecosystem
        {
            continue;
        }
        if let Some(filter_package) = &normalized_package
            && &record_package != filter_package
        {
            continue;
        }
        if let Some(limit) = limit
            && summary.packages_scanned >= limit
        {
            break;
        }

        summary.packages_scanned += 1;
        if !force
            && store
                .load_package_repository_identity(record_ecosystem, &record_package)
                .await?
                .is_some()
        {
            summary.already_known += 1;
            continue;
        }

        targets.push(collector::SeedPackageRecord {
            ecosystem: record_ecosystem,
            package: record_package,
            direct_popularity: None,
        });
    }
    let fetched = targets.len();
    let material = if targets.is_empty() {
        collector::CollectedGraphMaterial {
            records: Vec::new(),
            repositories: Vec::new(),
            summary: collector::CollectSummary {
                seed_packages: 0,
                discovered_packages: 0,
                emitted_package_records: 0,
                emitted_dependency_records: 0,
                fetch_failures: 0,
                external_fallback_fetches: 0,
                ecosystems: Vec::new(),
            },
        }
    } else {
        collector::collect_graph_material_from_records(
            targets,
            Vec::new(),
            &CollectConfig {
                max_depth: 0,
                max_packages: fetched,
                request_concurrency,
                allow_external_fallback: false,
            },
        )
        .await?
    };

    summary.fetched = fetched;
    summary.fetch_failures = material.summary.fetch_failures;
    summary.resolved = material.repositories.len();
    summary.missing_repository = fetched
        .saturating_sub(summary.resolved)
        .saturating_sub(summary.fetch_failures);

    if !material.repositories.is_empty() {
        store
            .record_package_repository_refs(&material.repositories)
            .await?;
        summary.stored = material.repositories.len();
    }

    Ok(summary)
}

async fn run_graph_backfill_command(command: GraphBackfillCommand) -> Result<GraphBackfillSummary> {
    let normalized_package = command
        .package
        .as_deref()
        .zip(command.ecosystem)
        .map(|(package, ecosystem)| priority::normalize_package_name(ecosystem, package));
    let capture_paths = collect_capture_json_paths(&command.data_dir.join("captures")).await?;

    let mut captures_scanned = 0usize;
    let mut captures_with_graph_records = 0usize;
    let mut records = Vec::new();
    let mut repositories = Vec::new();

    for capture_path in capture_paths {
        if let Some(limit) = command.limit
            && captures_scanned >= limit
        {
            break;
        }

        let bytes = fs::read(&capture_path)
            .await
            .with_context(|| format!("failed to read {}", capture_path.display()))?;
        let capture = serde_json::from_slice::<capture::CapturedRelease>(&bytes)
            .with_context(|| format!("failed to parse {}", capture_path.display()))?;

        if let Some(filter_ecosystem) = command.ecosystem
            && capture.ecosystem != filter_ecosystem
        {
            continue;
        }
        if let Some(filter_package) = &normalized_package
            && priority::normalize_package_name(capture.ecosystem, &capture.package)
                != *filter_package
        {
            continue;
        }

        captures_scanned += 1;
        let capture_records = capture::graph_records_from_captured_release(&capture);
        if !capture_records.is_empty() {
            captures_with_graph_records += 1;
            records.extend(capture_records);
        }
        if let Some(repository) =
            capture::package_repository_identity_from_captured_release(capture.ecosystem, &capture)
        {
            repositories.push(repository);
        }
    }

    let merged_records = if records.is_empty() {
        Vec::new()
    } else {
        let body = scoring::encode_score_input_ndjson(&records)?;
        let (merged, _) = scoring::merge_score_input_ndjson(&[body.as_str()], 1)?;
        merged
    };

    let summary = persist_incremental_graph_update(IncrementalPersistRequest {
        graph_output: &command.graph_output,
        graph_store_file: &command.graph_store_file,
        census_output: &command.census_output,
        output: &command.output,
        records: &merged_records,
        repositories: &repositories,
        extra_census_records: &[],
        scoring_config: command.scoring_config,
    })
    .await?;

    Ok(GraphBackfillSummary {
        data_dir: command.data_dir.display().to_string(),
        graph_output: command.graph_output.display().to_string(),
        graph_store_file: command.graph_store_file.display().to_string(),
        output: command.output.display().to_string(),
        census_output: command.census_output.display().to_string(),
        captures_scanned,
        captures_with_graph_records,
        repository_refs: repositories.len(),
        merge_summary: summary.merge_summary,
        build_summary: summary.build_summary,
        incremental_score_updates: summary.incremental_score_updates,
    })
}

async fn collect_capture_json_paths(root: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut paths = Vec::new();
    if !fs::try_exists(root).await.unwrap_or(false) {
        return Ok(paths);
    }

    let mut ecosystems = fs::read_dir(root)
        .await
        .with_context(|| format!("failed to read {}", root.display()))?;
    while let Some(ecosystem_entry) = ecosystems.next_entry().await? {
        if !ecosystem_entry.file_type().await?.is_dir() {
            continue;
        }
        let mut packages = fs::read_dir(ecosystem_entry.path()).await?;
        while let Some(package_entry) = packages.next_entry().await? {
            if !package_entry.file_type().await?.is_dir() {
                continue;
            }
            let mut versions = fs::read_dir(package_entry.path()).await?;
            while let Some(version_entry) = versions.next_entry().await? {
                if !version_entry.file_type().await?.is_dir() {
                    continue;
                }
                let capture_path = version_entry.path().join("capture.json");
                if fs::try_exists(&capture_path).await.unwrap_or(false) {
                    paths.push(capture_path);
                }
            }
        }
    }
    paths.sort();
    Ok(paths)
}

#[derive(Debug, Clone)]
struct BootstrapBigqueryOutcome {
    body: Option<String>,
    records: Option<Vec<scoring::ScoreInputRecord>>,
    summary_json: Option<serde_json::Value>,
    seed_collect_summary_json: Option<serde_json::Value>,
    error: Option<String>,
}

async fn load_bigquery_step(
    command: &BootstrapCommand,
    package_offset: usize,
) -> Result<BootstrapBigqueryOutcome> {
    if command.bigquery_baseline_package_limit == 0 {
        return Ok(BootstrapBigqueryOutcome {
            body: None,
            records: None,
            summary_json: None,
            seed_collect_summary_json: None,
            error: None,
        });
    }

    let ecosystems = [
        supply_stream_core::event::Ecosystem::Npm,
        supply_stream_core::event::Ecosystem::Pypi,
        supply_stream_core::event::Ecosystem::CratesIo,
    ];
    let baseline_config = deps_dev_bigquery::LiveBaselineConfig {
        package_limit_per_ecosystem: command.bigquery_baseline_package_limit,
        package_offset_per_ecosystem: package_offset,
        edge_limit_per_ecosystem: command.bigquery_baseline_edge_limit,
        default_direct_popularity: command.deps_dev_default_direct_popularity,
        direct_popularity_strategy: map_deps_dev_direct_popularity_mode(
            command.deps_dev_direct_popularity_mode,
        ),
    };

    if command.bigquery_baseline_via_collector {
        match deps_dev_bigquery::import_top_package_seeds_live(&ecosystems, &baseline_config).await
        {
            Ok((seeds, summary)) => {
                let (records, collect_summary) = collector::collect_score_input_from_records(
                    seeds,
                    Vec::new(),
                    &CollectConfig {
                        max_depth: command.max_depth,
                        max_packages: command.max_packages,
                        request_concurrency: command.request_concurrency,
                        allow_external_fallback: true,
                    },
                )
                .await?;
                Ok(BootstrapBigqueryOutcome {
                    body: Some(encode_ndjson(&records, &command.graph_output)?),
                    records: Some(records),
                    summary_json: Some(serde_json::to_value(&summary)?),
                    seed_collect_summary_json: Some(serde_json::to_value(&collect_summary)?),
                    error: None,
                })
            }
            Err(error) => Ok(BootstrapBigqueryOutcome {
                body: None,
                records: None,
                summary_json: None,
                seed_collect_summary_json: None,
                error: Some(format!("{error:#}")),
            }),
        }
    } else {
        match deps_dev_bigquery::import_dependencies_latest_live(&ecosystems, &baseline_config)
            .await
        {
            Ok((records, summary)) => Ok(BootstrapBigqueryOutcome {
                body: Some(encode_ndjson(&records, &command.graph_output)?),
                records: Some(records),
                summary_json: Some(serde_json::to_value(&summary)?),
                seed_collect_summary_json: None,
                error: None,
            }),
            Err(error) => Ok(BootstrapBigqueryOutcome {
                body: None,
                records: None,
                summary_json: None,
                seed_collect_summary_json: None,
                error: Some(format!("{error:#}")),
            }),
        }
    }
}

async fn merge_build_and_write_outputs(
    command: &BootstrapCommand,
    merge_bodies: &[String],
    extra_census_records: &[PackageCensusRecord],
) -> Result<(
    String,
    scoring::ScoreInputMergeSummary,
    scoring::ScoreBuildSummary,
)> {
    let merge_inputs = merge_bodies.iter().map(String::as_str).collect::<Vec<_>>();
    let (merged_records, merge_summary) =
        scoring::merge_score_input_ndjson(&merge_inputs, merge_inputs.len())?;
    write_ndjson_file(&command.graph_output, &merged_records).await?;
    let mut census_records = priority::package_census_from_score_input(&merged_records);
    if !extra_census_records.is_empty() {
        census_records.extend_from_slice(extra_census_records);
        census_records.sort();
        census_records.dedup_by(|left, right| {
            left.ecosystem == right.ecosystem && left.package == right.package
        });
    }
    write_ndjson_file(&command.census_output, &census_records).await?;
    let merged_body = encode_ndjson(&merged_records, &command.graph_output)?;
    let (scores, build_summary) = scoring::build_priority_scores_from_ndjson(
        &merged_body,
        &ScoreBuildConfig {
            alpha: command.alpha,
            max_iterations: command.max_iterations,
            epsilon: command.epsilon,
            high_quantile: command.high_quantile,
            medium_quantile: command.medium_quantile,
            score_source_version: command.score_source_version.clone(),
        },
    )?;
    write_ndjson_file(&command.output, &scores).await?;
    let store =
        supply_stream_core::store::OperationalStore::open(command.graph_store_file.clone()).await?;
    store.record_graph_records(&merged_records).await?;
    store.record_priority_score_records(&scores).await?;
    Ok((merged_body, merge_summary, build_summary))
}

fn bigquery_summary_is_empty(summary: &serde_json::Value) -> bool {
    summary["emitted_package_records"].as_u64().unwrap_or(0) == 0
        && summary["emitted_dependency_records"].as_u64().unwrap_or(0) == 0
}

fn map_deps_dev_direct_popularity_mode(
    mode: DepsDevDirectPopularityMode,
) -> DirectPopularityStrategy {
    match mode {
        DepsDevDirectPopularityMode::Constant => DirectPopularityStrategy::Constant,
        DepsDevDirectPopularityMode::DirectDependentCount => {
            DirectPopularityStrategy::DirectDependentCount
        }
    }
}

fn map_priority_score_metric(metric: PriorityScoreMetricArg) -> PriorityScoreMetric {
    match metric {
        PriorityScoreMetricArg::DirectPopularity => PriorityScoreMetric::DirectPopularity,
        PriorityScoreMetricArg::PropagatedImpact => PriorityScoreMetric::PropagatedImpact,
        PriorityScoreMetricArg::HiddenLeverage => PriorityScoreMetric::HiddenLeverage,
    }
}

fn encode_ndjson<T: serde::Serialize>(records: &[T], output: &std::path::Path) -> Result<String> {
    let mut encoded = String::new();
    for record in records {
        encoded.push_str(
            &serde_json::to_string(record)
                .with_context(|| format!("failed to encode {}", output.display()))?,
        );
        encoded.push('\n');
    }
    Ok(encoded)
}

#[derive(Debug, Clone)]
struct IncrementalScoringConfig {
    score_source_version: Option<String>,
    alpha: f64,
    max_iterations: usize,
    epsilon: f64,
    high_quantile: f64,
    medium_quantile: f64,
    max_packages: usize,
    request_concurrency: usize,
}

#[derive(Debug, Clone)]
struct IncrementalPersistSummary {
    merge_summary: scoring::ScoreInputMergeSummary,
    build_summary: scoring::ScoreBuildSummary,
    incremental_score_updates: usize,
}

struct IncrementalPersistRequest<'a> {
    graph_output: &'a std::path::Path,
    graph_store_file: &'a std::path::Path,
    census_output: &'a std::path::Path,
    output: &'a std::path::Path,
    records: &'a [scoring::ScoreInputRecord],
    repositories: &'a [supply_stream_core::repo_provenance::PackageRepositoryIdentity],
    extra_census_records: &'a [PackageCensusRecord],
    scoring_config: IncrementalScoringConfig,
}

fn can_incrementally_persist_graph(
    base_inputs: &[std::path::PathBuf],
    graph_output: &std::path::Path,
) -> bool {
    base_inputs.is_empty() || base_inputs.iter().all(|input| input == graph_output)
}

fn decode_score_input_ndjson(body: &str) -> Result<Vec<scoring::ScoreInputRecord>> {
    let mut records = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        records.push(serde_json::from_str::<scoring::ScoreInputRecord>(line)?);
    }
    Ok(records)
}

async fn ensure_graph_store_seeded_if_needed(
    graph_store_file: &std::path::Path,
    graph_output: &std::path::Path,
) -> Result<()> {
    let store_exists = fs::try_exists(graph_store_file).await.unwrap_or(false);
    let graph_exists = fs::try_exists(graph_output).await.unwrap_or(false);
    if store_exists || !graph_exists {
        return Ok(());
    }

    let existing_records = scoring::load_score_input_records(graph_output).await?;
    if existing_records.is_empty() {
        return Ok(());
    }

    let store =
        supply_stream_core::store::OperationalStore::open(graph_store_file.to_path_buf()).await?;
    store.record_graph_records(&existing_records).await?;
    Ok(())
}

async fn load_incremental_build_summary(
    graph_output: &std::path::Path,
    output: &std::path::Path,
    graph_store_file: Option<&std::path::Path>,
) -> Result<scoring::ScoreBuildSummary> {
    if let Some(graph_store_file) = graph_store_file {
        let store =
            supply_stream_core::store::OperationalStore::open(graph_store_file.to_path_buf())
                .await?;
        let graph_stats = store.graph_stats().await?;
        let score_stats = store.priority_score_stats().await?;

        let mut by_ecosystem = std::collections::BTreeMap::<
            supply_stream_core::event::Ecosystem,
            (usize, usize, supply_stream_core::priority::PriorityCounts),
        >::new();
        for ecosystem in graph_stats.ecosystems {
            by_ecosystem.entry(ecosystem.ecosystem).or_insert((
                0,
                0,
                supply_stream_core::priority::PriorityCounts::default(),
            ));
            if let Some(entry) = by_ecosystem.get_mut(&ecosystem.ecosystem) {
                entry.0 = ecosystem.packages;
                entry.1 = ecosystem.dependencies;
            }
        }
        for ecosystem in score_stats.ecosystems {
            by_ecosystem.entry(ecosystem.ecosystem).or_insert((
                0,
                0,
                supply_stream_core::priority::PriorityCounts::default(),
            ));
            if let Some(entry) = by_ecosystem.get_mut(&ecosystem.ecosystem) {
                entry.2 = ecosystem.priorities;
            }
        }

        let ecosystems = by_ecosystem
            .into_iter()
            .map(|(ecosystem, (packages, dependencies, priorities))| {
                scoring::EcosystemScoreSummary {
                    ecosystem,
                    packages,
                    dependencies,
                    priorities,
                }
            })
            .collect::<Vec<_>>();

        return Ok(scoring::ScoreBuildSummary {
            input_packages: graph_stats.packages,
            input_dependencies: graph_stats.dependencies,
            scored_packages: score_stats.scored_packages,
            ecosystems,
        });
    }

    let graph_records = if fs::try_exists(graph_output).await.unwrap_or(false) {
        scoring::load_score_input_records(graph_output).await?
    } else {
        Vec::new()
    };
    let score_records = if fs::try_exists(output).await.unwrap_or(false) {
        priority::load_priority_score_records(output).await?
    } else {
        Vec::new()
    };

    let mut graph_counts =
        std::collections::BTreeMap::<supply_stream_core::event::Ecosystem, (usize, usize)>::new();
    for record in graph_records {
        match record {
            scoring::ScoreInputRecord::Package { ecosystem, .. } => {
                graph_counts.entry(ecosystem).or_default().0 += 1;
            }
            scoring::ScoreInputRecord::Dependency { ecosystem, .. } => {
                graph_counts.entry(ecosystem).or_default().1 += 1;
            }
        }
    }

    let scored_summary = priority::summarize_priority_score_records(&score_records, 0);
    let ecosystems = scored_summary
        .ecosystems
        .into_iter()
        .map(|ecosystem_summary| {
            let (packages, dependencies) = graph_counts
                .get(&ecosystem_summary.ecosystem)
                .copied()
                .unwrap_or((0, 0));
            scoring::EcosystemScoreSummary {
                ecosystem: ecosystem_summary.ecosystem,
                packages,
                dependencies,
                priorities: ecosystem_summary.priorities,
            }
        })
        .collect::<Vec<_>>();

    Ok(scoring::ScoreBuildSummary {
        input_packages: graph_counts.values().map(|(packages, _)| *packages).sum(),
        input_dependencies: graph_counts
            .values()
            .map(|(_, dependencies)| *dependencies)
            .sum(),
        scored_packages: score_records.len(),
        ecosystems,
    })
}

async fn persist_incremental_graph_update(
    request: IncrementalPersistRequest<'_>,
) -> Result<IncrementalPersistSummary> {
    ensure_graph_store_seeded_if_needed(request.graph_store_file, request.graph_output).await?;

    let merge_summary = if request.records.is_empty() {
        scoring::ScoreInputMergeSummary {
            input_files: 0,
            input_packages: 0,
            input_dependencies: 0,
            merged_packages: 0,
            merged_dependencies: 0,
            ecosystems: Vec::new(),
        }
    } else {
        let body = scoring::encode_score_input_ndjson(request.records)?;
        let (_, summary) = scoring::merge_score_input_ndjson(&[body.as_str()], 1)?;
        summary
    };

    if !request.records.is_empty() {
        append_ndjson_file(request.graph_output, request.records).await?;
    }

    let mut census_records = priority::package_census_from_score_input(request.records);
    if !request.extra_census_records.is_empty() {
        census_records.extend_from_slice(request.extra_census_records);
        census_records.sort();
        census_records.dedup_by(|left, right| {
            left.ecosystem == right.ecosystem && left.package == right.package
        });
    }
    if !census_records.is_empty() {
        append_ndjson_file(request.census_output, &census_records).await?;
    }

    let store =
        supply_stream_core::store::OperationalStore::open(request.graph_store_file.to_path_buf())
            .await?;
    if !request.records.is_empty() {
        store.record_graph_records(request.records).await?;
    }
    if !request.repositories.is_empty() {
        store
            .record_package_repository_refs(request.repositories)
            .await?;
    }

    let roots = priority_roots_from_score_input(request.records);
    let config = PriorityConfig {
        score_file: request.output.to_path_buf(),
        graph_file: request.graph_output.to_path_buf(),
        census_file: request.census_output.to_path_buf(),
        graph_store_file: Some(request.graph_store_file.to_path_buf()),
        online_fallback: false,
        online_request_timeout: Duration::from_secs(10),
        deps_dev_v3_base: "https://api.deps.dev/v3".to_string(),
        deps_dev_v3alpha_base: "https://api.deps.dev/v3alpha".to_string(),
        online_expand_unknown: false,
        online_expand_min_observations: 3,
        expand_focus: supply_stream_core::deps_dev::FocusDependentsConfig {
            reverse_depth: 1,
            max_frontier_packages: 256,
            include_non_highest_dependent_releases: false,
            default_direct_popularity: 1.0,
            direct_popularity_strategy:
                supply_stream_core::deps_dev::DirectPopularityStrategy::DirectDependentCount,
        },
        expand_collect: supply_stream_core::collector::CollectConfig {
            max_depth: 0,
            max_packages: request.scoring_config.max_packages,
            request_concurrency: request.scoring_config.request_concurrency,
            allow_external_fallback: true,
        },
        expand_score_build: supply_stream_core::scoring::ScoreBuildConfig {
            alpha: request.scoring_config.alpha,
            max_iterations: request.scoring_config.max_iterations,
            epsilon: request.scoring_config.epsilon,
            high_quantile: request.scoring_config.high_quantile,
            medium_quantile: request.scoring_config.medium_quantile,
            score_source_version: request.scoring_config.score_source_version,
        },
    };
    let updates = priority::rescore_local_graph_roots(&config, &roots, 256).await?;
    if !updates.is_empty() {
        store.record_priority_score_records(&updates).await?;
        priority::export_priority_score_records(request.output, Some(request.graph_store_file))
            .await?;
    }

    let build_summary = load_incremental_build_summary(
        request.graph_output,
        request.output,
        Some(request.graph_store_file),
    )
    .await?;
    Ok(IncrementalPersistSummary {
        merge_summary,
        build_summary,
        incremental_score_updates: updates.len(),
    })
}

async fn read_input_bodies(inputs: &[std::path::PathBuf]) -> Result<Vec<String>> {
    let mut bodies = Vec::with_capacity(inputs.len());
    for input in inputs {
        bodies.push(
            fs::read_to_string(input)
                .await
                .with_context(|| format!("failed to read {}", input.display()))?,
        );
    }
    Ok(bodies)
}

async fn write_ndjson_file<T: serde::Serialize>(
    output: &std::path::Path,
    records: &[T],
) -> Result<()> {
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create output dir {}", parent.display()))?;
    }

    fs::write(output, encode_ndjson(records, output)?)
        .await
        .with_context(|| format!("failed to write {}", output.display()))
}

async fn append_ndjson_file<T: serde::Serialize>(
    output: &std::path::Path,
    records: &[T],
) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create output dir {}", parent.display()))?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
        .await
        .with_context(|| format!("failed to open {} for append", output.display()))?;
    use tokio::io::AsyncWriteExt;
    file.write_all(encode_ndjson(records, output)?.as_bytes())
        .await
        .with_context(|| format!("failed to append {}", output.display()))
}

#[derive(Debug, Clone)]
struct BroadenSelection {
    selected: Vec<collector::SeedPackageRecord>,
    cursor_after: usize,
    scanned: usize,
    exhausted: bool,
}

async fn load_score_input_from_paths(
    inputs: &[std::path::PathBuf],
) -> Result<Vec<scoring::ScoreInputRecord>> {
    let mut records = Vec::new();
    for input in inputs {
        if !fs::try_exists(input).await.unwrap_or(false) {
            continue;
        }
        records.extend(scoring::load_score_input_records(input).await?);
    }
    Ok(records)
}

fn priority_roots_from_score_input(
    records: &[scoring::ScoreInputRecord],
) -> Vec<(supply_stream_core::event::Ecosystem, String)> {
    let mut roots = std::collections::BTreeSet::new();
    for record in records {
        match record {
            scoring::ScoreInputRecord::Package {
                ecosystem, package, ..
            } => {
                roots.insert((*ecosystem, package.clone()));
            }
            scoring::ScoreInputRecord::Dependency {
                ecosystem,
                package,
                dependency,
                ..
            } => {
                roots.insert((*ecosystem, package.clone()));
                roots.insert((*ecosystem, dependency.clone()));
            }
        }
    }
    roots.into_iter().collect()
}

fn known_packages_from_records(
    records: &[scoring::ScoreInputRecord],
) -> std::collections::BTreeSet<(supply_stream_core::event::Ecosystem, String)> {
    let mut packages = std::collections::BTreeSet::new();
    for record in records {
        match record {
            scoring::ScoreInputRecord::Package {
                ecosystem, package, ..
            } => {
                packages.insert((
                    *ecosystem,
                    priority::normalize_package_name(*ecosystem, package),
                ));
            }
            scoring::ScoreInputRecord::Dependency {
                ecosystem,
                package,
                dependency,
                ..
            } => {
                packages.insert((
                    *ecosystem,
                    priority::normalize_package_name(*ecosystem, package),
                ));
                packages.insert((
                    *ecosystem,
                    priority::normalize_package_name(*ecosystem, dependency),
                ));
            }
        }
    }
    packages
}

async fn resolve_broaden_base_inputs(
    base_input: &[std::path::PathBuf],
    graph_output: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    let mut inputs = base_input.to_vec();
    if !inputs.iter().any(|path| path == graph_output)
        && fs::try_exists(graph_output).await.unwrap_or(false)
    {
        inputs.push(graph_output.to_path_buf());
    }
    inputs
}

async fn resolve_focus_base_inputs(
    base_input: &[std::path::PathBuf],
    graph_output: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    resolve_broaden_base_inputs(base_input, graph_output).await
}

fn merge_seed_records(
    left: Vec<collector::SeedPackageRecord>,
    right: Vec<collector::SeedPackageRecord>,
) -> Vec<collector::SeedPackageRecord> {
    let mut merged = std::collections::BTreeMap::<
        (supply_stream_core::event::Ecosystem, String),
        collector::SeedPackageRecord,
    >::new();
    for record in left.into_iter().chain(right) {
        let key = (record.ecosystem, record.package.clone());
        merged
            .entry(key)
            .and_modify(|existing| {
                existing.direct_popularity =
                    match (existing.direct_popularity, record.direct_popularity) {
                        (Some(left), Some(right)) => Some(left.max(right)),
                        (None, Some(right)) => Some(right),
                        (current, None) => current,
                    };
            })
            .or_insert(record);
    }
    merged.into_values().collect()
}

fn build_local_focus_frontier(
    records: &[scoring::ScoreInputRecord],
    ecosystem: supply_stream_core::event::Ecosystem,
    package: &str,
    reverse_depth: usize,
    max_frontier_packages: usize,
    default_direct_popularity: f64,
    direct_popularity_mode: DepsDevDirectPopularityMode,
) -> (Vec<collector::SeedPackageRecord>, LocalFocusSummary) {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    let target = priority::normalize_package_name(ecosystem, package);
    let mut package_popularity = BTreeMap::<String, f64>::new();
    let mut reverse_edges = BTreeMap::<String, BTreeSet<String>>::new();
    let mut dependent_counts = BTreeMap::<String, usize>::new();

    for record in records {
        match record {
            scoring::ScoreInputRecord::Package {
                ecosystem: record_ecosystem,
                package,
                direct_popularity,
            } if *record_ecosystem == ecosystem => {
                package_popularity.insert(
                    priority::normalize_package_name(*record_ecosystem, package),
                    *direct_popularity,
                );
            }
            scoring::ScoreInputRecord::Dependency {
                ecosystem: record_ecosystem,
                package,
                dependency,
                ..
            } if *record_ecosystem == ecosystem => {
                let normalized_package =
                    priority::normalize_package_name(*record_ecosystem, package);
                let normalized_dependency =
                    priority::normalize_package_name(*record_ecosystem, dependency);
                if normalized_package == normalized_dependency {
                    continue;
                }
                reverse_edges
                    .entry(normalized_dependency.clone())
                    .or_default()
                    .insert(normalized_package);
                *dependent_counts.entry(normalized_dependency).or_default() += 1;
            }
            _ => {}
        }
    }

    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::from([(target, 0usize)]);
    let mut frontier_truncated = false;

    while let Some((dependency, depth)) = queue.pop_front() {
        if !visited.insert(dependency.clone()) {
            continue;
        }
        if depth >= reverse_depth {
            continue;
        }
        let Some(dependents) = reverse_edges.get(&dependency) else {
            continue;
        };
        for dependent in dependents {
            if visited.len() >= max_frontier_packages && !visited.contains(dependent) {
                frontier_truncated = true;
                break;
            }
            queue.push_back((dependent.clone(), depth + 1));
        }
        if frontier_truncated {
            break;
        }
    }

    let frontier_packages = visited.len();
    let emitted_dependency_records = reverse_edges
        .iter()
        .filter(|(dependency, dependents)| {
            visited.contains(*dependency)
                && dependents
                    .iter()
                    .any(|dependent| visited.contains(dependent))
        })
        .map(|(_, dependents)| {
            dependents
                .iter()
                .filter(|dependent| visited.contains(*dependent))
                .count()
        })
        .sum();

    let seeds = visited
        .into_iter()
        .map(|package| {
            let direct_popularity = match direct_popularity_mode {
                DepsDevDirectPopularityMode::Constant => default_direct_popularity,
                DepsDevDirectPopularityMode::DirectDependentCount => package_popularity
                    .get(&package)
                    .copied()
                    .unwrap_or_else(|| {
                        (dependent_counts.get(&package).copied().unwrap_or(0) as f64)
                            .max(default_direct_popularity)
                    }),
            };
            collector::SeedPackageRecord {
                ecosystem,
                package,
                direct_popularity: Some(direct_popularity.max(default_direct_popularity)),
            }
        })
        .collect::<Vec<_>>();

    (
        seeds,
        LocalFocusSummary {
            frontier_packages,
            frontier_truncated,
            emitted_dependency_records,
        },
    )
}

async fn discover_reverse_dependents_from_census(
    census_path: &std::path::Path,
    base_records: &[scoring::ScoreInputRecord],
    package: &str,
    config: FirstPartyReverseScanConfig,
) -> Result<(
    Vec<scoring::ScoreInputRecord>,
    Vec<collector::SeedPackageRecord>,
    FirstPartyReverseScanSummary,
)> {
    if config.max_packages == 0 || config.max_frontier_packages == 0 {
        return Ok((
            Vec::new(),
            Vec::new(),
            FirstPartyReverseScanSummary::default(),
        ));
    }

    let target = priority::normalize_package_name(config.ecosystem, package);
    let census = priority::load_package_census_records(census_path).await?;
    if census.is_empty() {
        return Ok((
            Vec::new(),
            Vec::new(),
            FirstPartyReverseScanSummary::default(),
        ));
    }

    let mut known_packages = known_packages_from_records(base_records);
    let mut known_reverse_dependents = std::collections::BTreeSet::<String>::new();
    let mut known_direct_popularity = std::collections::BTreeMap::<String, f64>::new();
    for record in base_records {
        match record {
            scoring::ScoreInputRecord::Package {
                ecosystem: record_ecosystem,
                package,
                direct_popularity,
            } if *record_ecosystem == config.ecosystem => {
                known_direct_popularity.insert(
                    priority::normalize_package_name(*record_ecosystem, package),
                    *direct_popularity,
                );
            }
            scoring::ScoreInputRecord::Dependency {
                ecosystem: record_ecosystem,
                package,
                dependency,
                ..
            } if *record_ecosystem == config.ecosystem
                && priority::normalize_package_name(*record_ecosystem, dependency) == target =>
            {
                known_reverse_dependents
                    .insert(priority::normalize_package_name(*record_ecosystem, package));
            }
            _ => {}
        }
    }

    let candidates = census
        .into_iter()
        .filter(|record| record.ecosystem == config.ecosystem)
        .map(|record| priority::normalize_package_name(record.ecosystem, &record.package))
        .filter(|candidate| candidate != &target)
        .filter(|candidate| !known_reverse_dependents.contains(candidate))
        .filter(|candidate| !known_packages.contains(&(config.ecosystem, candidate.clone())))
        .take(config.max_packages)
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return Ok((
            Vec::new(),
            Vec::new(),
            FirstPartyReverseScanSummary::default(),
        ));
    }

    let batch_size = config.request_concurrency.max(1).saturating_mul(8).max(32);
    let mut emitted_records = Vec::<scoring::ScoreInputRecord>::new();
    let mut seeds = Vec::<collector::SeedPackageRecord>::new();
    let mut summary = FirstPartyReverseScanSummary::default();

    for batch in candidates.chunks(batch_size) {
        if summary.matched_dependents >= config.max_frontier_packages {
            break;
        }

        let batch_seeds = batch
            .iter()
            .map(|package| collector::SeedPackageRecord {
                ecosystem: config.ecosystem,
                package: package.clone(),
                direct_popularity: known_direct_popularity
                    .get(package)
                    .copied()
                    .or(Some(config.default_direct_popularity)),
            })
            .collect::<Vec<_>>();

        let (records, collect_summary) = collector::collect_score_input_from_records(
            batch_seeds.clone(),
            Vec::new(),
            &CollectConfig {
                max_depth: 0,
                max_packages: batch.len(),
                request_concurrency: config.request_concurrency,
                allow_external_fallback: false,
            },
        )
        .await?;

        summary.batches += 1;
        summary.scanned_packages += batch.len();
        summary.fetch_failures += collect_summary.fetch_failures;

        let mut matched_packages = std::collections::BTreeSet::<String>::new();
        for record in &records {
            if let scoring::ScoreInputRecord::Dependency {
                ecosystem: record_ecosystem,
                package,
                dependency,
                ..
            } = record
                && *record_ecosystem == config.ecosystem
                && priority::normalize_package_name(*record_ecosystem, dependency) == target
            {
                matched_packages
                    .insert(priority::normalize_package_name(*record_ecosystem, package));
            }
        }

        if matched_packages.is_empty() {
            continue;
        }

        for record in records {
            match &record {
                scoring::ScoreInputRecord::Package {
                    ecosystem: record_ecosystem,
                    package,
                    direct_popularity,
                } if *record_ecosystem == config.ecosystem
                    && matched_packages.contains(&priority::normalize_package_name(
                        *record_ecosystem,
                        package,
                    )) =>
                {
                    let normalized_package =
                        priority::normalize_package_name(*record_ecosystem, package);
                    seeds.push(collector::SeedPackageRecord {
                        ecosystem: *record_ecosystem,
                        package: normalized_package.clone(),
                        direct_popularity: Some(
                            (*direct_popularity).max(config.default_direct_popularity),
                        ),
                    });
                    emitted_records.push(scoring::ScoreInputRecord::Package {
                        ecosystem: *record_ecosystem,
                        package: normalized_package,
                        direct_popularity: *direct_popularity,
                    });
                    summary.emitted_package_records += 1;
                }
                scoring::ScoreInputRecord::Dependency {
                    ecosystem: record_ecosystem,
                    package,
                    dependency,
                    weight,
                    sources,
                    confidence,
                } if *record_ecosystem == config.ecosystem
                    && matched_packages.contains(&priority::normalize_package_name(
                        *record_ecosystem,
                        package,
                    )) =>
                {
                    emitted_records.push(scoring::ScoreInputRecord::Dependency {
                        ecosystem: *record_ecosystem,
                        package: priority::normalize_package_name(*record_ecosystem, package),
                        dependency: priority::normalize_package_name(*record_ecosystem, dependency),
                        weight: *weight,
                        sources: sources.clone(),
                        confidence: *confidence,
                    });
                    summary.emitted_dependency_records += 1;
                }
                _ => {}
            }
        }

        for matched in matched_packages {
            if known_reverse_dependents.insert(matched.clone()) {
                summary.matched_dependents += 1;
            }
        }

        known_packages.extend(
            seeds
                .iter()
                .map(|seed| (seed.ecosystem, seed.package.clone()))
                .collect::<Vec<_>>(),
        );
    }

    let seeds = merge_seed_records(seeds, Vec::new());
    Ok((emitted_records, seeds, summary))
}

fn select_broaden_batch(
    census: &[collector::SeedPackageRecord],
    known_packages: &std::collections::BTreeSet<(supply_stream_core::event::Ecosystem, String)>,
    cursor: usize,
    batch_size: usize,
) -> BroadenSelection {
    let mut selected = Vec::new();
    let mut scanned = 0usize;
    let mut index = cursor.min(census.len());
    while index < census.len() && selected.len() < batch_size {
        let record = &census[index];
        scanned += 1;
        if !known_packages.contains(&(record.ecosystem, record.package.clone())) {
            selected.push(record.clone());
        }
        index += 1;
    }
    BroadenSelection {
        selected,
        cursor_after: index,
        scanned,
        exhausted: index >= census.len(),
    }
}

async fn load_broaden_progress(path: &std::path::Path) -> Result<Option<BroadenProgress>> {
    match fs::read_to_string(path).await {
        Ok(body) => {
            Ok(Some(serde_json::from_str(&body).with_context(|| {
                format!("failed to parse {}", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

async fn save_broaden_progress(path: &std::path::Path, progress: &BroadenProgress) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create progress dir {}", parent.display()))?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(progress)
            .with_context(|| format!("failed to encode {}", path.display()))?,
    )
    .await
    .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use supply_stream_core::event::Ecosystem;
    use supply_stream_core::scoring::ScoreInputRecord;

    #[test]
    fn select_broaden_batch_skips_known_packages_and_advances_cursor() {
        let census = vec![
            collector::SeedPackageRecord {
                ecosystem: Ecosystem::Npm,
                package: "known-a".to_string(),
                direct_popularity: None,
            },
            collector::SeedPackageRecord {
                ecosystem: Ecosystem::Npm,
                package: "new-b".to_string(),
                direct_popularity: None,
            },
            collector::SeedPackageRecord {
                ecosystem: Ecosystem::Pypi,
                package: "new-c".to_string(),
                direct_popularity: None,
            },
        ];
        let known = std::collections::BTreeSet::from([(Ecosystem::Npm, "known-a".to_string())]);
        let selection = select_broaden_batch(&census, &known, 0, 2);
        assert_eq!(selection.scanned, 3);
        assert_eq!(selection.cursor_after, 3);
        assert!(selection.exhausted);
        assert_eq!(selection.selected.len(), 2);
        assert_eq!(selection.selected[0].package, "new-b");
        assert_eq!(selection.selected[1].package, "new-c");
    }

    #[test]
    fn build_local_focus_frontier_uses_reverse_edges_from_base_records() {
        let records = vec![
            ScoreInputRecord::Package {
                ecosystem: Ecosystem::Pypi,
                package: "telnyx".to_string(),
                direct_popularity: 1.0,
            },
            ScoreInputRecord::Dependency {
                ecosystem: Ecosystem::Pypi,
                package: "open-webui".to_string(),
                dependency: "telnyx".to_string(),
                weight: 1.0,
                sources: vec!["local_graph".to_string()],
                confidence: Some(1.0),
            },
            ScoreInputRecord::Dependency {
                ecosystem: Ecosystem::Pypi,
                package: "aider-chat".to_string(),
                dependency: "telnyx".to_string(),
                weight: 1.0,
                sources: vec!["local_graph".to_string()],
                confidence: Some(1.0),
            },
        ];

        let (seeds, summary) = build_local_focus_frontier(
            &records,
            Ecosystem::Pypi,
            "telnyx",
            1,
            16,
            1.0,
            DepsDevDirectPopularityMode::DirectDependentCount,
        );

        assert_eq!(summary.frontier_packages, 3);
        assert_eq!(summary.emitted_dependency_records, 2);
        let packages = seeds
            .into_iter()
            .map(|seed| seed.package)
            .collect::<Vec<_>>();
        assert!(packages.contains(&"telnyx".to_string()));
        assert!(packages.contains(&"open-webui".to_string()));
        assert!(packages.contains(&"aider-chat".to_string()));
    }

    #[tokio::test]
    async fn resolve_focus_base_inputs_includes_existing_graph_output() {
        let graph_output = std::env::temp_dir().join(format!(
            "supply-stream-focus-base-{}.ndjson",
            std::process::id()
        ));
        fs::write(&graph_output, b"").await.unwrap();

        let resolved = resolve_focus_base_inputs(&[], &graph_output).await;
        assert_eq!(resolved, vec![graph_output.clone()]);
        let _ = fs::remove_file(&graph_output).await;
    }
}
