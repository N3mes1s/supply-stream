use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tar::{Builder as TarBuilder, Header as TarHeader};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter, write::FileOptions};

use crate::{
    assessment::assess_release,
    capture::{CapturedArtifact, CapturedRelease, ReleaseStatus},
    content_risk::{ContentRiskMatch, scan_captured_release},
    event::{
        DetectionMatchClass, Ecosystem, EmittedMatchedRuleEvidence, PackageReleaseEvent,
        ReleaseAssessmentSeverity, ReleaseVerdictClass,
    },
    priority::{PrioritySnapshot, PrioritySource, PriorityTier},
};

#[derive(Debug, Clone)]
pub struct RuleBehaviorProfile {
    pub match_class: DetectionMatchClass,
    pub behavior_tags: Vec<String>,
    pub strong_malicious_chain: bool,
}

pub fn rule_behavior_profile(rule_id: &str, rule_tags: &[String]) -> RuleBehaviorProfile {
    let match_class = classify_rule_match(rule_id);
    let behavior_tags = derive_behavior_tags(rule_id, rule_tags);
    let strong_malicious_chain = matches!(match_class, DetectionMatchClass::MaliciousBehavior)
        && !matches!(
            rule_id,
            "pypi_browser_credential_theft"
                | "npm_cloudflare_workers_exfil"
                | "npm_electron_app_injection"
                | "npm_powershell_hidden_execution"
                | "npm_macos_payload_dropper"
                | "npm_exfil_channel_with_theft_markers"
                | "pypi_exfil_channel_with_theft_markers"
        )
        && (rule_id.contains("reverse_shell")
            || rule_id.contains("runtime_encoded_remote_loader")
            || rule_id.contains("persistent_shell_backdoor")
            || rule_id.contains("secrets_harvesting_c2_agent")
            || rule_id.contains("multiphase_secrets_exfil_agent")
            || rule_id.contains("redis_reverse_shell_dropper")
            || rule_id.contains("environment_callback_probe")
            || rule_id.contains("credential_theft_toolchain")
            || rule_id.contains("worm_propagation")
            || rule_id.contains("token_publish_worm_propagation")
            || rule_id.contains("github_propagation_worm")
            || rule_id.contains("github_commit_secret_exfil")
            || rule_id.contains("github_actions_secret_artifact_exfil")
            || rule_id.contains("runner_memory_secret_scrape")
            || rule_id.contains("cloud_secret_manager_exfiltration")
            || rule_id.contains("remote_code_fetch_exec")
            || rule_id.contains("remote_payload_shell_exec")
            || rule_id.contains("in_memory_payload_loader")
            || rule_id.contains("build_script_env_exfil")
            || rule_id.contains("build_script_file_read_exfil")
            || rule_id.contains("browser_process_kill_and_theft")
            || rule_id.contains("discord_bot_rat")
            || rule_id.contains("discord_token_theft")
            || rule_id.contains("keylogger")
            || rule_id.contains("password_manager_theft")
            || rule_id.contains("browser_wallet_extension_theft")
            || rule_id.contains("ssh_or_cloud_credential_theft")
            || rule_id.contains("crypto_wallet_file_theft")
            || rule_id.contains("bulk_env_exfiltration")
            || rule_id.contains("wallet_or_session_theft_markers")
            || rule_id.contains("npm_token_worm")
            || rule_id.contains("release_toolchain_poisoning")
            || rule_id.contains("indirect_eval_payload")
            || rule_id.contains("ethereum_transaction_hook")
            || rule_id.contains("sandworm_markers")
            || rule_id.contains("ghostclaw_markers")
            || rule_id.contains("git_hook_injection")
            || rule_id.contains("shell_profile_persistence")
            || rule_id.contains("base64_exec_chain")
            || rule_id.contains("marshal_zlib_obfuscation")
            || rule_id.contains("getattr_builtins_indirection")
            || rule_id.contains("fernet_encrypted_payload")
            || rule_id.contains("clipboard_crypto_hijack")
            || rule_id.contains("steganographic_payload")
            || rule_id.contains("ctor_auto_init_antivirus")
            || rule_id.contains("crypto_key_scanner")
            || rule_id.contains("self_deletion_destructive")
            || rule_id.contains("defender_evasion")
            || rule_id.contains("smart_contract_c2")
            || rule_id.contains("trufflehog_gitleaks"));

    RuleBehaviorProfile {
        match_class,
        behavior_tags,
        strong_malicious_chain,
    }
}

pub fn emitted_rule_evidence(match_: &ContentRiskMatch) -> EmittedMatchedRuleEvidence {
    let profile = rule_behavior_profile(&match_.rule_id, &match_.tags);
    let match_class = match_.match_class.unwrap_or(profile.match_class);
    let behavior_tags = if match_.behavior_tags.is_empty() {
        profile.behavior_tags
    } else {
        match_.behavior_tags.clone()
    };

    EmittedMatchedRuleEvidence {
        rule_id: match_.rule_id.clone(),
        match_class,
        behavior_tags,
        file_path: match_.file_path.clone(),
        file_role: match_.file_role.clone(),
        evidence_kind: match_.evidence_kind.clone(),
        pattern_ids: match_
            .pattern_matches
            .iter()
            .map(|pattern| pattern.pattern_id.clone())
            .collect(),
        preview: match_
            .pattern_matches
            .iter()
            .find_map(|pattern| pattern.preview.clone()),
    }
}

fn classify_rule_match(rule_id: &str) -> DetectionMatchClass {
    match rule_id {
        "npm_downloader_and_exec_installer"
        | "npm_downloader_pipe_to_shell_installer"
        | "pypi_build_hook_downloader"
        | "crate_build_script_downloader" => DetectionMatchClass::RiskyInstaller,
        "npm_mcp_server_injection" => DetectionMatchClass::InvasiveTooling,
        "npm_ci_environment_targeting"
        | "pypi_ci_environment_targeting"
        | "crate_ci_pipeline_targeting"
        | "npm_string_construction_obfuscation"
        | "pypi_setup_cmdclass_override"
        | "pypi_anti_analysis_evasion"
        | "pypi_environment_fingerprint_exfil"
        | "pypi_pyarmor_obfuscation"
        | "crate_runtime_obfuscated_strings"
        | "generic_cloud_credential_paths"
        | "generic_cloud_metadata_service"
        | "generic_oast_callback"
        | "generic_git_token_patterns"
        | "generic_browser_credential_database"
        | "generic_crypto_wallet_paths"
        | "crate_ctor_auto_init_network" => DetectionMatchClass::ContextOnly,
        _ => {
            if rule_id.contains("installer") && rule_id.contains("downloader") {
                DetectionMatchClass::RiskyInstaller
            } else if rule_id.contains("mcp_server_injection") {
                DetectionMatchClass::InvasiveTooling
            } else if rule_id.contains("ci_environment") || rule_id.contains("pipeline_targeting") {
                DetectionMatchClass::ContextOnly
            } else {
                DetectionMatchClass::MaliciousBehavior
            }
        }
    }
}

fn derive_behavior_tags(rule_id: &str, rule_tags: &[String]) -> Vec<String> {
    let mut tags = BTreeSet::new();
    for rule_tag in rule_tags {
        match rule_tag.as_str() {
            "loader" => {
                tags.insert("remote_fetch".to_string());
                tags.insert("dynamic_execution".to_string());
            }
            "installer" | "build" => {
                tags.insert("install_or_build_execution".to_string());
            }
            "callback" => {
                tags.insert("callback".to_string());
            }
            "recon" => {
                tags.insert("reconnaissance".to_string());
            }
            "exfil" => {
                tags.insert("exfiltration".to_string());
            }
            "c2" | "rat" | "backdoor" => {
                tags.insert("command_and_control".to_string());
            }
            "theft" | "stealer" => {
                tags.insert("credential_or_wallet_theft".to_string());
            }
            "shell" => {
                tags.insert("shell_execution".to_string());
            }
            "persistence" | "worm" => {
                tags.insert("persistence_or_propagation".to_string());
            }
            "injection" => {
                tags.insert("target_mutation".to_string());
            }
            "ci" => {
                tags.insert("ci_targeting".to_string());
            }
            "crypto" => {
                tags.insert("crypto_targeting".to_string());
            }
            _ => {}
        }
    }

    let rule_lower = rule_id.to_ascii_lowercase();
    let inferred = [
        ("loader", "remote_fetch"),
        ("remote_code_fetch_exec", "dynamic_execution"),
        ("downloader", "remote_fetch"),
        ("callback", "callback"),
        ("recon", "reconnaissance"),
        ("exfil", "exfiltration"),
        ("c2", "command_and_control"),
        ("rat", "command_and_control"),
        ("backdoor", "command_and_control"),
        ("shell", "shell_execution"),
        ("powershell", "shell_execution"),
        ("credential", "credential_or_wallet_theft"),
        ("browser", "browser_targeting"),
        ("wallet", "credential_or_wallet_theft"),
        ("crypto", "credential_or_wallet_theft"),
        ("persistent", "persistence_or_propagation"),
        ("persistence", "persistence_or_propagation"),
        ("worm", "persistence_or_propagation"),
        ("injection", "target_mutation"),
        ("asar", "target_mutation"),
        ("workers", "cloud_exfiltration"),
        ("ci", "ci_targeting"),
        ("install", "install_or_build_execution"),
        ("build", "install_or_build_execution"),
        ("dropper", "payload_drop"),
        ("obfuscation", "obfuscation"),
        ("evasion", "evasion"),
        ("discord", "discord_or_telegram_channel"),
        ("telegram", "discord_or_telegram_channel"),
        ("clipboard", "credential_or_wallet_theft"),
        ("steganograph", "obfuscation"),
        ("defender", "evasion"),
        ("destructive", "shell_execution"),
        ("marshal", "obfuscation"),
        ("fernet", "obfuscation"),
        ("hex_encoded", "obfuscation"),
        ("base64_exec", "obfuscation"),
        ("indirect_eval", "dynamic_execution"),
        ("getattr_builtins", "obfuscation"),
        ("pyarmor", "obfuscation"),
        ("miner", "crypto_targeting"),
        ("ctor_auto_init", "install_or_build_execution"),
        ("smart_contract_c2", "command_and_control"),
        ("propagation", "persistence_or_propagation"),
        ("mcp_server", "target_mutation"),
        ("smtp", "exfiltration"),
    ];
    for (needle, behavior_tag) in inferred {
        if rule_lower.contains(needle) {
            tags.insert(behavior_tag.to_string());
        }
    }

    tags.into_iter().collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCorpusManifest {
    pub fixtures: Vec<DetectionCorpusFixture>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCorpusFixture {
    pub id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub format: DetectionFixtureFormat,
    pub fixture_dir: String,
    pub expected_verdict_class: ReleaseVerdictClass,
    pub expected_max_severity: ReleaseAssessmentSeverity,
    #[serde(default)]
    pub required_rules: Vec<String>,
    #[serde(default)]
    pub required_behavior_tags: Vec<String>,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionFixtureFormat {
    NpmTgz,
    PypiWheel,
    PypiSdist,
    Crate,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionCorpusReport {
    pub manifest_path: String,
    pub fixtures_total: usize,
    pub fixtures_passed: usize,
    pub fixtures_failed: usize,
    pub rule_stats: Vec<DetectionRuleStat>,
    pub fixture_results: Vec<DetectionFixtureResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionRuleStat {
    pub rule_id: String,
    pub expected_hits: usize,
    pub actual_hits: usize,
    pub missing_hits: usize,
    pub unexpected_hits: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionFixtureResult {
    pub id: String,
    pub package: String,
    pub version: String,
    pub expected_verdict_class: ReleaseVerdictClass,
    pub actual_verdict_class: ReleaseVerdictClass,
    pub expected_max_severity: ReleaseAssessmentSeverity,
    pub actual_severity: ReleaseAssessmentSeverity,
    pub matched_rules: Vec<String>,
    pub behavior_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
}

pub async fn evaluate_detection_corpus(manifest_path: &Path) -> Result<DetectionCorpusReport> {
    let raw = fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let manifest: DetectionCorpusManifest = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", manifest_path.display()))?;

    let http = reqwest::Client::builder()
        .user_agent("supply-stream-detection-eval/0.1.0")
        .build()
        .context("failed to build HTTP client for detection corpus evaluation")?;

    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("manifest path {} has no parent", manifest_path.display()))?;
    let mut fixture_results = Vec::new();
    let mut rule_stats = BTreeMap::<String, DetectionRuleStat>::new();

    for fixture in manifest.fixtures {
        let result = evaluate_fixture(&http, manifest_dir, &fixture).await?;

        let actual_rule_set = result
            .matched_rules
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected_rule_set = fixture
            .required_rules
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for rule_id in expected_rule_set.union(&actual_rule_set) {
            let stat = rule_stats
                .entry(rule_id.clone())
                .or_insert(DetectionRuleStat {
                    rule_id: rule_id.clone(),
                    expected_hits: 0,
                    actual_hits: 0,
                    missing_hits: 0,
                    unexpected_hits: 0,
                });
            if expected_rule_set.contains(rule_id) {
                stat.expected_hits += 1;
            }
            if actual_rule_set.contains(rule_id) {
                stat.actual_hits += 1;
            }
            if expected_rule_set.contains(rule_id) && !actual_rule_set.contains(rule_id) {
                stat.missing_hits += 1;
            }
            if actual_rule_set.contains(rule_id) && !expected_rule_set.contains(rule_id) {
                stat.unexpected_hits += 1;
            }
        }

        fixture_results.push(result);
    }

    fixture_results.sort_by(|left, right| left.id.cmp(&right.id));
    let fixtures_total = fixture_results.len();
    let fixtures_failed = fixture_results
        .iter()
        .filter(|fixture| !fixture.failures.is_empty())
        .count();
    let fixtures_passed = fixtures_total.saturating_sub(fixtures_failed);

    Ok(DetectionCorpusReport {
        manifest_path: manifest_path.display().to_string(),
        fixtures_total,
        fixtures_passed,
        fixtures_failed,
        rule_stats: rule_stats.into_values().collect(),
        fixture_results,
    })
}

async fn evaluate_fixture(
    http: &reqwest::Client,
    manifest_dir: &Path,
    fixture: &DetectionCorpusFixture,
) -> Result<DetectionFixtureResult> {
    let temp = tempdir().context("failed to create detection corpus tempdir")?;
    let fixture_root = manifest_dir.join(&fixture.fixture_dir);
    let archive_path = build_fixture_archive(temp.path(), &fixture_root, fixture)?;

    let event = sample_event(fixture);
    let mut capture = sample_capture(fixture, &archive_path);
    let signal = scan_captured_release(http, temp.path(), &capture).await;
    capture.details["content_risk"] =
        serde_json::to_value(&signal).context("failed to encode content-risk signal")?;
    let assessment = assess_release(&event, None, &capture, None, None);

    let matched_rules = assessment.matched_rules.clone();
    let matched_rule_set = matched_rules.iter().cloned().collect::<BTreeSet<_>>();
    let behavior_tag_set = assessment
        .behavior_tags
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut failures = Vec::new();
    if assessment.verdict_class != fixture.expected_verdict_class {
        failures.push(format!(
            "verdict_class expected={} actual={}",
            fixture.expected_verdict_class.as_str(),
            assessment.verdict_class.as_str()
        ));
    }
    if severity_rank(assessment.severity) > severity_rank(fixture.expected_max_severity) {
        failures.push(format!(
            "severity expected_max={} actual={}",
            fixture.expected_max_severity.as_str(),
            assessment.severity.as_str()
        ));
    }
    for required_rule in &fixture.required_rules {
        if !matched_rule_set.contains(required_rule) {
            failures.push(format!("missing rule {required_rule}"));
        }
    }
    for required_tag in &fixture.required_behavior_tags {
        if !behavior_tag_set.contains(required_tag) {
            failures.push(format!("missing behavior_tag {required_tag}"));
        }
    }

    Ok(DetectionFixtureResult {
        id: fixture.id.clone(),
        package: fixture.package.clone(),
        version: fixture.version.clone(),
        expected_verdict_class: fixture.expected_verdict_class,
        actual_verdict_class: assessment.verdict_class,
        expected_max_severity: fixture.expected_max_severity,
        actual_severity: assessment.severity,
        matched_rules,
        behavior_tags: assessment.behavior_tags,
        failures,
    })
}

fn sample_event(fixture: &DetectionCorpusFixture) -> PackageReleaseEvent {
    PackageReleaseEvent {
        event_id: format!(
            "{}:{}@{}",
            fixture.ecosystem.as_str(),
            fixture.package,
            fixture.version
        ),
        ecosystem: fixture.ecosystem,
        package: fixture.package.clone(),
        version: fixture.version.clone(),
        published_at: None,
        observed_at: Utc::now(),
        source: "detection-corpus".to_string(),
        sequence: None,
        package_url: None,
        release_url: None,
        metadata_url: None,
        priority: Some(PrioritySnapshot {
            tier: PriorityTier::Low,
            source: PrioritySource::KnownPackageStub,
            direct_popularity: Some(0.0),
            propagated_impact: Some(0.0),
            hidden_leverage: Some(0.0),
            computed_at: Some(Utc::now()),
            score_source_version: Some("detection-corpus".to_string()),
        }),
    }
}

fn sample_capture(fixture: &DetectionCorpusFixture, archive_path: &Path) -> CapturedRelease {
    let filename = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact.bin")
        .to_string();
    let kind = match fixture.format {
        DetectionFixtureFormat::NpmTgz => Some("npm".to_string()),
        DetectionFixtureFormat::PypiWheel => Some("wheel".to_string()),
        DetectionFixtureFormat::PypiSdist => Some("sdist".to_string()),
        DetectionFixtureFormat::Crate => Some("crate".to_string()),
    };

    let mut details = if fixture.details.is_object() {
        fixture.details.clone()
    } else {
        json!({})
    };
    if !details.is_object() {
        details = json!({});
    }
    if let Some(object) = details.as_object_mut() {
        object.insert(
            "local_artifact".to_string(),
            json!({ "path": archive_path.display().to_string(), "filename": filename }),
        );
        object
            .entry("dependencies".to_string())
            .or_insert_with(|| json!([]));
        object
            .entry("bin".to_string())
            .or_insert(serde_json::Value::Null);
        object
            .entry("main".to_string())
            .or_insert(serde_json::Value::Null);
        object
            .entry("pkg_targets".to_string())
            .or_insert_with(|| json!([]));
        object
            .entry("has_install_scripts".to_string())
            .or_insert_with(|| json!(false));
    }

    CapturedRelease {
        event_id: format!(
            "{}:{}@{}",
            fixture.ecosystem.as_str(),
            fixture.package,
            fixture.version
        ),
        ecosystem: fixture.ecosystem,
        package: fixture.package.clone(),
        version: fixture.version.clone(),
        observed_at: Utc::now(),
        published_at: None,
        captured_at: Utc::now(),
        status: ReleaseStatus::Active,
        package_url: None,
        release_url: None,
        metadata_url: None,
        raw_metadata_path: None,
        artifacts: vec![CapturedArtifact {
            filename,
            kind,
            url: None,
            size_bytes: fs::metadata(archive_path)
                .ok()
                .map(|metadata| metadata.len()),
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }],
        upstream_repository: None,
        details,
    }
}

fn build_fixture_archive(
    output_dir: &Path,
    fixture_root: &Path,
    fixture: &DetectionCorpusFixture,
) -> Result<PathBuf> {
    let archive_path = match fixture.format {
        DetectionFixtureFormat::NpmTgz => output_dir.join("package.tgz"),
        DetectionFixtureFormat::PypiWheel => output_dir.join(format!(
            "{}-{}-py3-none-any.whl",
            fixture.package.replace('-', "_"),
            fixture.version
        )),
        DetectionFixtureFormat::PypiSdist => output_dir.join(format!(
            "{}-{}.tar.gz",
            fixture.package.replace('-', "_"),
            fixture.version
        )),
        DetectionFixtureFormat::Crate => {
            output_dir.join(format!("{}-{}.crate", fixture.package, fixture.version))
        }
    };
    let files = collect_fixture_files(fixture_root)?;
    match fixture.format {
        DetectionFixtureFormat::NpmTgz => write_tar_archive(&archive_path, &files, Some("package")),
        DetectionFixtureFormat::PypiWheel => write_zip_archive(&archive_path, &files, None),
        DetectionFixtureFormat::PypiSdist => write_tar_archive(&archive_path, &files, None),
        DetectionFixtureFormat::Crate => write_tar_archive(&archive_path, &files, None),
    }?;
    Ok(archive_path)
}

fn collect_fixture_files(root: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut entries = Vec::new();
    collect_fixture_files_recursive(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn collect_fixture_files_recursive(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(PathBuf, Vec<u8>)>,
) -> Result<()> {
    for entry in
        fs::read_dir(current).with_context(|| format!("failed to read {}", current.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_fixture_files_recursive(root, &path, entries)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .with_context(|| format!("failed to strip prefix for {}", path.display()))?;
            let bytes = fs::read(&path)
                .with_context(|| format!("failed to read fixture file {}", path.display()))?;
            entries.push((relative.to_path_buf(), bytes));
        }
    }
    Ok(())
}

fn write_tar_archive(
    archive_path: &Path,
    files: &[(PathBuf, Vec<u8>)],
    prefix: Option<&str>,
) -> Result<()> {
    let archive_file = fs::File::create(archive_path)
        .with_context(|| format!("failed to create {}", archive_path.display()))?;
    let encoder = GzEncoder::new(archive_file, Compression::default());
    let mut builder = TarBuilder::new(encoder);

    for (relative_path, bytes) in files {
        let target_path = prefix
            .map(|prefix| Path::new(prefix).join(relative_path))
            .unwrap_or_else(|| relative_path.clone());
        let mut header = TarHeader::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, target_path, std::io::Cursor::new(bytes))
            .context("failed to append tar entry")?;
    }

    builder.finish().context("failed to finish tar archive")?;
    Ok(())
}

fn write_zip_archive(
    archive_path: &Path,
    files: &[(PathBuf, Vec<u8>)],
    prefix: Option<&str>,
) -> Result<()> {
    let file = fs::File::create(archive_path)
        .with_context(|| format!("failed to create {}", archive_path.display()))?;
    let mut writer = ZipWriter::new(file);
    let options: FileOptions<'_, ()> =
        FileOptions::default().compression_method(CompressionMethod::Deflated);

    for (relative_path, bytes) in files {
        let target_path = prefix
            .map(|prefix| Path::new(prefix).join(relative_path))
            .unwrap_or_else(|| relative_path.clone());
        writer
            .start_file(target_path.to_string_lossy().replace('\\', "/"), options)
            .context("failed to start zip entry")?;
        writer
            .write_all(bytes)
            .context("failed to write zip entry")?;
    }

    writer.finish().context("failed to finish zip archive")?;
    Ok(())
}

fn severity_rank(severity: ReleaseAssessmentSeverity) -> u8 {
    match severity {
        ReleaseAssessmentSeverity::Informational => 0,
        ReleaseAssessmentSeverity::Warning => 1,
        ReleaseAssessmentSeverity::High => 2,
    }
}
