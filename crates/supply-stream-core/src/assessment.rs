use crate::{
    capture::{CapturedRelease, ReleaseStatus, captured_metadata_risk},
    content_risk::{ContentRiskMatch, ContentRiskSignal, captured_content_risk},
    detection::{emitted_rule_evidence, rule_behavior_profile},
    diff::StoredReleaseDiff,
    event::{
        DetectionMatchClass, EmittedDiffEvidence, EmittedGraphEvidence, EmittedMatchedRuleEvidence,
        PackageReleaseEvent, ReleaseAssessmentSeverity, ReleaseVerdictClass,
    },
    repo_provenance::RepositoryReleaseProvenance,
    store::GraphEvidence,
};

#[derive(Debug, Clone)]
pub struct DiffAssessmentInput {
    pub status: &'static str,
    pub baseline_version: Option<String>,
    pub available: bool,
    pub patches_included: bool,
    pub files_added_count: usize,
    pub files_removed_count: usize,
    pub files_changed_count: usize,
    pub package_manifest_only: bool,
    pub target_has_install_scripts: Option<bool>,
    pub install_scripts_longstanding: Option<bool>,
    pub install_hook_changed: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ReleaseAssessment {
    pub suspicious: bool,
    pub severity: ReleaseAssessmentSeverity,
    pub verdict_class: ReleaseVerdictClass,
    pub factors: Vec<String>,
    pub behavior_tags: Vec<String>,
    pub matched_rules: Vec<String>,
    pub matched_evidence: Vec<EmittedMatchedRuleEvidence>,
    pub reason: String,
    pub graph: EmittedGraphEvidence,
    pub diff: Option<EmittedDiffEvidence>,
}

pub fn assess_release(
    event: &PackageReleaseEvent,
    graph: Option<&GraphEvidence>,
    capture: &CapturedRelease,
    repository: Option<&RepositoryReleaseProvenance>,
    stored_diff: Option<&DiffAssessmentInput>,
) -> ReleaseAssessment {
    let graph = emitted_graph_evidence(graph);
    let diff = emitted_diff_evidence(stored_diff);

    let prerelease = is_prerelease_version(&event.version);
    let install_time_execution = stored_diff
        .and_then(|diff| diff.target_has_install_scripts)
        .unwrap_or_else(|| capture_has_install_time_execution(capture));
    let install_time_execution_longstanding = stored_diff
        .and_then(|diff| diff.install_scripts_longstanding)
        .unwrap_or_else(|| capture_has_longstanding_install_time_execution(capture));
    let install_hook_changed = stored_diff
        .and_then(|diff| diff.install_hook_changed)
        .unwrap_or(false);
    let install_time_execution_benign = capture_has_benign_install_time_execution(capture);
    let risky_install_time_execution = install_time_execution
        && !install_time_execution_benign
        && (!install_time_execution_longstanding || install_hook_changed);
    let medium_or_high_impact = matches!(
        event.priority_snapshot().tier,
        crate::priority::PriorityTier::Medium | crate::priority::PriorityTier::High
    );
    let reverse_dependents_present = graph.reverse_dependents_seen > 0;
    let repo_mismatch = repository.is_some_and(|repository| repository.suspicious);
    let removed_or_yanked = matches!(
        capture.status,
        ReleaseStatus::Removed | ReleaseStatus::Yanked
    );
    let metadata_risk = captured_metadata_risk(capture);
    let content_risk = captured_content_risk(capture);
    let content_summary = summarize_content_matches(&content_risk);

    let mut factors = Vec::new();
    if repo_mismatch {
        factors.push("repo_release_mismatch".to_string());
    }
    if prerelease {
        factors.push("prerelease_or_nightly".to_string());
    } else {
        factors.push("stable_version".to_string());
    }
    if install_time_execution {
        factors.push("install_time_execution".to_string());
    }
    if install_time_execution_longstanding {
        factors.push("install_time_execution_longstanding".to_string());
    }
    if install_time_execution_benign {
        factors.push("install_time_execution_benign".to_string());
    }
    if install_hook_changed {
        factors.push("install_hook_changed".to_string());
    }
    if medium_or_high_impact {
        factors.push("high_or_medium_impact".to_string());
    }
    if reverse_dependents_present {
        factors.push("reverse_dependents_present".to_string());
    }
    if removed_or_yanked {
        factors.push("removed_or_yanked".to_string());
    }
    if metadata_risk.suspicious {
        factors.push("malware_shaped_metadata".to_string());
        factors.extend(metadata_risk.factors.clone());
    }
    if content_risk.suspicious {
        factors.push("malware_shaped_content".to_string());
        factors.extend(content_risk.factors.clone());
    }
    if !content_risk.iocs.is_empty() {
        factors.push("content_iocs_present".to_string());
    }

    let content_changed = diff.as_ref().is_some_and(|diff| {
        diff.files_added_count + diff.files_removed_count + diff.files_changed_count > 0
    });
    let content_large = diff.as_ref().is_some_and(|diff| {
        diff.files_added_count + diff.files_removed_count + diff.files_changed_count >= 10
            || diff.files_changed_count >= 5
    });
    let package_manifest_only = stored_diff.is_some_and(|diff| diff.package_manifest_only);
    if content_changed {
        factors.push("content_changed".to_string());
    }
    if content_large {
        factors.push("content_churn_large".to_string());
    }
    if package_manifest_only {
        factors.push("package_manifest_only".to_string());
    }

    let (severity, verdict_class, suspicious, reason) = if content_summary.confident_malware {
        (
            ReleaseAssessmentSeverity::High,
            ReleaseVerdictClass::Malware,
            true,
            content_risk.reason.clone(),
        )
    } else if content_summary.has_malicious_behavior {
        (
            ReleaseAssessmentSeverity::Warning,
            ReleaseVerdictClass::SuspiciousUnknown,
            true,
            format!(
                "content matched malicious behavior heuristics without a confident behavior chain [{}]",
                content_summary.matched_rules.join(", ")
            ),
        )
    } else if content_summary.has_risky_installer || risky_install_time_execution {
        (
            ReleaseAssessmentSeverity::Warning,
            ReleaseVerdictClass::RiskyInstaller,
            true,
            if content_summary.has_risky_installer {
                content_risk.reason.clone()
            } else {
                "repository mismatch combined with install-time execution".to_string()
            },
        )
    } else if content_summary.has_invasive_tooling {
        (
            ReleaseAssessmentSeverity::Warning,
            ReleaseVerdictClass::InvasiveTooling,
            true,
            content_risk.reason.clone(),
        )
    } else if metadata_risk.suspicious {
        (
            ReleaseAssessmentSeverity::Warning,
            ReleaseVerdictClass::SuspiciousUnknown,
            true,
            metadata_risk.reason.clone(),
        )
    } else if removed_or_yanked
        && content_changed
        && (medium_or_high_impact || reverse_dependents_present)
    {
        (
            ReleaseAssessmentSeverity::Warning,
            ReleaseVerdictClass::SuspiciousUnknown,
            true,
            "removed or yanked release with content changes and downstream impact".to_string(),
        )
    } else if repo_mismatch && !prerelease && content_changed && !package_manifest_only {
        (
            ReleaseAssessmentSeverity::Informational,
            ReleaseVerdictClass::Clean,
            false,
            "repository mismatch observed with concrete content changes but no additional corroborating security signals".to_string(),
        )
    } else if content_large && (medium_or_high_impact || reverse_dependents_present) {
        (
            ReleaseAssessmentSeverity::Warning,
            ReleaseVerdictClass::SuspiciousUnknown,
            true,
            "large content churn on a package with observable downstream impact".to_string(),
        )
    } else if repo_mismatch && !prerelease && (medium_or_high_impact || reverse_dependents_present)
    {
        (
            ReleaseAssessmentSeverity::Informational,
            ReleaseVerdictClass::Clean,
            false,
            "stable upstream mismatch on a package with observable downstream impact".to_string(),
        )
    } else if repo_mismatch {
        (
            ReleaseAssessmentSeverity::Informational,
            ReleaseVerdictClass::Clean,
            false,
            "repository mismatch observed without additional corroborating signals".to_string(),
        )
    } else {
        (
            ReleaseAssessmentSeverity::Informational,
            ReleaseVerdictClass::Clean,
            false,
            "no corroborating multi-signal release risk factors observed".to_string(),
        )
    };

    ReleaseAssessment {
        suspicious,
        severity,
        verdict_class,
        factors,
        behavior_tags: content_summary.behavior_tags,
        matched_rules: content_summary.matched_rules,
        matched_evidence: content_summary.matched_evidence,
        reason,
        graph,
        diff,
    }
}

#[derive(Default)]
struct ContentMatchSummary {
    matched_rules: Vec<String>,
    behavior_tags: Vec<String>,
    matched_evidence: Vec<EmittedMatchedRuleEvidence>,
    has_malicious_behavior: bool,
    has_risky_installer: bool,
    has_invasive_tooling: bool,
    confident_malware: bool,
}

fn summarize_content_matches(content_risk: &ContentRiskSignal) -> ContentMatchSummary {
    let mut summary = ContentMatchSummary::default();
    let mut matched_rules = std::collections::BTreeSet::new();
    let mut behavior_tags = std::collections::BTreeSet::new();
    let mut malicious_groups = std::collections::BTreeSet::new();
    let mut malicious_behavior_tags = std::collections::BTreeSet::new();
    let mut malicious_match_count = 0usize;
    let mut strong_chain_count = 0usize;
    let mut has_concrete_malicious_evidence = false;

    for matched in &content_risk.matches {
        let profile = rule_behavior_profile(&matched.rule_id, &matched.tags);
        let match_class = matched.match_class.unwrap_or(profile.match_class);
        let matched_behavior_tags = if matched.behavior_tags.is_empty() {
            profile.behavior_tags.clone()
        } else {
            matched.behavior_tags.clone()
        };

        matched_rules.insert(matched.rule_id.clone());
        for behavior_tag in &matched_behavior_tags {
            behavior_tags.insert(behavior_tag.clone());
        }
        summary
            .matched_evidence
            .push(emitted_rule_evidence_from_match(
                matched,
                match_class,
                &matched_behavior_tags,
            ));

        match match_class {
            DetectionMatchClass::MaliciousBehavior => {
                summary.has_malicious_behavior = true;
                malicious_match_count += 1;
                if matched.evidence_kind.as_deref() != Some("module_condition") {
                    has_concrete_malicious_evidence = true;
                }
                if profile.strong_malicious_chain {
                    strong_chain_count += 1;
                }
                for behavior_tag in &matched_behavior_tags {
                    malicious_behavior_tags.insert(behavior_tag.clone());
                    malicious_groups.insert(behavior_group(behavior_tag).to_string());
                }
            }
            DetectionMatchClass::RiskyInstaller => summary.has_risky_installer = true,
            DetectionMatchClass::InvasiveTooling => summary.has_invasive_tooling = true,
            DetectionMatchClass::ContextOnly => {}
        }
    }

    let has_iocs = !content_risk.iocs.is_empty();
    let strong_chain_is_self_sufficient = strong_chain_count > 0
        && (malicious_groups.len() >= 2 || malicious_behavior_tags.len() >= 2);
    let corroborated_malicious_signal = has_concrete_malicious_evidence || has_iocs;

    summary.confident_malware = strong_chain_count > 0
        && (corroborated_malicious_signal || strong_chain_is_self_sufficient)
        || malicious_groups.len() >= 2
            && corroborated_malicious_signal
            && malicious_match_count >= 2;
    summary.matched_rules = matched_rules.into_iter().collect();
    summary.behavior_tags = behavior_tags.into_iter().collect();
    summary.matched_evidence.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then(left.file_path.cmp(&right.file_path))
    });
    summary
}

fn emitted_rule_evidence_from_match(
    matched: &ContentRiskMatch,
    match_class: DetectionMatchClass,
    behavior_tags: &[String],
) -> EmittedMatchedRuleEvidence {
    let mut evidence = emitted_rule_evidence(matched);
    evidence.match_class = match_class;
    evidence.behavior_tags = behavior_tags.to_vec();
    evidence
}

fn behavior_group(tag: &str) -> &'static str {
    match tag {
        "remote_fetch" | "dynamic_execution" | "payload_drop" | "shell_execution" => "execution",
        "callback" | "exfiltration" | "cloud_exfiltration" => "exfiltration",
        "command_and_control" => "command_and_control",
        "reconnaissance" | "ci_targeting" => "reconnaissance",
        "credential_or_wallet_theft" | "browser_targeting" | "crypto_targeting" => "theft",
        "persistence_or_propagation" => "persistence",
        "target_mutation" => "target_mutation",
        "install_or_build_execution" => "install_or_build_execution",
        "evasion" | "obfuscation" => "stealth",
        _ => "misc",
    }
}

fn emitted_graph_evidence(graph: Option<&GraphEvidence>) -> EmittedGraphEvidence {
    match graph {
        Some(graph) => EmittedGraphEvidence {
            known_in_local_graph: graph.known,
            known_in_census: false,
            observed_count: 0,
            direct_dependencies_seen: graph.direct_dependencies_seen,
            reverse_dependents_seen: graph.reverse_dependents_seen,
            repository: graph.repository.clone(),
        },
        None => EmittedGraphEvidence::default(),
    }
}

fn emitted_diff_evidence(stored_diff: Option<&DiffAssessmentInput>) -> Option<EmittedDiffEvidence> {
    let stored_diff = stored_diff?;
    Some(EmittedDiffEvidence {
        status: stored_diff.status,
        available: stored_diff.available,
        patches_included: stored_diff.patches_included,
        baseline_version: stored_diff.baseline_version.clone(),
        files_added_count: stored_diff.files_added_count,
        files_removed_count: stored_diff.files_removed_count,
        files_changed_count: stored_diff.files_changed_count,
    })
}

impl From<&StoredReleaseDiff> for DiffAssessmentInput {
    fn from(value: &StoredReleaseDiff) -> Self {
        let (
            available,
            patches_included,
            files_added_count,
            files_removed_count,
            files_changed_count,
            package_manifest_only,
            target_has_install_scripts,
            install_scripts_longstanding,
            install_hook_changed,
        ) = match &value.diff {
            Some(diff) => (
                diff.content.available,
                diff.content.patches_included,
                diff.content.files_added_count,
                diff.content.files_removed_count,
                diff.content.files_changed_count,
                is_package_manifest_only(
                    &diff.content.files_added,
                    &diff.content.files_removed,
                    &diff.content.files_changed,
                ),
                diff.content
                    .npm_install_hook
                    .as_ref()
                    .map(|hook| hook.target_has_install_scripts),
                diff.content
                    .npm_install_hook
                    .as_ref()
                    .map(|hook| hook.longstanding_unchanged),
                diff.content
                    .npm_install_hook
                    .as_ref()
                    .map(|hook| hook.effective_changed),
            ),
            None => (false, false, 0, 0, 0, false, None, None, None),
        };
        Self {
            status: value.status.as_str(),
            baseline_version: value.baseline_version.clone(),
            available,
            patches_included,
            files_added_count,
            files_removed_count,
            files_changed_count,
            package_manifest_only,
            target_has_install_scripts,
            install_scripts_longstanding,
            install_hook_changed,
        }
    }
}

pub(crate) fn is_package_manifest_only(
    files_added: &[String],
    files_removed: &[String],
    files_changed: &[String],
) -> bool {
    if !files_added.is_empty() || !files_removed.is_empty() || files_changed.is_empty() {
        return false;
    }
    files_changed.iter().all(|path| {
        matches!(
            path,
            p if p == "package.json"
                || p == "Cargo.toml"
                || p == "pyproject.toml"
                || p == "setup.py"
                || p == "setup.cfg"
                || p.ends_with("/package.json")
                || p.ends_with("/Cargo.toml")
                || p.ends_with("/pyproject.toml")
                || p.ends_with("/setup.py")
                || p.ends_with("/setup.cfg")
        )
    })
}

fn is_prerelease_version(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    if ["nightly", "alpha", "beta", "rc", "dev", "canary", "preview"]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return true;
    }

    if lower.contains('-') {
        return true;
    }

    lower.chars().any(|ch| !(ch.is_ascii_digit() || ch == '.'))
}

fn capture_has_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("has_install_scripts")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn capture_has_longstanding_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("install_scripts_longstanding")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn capture_has_benign_install_time_execution(capture: &CapturedRelease) -> bool {
    capture
        .details
        .get("install_scripts_benign")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::{
        capture::ReleaseStatus,
        diff::{ReleaseDiff, StoredReleaseDiffStatus},
        event::{DetectionMatchClass, Ecosystem, ReleaseVerdictClass},
        priority::{PrioritySnapshot, PrioritySource, PriorityTier},
        repo_provenance::{RepositoryMatchKind, RepositoryProvider},
        store::PackageRepositoryIdentity,
    };

    #[test]
    fn assessment_keeps_repo_mismatch_with_impact_and_content_informational() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let capture = sample_capture(false);
        let repository = Some(sample_repository(true));
        let graph = Some(GraphEvidence {
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            known: true,
            direct_popularity: 0.0,
            direct_dependencies_seen: 1,
            reverse_dependents_seen: 2,
            repository: Some(PackageRepositoryIdentity {
                provider: "github".to_string(),
                repository_url: "https://github.com/example/demo".to_string(),
                normalized_repository_url: "https://github.com/example/demo".to_string(),
                source: "capture".to_string(),
                last_version: Some("1.2.3".to_string()),
                updated_at: Utc::now().to_rfc3339(),
            }),
        });
        let diff = Some(sample_diff(1, 0, 5));

        let assessment = assess_release(
            &event,
            graph.as_ref(),
            &capture,
            repository.as_ref(),
            diff.as_ref(),
        );
        assert!(!assessment.suspicious);
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "repo_release_mismatch")
        );
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "content_changed")
        );
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "content_churn_large")
        );
    }

    #[test]
    fn assessment_keeps_bare_repo_mismatch_informational() {
        let event = sample_event(PriorityTier::Low, "1.2.3-nightly.1");
        let capture = sample_capture(false);
        let repository = Some(sample_repository(true));

        let assessment = assess_release(&event, None, &capture, repository.as_ref(), None);
        assert!(!assessment.suspicious);
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
    }

    #[test]
    fn assessment_treats_hyphenated_versions_as_prerelease() {
        let event = sample_event(PriorityTier::Medium, "0.0.0-satin-jumpsuit-20260327151201");
        let capture = sample_capture(false);
        let repository = Some(sample_repository(true));
        let graph = Some(GraphEvidence {
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            known: true,
            direct_popularity: 0.0,
            direct_dependencies_seen: 1,
            reverse_dependents_seen: 1,
            repository: None,
        });

        let assessment =
            assess_release(&event, graph.as_ref(), &capture, repository.as_ref(), None);
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "prerelease_or_nightly")
        );
    }

    #[test]
    fn assessment_keeps_stable_repo_mismatch_without_content_informational() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let capture = sample_capture(false);
        let repository = Some(sample_repository(true));
        let graph = Some(GraphEvidence {
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            known: true,
            direct_popularity: 0.0,
            direct_dependencies_seen: 1,
            reverse_dependents_seen: 1,
            repository: None,
        });

        let assessment =
            assess_release(&event, graph.as_ref(), &capture, repository.as_ref(), None);
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(!assessment.suspicious);
    }

    #[test]
    fn assessment_escalates_malware_shaped_metadata_without_diff() {
        let event = sample_event(PriorityTier::Low, "2.0.0");
        let mut capture = sample_capture(false);
        capture.ecosystem = Ecosystem::Npm;
        capture.package = "undicy-http".to_string();
        capture.details["metadata_risk"] = json!({
            "suspicious": true,
            "score": 9,
            "factors": [
                "native_credential_access_dependency",
                "credential_theft_capability_combo",
                "confusable_package_name"
            ],
            "reason": "npm metadata for undicy-http combines high-risk native credential, surveillance, or exfiltration dependencies"
        });

        let assessment = assess_release(&event, None, &capture, None, None);
        assert!(assessment.suspicious);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert_eq!(
            assessment.verdict_class,
            ReleaseVerdictClass::SuspiciousUnknown
        );
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "malware_shaped_metadata")
        );
    }

    #[test]
    fn assessment_escalates_malware_shaped_content_without_diff() {
        let event = sample_event(PriorityTier::Low, "1.0.0");
        let mut capture = sample_capture(false);
        capture.details["content_risk"] = json!({
            "scanned": true,
            "suspicious": true,
            "score": 10,
            "factors": [
                "npm_runtime_encoded_remote_loader"
            ],
            "reason": "npm package fetches remote code and executes it dynamically at runtime",
            "matches": [{
                "rule_id": "npm_runtime_encoded_remote_loader",
                "namespace": "default",
                "tags": ["malware", "npm", "runtime", "loader"],
                "match_class": DetectionMatchClass::MaliciousBehavior,
                "behavior_tags": ["remote_fetch", "dynamic_execution"],
                "score": 10,
                "file_path": "index.js",
                "file_role": "entrypoint",
                "matched_patterns": ["$loader"],
                "pattern_matches": [{
                    "pattern_id": "$loader",
                    "range_start": 0,
                    "range_end": 32,
                    "preview": "new Function.constructor(...)"
                }],
                "evidence_kind": "pattern",
                "description": "npm package fetches remote code and executes it dynamically at runtime"
            }],
            "iocs": [
                {
                    "kind": "url",
                    "value": "https://example.com/loader",
                    "file_path": "index.js"
                }
            ],
            "scanned_files": [],
            "engine": "yara_x",
            "rule_set_version": "test"
        });

        let assessment = assess_release(&event, None, &capture, None, None);
        assert!(assessment.suspicious);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::High);
        assert_eq!(assessment.verdict_class, ReleaseVerdictClass::Malware);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "malware_shaped_content")
        );
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "content_iocs_present")
        );
        assert!(
            assessment
                .behavior_tags
                .iter()
                .any(|tag| tag == "dynamic_execution")
        );
    }

    #[test]
    fn assessment_downgrades_risky_installer_content_to_warning() {
        let event = sample_event(PriorityTier::Low, "1.0.0");
        let mut capture = sample_capture(true);
        capture.ecosystem = Ecosystem::Npm;
        capture.details["content_risk"] = json!({
            "scanned": true,
            "suspicious": true,
            "score": 8,
            "factors": ["npm_downloader_and_exec_installer"],
            "reason": "npm install-time lifecycle target downloads and executes remote content",
            "matches": [{
                "rule_id": "npm_downloader_and_exec_installer",
                "namespace": "default",
                "tags": ["malware", "npm", "downloader", "installer"],
                "match_class": DetectionMatchClass::RiskyInstaller,
                "behavior_tags": ["install_or_build_execution", "remote_fetch"],
                "score": 8,
                "file_path": "scripts/install.js",
                "file_role": "install_script",
                "matched_patterns": ["$curl"],
                "pattern_matches": [{
                    "pattern_id": "$curl",
                    "range_start": 0,
                    "range_end": 16,
                    "preview": "curl https://"
                }],
                "evidence_kind": "pattern",
                "description": "npm install-time lifecycle target downloads and executes remote content"
            }],
            "iocs": [],
            "scanned_files": [],
            "engine": "yara_x",
            "rule_set_version": "test"
        });

        let assessment = assess_release(&event, None, &capture, None, None);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert_eq!(
            assessment.verdict_class,
            ReleaseVerdictClass::RiskyInstaller
        );
    }

    #[test]
    fn assessment_downgrades_invasive_tooling_to_warning() {
        let event = sample_event(PriorityTier::Low, "0.2.3");
        let mut capture = sample_capture(false);
        capture.ecosystem = Ecosystem::Npm;
        capture.details["content_risk"] = json!({
            "scanned": true,
            "suspicious": true,
            "score": 12,
            "factors": ["npm_mcp_server_injection"],
            "reason": "npm code injects a rogue MCP server configuration into AI coding tools",
            "matches": [{
                "rule_id": "npm_mcp_server_injection",
                "namespace": "default",
                "tags": ["malware", "npm", "persistence", "ai"],
                "match_class": DetectionMatchClass::InvasiveTooling,
                "behavior_tags": ["target_mutation"],
                "score": 12,
                "file_path": "dist/init.js",
                "file_role": "entrypoint",
                "matched_patterns": ["$claude"],
                "pattern_matches": [{
                    "pattern_id": "$claude",
                    "range_start": 0,
                    "range_end": 20,
                    "preview": ".claude/commands/"
                }],
                "evidence_kind": "pattern",
                "description": "npm code injects a rogue MCP server configuration into AI coding tools"
            }],
            "iocs": [],
            "scanned_files": [],
            "engine": "yara_x",
            "rule_set_version": "test"
        });

        let assessment = assess_release(&event, None, &capture, None, None);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert_eq!(
            assessment.verdict_class,
            ReleaseVerdictClass::InvasiveTooling
        );
    }

    #[test]
    fn assessment_downgrades_single_broad_malicious_rule_to_suspicious_unknown_warning() {
        let event = sample_event(PriorityTier::Low, "3.6.0");
        let mut capture = sample_capture(false);
        capture.ecosystem = Ecosystem::Pypi;
        capture.details["content_risk"] = json!({
            "scanned": true,
            "suspicious": true,
            "score": 10,
            "factors": ["pypi_browser_credential_theft"],
            "reason": "PyPI package targets browser login databases, cookies, or credit card storage for credential theft",
            "matches": [{
                "rule_id": "pypi_browser_credential_theft",
                "namespace": "default",
                "tags": ["malware", "pypi", "theft", "browser"],
                "match_class": DetectionMatchClass::MaliciousBehavior,
                "behavior_tags": ["browser_targeting", "credential_or_wallet_theft"],
                "score": 10,
                "file_path": "anikoto.py",
                "file_role": "entrypoint",
                "matched_patterns": ["$cookies"],
                "pattern_matches": [{
                    "pattern_id": "$cookies",
                    "range_start": 0,
                    "range_end": 20,
                    "preview": "cookiesfrombrowser"
                }],
                "evidence_kind": "pattern",
                "description": "PyPI package targets browser login databases, cookies, or credit card storage for credential theft"
            }],
            "iocs": [],
            "scanned_files": [],
            "engine": "yara_x",
            "rule_set_version": "test"
        });

        let assessment = assess_release(&event, None, &capture, None, None);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert_eq!(
            assessment.verdict_class,
            ReleaseVerdictClass::SuspiciousUnknown
        );
    }

    #[test]
    fn assessment_downgrades_lone_webhook_marker_rule_to_suspicious_unknown_warning() {
        let event = sample_event(PriorityTier::Low, "3.6.0");
        let mut capture = sample_capture(false);
        capture.details["content_risk"] = json!({
            "scanned": true,
            "suspicious": true,
            "score": 6,
            "factors": ["generic_discord_or_telegram_exfil"],
            "reason": "content embeds a Discord webhook or Telegram bot token for exfiltration",
            "matches": [{
                "rule_id": "generic_discord_or_telegram_exfil",
                "namespace": "default",
                "tags": ["malware", "exfil"],
                "score": 6,
                "file_path": "lib/notify.js",
                "file_role": "entrypoint",
                "matched_patterns": ["$discord"],
                "pattern_matches": [{
                    "pattern_id": "$discord",
                    "range_start": 0,
                    "range_end": 25,
                    "preview": "discord.com/api/webhooks/"
                }],
                "evidence_kind": "pattern",
                "description": "content embeds a Discord webhook or Telegram bot token for exfiltration"
            }],
            "iocs": [],
            "scanned_files": [],
            "engine": "yara_x",
            "rule_set_version": "test"
        });

        let assessment = assess_release(&event, None, &capture, None, None);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert_eq!(
            assessment.verdict_class,
            ReleaseVerdictClass::SuspiciousUnknown
        );
    }

    #[test]
    fn assessment_keeps_longstanding_install_script_repo_mismatch_informational() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let mut capture = sample_capture(true);
        capture.details["install_scripts_longstanding"] = json!(true);
        let repository = Some(sample_repository(true));

        let assessment = assess_release(&event, None, &capture, repository.as_ref(), None);
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(!assessment.suspicious);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "install_time_execution_longstanding")
        );
    }

    #[test]
    fn assessment_keeps_benign_install_script_repo_mismatch_informational() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let mut capture = sample_capture(true);
        capture.details["install_scripts_benign"] = json!(true);
        let repository = Some(sample_repository(true));

        let assessment = assess_release(&event, None, &capture, repository.as_ref(), None);
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(!assessment.suspicious);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "install_time_execution_benign")
        );
    }

    #[test]
    fn assessment_keeps_repo_mismatch_manifest_only_change_informational() {
        let event = sample_event(PriorityTier::High, "1.2.3");
        let capture = sample_capture(false);
        let repository = Some(sample_repository(true));
        let graph = Some(GraphEvidence {
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            known: true,
            direct_popularity: 0.0,
            direct_dependencies_seen: 0,
            reverse_dependents_seen: 6,
            repository: None,
        });
        let mut diff = sample_diff(0, 0, 1);
        diff.package_manifest_only = true;

        let assessment = assess_release(
            &event,
            graph.as_ref(),
            &capture,
            repository.as_ref(),
            Some(&diff),
        );
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(!assessment.suspicious);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "package_manifest_only")
        );
    }

    #[test]
    fn assessment_keeps_small_repo_mismatch_content_informational() {
        let event = sample_event(PriorityTier::Medium, "0.1.6");
        let capture = sample_capture(false);
        let repository = Some(sample_repository(true));
        let graph = Some(GraphEvidence {
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            known: true,
            direct_popularity: 0.0,
            direct_dependencies_seen: 2,
            reverse_dependents_seen: 3,
            repository: None,
        });
        let diff = sample_diff(0, 0, 2);

        let assessment = assess_release(
            &event,
            graph.as_ref(),
            &capture,
            repository.as_ref(),
            Some(&diff),
        );
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(!assessment.suspicious);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "content_changed")
        );
        assert!(
            !assessment
                .factors
                .iter()
                .any(|factor| factor == "content_churn_large")
        );
        assert_eq!(
            assessment.reason,
            "repository mismatch observed with concrete content changes but no additional corroborating security signals"
        );
    }

    #[test]
    fn assessment_keeps_repo_mismatch_with_risky_install_time_execution_as_warning() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let mut capture = sample_capture(true);
        capture.details["install_scripts_longstanding"] = json!(false);
        capture.details["install_scripts_benign"] = json!(false);
        let repository = Some(sample_repository(true));

        let assessment = assess_release(&event, None, &capture, repository.as_ref(), None);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert!(assessment.suspicious);
        assert_eq!(
            assessment.reason,
            "repository mismatch combined with install-time execution"
        );
    }

    #[test]
    fn assessment_does_not_escalate_longstanding_unchanged_install_hook() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let mut capture = sample_capture(true);
        capture.details["install_scripts_benign"] = json!(false);
        capture.details["install_scripts_longstanding"] = json!(false);
        let graph = Some(GraphEvidence {
            ecosystem: Ecosystem::Npm,
            package: "demo".to_string(),
            known: true,
            direct_popularity: 0.0,
            direct_dependencies_seen: 1,
            reverse_dependents_seen: 2,
            repository: None,
        });
        let mut diff = sample_diff(0, 0, 3);
        diff.target_has_install_scripts = Some(true);
        diff.install_scripts_longstanding = Some(true);
        diff.install_hook_changed = Some(false);

        let assessment = assess_release(&event, graph.as_ref(), &capture, None, Some(&diff));
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(!assessment.suspicious);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "install_time_execution_longstanding")
        );
    }

    fn sample_event(tier: PriorityTier, version: &str) -> PackageReleaseEvent {
        PackageReleaseEvent {
            event_id: format!("pypi:demo@{version}"),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: version.to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier,
                source: PrioritySource::KnownPackageStub,
                direct_popularity: Some(0.0),
                propagated_impact: Some(0.0),
                hidden_leverage: Some(0.0),
                computed_at: Some(Utc::now()),
                score_source_version: Some("test".to_string()),
            }),
        }
    }

    fn sample_capture(has_install_scripts: bool) -> CapturedRelease {
        CapturedRelease {
            event_id: "pypi:demo@1.2.3".to_string(),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: "1.2.3".to_string(),
            observed_at: Utc::now(),
            published_at: None,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: Vec::new(),
            upstream_repository: None,
            details: json!({ "has_install_scripts": has_install_scripts }),
        }
    }

    fn sample_repository(suspicious: bool) -> RepositoryReleaseProvenance {
        RepositoryReleaseProvenance {
            provider: RepositoryProvider::Github,
            repository_url: "https://github.com/example/demo".to_string(),
            normalized_repository_url: "https://github.com/example/demo".to_string(),
            package_version: "1.2.3".to_string(),
            checked_at: Utc::now(),
            candidate_refs: vec!["1.2.3".to_string(), "v1.2.3".to_string()],
            match_kind: if suspicious {
                RepositoryMatchKind::None
            } else {
                RepositoryMatchKind::Tag
            },
            matched_ref: (!suspicious).then_some("v1.2.3".to_string()),
            matched_commit: None,
            suspicious,
            reason: if suspicious {
                "repository resolved on GitHub but no matching tag or release was found for the package version".to_string()
            } else {
                "matched upstream tag".to_string()
            },
        }
    }

    fn sample_diff(
        files_added_count: usize,
        files_removed_count: usize,
        files_changed_count: usize,
    ) -> DiffAssessmentInput {
        let stored = StoredReleaseDiff {
            event_id: "pypi:demo@1.2.3".to_string(),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: "1.2.3".to_string(),
            generated_at: Utc::now(),
            baseline_event_id: Some("pypi:demo@1.2.2".to_string()),
            baseline_version: Some("1.2.2".to_string()),
            status: StoredReleaseDiffStatus::Ready,
            reason: None,
            diff: Some(ReleaseDiff {
                ecosystem: Ecosystem::Pypi,
                package: "demo".to_string(),
                baseline_event_id: "pypi:demo@1.2.2".to_string(),
                target_event_id: "pypi:demo@1.2.3".to_string(),
                baseline_version: "1.2.2".to_string(),
                target_version: "1.2.3".to_string(),
                generated_at: Utc::now(),
                status: crate::diff::StatusDiff {
                    baseline: "active".to_string(),
                    target: "active".to_string(),
                    changed: false,
                },
                artifacts: crate::diff::ArtifactDiff {
                    added: Vec::new(),
                    removed: Vec::new(),
                    changed: Vec::new(),
                },
                details: crate::diff::DetailsDiff {
                    added_keys: Vec::new(),
                    removed_keys: Vec::new(),
                    changed_keys: Vec::new(),
                    added: Default::default(),
                    removed: Default::default(),
                    changed: Vec::new(),
                },
                content: crate::diff::ContentDiff {
                    available: true,
                    reason: None,
                    artifact_kind: Some("wheel".to_string()),
                    baseline_artifact: None,
                    target_artifact: None,
                    patches_included: false,
                    patch_context: None,
                    files_added_count,
                    files_removed_count,
                    files_changed_count,
                    files_added: Vec::new(),
                    files_removed: Vec::new(),
                    files_changed: Vec::new(),
                    files_added_detail: Vec::new(),
                    files_removed_detail: Vec::new(),
                    files_changed_detail: Vec::new(),
                    file_patches: Vec::new(),
                    npm_install_hook: None,
                    crate_repository_commit: None,
                },
                notes: Vec::new(),
            }),
        };
        DiffAssessmentInput::from(&stored)
    }
}
