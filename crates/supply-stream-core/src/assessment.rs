use serde::{Deserialize, Serialize};

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

/// Configurable thresholds for the rapid version-burst signal.
///
/// Threshold reasoning:
/// - `window`: the Trinitite npm worm published 10 versions of one package
///   across 4 major-version lines (0.5.x, 1.6.x, 2.2.x, 3.0.x) within ~20
///   minutes from a compromised maintainer token. A 30-minute window catches
///   that burst with margin for feed polling jitter, while staying far below
///   any legitimate release cadence.
/// - `min_versions`: 5 versions inside the window is already unusual for
///   humans and CI pipelines (which publish one version per pipeline run);
///   combined with the major-line requirement it selects exactly the
///   mass-republish shape.
/// - `min_major_lines`: the strong form of the signal requires >=2 distinct
///   major-version lines in the window. Legitimate fast publishing (CI
///   prerelease churn, monorepo bulk releases, a maintainer fixing a broken
///   publish) almost always advances ONE version line; jumping several major
///   lines back-to-back is the token-hijack mass-republish tell. A count-only
///   burst on a single line therefore never escalates severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionBurstConfig {
    pub window_secs: u64,
    pub min_versions: usize,
    pub min_major_lines: usize,
}

impl Default for VersionBurstConfig {
    fn default() -> Self {
        Self {
            window_secs: 1800,
            min_versions: 5,
            min_major_lines: 2,
        }
    }
}

impl VersionBurstConfig {
    pub fn window(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.window_secs.clamp(1, i64::MAX as u64) as i64)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionBurstSignal {
    pub suspicious: bool,
    pub versions_in_window: usize,
    pub distinct_major_lines: usize,
    pub window_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Evaluates a rapid version-burst from the release timestamps of the same
/// package within the configured window.
///
/// `timestamps` are (version, release time) pairs for the package; the
/// candidate release itself MUST be included so the count reflects the burst
/// as observed at assessment time. Timestamps may arrive in any order.
pub fn evaluate_version_burst(
    timestamps: &[(String, chrono::DateTime<chrono::Utc>)],
    config: &VersionBurstConfig,
) -> VersionBurstSignal {
    let Some(&(_, latest)) = timestamps.iter().max_by(|left, right| left.1.cmp(&right.1)) else {
        return VersionBurstSignal::default();
    };
    let window_start = latest - config.window();

    let in_window: Vec<&str> = timestamps
        .iter()
        .filter(|(_, at)| *at >= window_start && *at <= latest)
        .map(|(version, _)| version.as_str())
        .collect();
    let versions_in_window = in_window.len();
    let distinct_major_lines = in_window
        .iter()
        .filter_map(|version| major_version_line(version))
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    let mut signal = VersionBurstSignal {
        suspicious: false,
        versions_in_window,
        distinct_major_lines,
        window_secs: config.window_secs,
        reason: None,
    };

    // Escalation requires BOTH the version count and the multi-major-line
    // spread: count-only bursts (single-line CI/monorepo publishing) are
    // common and benign and must not escalate.
    if versions_in_window >= config.min_versions && distinct_major_lines >= config.min_major_lines {
        signal.suspicious = true;
        signal.reason = Some(format!(
            "{versions_in_window} versions of this package across {distinct_major_lines} major-version lines within {}s; rapid multi-major-line republish bursts are a mass-republish compromise shape, not a normal release cadence",
            config.window_secs
        ));
    }
    signal
}

/// Major-version line of a semver-ish version string: the leading numeric
/// segment ("2.2.1" -> "2", "0.5.3" -> "0"). Non-numeric or missing leading
/// segments map to `None` (excluded from the major-line spread).
pub fn major_version_line(version: &str) -> Option<String> {
    let head = version
        .split(['.', '-', '+', '_'])
        .find(|segment| !segment.is_empty())?;
    if !head.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(head.to_string())
}

pub fn captured_version_burst(capture: &CapturedRelease) -> VersionBurstSignal {
    capture
        .details
        .get("version_burst")
        .cloned()
        .and_then(|value| serde_json::from_value::<VersionBurstSignal>(value).ok())
        .unwrap_or_default()
}

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
    let version_burst = captured_version_burst(capture);

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
    if version_burst.suspicious {
        factors.push("rapid_version_burst".to_string());
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
    } else if version_burst.suspicious {
        // The burst signal is deliberately a WARNING-level suspicious
        // contributor, never a standalone malware verdict: legit rapid
        // publishing exists (CI prerelease churn, monorepo bulk releases,
        // republishing a broken release), and the multi-major-line spread
        // only marks the release as worth a human look.
        (
            ReleaseAssessmentSeverity::Warning,
            ReleaseVerdictClass::SuspiciousUnknown,
            true,
            version_burst.reason.clone().unwrap_or_else(|| {
                "rapid multi-major-line version burst observed for this package".to_string()
            }),
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

    #[test]
    fn version_burst_fires_on_cross_major_line_burst() {
        // Trinitite shape: 10 versions across 4 major lines (0.5.x, 1.6.x,
        // 2.2.x, 3.0.x) within ~20 minutes.
        let base = Utc::now();
        let timestamps = [
            ("0.5.0", 0),
            ("0.5.1", 60),
            ("1.6.0", 300),
            ("1.6.1", 360),
            ("2.2.0", 600),
            ("2.2.1", 660),
            ("2.2.2", 720),
            ("3.0.0", 900),
            ("3.0.1", 960),
            ("3.0.2", 1020),
        ]
        .into_iter()
        .map(|(version, offset)| {
            (
                version.to_string(),
                base + chrono::Duration::seconds(offset),
            )
        })
        .collect::<Vec<_>>();

        let signal = evaluate_version_burst(&timestamps, &VersionBurstConfig::default());
        assert!(signal.suspicious);
        assert_eq!(signal.versions_in_window, 10);
        assert_eq!(signal.distinct_major_lines, 4);
        assert!(signal.reason.is_some());
    }

    #[test]
    fn version_burst_does_not_escalate_single_line_patch_burst() {
        // Common benign shape: CI/monorepo publishing many patch versions of
        // ONE major line quickly.
        let base = Utc::now();
        let timestamps = [
            ("1.4.0", 0),
            ("1.4.1", 120),
            ("1.4.2", 240),
            ("1.4.3", 360),
            ("1.4.4", 480),
            ("1.4.5", 600),
            ("1.4.6", 720),
        ]
        .into_iter()
        .map(|(version, offset)| {
            (
                version.to_string(),
                base + chrono::Duration::seconds(offset),
            )
        })
        .collect::<Vec<_>>();

        let signal = evaluate_version_burst(&timestamps, &VersionBurstConfig::default());
        assert!(!signal.suspicious);
        assert_eq!(signal.versions_in_window, 7);
        assert_eq!(signal.distinct_major_lines, 1);
    }

    #[test]
    fn version_burst_stays_quiet_on_normal_release_cadence() {
        // Normal cadence: a handful of releases spread over days.
        let base = Utc::now();
        let timestamps = [
            ("1.0.0", 0),
            ("1.1.0", 86_400),
            ("1.2.0", 172_800),
            ("2.0.0", 259_200),
        ]
        .into_iter()
        .map(|(version, offset)| {
            (
                version.to_string(),
                base + chrono::Duration::seconds(offset),
            )
        })
        .collect::<Vec<_>>();

        let signal = evaluate_version_burst(&timestamps, &VersionBurstConfig::default());
        assert!(!signal.suspicious);
        assert_eq!(signal.versions_in_window, 1);
        assert_eq!(signal.distinct_major_lines, 1);
    }

    #[test]
    fn version_burst_requires_both_count_and_major_line_spread() {
        let base = Utc::now();
        let at = |offset: i64| base + chrono::Duration::seconds(offset);

        // Count met, but only one major line: no signal even at 9 versions.
        let single_line = [
            "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, version)| (version.to_string(), at(index as i64 * 60)))
        .collect::<Vec<_>>();
        assert!(!evaluate_version_burst(&single_line, &VersionBurstConfig::default()).suspicious);

        // Major lines met, but only 4 versions (< default 5): no signal.
        let few_cross_major = ["0.5.0", "1.6.0", "2.2.0", "3.0.0"]
            .into_iter()
            .enumerate()
            .map(|(index, version)| (version.to_string(), at(index as i64 * 60)))
            .collect::<Vec<_>>();
        let signal = evaluate_version_burst(&few_cross_major, &VersionBurstConfig::default());
        assert!(!signal.suspicious);
        assert_eq!(signal.versions_in_window, 4);
        assert_eq!(signal.distinct_major_lines, 4);

        // Custom thresholds are honored: with min_versions=4 the same set fires.
        let relaxed = VersionBurstConfig {
            window_secs: 1800,
            min_versions: 4,
            min_major_lines: 2,
        };
        assert!(evaluate_version_burst(&few_cross_major, &relaxed).suspicious);
    }

    #[test]
    fn version_burst_ignores_prerelease_build_metadata_in_major_line() {
        assert_eq!(major_version_line("2.2.1"), Some("2".to_string()));
        assert_eq!(major_version_line("0.5.3-beta.1"), Some("0".to_string()));
        assert_eq!(major_version_line("v3.0.0"), None);
        assert_eq!(major_version_line(""), None);
    }

    #[tokio::test]
    async fn version_burst_seeded_store_query_and_assessment_escalation() {
        use crate::store::{EventOrigin, OperationalStore};
        use tempfile::tempdir;

        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let store = OperationalStore::open(crate::store::index_db_path(&data_dir))
            .await
            .unwrap();

        // Seed the store with a cross-major burst for package "bursty" plus
        // old releases outside the window, and a burst of a different
        // package that must not leak into the query.
        let now = Utc::now();
        let seed = |package: &str, version: &str, offset_secs: i64| PackageReleaseEvent {
            event_id: format!("npm:{package}@{version}"),
            ecosystem: Ecosystem::Npm,
            package: package.to_string(),
            version: version.to_string(),
            published_at: Some(now + chrono::Duration::seconds(offset_secs)),
            observed_at: now + chrono::Duration::seconds(offset_secs),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot::default_unknown()),
        };
        for (version, offset) in [
            ("0.5.0", -600),
            ("1.6.0", -480),
            ("2.2.0", -360),
            ("3.0.0", -240),
        ] {
            store
                .record_event(&seed("bursty", version, offset), EventOrigin::Observed)
                .await
                .unwrap();
        }
        for (version, offset) in [("1.0.0", -600), ("1.0.1", -480)] {
            store
                .record_event(&seed("other", version, offset), EventOrigin::Observed)
                .await
                .unwrap();
        }
        // Old release of "bursty" outside the 30-minute window.
        store
            .record_event(&seed("bursty", "0.1.0", -86_400), EventOrigin::Observed)
            .await
            .unwrap();

        let since = now - chrono::Duration::seconds(1800);
        let times = store
            .load_package_release_times_since(Ecosystem::Npm, "bursty", since)
            .await
            .unwrap();
        assert_eq!(times.len(), 4);
        assert!(times.iter().all(|(version, _)| version != "0.1.0"));

        // The candidate release (3.0.1, published now) joins the seeded
        // four to cross the threshold: 5 versions across 4 major lines.
        let mut timestamps = times;
        timestamps.push(("3.0.1".to_string(), now));
        let burst = evaluate_version_burst(&timestamps, &VersionBurstConfig::default());
        assert!(burst.suspicious);
        assert_eq!(burst.versions_in_window, 5);
        assert_eq!(burst.distinct_major_lines, 4);

        // End to end: the embedded signal escalates the assessment to a
        // WARNING-level suspicious factor, never a malware verdict.
        let event = sample_event(PriorityTier::Low, "3.0.1");
        let mut capture = sample_capture(false);
        capture.details["version_burst"] = serde_json::to_value(&burst).unwrap();
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
                .any(|factor| factor == "rapid_version_burst")
        );
    }

    #[test]
    fn version_burst_embedded_signal_round_trips_through_capture_details() {
        let mut capture = sample_capture(false);
        capture.details["version_burst"] = json!({
            "suspicious": true,
            "versions_in_window": 6,
            "distinct_major_lines": 3,
            "window_secs": 1800,
            "reason": "6 versions of this package across 3 major-version lines within 1800s"
        });
        let signal = captured_version_burst(&capture);
        assert!(signal.suspicious);
        assert_eq!(signal.versions_in_window, 6);
        assert_eq!(signal.distinct_major_lines, 3);
    }

    #[test]
    fn assessment_without_burst_detail_stays_clean() {
        // No version_burst detail (legacy captures, detection corpus): no
        // factor, no escalation.
        let event = sample_event(PriorityTier::Low, "1.2.3");
        let capture = sample_capture(false);
        let assessment = assess_release(&event, None, &capture, None, None);
        assert_eq!(
            assessment.severity,
            ReleaseAssessmentSeverity::Informational
        );
        assert!(
            !assessment
                .factors
                .iter()
                .any(|factor| factor == "rapid_version_burst")
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
