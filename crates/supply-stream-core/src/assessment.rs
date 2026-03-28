use crate::{
    capture::{CapturedRelease, ReleaseStatus},
    diff::StoredReleaseDiff,
    event::{
        EmittedDiffEvidence, EmittedGraphEvidence, PackageReleaseEvent, ReleaseAssessmentSeverity,
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
}

#[derive(Debug, Clone)]
pub struct ReleaseAssessment {
    pub suspicious: bool,
    pub severity: ReleaseAssessmentSeverity,
    pub factors: Vec<String>,
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
    let install_time_execution = capture_has_install_time_execution(capture);
    let install_time_execution_longstanding =
        capture_has_longstanding_install_time_execution(capture);
    let install_time_execution_benign = capture_has_benign_install_time_execution(capture);
    let risky_install_time_execution = install_time_execution
        && !install_time_execution_longstanding
        && !install_time_execution_benign;
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
    if medium_or_high_impact {
        factors.push("high_or_medium_impact".to_string());
    }
    if reverse_dependents_present {
        factors.push("reverse_dependents_present".to_string());
    }
    if removed_or_yanked {
        factors.push("removed_or_yanked".to_string());
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

    let (severity, suspicious, reason) = if repo_mismatch
        && (risky_install_time_execution
            || (!prerelease && (medium_or_high_impact || reverse_dependents_present)))
        && content_changed
        && !package_manifest_only
    {
        (
            ReleaseAssessmentSeverity::High,
            true,
            "repository mismatch combined with impactful release and concrete content changes"
                .to_string(),
        )
    } else if repo_mismatch && risky_install_time_execution {
        (
            ReleaseAssessmentSeverity::High,
            true,
            "repository mismatch combined with install-time execution".to_string(),
        )
    } else if repo_mismatch && !prerelease && (medium_or_high_impact || reverse_dependents_present)
    {
        (
            ReleaseAssessmentSeverity::Warning,
            true,
            "stable upstream mismatch on a package with observable downstream impact".to_string(),
        )
    } else if repo_mismatch && !prerelease && content_changed {
        (
            ReleaseAssessmentSeverity::Warning,
            true,
            "stable upstream mismatch with concrete content changes".to_string(),
        )
    } else if install_time_execution
        && content_changed
        && (medium_or_high_impact || reverse_dependents_present)
    {
        (
            ReleaseAssessmentSeverity::Warning,
            true,
            "install-time execution combined with impact and content changes".to_string(),
        )
    } else if content_large && (medium_or_high_impact || reverse_dependents_present) {
        (
            ReleaseAssessmentSeverity::Warning,
            true,
            "large content churn on a package with observable downstream impact".to_string(),
        )
    } else if repo_mismatch {
        (
            ReleaseAssessmentSeverity::Informational,
            false,
            "repository mismatch observed without additional corroborating signals".to_string(),
        )
    } else {
        (
            ReleaseAssessmentSeverity::Informational,
            false,
            "no corroborating multi-signal release risk factors observed".to_string(),
        )
    };

    ReleaseAssessment {
        suspicious,
        severity,
        factors,
        reason,
        graph,
        diff,
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
            ),
            None => (false, false, 0, 0, 0, false),
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
        event::Ecosystem,
        priority::{PrioritySnapshot, PrioritySource, PriorityTier},
        repo_provenance::{RepositoryMatchKind, RepositoryProvider},
        store::PackageRepositoryIdentity,
    };

    #[test]
    fn assessment_escalates_repo_mismatch_with_impact_and_content() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let capture = sample_capture(true);
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
        let diff = Some(sample_diff(1, 0, 3));

        let assessment = assess_release(
            &event,
            graph.as_ref(),
            &capture,
            repository.as_ref(),
            diff.as_ref(),
        );
        assert!(assessment.suspicious);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::High);
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
    fn assessment_downgrades_stable_repo_mismatch_without_content_to_warning() {
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
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert!(assessment.suspicious);
    }

    #[test]
    fn assessment_downgrades_longstanding_install_script_repo_mismatch() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let mut capture = sample_capture(true);
        capture.details["install_scripts_longstanding"] = json!(true);
        let repository = Some(sample_repository(true));

        let assessment = assess_release(&event, None, &capture, repository.as_ref(), None);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert!(assessment.suspicious);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "install_time_execution_longstanding")
        );
    }

    #[test]
    fn assessment_downgrades_benign_install_script_repo_mismatch() {
        let event = sample_event(PriorityTier::Medium, "1.2.3");
        let mut capture = sample_capture(true);
        capture.details["install_scripts_benign"] = json!(true);
        let repository = Some(sample_repository(true));

        let assessment = assess_release(&event, None, &capture, repository.as_ref(), None);
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert!(assessment.suspicious);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "install_time_execution_benign")
        );
    }

    #[test]
    fn assessment_downgrades_repo_mismatch_when_only_package_manifest_changed() {
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
        assert_eq!(assessment.severity, ReleaseAssessmentSeverity::Warning);
        assert!(assessment.suspicious);
        assert!(
            assessment
                .factors
                .iter()
                .any(|factor| factor == "package_manifest_only")
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
                },
                notes: Vec::new(),
            }),
        };
        DiffAssessmentInput::from(&stored)
    }
}
