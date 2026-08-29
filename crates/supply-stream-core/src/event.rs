use std::fmt;

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::{
    priority::{PrioritySnapshot, PriorityTier},
    repo_provenance::RepositoryReleaseProvenance,
    store::PackageRepositoryIdentity,
};

#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize, ValueEnum,
)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "pypi")]
    Pypi,
    #[serde(rename = "crates-io")]
    #[value(name = "crates-io", alias = "crates_io")]
    CratesIo,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::CratesIo => "crates-io",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageReleaseEvent {
    pub event_id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub published_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub source: String,
    pub sequence: Option<String>,
    pub package_url: Option<String>,
    pub release_url: Option<String>,
    pub metadata_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<PrioritySnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedPackageReleaseEvent {
    #[serde(flatten)]
    pub event: PackageReleaseEvent,
    pub resolution: EmittedPriorityResolution,
    pub graph: EmittedGraphEvidence,
    pub plan: EmittedProcessingPlan,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedRepositorySignal {
    pub kind: &'static str,
    pub event_id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub suspicious: bool,
    pub signal_type: &'static str,
    pub severity: RepositorySignalSeverity,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<String>,
    pub reason: String,
    pub repository: RepositoryReleaseProvenance,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedReleaseAssessmentSignal {
    pub kind: &'static str,
    pub event_id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub suspicious: bool,
    pub signal_type: &'static str,
    pub severity: ReleaseAssessmentSeverity,
    pub verdict_class: ReleaseVerdictClass,
    pub priority_tier: PriorityTier,
    pub graph: EmittedGraphEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub behavior_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_evidence: Vec<EmittedMatchedRuleEvidence>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RepositoryReleaseProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<EmittedDiffEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedPrioritySignal {
    pub kind: &'static str,
    pub event_id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub signal_type: &'static str,
    pub previous_priority: Option<PrioritySnapshot>,
    pub current_priority: PrioritySnapshot,
    pub graph: EmittedGraphEvidence,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositorySignalSeverity {
    Informational,
    Warning,
    High,
}

impl RepositorySignalSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Warning => "warning",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseAssessmentSeverity {
    Informational,
    Warning,
    High,
}

impl ReleaseAssessmentSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Warning => "warning",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseVerdictClass {
    Clean,
    SuspiciousUnknown,
    RiskyInstaller,
    InvasiveTooling,
    Malware,
}

impl ReleaseVerdictClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::SuspiciousUnknown => "suspicious_unknown",
            Self::RiskyInstaller => "risky_installer",
            Self::InvasiveTooling => "invasive_tooling",
            Self::Malware => "malware",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMatchClass {
    MaliciousBehavior,
    RiskyInstaller,
    InvasiveTooling,
    ContextOnly,
}

impl DetectionMatchClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaliciousBehavior => "malicious_behavior",
            Self::RiskyInstaller => "risky_installer",
            Self::InvasiveTooling => "invasive_tooling",
            Self::ContextOnly => "context_only",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedMatchedRuleEvidence {
    pub rule_id: String,
    pub match_class: DetectionMatchClass,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub behavior_tags: Vec<String>,
    pub file_path: String,
    pub file_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pattern_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedPriorityResolution {
    pub knowledge: PriorityKnowledgeLevel,
    pub score_hit: bool,
    pub local_graph_hit: bool,
    pub census_hit: bool,
    pub runtime_stub: bool,
    pub external_fallback: bool,
    pub provisional: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PriorityKnowledgeLevel {
    Scored,
    LocalGraph,
    PackageExistence,
    RuntimeObserved,
    External,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EmittedGraphEvidence {
    pub known_in_local_graph: bool,
    pub known_in_census: bool,
    pub observed_count: usize,
    pub direct_dependencies_seen: usize,
    pub reverse_dependents_seen: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<PackageRepositoryIdentity>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedProcessingPlan {
    pub capture: EmittedJobPlan,
    pub diff: EmittedJobPlan,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedJobPlan {
    pub requested: bool,
    pub planned_state: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmittedDiffEvidence {
    pub status: &'static str,
    pub available: bool,
    pub patches_included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_version: Option<String>,
    pub files_added_count: usize,
    pub files_removed_count: usize,
    pub files_changed_count: usize,
}

impl PackageReleaseEvent {
    pub fn release_key(&self) -> String {
        format!("{}:{}@{}", self.ecosystem, self.package, self.version)
    }

    pub fn priority_snapshot(&self) -> PrioritySnapshot {
        self.priority
            .clone()
            .unwrap_or_else(PrioritySnapshot::default_unknown)
    }

    pub fn capture_requested(&self) -> bool {
        self.priority_snapshot().capture_requested()
    }

    pub fn diff_requested(&self) -> bool {
        self.priority_snapshot().diff_requested()
    }

    pub fn capture_requested_with_graph(&self, graph: &EmittedGraphEvidence) -> bool {
        let priority = self.priority_snapshot();
        priority.capture_requested() || graph_capture_escalation(&priority, graph)
    }

    pub fn diff_requested_with_graph(&self, graph: &EmittedGraphEvidence) -> bool {
        let priority = self.priority_snapshot();
        priority.diff_requested() || graph_diff_escalation(&priority, graph)
    }

    pub fn emitted_view(&self, graph: EmittedGraphEvidence) -> EmittedPackageReleaseEvent {
        let priority = self.priority_snapshot();
        let resolution = match priority.source {
            crate::priority::PrioritySource::OfflineScoreFile => EmittedPriorityResolution {
                knowledge: PriorityKnowledgeLevel::Scored,
                score_hit: true,
                local_graph_hit: false,
                census_hit: false,
                runtime_stub: false,
                external_fallback: false,
                provisional: false,
            },
            crate::priority::PrioritySource::LocalGraph => EmittedPriorityResolution {
                knowledge: PriorityKnowledgeLevel::LocalGraph,
                score_hit: false,
                local_graph_hit: true,
                census_hit: false,
                runtime_stub: false,
                external_fallback: false,
                provisional: true,
            },
            crate::priority::PrioritySource::PackageCensus => EmittedPriorityResolution {
                knowledge: PriorityKnowledgeLevel::PackageExistence,
                score_hit: false,
                local_graph_hit: false,
                census_hit: true,
                runtime_stub: false,
                external_fallback: false,
                provisional: true,
            },
            crate::priority::PrioritySource::KnownPackageStub => EmittedPriorityResolution {
                knowledge: PriorityKnowledgeLevel::RuntimeObserved,
                score_hit: false,
                local_graph_hit: false,
                census_hit: false,
                runtime_stub: true,
                external_fallback: false,
                provisional: true,
            },
            crate::priority::PrioritySource::DepsDevDependentsApi
            | crate::priority::PrioritySource::EcosysteMsCountsApi => EmittedPriorityResolution {
                knowledge: PriorityKnowledgeLevel::External,
                score_hit: false,
                local_graph_hit: false,
                census_hit: false,
                runtime_stub: false,
                external_fallback: true,
                provisional: true,
            },
            crate::priority::PrioritySource::DefaultUnknown => EmittedPriorityResolution {
                knowledge: PriorityKnowledgeLevel::Unknown,
                score_hit: false,
                local_graph_hit: false,
                census_hit: false,
                runtime_stub: false,
                external_fallback: false,
                provisional: true,
            },
        };

        let capture_requested = self.capture_requested_with_graph(&graph);
        let diff_requested = self.diff_requested_with_graph(&graph);
        let plan = EmittedProcessingPlan {
            capture: EmittedJobPlan {
                requested: capture_requested,
                planned_state: if capture_requested {
                    "pending"
                } else {
                    "skipped"
                },
                reason: if graph_capture_escalation(&priority, &graph) {
                    "graph policy escalated capture"
                } else if capture_requested {
                    "priority policy requested capture"
                } else {
                    "priority policy skipped capture"
                },
            },
            diff: EmittedJobPlan {
                requested: diff_requested,
                planned_state: if diff_requested { "pending" } else { "skipped" },
                reason: if graph_diff_escalation(&priority, &graph) {
                    "graph policy escalated diff"
                } else if diff_requested {
                    "priority policy requested diff"
                } else {
                    "priority policy skipped diff"
                },
            },
        };

        EmittedPackageReleaseEvent {
            event: self.clone(),
            resolution,
            graph,
            plan,
        }
    }
}

impl EmittedRepositorySignal {
    pub fn repo_release_parity(
        event: &PackageReleaseEvent,
        repository: RepositoryReleaseProvenance,
        severity: RepositorySignalSeverity,
        factors: Vec<String>,
    ) -> Self {
        Self {
            kind: "repository_signal",
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            suspicious: repository.suspicious,
            signal_type: "repo_release_parity",
            severity,
            factors,
            reason: repository.reason.clone(),
            repository,
        }
    }
}

impl EmittedPrioritySignal {
    pub fn local_graph_promotion(
        event: &PackageReleaseEvent,
        previous_priority: Option<PrioritySnapshot>,
        current_priority: PrioritySnapshot,
        graph: EmittedGraphEvidence,
    ) -> Self {
        let previous_source = previous_priority
            .as_ref()
            .map(|snapshot| snapshot.source.as_str())
            .unwrap_or("none");
        let reason = format!(
            "capture-derived graph knowledge promoted package priority from {previous_source} to {}",
            current_priority.source.as_str()
        );
        Self {
            kind: "priority_signal",
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            signal_type: "local_graph_promotion",
            previous_priority,
            current_priority,
            graph,
            reason,
        }
    }
}

fn graph_capture_escalation(priority: &PrioritySnapshot, graph: &EmittedGraphEvidence) -> bool {
    !priority.capture_requested()
        && graph.known_in_local_graph
        && graph.reverse_dependents_seen > 0
        && graph.observed_count >= 2
}

fn graph_diff_escalation(priority: &PrioritySnapshot, graph: &EmittedGraphEvidence) -> bool {
    !priority.diff_requested()
        && graph.known_in_local_graph
        && graph.reverse_dependents_seen > 0
        && graph.observed_count >= 2
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::priority::{PrioritySource, PriorityTier};

    #[test]
    fn emitted_view_includes_resolution_and_plan() {
        let event = PackageReleaseEvent {
            event_id: "npm:react@1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "react".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "npm.replication".to_string(),
            sequence: Some("1".to_string()),
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: PriorityTier::Medium,
                source: PrioritySource::PackageCensus,
                direct_popularity: Some(0.0),
                propagated_impact: Some(0.0),
                hidden_leverage: Some(0.0),
                computed_at: Some(Utc::now()),
                score_source_version: Some("package_census_v1".to_string()),
            }),
        };

        let emitted = event.emitted_view(EmittedGraphEvidence {
            known_in_local_graph: false,
            known_in_census: true,
            observed_count: 1,
            direct_dependencies_seen: 0,
            reverse_dependents_seen: 0,
            repository: None,
        });
        assert!(emitted.resolution.census_hit);
        assert_eq!(
            emitted.resolution.knowledge,
            PriorityKnowledgeLevel::PackageExistence
        );
        assert!(emitted.graph.known_in_census);
        assert!(emitted.plan.capture.requested);
        assert!(!emitted.plan.diff.requested);
        assert_eq!(emitted.plan.capture.planned_state, "pending");
        assert_eq!(emitted.plan.diff.planned_state, "skipped");
    }

    #[test]
    fn emitted_view_escalates_diff_from_graph_evidence() {
        let event = PackageReleaseEvent {
            event_id: "pypi:demo@1.0.0".to_string(),
            ecosystem: Ecosystem::Pypi,
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            published_at: None,
            observed_at: Utc::now(),
            source: "test".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: Some(PrioritySnapshot {
                tier: crate::priority::PriorityTier::Low,
                source: crate::priority::PrioritySource::LocalGraph,
                direct_popularity: Some(1.0),
                propagated_impact: Some(1.0),
                hidden_leverage: Some(0.0),
                computed_at: Some(Utc::now()),
                score_source_version: Some("local_graph".to_string()),
            }),
        };

        let emitted = event.emitted_view(EmittedGraphEvidence {
            known_in_local_graph: true,
            known_in_census: true,
            observed_count: 2,
            direct_dependencies_seen: 1,
            reverse_dependents_seen: 1,
            repository: None,
        });

        assert!(emitted.plan.capture.requested);
        assert!(emitted.plan.diff.requested);
        assert_eq!(
            emitted.plan.capture.reason,
            "graph policy escalated capture"
        );
        assert_eq!(emitted.plan.diff.reason, "graph policy escalated diff");
    }
}
