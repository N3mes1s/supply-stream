use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use tokio::fs;

use crate::{
    assessment::{DiffAssessmentInput, assess_release},
    capture::CapturedRelease,
    event::{
        EmittedGraphEvidence, EmittedPackageReleaseEvent, EmittedReleaseAssessmentSignal,
        PackageReleaseEvent,
    },
    history,
    store::{OperationalStore, PackageRepositoryIdentity},
};

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseEvidenceBundle {
    pub kind: &'static str,
    pub generated_at: DateTime<Utc>,
    pub event: EmittedPackageReleaseEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_repository: Option<PackageRepositoryIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CapturedRelease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_assessment: Option<EmittedReleaseAssessmentSignal>,
}

pub fn bundle_path_for_event(data_dir: &Path, event: &PackageReleaseEvent) -> PathBuf {
    history::capture_dir_for_event(data_dir, event).join("bundle.json")
}

pub async fn write_release_bundle(
    data_dir: &Path,
    store: &OperationalStore,
    event: &PackageReleaseEvent,
    capture: Option<&CapturedRelease>,
    diff: Option<&Value>,
) -> Result<ReleaseEvidenceBundle> {
    let bundle = build_release_bundle(data_dir, store, event, capture, diff).await?;
    let path = bundle_path_for_event(data_dir, event);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create bundle dir {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(&bundle)?;
    fs::write(&path, body)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(bundle)
}

pub async fn build_release_bundle(
    data_dir: &Path,
    store: &OperationalStore,
    event: &PackageReleaseEvent,
    capture: Option<&CapturedRelease>,
    diff: Option<&Value>,
) -> Result<ReleaseEvidenceBundle> {
    let capture_dir = history::capture_dir_for_event(data_dir, event);
    let capture = match capture {
        Some(capture) => Some(capture.clone()),
        None => read_json_if_exists::<CapturedRelease>(&capture_dir.join("capture.json")).await?,
    };
    let diff = match diff {
        Some(diff) => Some(diff.clone()),
        None => read_json_if_exists::<Value>(&capture_dir.join("diff.json")).await?,
    };

    let graph = store
        .load_graph_evidence(event.ecosystem, &event.package)
        .await?;
    let package_repository = store
        .load_package_repository_identity(event.ecosystem, &event.package)
        .await?;
    let observed_count = store
        .load_package_events(event.ecosystem, &event.package)
        .await?
        .len();
    let emitted_graph = EmittedGraphEvidence {
        known_in_local_graph: graph.as_ref().is_some_and(|graph| graph.known),
        known_in_census: false,
        observed_count,
        direct_dependencies_seen: graph
            .as_ref()
            .map(|graph| graph.direct_dependencies_seen)
            .unwrap_or(0),
        reverse_dependents_seen: graph
            .as_ref()
            .map(|graph| graph.reverse_dependents_seen)
            .unwrap_or(0),
        repository: package_repository
            .clone()
            .or_else(|| graph.as_ref().and_then(|graph| graph.repository.clone())),
    };
    let emitted_event = event.emitted_view(emitted_graph.clone());

    let release_assessment = capture.as_ref().map(|capture| {
        let repository = capture.upstream_repository.clone();
        let diff_input = diff.as_ref().and_then(diff_assessment_input_from_value);
        let assessment = assess_release(
            event,
            graph.as_ref(),
            capture,
            repository.as_ref(),
            diff_input.as_ref(),
        );
        EmittedReleaseAssessmentSignal {
            kind: "release_assessment",
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            suspicious: assessment.suspicious,
            signal_type: "repo_graph_diff_fusion",
            severity: assessment.severity,
            priority_tier: event.priority_snapshot().tier,
            graph: assessment.graph,
            factors: assessment.factors,
            reason: assessment.reason,
            repository,
            diff: assessment.diff,
        }
    });

    Ok(ReleaseEvidenceBundle {
        kind: "release_evidence_bundle",
        generated_at: Utc::now(),
        event: emitted_event,
        package_repository,
        capture,
        diff,
        release_assessment,
    })
}

fn diff_assessment_input_from_value(value: &Value) -> Option<DiffAssessmentInput> {
    let status = match value.get("status").and_then(Value::as_str)? {
        "ready" => "ready",
        "no_baseline" => "no_baseline",
        _ => return None,
    };
    let baseline_version = value
        .get("baseline_version")
        .and_then(Value::as_str)
        .map(str::to_string);
    let content = value.get("diff").and_then(|value| value.get("content"));
    Some(DiffAssessmentInput {
        status,
        baseline_version,
        available: content
            .and_then(|value| value.get("available"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        patches_included: content
            .and_then(|value| value.get("patches_included"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        files_added_count: content
            .and_then(|value| value.get("files_added_count"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        files_removed_count: content
            .and_then(|value| value.get("files_removed_count"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        files_changed_count: content
            .and_then(|value| value.get("files_changed_count"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        package_manifest_only: content
            .and_then(|value| value.get("files_added"))
            .and_then(Value::as_array)
            .zip(
                content
                    .and_then(|value| value.get("files_removed"))
                    .and_then(Value::as_array),
            )
            .zip(
                content
                    .and_then(|value| value.get("files_changed"))
                    .and_then(Value::as_array),
            )
            .map(|((added, removed), changed)| {
                let added: Vec<String> = added
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
                let removed: Vec<String> = removed
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
                let changed: Vec<String> = changed
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
                added.is_empty()
                    && removed.is_empty()
                    && !changed.is_empty()
                    && changed.iter().all(|path| {
                        matches!(
                            path.as_str(),
                            "package.json"
                                | "Cargo.toml"
                                | "pyproject.toml"
                                | "setup.py"
                                | "setup.cfg"
                        ) || path.ends_with("/package.json")
                            || path.ends_with("/Cargo.toml")
                            || path.ends_with("/pyproject.toml")
                            || path.ends_with("/setup.py")
                            || path.ends_with("/setup.cfg")
                    })
            })
            .unwrap_or(false),
    })
}

async fn read_json_if_exists<T>(path: &Path) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use chrono::Utc;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        capture::{ArtifactHashes, CapturedArtifact, ReleaseStatus},
        diff::StoredReleaseDiffStatus,
        event::Ecosystem,
        priority::{PrioritySnapshot, PrioritySource, PriorityTier},
        store::{EventOrigin, OperationalStore},
    };

    #[tokio::test]
    async fn writes_bundle_with_capture_and_diff() -> Result<()> {
        let temp = tempdir()?;
        let data_dir = temp.path().join("data");
        let store = OperationalStore::open(data_dir.join("index.sqlite")).await?;
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
                tier: PriorityTier::Medium,
                source: PrioritySource::LocalGraph,
                direct_popularity: Some(1.0),
                propagated_impact: Some(2.0),
                hidden_leverage: Some(1.0),
                computed_at: Some(Utc::now()),
                score_source_version: Some("local_graph".to_string()),
            }),
        };
        store.record_event(&event, EventOrigin::Observed).await?;
        let capture_dir = history::capture_dir_for_event(&data_dir, &event);
        fs::create_dir_all(&capture_dir).await?;
        let capture = CapturedRelease {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            observed_at: event.observed_at,
            published_at: event.published_at,
            captured_at: Utc::now(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: vec![CapturedArtifact {
                filename: "demo-1.0.0.whl".to_string(),
                kind: Some("wheel".to_string()),
                url: None,
                size_bytes: Some(1),
                uploaded_at: None,
                yanked: None,
                hashes: ArtifactHashes {
                    sha256: Some("abc".to_string()),
                    ..ArtifactHashes::default()
                },
                provenance_path: None,
            }],
            upstream_repository: None,
            details: serde_json::json!({"dependencies": ["urllib3"]}),
        };
        store
            .record_capture(&event, EventOrigin::Observed, &capture_dir, &capture)
            .await?;
        store
            .record_graph_records(&crate::capture::graph_records_from_captured_release(
                &capture,
            ))
            .await?;
        let diff_record = crate::diff::StoredReleaseDiff {
            event_id: event.event_id.clone(),
            ecosystem: event.ecosystem,
            package: event.package.clone(),
            version: event.version.clone(),
            generated_at: Utc::now(),
            baseline_event_id: None,
            baseline_version: Some("0.9.0".to_string()),
            status: StoredReleaseDiffStatus::Ready,
            reason: None,
            diff: None,
        };
        store
            .record_diff(&event, EventOrigin::Observed, &capture_dir, &diff_record)
            .await?;
        let diff = serde_json::json!({
            "event_id": event.event_id.clone(),
            "ecosystem": "pypi",
            "package": "demo",
            "version": "1.0.0",
            "generated_at": Utc::now(),
            "baseline_version": "0.9.0",
            "status": StoredReleaseDiffStatus::Ready,
            "diff": {
                "content": {
                    "available": true,
                    "patches_included": false,
                    "files_added_count": 1,
                    "files_removed_count": 0,
                    "files_changed_count": 0
                }
            }
        });

        let bundle =
            write_release_bundle(&data_dir, &store, &event, Some(&capture), Some(&diff)).await?;

        assert_eq!(bundle.kind, "release_evidence_bundle");
        assert_eq!(bundle.event.event.event_id, event.event_id);
        assert!(bundle.capture.is_some());
        assert!(bundle.diff.is_some());
        assert!(bundle.release_assessment.is_some());
        assert!(bundle.event.graph.known_in_local_graph);
        Ok(())
    }
}
