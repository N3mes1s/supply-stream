use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::OsStr,
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    process::Command as StdCommand,
    sync::LazyLock,
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use tempfile::TempDir;
use tokio::{fs as tokio_fs, io::AsyncWriteExt, process::Command, task};

use crate::{
    capture::{ArtifactHashes, CapturedArtifact, CapturedRelease, ReleaseStatus},
    event::Ecosystem,
    history::{self, HistoryEntry},
    install_scripts::npm_install_scripts,
};

pub const DEFAULT_PATCH_CONTEXT: usize = 3;

static DIFF_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .user_agent("supply-stream-diff/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build diff HTTP client")
});

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseDiff {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub baseline_event_id: String,
    pub target_event_id: String,
    pub baseline_version: String,
    pub target_version: String,
    pub generated_at: DateTime<Utc>,
    pub status: StatusDiff,
    pub artifacts: ArtifactDiff,
    pub details: DetailsDiff,
    pub content: ContentDiff,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusDiff {
    pub baseline: String,
    pub target: String,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactDiff {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<ArtifactSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<ArtifactSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<ArtifactChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactSummary {
    pub filename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yanked: Option<bool>,
    #[serde(default, skip_serializing_if = "ArtifactHashes::is_empty")]
    pub hashes: ArtifactHashes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactChange {
    pub filename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub baseline: ArtifactSummary,
    pub target: ArtifactSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetailsDiff {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub added: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub removed: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<MetadataValueChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentDiff {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_artifact: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_artifact: Option<ArtifactRef>,
    pub patches_included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch_context: Option<usize>,
    pub files_added_count: usize,
    pub files_removed_count: usize,
    pub files_changed_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_added: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_removed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_changed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_added_detail: Vec<FileRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_removed_detail: Vec<FileRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_changed_detail: Vec<FileRecordChange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_patches: Vec<FilePatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_install_hook: Option<NpmInstallHookDiff>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crate_repository_commit: Option<CrateRepositoryCommitDiff>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NpmInstallHookDiff {
    pub baseline_has_install_scripts: bool,
    pub target_has_install_scripts: bool,
    pub scripts_changed: bool,
    pub hook_files_changed: bool,
    pub effective_changed: bool,
    pub longstanding_unchanged: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub baseline_scripts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub target_scripts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub referenced_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub referenced_files_changed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrateRepositoryCommitDiff {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_commit: Option<String>,
    pub commit_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactRef {
    pub filename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yanked: Option<bool>,
    #[serde(default, skip_serializing_if = "ArtifactHashes::is_empty")]
    pub hashes: ArtifactHashes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Added,
    Removed,
    Changed,
}

impl FileChangeKind {
    fn label(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Changed => "changed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FilePatch {
    pub path: String,
    pub change: FileChangeKind,
    pub text: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetadataValueChange {
    pub key: String,
    pub baseline: serde_json::Value,
    pub target: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRecord {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub text: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRecordChange {
    pub path: String,
    pub baseline: FileRecord,
    pub target: FileRecord,
}

#[derive(Debug, Clone)]
struct DiffInput {
    entry: HistoryEntry,
    artifact_path: Option<PathBuf>,
    history_lookup_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReleaseDiffRequest<'a> {
    pub data_dir: &'a Path,
    pub ecosystem: Ecosystem,
    pub package: &'a str,
    pub target_version: Option<&'a str>,
    pub baseline_selector: Option<&'a str>,
    pub online: bool,
    pub target_artifact_path: Option<&'a Path>,
    pub baseline_artifact_path: Option<&'a Path>,
    pub include_patches: bool,
    pub patch_context: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredReleaseDiff {
    pub event_id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub generated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_version: Option<String>,
    pub status: StoredReleaseDiffStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<ReleaseDiff>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredReleaseDiffStatus {
    Ready,
    NoBaseline,
}

impl StoredReleaseDiffStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NoBaseline => "no_baseline",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredReleaseDiffRequest<'a> {
    pub data_dir: &'a Path,
    pub ecosystem: Ecosystem,
    pub package: &'a str,
    pub target_version: &'a str,
    pub include_patches: bool,
    pub patch_context: usize,
}

pub async fn load_release_diff(request: ReleaseDiffRequest<'_>) -> Result<ReleaseDiff> {
    let ReleaseDiffRequest {
        data_dir,
        ecosystem,
        package,
        target_version,
        baseline_selector,
        online,
        target_artifact_path,
        baseline_artifact_path,
        include_patches,
        patch_context,
    } = request;

    let entries = if target_artifact_path.is_none() || baseline_artifact_path.is_none() {
        let entries = if online {
            history::load_package_history_online(ecosystem, package).await?
        } else {
            history::load_package_history(data_dir, ecosystem, package).await?
        };
        Some(dedupe_history_entries(entries))
    } else {
        None
    };

    let target = resolve_target_input(
        ecosystem,
        package,
        target_version,
        target_artifact_path,
        entries.as_deref(),
    )
    .await?;
    let baseline = resolve_baseline_input(
        ecosystem,
        package,
        baseline_selector,
        baseline_artifact_path,
        entries.as_deref(),
        &target,
    )
    .await?;

    build_release_diff_from_inputs(&target, &baseline, include_patches, patch_context).await
}

pub async fn build_release_diff(
    target: &HistoryEntry,
    baseline: &HistoryEntry,
) -> Result<ReleaseDiff> {
    let target = DiffInput {
        entry: target.clone(),
        artifact_path: None,
        history_lookup_version: Some(target.event.version.clone()),
    };
    let baseline = DiffInput {
        entry: baseline.clone(),
        artifact_path: None,
        history_lookup_version: Some(baseline.event.version.clone()),
    };
    build_release_diff_from_inputs(&target, &baseline, false, 0).await
}

pub async fn build_stored_release_diff(
    request: StoredReleaseDiffRequest<'_>,
) -> Result<StoredReleaseDiff> {
    let StoredReleaseDiffRequest {
        data_dir,
        ecosystem,
        package,
        target_version,
        include_patches,
        patch_context,
    } = request;

    let entries =
        dedupe_history_entries(history::load_package_history(data_dir, ecosystem, package).await?);
    let target_idx = release_index(&entries, target_version)?;
    let target = history_input(entries[target_idx].clone());

    let Some(baseline_idx) = target_idx.checked_sub(1) else {
        return Ok(StoredReleaseDiff {
            event_id: target.entry.event.event_id.clone(),
            ecosystem: target.entry.event.ecosystem,
            package: target.entry.event.package.clone(),
            version: target.entry.event.version.clone(),
            generated_at: Utc::now(),
            baseline_event_id: None,
            baseline_version: None,
            status: StoredReleaseDiffStatus::NoBaseline,
            reason: Some("first observed release has no previous baseline".to_string()),
            diff: None,
        });
    };

    let baseline = history_input(entries[baseline_idx].clone());
    let release_diff =
        build_release_diff_from_inputs(&target, &baseline, include_patches, patch_context).await?;

    Ok(StoredReleaseDiff {
        event_id: target.entry.event.event_id.clone(),
        ecosystem: target.entry.event.ecosystem,
        package: target.entry.event.package.clone(),
        version: target.entry.event.version.clone(),
        generated_at: release_diff.generated_at,
        baseline_event_id: Some(release_diff.baseline_event_id.clone()),
        baseline_version: Some(release_diff.baseline_version.clone()),
        status: StoredReleaseDiffStatus::Ready,
        reason: None,
        diff: Some(release_diff),
    })
}

async fn build_release_diff_from_inputs(
    target: &DiffInput,
    baseline: &DiffInput,
    include_patches: bool,
    patch_context: usize,
) -> Result<ReleaseDiff> {
    let status = build_status_diff(
        target.entry.capture.as_ref(),
        baseline.entry.capture.as_ref(),
    );
    let artifacts = build_artifact_diff(
        target.entry.capture.as_ref(),
        baseline.entry.capture.as_ref(),
    );
    let details = build_details_diff(
        target.entry.capture.as_ref(),
        baseline.entry.capture.as_ref(),
    );
    let content = build_content_diff(
        target.entry.capture.as_ref(),
        baseline.entry.capture.as_ref(),
        target.artifact_path.as_deref(),
        baseline.artifact_path.as_deref(),
        include_patches,
        patch_context,
    )
    .await;
    let notes = build_notes(target, baseline, &content);

    Ok(ReleaseDiff {
        ecosystem: target.entry.event.ecosystem,
        package: target.entry.event.package.clone(),
        baseline_event_id: baseline.entry.event.event_id.clone(),
        target_event_id: target.entry.event.event_id.clone(),
        baseline_version: baseline.entry.event.version.clone(),
        target_version: target.entry.event.version.clone(),
        generated_at: Utc::now(),
        status,
        artifacts,
        details,
        content,
        notes,
    })
}

pub fn print_release_diff(diff: &ReleaseDiff) {
    print!("{}", render_release_diff_text(diff));
}

pub fn render_release_diff_text(diff: &ReleaseDiff) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Diff {}:{}", diff.ecosystem, diff.package);
    let _ = writeln!(output, "Baseline: {}", diff.baseline_version);
    let _ = writeln!(output, "Target: {}", diff.target_version);
    let _ = writeln!(output, "Generated: {}", diff.generated_at.to_rfc3339());
    let _ = writeln!(
        output,
        "Status: {} -> {}{}",
        diff.status.baseline,
        diff.status.target,
        if diff.status.changed {
            " (changed)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        output,
        "Artifacts: +{} -{} ~{}",
        diff.artifacts.added.len(),
        diff.artifacts.removed.len(),
        diff.artifacts.changed.len()
    );
    let _ = writeln!(
        output,
        "Metadata Keys: +{} -{} ~{}",
        diff.details.added_keys.len(),
        diff.details.removed_keys.len(),
        diff.details.changed_keys.len()
    );

    if diff.content.available {
        let _ = writeln!(
            output,
            "Content: kind={} +{} -{} ~{}",
            diff.content.artifact_kind.as_deref().unwrap_or("unknown"),
            diff.content.files_added_count,
            diff.content.files_removed_count,
            diff.content.files_changed_count
        );
        if diff.content.patches_included {
            match diff.content.patch_context {
                Some(context) => {
                    let _ = writeln!(
                        output,
                        "Patches: included for {} files (context={context})",
                        diff.content.file_patches.len()
                    );
                }
                None => {
                    let _ = writeln!(
                        output,
                        "Patches: included for {} files",
                        diff.content.file_patches.len()
                    );
                }
            }
        }
    } else if let Some(reason) = &diff.content.reason {
        let _ = writeln!(output, "Content: unavailable ({reason})");
    }

    write_text_list_section(&mut output, "Notes", &diff.notes);
    write_text_artifact_section(&mut output, "Artifacts Added", &diff.artifacts.added);
    write_text_artifact_section(&mut output, "Artifacts Removed", &diff.artifacts.removed);
    write_text_artifact_change_section(&mut output, "Artifacts Changed", &diff.artifacts.changed);
    write_text_list_section(&mut output, "Metadata Keys Added", &diff.details.added_keys);
    write_text_list_section(
        &mut output,
        "Metadata Keys Removed",
        &diff.details.removed_keys,
    );
    write_text_list_section(
        &mut output,
        "Metadata Keys Changed",
        &diff.details.changed_keys,
    );
    write_text_metadata_section(&mut output, "Metadata Added", &diff.details.added);
    write_text_metadata_section(&mut output, "Metadata Removed", &diff.details.removed);
    write_text_metadata_change_section(&mut output, "Metadata Changed", &diff.details.changed);

    if diff.content.available {
        write_text_compared_artifact_section(
            &mut output,
            "Compared Artifacts",
            diff.content.baseline_artifact.as_ref(),
            diff.content.target_artifact.as_ref(),
        );
        write_text_list_section(&mut output, "Files Added", &diff.content.files_added);
        write_text_list_section(&mut output, "Files Removed", &diff.content.files_removed);
        write_text_list_section(&mut output, "Files Changed", &diff.content.files_changed);
        write_text_file_record_section(
            &mut output,
            "Files Added Detail",
            &diff.content.files_added_detail,
        );
        write_text_file_record_section(
            &mut output,
            "Files Removed Detail",
            &diff.content.files_removed_detail,
        );
        write_text_file_record_change_section(
            &mut output,
            "Files Changed Detail",
            &diff.content.files_changed_detail,
        );
        write_text_patch_section(&mut output, "File Patches", &diff.content.file_patches);
    }

    output
}

pub fn render_release_diff_markdown(diff: &ReleaseDiff) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "# Release Diff: `{}:{}`\n",
        diff.ecosystem, diff.package
    );
    let _ = writeln!(output, "- Baseline: `{}`", diff.baseline_version);
    let _ = writeln!(output, "- Target: `{}`", diff.target_version);
    let _ = writeln!(output, "- Generated: `{}`", diff.generated_at.to_rfc3339());
    let _ = writeln!(
        output,
        "- Status: `{} -> {}`{}",
        diff.status.baseline,
        diff.status.target,
        if diff.status.changed {
            " (changed)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        output,
        "- Artifacts: `+{} -{} ~{}`",
        diff.artifacts.added.len(),
        diff.artifacts.removed.len(),
        diff.artifacts.changed.len()
    );
    let _ = writeln!(
        output,
        "- Metadata keys: `+{} -{} ~{}`",
        diff.details.added_keys.len(),
        diff.details.removed_keys.len(),
        diff.details.changed_keys.len()
    );
    if diff.content.available {
        let _ = writeln!(
            output,
            "- Content: `{}` `+{} -{} ~{}`\n",
            diff.content.artifact_kind.as_deref().unwrap_or("unknown"),
            diff.content.files_added_count,
            diff.content.files_removed_count,
            diff.content.files_changed_count
        );
        if diff.content.patches_included {
            match diff.content.patch_context {
                Some(context) => {
                    let _ = writeln!(
                        output,
                        "- Patches: included for `{}` files with `{}` lines of context\n",
                        diff.content.file_patches.len(),
                        context
                    );
                }
                None => {
                    let _ = writeln!(
                        output,
                        "- Patches: included for `{}` files\n",
                        diff.content.file_patches.len()
                    );
                }
            }
        }
    } else if let Some(reason) = &diff.content.reason {
        let _ = writeln!(output, "- Content: unavailable `{reason}`\n");
    }

    write_markdown_list_section(&mut output, "Notes", &diff.notes);
    write_markdown_artifact_section(&mut output, "Artifacts Added", &diff.artifacts.added);
    write_markdown_artifact_section(&mut output, "Artifacts Removed", &diff.artifacts.removed);
    write_markdown_artifact_change_section(
        &mut output,
        "Artifacts Changed",
        &diff.artifacts.changed,
    );
    write_markdown_list_section(&mut output, "Metadata Keys Added", &diff.details.added_keys);
    write_markdown_list_section(
        &mut output,
        "Metadata Keys Removed",
        &diff.details.removed_keys,
    );
    write_markdown_list_section(
        &mut output,
        "Metadata Keys Changed",
        &diff.details.changed_keys,
    );
    write_markdown_metadata_section(&mut output, "Metadata Added", &diff.details.added);
    write_markdown_metadata_section(&mut output, "Metadata Removed", &diff.details.removed);
    write_markdown_metadata_change_section(&mut output, "Metadata Changed", &diff.details.changed);

    if diff.content.available {
        write_markdown_compared_artifact_section(
            &mut output,
            "Compared Artifacts",
            diff.content.baseline_artifact.as_ref(),
            diff.content.target_artifact.as_ref(),
        );
        write_markdown_code_list_section(&mut output, "Files Added", &diff.content.files_added);
        write_markdown_code_list_section(&mut output, "Files Removed", &diff.content.files_removed);
        write_markdown_code_list_section(&mut output, "Files Changed", &diff.content.files_changed);
        write_markdown_file_record_section(
            &mut output,
            "Files Added Detail",
            &diff.content.files_added_detail,
        );
        write_markdown_file_record_section(
            &mut output,
            "Files Removed Detail",
            &diff.content.files_removed_detail,
        );
        write_markdown_file_record_change_section(
            &mut output,
            "Files Changed Detail",
            &diff.content.files_changed_detail,
        );
        write_markdown_patch_section(&mut output, "File Patches", &diff.content.file_patches);
    }

    output
}

pub fn render_stored_release_diff_markdown(stored: &StoredReleaseDiff) -> String {
    if let Some(diff) = &stored.diff {
        return render_release_diff_markdown(diff);
    }

    let mut output = String::new();
    let _ = writeln!(
        output,
        "# Release Diff: `{}:{}`\n",
        stored.ecosystem, stored.package
    );
    let _ = writeln!(output, "- Target: `{}`", stored.version);
    let _ = writeln!(
        output,
        "- Generated: `{}`",
        stored.generated_at.to_rfc3339()
    );
    let _ = writeln!(output, "- Status: `{}`", stored.status.as_str());
    if let Some(reason) = &stored.reason {
        let _ = writeln!(output, "- Reason: `{reason}`");
    }
    output.push('\n');
    output
}

#[cfg(test)]
fn resolve_release_pair(
    entries: Vec<HistoryEntry>,
    target_version: &str,
    baseline_selector: &str,
) -> Result<(HistoryEntry, HistoryEntry)> {
    let entries = dedupe_history_entries(entries);
    let target_idx = release_index(&entries, target_version)?;
    let baseline_idx = baseline_index(&entries, target_idx, target_version, baseline_selector)?;
    Ok((entries[baseline_idx].clone(), entries[target_idx].clone()))
}

async fn resolve_target_input(
    ecosystem: Ecosystem,
    package: &str,
    target_version: Option<&str>,
    target_artifact_path: Option<&Path>,
    entries: Option<&[HistoryEntry]>,
) -> Result<DiffInput> {
    if let Some(path) = target_artifact_path {
        return synthesize_local_input(ecosystem, package, target_version, path).await;
    }

    let target_version =
        target_version.context("target version is required unless --artifact is provided")?;
    let entries = entries.context("history is required to resolve the target release")?;
    let target_idx = release_index(entries, target_version)?;
    Ok(history_input(entries[target_idx].clone()))
}

async fn resolve_baseline_input(
    ecosystem: Ecosystem,
    package: &str,
    baseline_selector: Option<&str>,
    baseline_artifact_path: Option<&Path>,
    entries: Option<&[HistoryEntry]>,
    target: &DiffInput,
) -> Result<DiffInput> {
    if let Some(path) = baseline_artifact_path {
        let explicit_version = baseline_selector.filter(|selector| *selector != "previous");
        return synthesize_local_input(ecosystem, package, explicit_version, path).await;
    }

    let entries = entries.context("history is required to resolve the baseline release")?;
    let selector = baseline_selector.unwrap_or("previous");
    let baseline_idx = if selector == "previous" {
        let lookup_version = target.history_lookup_version.as_deref().with_context(
            || "target version is required to resolve --baseline previous when using --artifact",
        )?;
        let target_idx = release_index(entries, lookup_version)?;
        baseline_index(entries, target_idx, lookup_version, selector)?
    } else {
        let baseline_idx = release_index(entries, selector)?;
        if target
            .history_lookup_version
            .as_deref()
            .is_some_and(|value| value == selector)
        {
            anyhow::bail!("baseline version matches target version: {selector}");
        }
        baseline_idx
    };

    Ok(history_input(entries[baseline_idx].clone()))
}

fn history_input(entry: HistoryEntry) -> DiffInput {
    DiffInput {
        history_lookup_version: Some(entry.event.version.clone()),
        entry,
        artifact_path: None,
    }
}

async fn synthesize_local_input(
    ecosystem: Ecosystem,
    package: &str,
    explicit_version: Option<&str>,
    artifact_path: &Path,
) -> Result<DiffInput> {
    if !artifact_path.exists() {
        anyhow::bail!("local artifact does not exist: {}", artifact_path.display());
    }
    if artifact_path.is_dir() {
        anyhow::bail!(
            "local artifact path must be a file, not a directory: {}",
            artifact_path.display()
        );
    }

    let filename = artifact_path
        .file_name()
        .and_then(OsStr::to_str)
        .with_context(|| {
            format!(
                "failed to determine artifact filename for {}",
                artifact_path.display()
            )
        })?
        .to_string();
    let history_lookup_version = explicit_version
        .map(str::to_string)
        .or_else(|| infer_version_from_filename(ecosystem, package, &filename));
    let display_version = history_lookup_version
        .clone()
        .unwrap_or_else(|| local_version_label(&filename));
    let kind = infer_local_artifact_kind(&filename).map(str::to_string);
    let digests = hash_file_digests(artifact_path)?;
    let sha256 = digests.sha256.clone();
    let size_bytes = digests.size_bytes;
    let observed_at = Utc::now();
    let path_text = artifact_path.display().to_string();

    let artifact = CapturedArtifact {
        filename,
        kind,
        url: None,
        size_bytes: Some(size_bytes),
        uploaded_at: None,
        yanked: None,
        hashes: ArtifactHashes {
            sha256: Some(sha256.clone()),
            sha512: Some(digests.sha512.clone()),
            ..ArtifactHashes::default()
        },
        provenance_path: None,
    };

    let entry = HistoryEntry {
        event: crate::event::PackageReleaseEvent {
            event_id: format!("local:{}:{}@{}", ecosystem, package, display_version),
            ecosystem,
            package: package.to_string(),
            version: display_version.clone(),
            published_at: None,
            observed_at,
            source: "local.artifact".to_string(),
            sequence: None,
            package_url: None,
            release_url: None,
            metadata_url: None,
            priority: None,
        },
        capture: Some(CapturedRelease {
            event_id: format!("local:{}:{}@{}", ecosystem, package, display_version),
            ecosystem,
            package: package.to_string(),
            version: display_version,
            observed_at,
            published_at: None,
            captured_at: observed_at,
            status: ReleaseStatus::Unknown,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts: vec![artifact],
            upstream_repository: None,
            details: json!({
                "local_artifact": {
                    "path": path_text,
                    "sha256": sha256,
                    "sha512": digests.sha512,
                    "size_bytes": size_bytes
                }
            }),
        }),
        capture_dir: None,
    };

    Ok(DiffInput {
        entry,
        artifact_path: Some(artifact_path.to_path_buf()),
        history_lookup_version,
    })
}

fn release_index(entries: &[HistoryEntry], version: &str) -> Result<usize> {
    entries
        .iter()
        .position(|entry| entry.event.version == version)
        .with_context(|| format!("version not found: {version}"))
}

fn baseline_index(
    entries: &[HistoryEntry],
    target_idx: usize,
    target_version: &str,
    baseline_selector: &str,
) -> Result<usize> {
    if baseline_selector == "previous" {
        target_idx
            .checked_sub(1)
            .with_context(|| format!("no previous release exists before {target_version}"))
    } else {
        let baseline_idx = release_index(entries, baseline_selector)?;
        if baseline_idx == target_idx {
            anyhow::bail!("baseline version matches target version: {target_version}");
        }
        Ok(baseline_idx)
    }
}

fn dedupe_history_entries(entries: Vec<HistoryEntry>) -> Vec<HistoryEntry> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for entry in entries.into_iter().rev() {
        if seen.insert(entry.event.version.clone()) {
            deduped.push(entry);
        }
    }

    deduped.reverse();
    deduped
}

fn infer_version_from_filename(
    ecosystem: Ecosystem,
    package: &str,
    filename: &str,
) -> Option<String> {
    match ecosystem {
        Ecosystem::Pypi => infer_pypi_version(package, filename),
        Ecosystem::Npm | Ecosystem::CratesIo => infer_dash_version(package, filename),
    }
}

fn infer_pypi_version(package: &str, filename: &str) -> Option<String> {
    let candidates = pypi_distribution_candidates(package);
    let canonical = canonical_archive_name(filename).unwrap_or(filename);

    if let Some(stem) = canonical.strip_suffix(".whl") {
        for candidate in &candidates {
            let prefix = format!("{candidate}-");
            if let Some(rest) = stem.strip_prefix(&prefix) {
                return rest.split('-').next().map(str::to_string);
            }
        }
    }

    infer_dash_version_with_candidates(canonical, &candidates)
}

fn infer_dash_version(package: &str, filename: &str) -> Option<String> {
    let package_variants = [package.to_string(), package.replace('/', "-")];
    infer_dash_version_with_candidates(filename, &package_variants)
}

fn infer_dash_version_with_candidates(filename: &str, candidates: &[String]) -> Option<String> {
    let stem = strip_archive_extension(filename)?;
    candidates.iter().find_map(|candidate| {
        let prefix = format!("{candidate}-");
        stem.strip_prefix(&prefix).map(str::to_string)
    })
}

fn strip_archive_extension(filename: &str) -> Option<&str> {
    let canonical = canonical_archive_name(filename).unwrap_or(filename);
    [".tar.gz", ".whl", ".crate", ".tgz", ".zip"]
        .into_iter()
        .find_map(|suffix| canonical.strip_suffix(suffix))
}

fn canonical_archive_name(filename: &str) -> Option<&str> {
    let suffixes = [".tar.gz", ".whl", ".crate", ".tgz", ".zip"];

    for suffix in suffixes {
        if filename.ends_with(suffix) {
            return Some(filename);
        }
    }

    let mut candidate = filename;
    while let Some((prefix, _)) = candidate.rsplit_once('.') {
        candidate = prefix;
        for suffix in suffixes {
            if candidate.ends_with(suffix) {
                return Some(candidate);
            }
        }
    }

    None
}

fn pypi_distribution_candidates(package: &str) -> Vec<String> {
    let normalized_dash = normalize_pypi_name(package, '-');
    let normalized_underscore = normalize_pypi_name(package, '_');
    let mut candidates = Vec::new();
    for candidate in [
        package.to_string(),
        package.replace('-', "_"),
        package.replace('.', "_"),
        normalized_dash,
        normalized_underscore,
    ] {
        if !candidates.iter().any(|existing| existing == &candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn normalize_pypi_name(package: &str, separator: char) -> String {
    let mut normalized = String::new();
    let mut previous_was_separator = false;
    for ch in package.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !previous_was_separator {
                normalized.push(separator);
                previous_was_separator = true;
            }
        } else {
            normalized.push(ch);
            previous_was_separator = false;
        }
    }
    normalized
}

fn local_version_label(filename: &str) -> String {
    strip_archive_extension(filename)
        .unwrap_or(filename)
        .to_string()
}

fn infer_local_artifact_kind(filename: &str) -> Option<&'static str> {
    match classify_filename(filename) {
        Some(ArtifactKind::NpmTarball) => Some("npm-tarball"),
        Some(ArtifactKind::CrateTarball) => Some("crate"),
        Some(ArtifactKind::TarGz) => Some("sdist"),
        Some(ArtifactKind::Wheel) => Some("bdist_wheel"),
        Some(ArtifactKind::Zip) => Some("zip"),
        None => None,
    }
}

struct FileDigests {
    size_bytes: u64,
    sha256: String,
    sha512: String,
}

fn hash_file_digests(path: &Path) -> Result<FileDigests> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut buffer = [0u8; 8192];
    let mut size_bytes = 0u64;

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        size_bytes += read as u64;
        sha256.update(&buffer[..read]);
        sha512.update(&buffer[..read]);
    }

    Ok(FileDigests {
        size_bytes,
        sha256: format!("{:x}", sha256.finalize()),
        sha512: format!("{:x}", sha512.finalize()),
    })
}

fn build_file_record(path: &str, bytes: &[u8]) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size_bytes: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        text: is_probably_text(bytes),
    }
}

fn build_status_diff(
    target: Option<&CapturedRelease>,
    baseline: Option<&CapturedRelease>,
) -> StatusDiff {
    let baseline_status = capture_status_label(baseline);
    let target_status = capture_status_label(target);
    StatusDiff {
        baseline: baseline_status.to_string(),
        target: target_status.to_string(),
        changed: baseline_status != target_status,
    }
}

fn build_artifact_diff(
    target: Option<&CapturedRelease>,
    baseline: Option<&CapturedRelease>,
) -> ArtifactDiff {
    let target_artifacts = artifact_map(target);
    let baseline_artifacts = artifact_map(baseline);
    let keys = target_artifacts
        .keys()
        .chain(baseline_artifacts.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for key in keys {
        match (baseline_artifacts.get(&key), target_artifacts.get(&key)) {
            (None, Some(target_artifact)) => added.push(artifact_summary(*target_artifact)),
            (Some(baseline_artifact), None) => removed.push(artifact_summary(*baseline_artifact)),
            (Some(baseline_artifact), Some(target_artifact))
                if artifact_changed(*baseline_artifact, *target_artifact) =>
            {
                changed.push(ArtifactChange {
                    filename: key,
                    kind: target_artifact
                        .artifact
                        .kind
                        .clone()
                        .or_else(|| baseline_artifact.artifact.kind.clone()),
                    baseline: artifact_summary(*baseline_artifact),
                    target: artifact_summary(*target_artifact),
                });
            }
            _ => {}
        }
    }

    ArtifactDiff {
        added,
        removed,
        changed,
    }
}

fn build_details_diff(
    target: Option<&CapturedRelease>,
    baseline: Option<&CapturedRelease>,
) -> DetailsDiff {
    let target_details = target.map(|capture| &capture.details);
    let baseline_details = baseline.map(|capture| &capture.details);
    let target_keys = top_level_keys(target_details);
    let baseline_keys = top_level_keys(baseline_details);
    let all_keys = target_keys
        .union(&baseline_keys)
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut added_keys = Vec::new();
    let mut removed_keys = Vec::new();
    let mut changed_keys = Vec::new();
    let mut added = BTreeMap::new();
    let mut removed = BTreeMap::new();
    let mut changed = Vec::new();

    for key in all_keys {
        let baseline_value = baseline_details.and_then(|value| value.get(&key));
        let target_value = target_details.and_then(|value| value.get(&key));
        match (baseline_value, target_value) {
            (None, Some(right)) => {
                added_keys.push(key.clone());
                if !right.is_null() {
                    added.insert(key, right.clone());
                }
            }
            (Some(left), None) => {
                removed_keys.push(key.clone());
                if !left.is_null() {
                    removed.insert(key, left.clone());
                }
            }
            (Some(left), Some(right)) if left != right => {
                changed_keys.push(key.clone());
                if !left.is_null() || !right.is_null() {
                    changed.push(MetadataValueChange {
                        key,
                        baseline: left.clone(),
                        target: right.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    DetailsDiff {
        added_keys,
        removed_keys,
        changed_keys,
        added,
        removed,
        changed,
    }
}

async fn build_content_diff(
    target: Option<&CapturedRelease>,
    baseline: Option<&CapturedRelease>,
    target_artifact_path: Option<&Path>,
    baseline_artifact_path: Option<&Path>,
    include_patches: bool,
    patch_context: usize,
) -> ContentDiff {
    let Some(target) = target else {
        return unavailable_content_diff("target capture is unavailable");
    };
    let Some(baseline) = baseline else {
        return unavailable_content_diff("baseline capture is unavailable");
    };

    let Some((baseline_artifact, target_artifact, artifact_kind)) =
        select_artifact_pair(baseline, target)
    else {
        return unavailable_content_diff("no comparable artifact pair was found");
    };

    let Some(baseline_source) = artifact_source(baseline_artifact, baseline_artifact_path) else {
        return unavailable_content_diff("baseline artifact source is unavailable");
    };
    let Some(target_source) = artifact_source(target_artifact, target_artifact_path) else {
        return unavailable_content_diff("target artifact source is unavailable");
    };

    let workspace = match TempDir::new() {
        Ok(dir) => dir,
        Err(error) => {
            return unavailable_content_diff(&format!("failed to create temp dir: {error}"));
        }
    };

    let baseline_archive = workspace.path().join("baseline.artifact");
    let target_archive = workspace.path().join("target.artifact");
    let baseline_dir = workspace.path().join("baseline");
    let target_dir = workspace.path().join("target");
    let content = async {
        if let Err(error) = tokio_fs::create_dir_all(&baseline_dir).await {
            return unavailable_content_diff(&format!(
                "failed to create baseline extract dir: {error}"
            ));
        }
        if let Err(error) = tokio_fs::create_dir_all(&target_dir).await {
            return unavailable_content_diff(&format!(
                "failed to create target extract dir: {error}"
            ));
        }

        if let Err(error) =
            materialize_artifact(&DIFF_HTTP_CLIENT, baseline_source, &baseline_archive).await
        {
            return unavailable_content_diff(&format!(
                "failed to fetch baseline artifact: {error}"
            ));
        }
        if let Err(error) =
            materialize_artifact(&DIFF_HTTP_CLIENT, target_source, &target_archive).await
        {
            return unavailable_content_diff(&format!("failed to fetch target artifact: {error}"));
        }

        if let Err(error) = extract_artifact(&baseline_archive, &baseline_dir, artifact_kind).await
        {
            return unavailable_content_diff(&format!(
                "failed to extract baseline artifact: {error}"
            ));
        }
        if let Err(error) = extract_artifact(&target_archive, &target_dir, artifact_kind).await {
            return unavailable_content_diff(&format!(
                "failed to extract target artifact: {error}"
            ));
        }

        let baseline_ref = match artifact_ref(
            baseline_artifact,
            baseline_artifact_path,
            Some(&baseline_archive),
        ) {
            Ok(value) => value,
            Err(error) => {
                return unavailable_content_diff(&format!(
                    "failed to inspect baseline artifact: {error}"
                ));
            }
        };
        let target_ref =
            match artifact_ref(target_artifact, target_artifact_path, Some(&target_archive)) {
                Ok(value) => value,
                Err(error) => {
                    return unavailable_content_diff(&format!(
                        "failed to inspect target artifact: {error}"
                    ));
                }
            };

        match compare_extracted_dirs(&baseline_dir, &target_dir, include_patches, patch_context) {
            Ok(compared) => ContentDiff {
                available: true,
                reason: None,
                artifact_kind: Some(artifact_kind.label().to_string()),
                baseline_artifact: Some(baseline_ref),
                target_artifact: Some(target_ref),
                patches_included: include_patches,
                patch_context: include_patches.then_some(patch_context),
                files_added_count: compared.added.len(),
                files_removed_count: compared.removed.len(),
                files_changed_count: compared.changed.len(),
                files_added: compared.added,
                files_removed: compared.removed,
                files_changed: compared.changed,
                files_added_detail: compared.added_detail,
                files_removed_detail: compared.removed_detail,
                files_changed_detail: compared.changed_detail,
                file_patches: compared.file_patches,
                npm_install_hook: compared.npm_install_hook,
                crate_repository_commit: compared.crate_repository_commit,
            },
            Err(error) => {
                unavailable_content_diff(&format!("failed to compare extracted content: {error}"))
            }
        }
    }
    .await;

    schedule_tempdir_cleanup(workspace);
    content
}

fn schedule_tempdir_cleanup(workspace: TempDir) {
    let path = workspace.keep();

    task::spawn_blocking(move || {
        let _ = std::fs::remove_dir_all(path);
    });
}

#[derive(Debug, Clone, Copy)]
enum ArtifactSource<'a> {
    Url(&'a str),
    LocalPath(&'a Path),
}

fn artifact_source<'a>(
    artifact: &'a CapturedArtifact,
    local_path: Option<&'a Path>,
) -> Option<ArtifactSource<'a>> {
    if let Some(path) = local_path {
        return Some(ArtifactSource::LocalPath(path));
    }

    artifact.url.as_deref().map(ArtifactSource::Url)
}

fn build_notes(target: &DiffInput, baseline: &DiffInput, content: &ContentDiff) -> Vec<String> {
    let mut notes = Vec::new();
    if target.entry.capture.is_none() {
        notes.push("target release has no capture data".to_string());
    }
    if baseline.entry.capture.is_none() {
        notes.push("baseline release has no capture data".to_string());
    }
    if let Some(path) = &target.artifact_path {
        notes.push(format!("target artifact source: {}", path.display()));
    }
    if let Some(path) = &baseline.artifact_path {
        notes.push(format!("baseline artifact source: {}", path.display()));
    }
    if !content.available
        && let Some(reason) = &content.reason
    {
        notes.push(format!("content diff unavailable: {reason}"));
    }
    notes
}

fn write_text_list_section(output: &mut String, title: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    for value in values {
        let _ = writeln!(output, "  - {value}");
    }
}

fn write_text_artifact_section(output: &mut String, title: &str, artifacts: &[ArtifactSummary]) {
    if artifacts.is_empty() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    for artifact in artifacts {
        let _ = writeln!(output, "  - {}", format_artifact_summary(artifact));
    }
}

fn write_text_artifact_change_section(
    output: &mut String,
    title: &str,
    changes: &[ArtifactChange],
) {
    if changes.is_empty() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    for change in changes {
        let _ = writeln!(output, "  - {}", change.filename);
        let _ = writeln!(
            output,
            "    baseline: {}",
            format_artifact_summary(&change.baseline)
        );
        let _ = writeln!(
            output,
            "    target: {}",
            format_artifact_summary(&change.target)
        );
    }
}

fn write_text_metadata_section(
    output: &mut String,
    title: &str,
    values: &BTreeMap<String, serde_json::Value>,
) {
    if values.is_empty() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    for (key, value) in values {
        let _ = writeln!(output, "  - {key}: {}", format_json_value_inline(value));
    }
}

fn write_text_metadata_change_section(
    output: &mut String,
    title: &str,
    changes: &[MetadataValueChange],
) {
    if changes.is_empty() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    for change in changes {
        let _ = writeln!(output, "  - {}", change.key);
        let _ = writeln!(
            output,
            "    baseline: {}",
            format_json_value_inline(&change.baseline)
        );
        let _ = writeln!(
            output,
            "    target: {}",
            format_json_value_inline(&change.target)
        );
    }
}

fn write_text_compared_artifact_section(
    output: &mut String,
    title: &str,
    baseline: Option<&ArtifactRef>,
    target: Option<&ArtifactRef>,
) {
    if baseline.is_none() && target.is_none() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    if let Some(baseline) = baseline {
        let _ = writeln!(
            output,
            "  - baseline: {}",
            format_artifact_ref_summary(baseline)
        );
    }
    if let Some(target) = target {
        let _ = writeln!(
            output,
            "  - target: {}",
            format_artifact_ref_summary(target)
        );
    }
}

fn write_text_file_record_section(output: &mut String, title: &str, files: &[FileRecord]) {
    if files.is_empty() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    for file in files {
        let _ = writeln!(output, "  - {}", format_file_record(file));
    }
}

fn write_text_file_record_change_section(
    output: &mut String,
    title: &str,
    changes: &[FileRecordChange],
) {
    if changes.is_empty() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    for change in changes {
        let _ = writeln!(output, "  - {}", change.path);
        let _ = writeln!(
            output,
            "    baseline: {}",
            format_file_record(&change.baseline)
        );
        let _ = writeln!(output, "    target: {}", format_file_record(&change.target));
    }
}

fn write_text_patch_section(output: &mut String, title: &str, patches: &[FilePatch]) {
    if patches.is_empty() {
        return;
    }

    let _ = writeln!(output, "\n{title}:");
    for patch in patches {
        let _ = writeln!(output, "\n  [{}] {}", patch.change.label(), patch.path);
        if let Some(reason) = &patch.reason {
            let _ = writeln!(output, "    reason: {reason}");
        }
        if let Some(body) = &patch.patch {
            for line in body.lines() {
                let _ = writeln!(output, "    {line}");
            }
        }
    }
}

fn write_markdown_list_section(output: &mut String, title: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title}\n");
    for value in values {
        let _ = writeln!(output, "- {value}");
    }
    let _ = writeln!(output);
}

fn write_markdown_metadata_section(
    output: &mut String,
    title: &str,
    values: &BTreeMap<String, serde_json::Value>,
) {
    if values.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title}\n");
    for (key, value) in values {
        let _ = writeln!(output, "### `{key}`\n");
        write_markdown_json_block(output, value);
    }
    let _ = writeln!(output);
}

fn write_markdown_metadata_change_section(
    output: &mut String,
    title: &str,
    changes: &[MetadataValueChange],
) {
    if changes.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title}\n");
    for change in changes {
        let _ = writeln!(output, "### `{}`\n", change.key);
        let _ = writeln!(output, "Baseline:\n");
        write_markdown_json_block(output, &change.baseline);
        let _ = writeln!(output, "Target:\n");
        write_markdown_json_block(output, &change.target);
    }
    let _ = writeln!(output);
}

fn write_markdown_code_list_section(output: &mut String, title: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title} ({})\n", values.len());
    let _ = writeln!(output, "```text");
    for value in values {
        let _ = writeln!(output, "{value}");
    }
    let _ = writeln!(output, "```\n");
}

fn write_markdown_compared_artifact_section(
    output: &mut String,
    title: &str,
    baseline: Option<&ArtifactRef>,
    target: Option<&ArtifactRef>,
) {
    if baseline.is_none() && target.is_none() {
        return;
    }

    let _ = writeln!(output, "## {title}\n");
    if let Some(baseline) = baseline {
        let _ = writeln!(output, "### Baseline\n");
        write_markdown_artifact_ref_details(output, baseline);
    }
    if let Some(target) = target {
        let _ = writeln!(output, "### Target\n");
        write_markdown_artifact_ref_details(output, target);
    }
    let _ = writeln!(output);
}

fn write_markdown_artifact_section(
    output: &mut String,
    title: &str,
    artifacts: &[ArtifactSummary],
) {
    if artifacts.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title} ({})\n", artifacts.len());
    for artifact in artifacts {
        let _ = writeln!(output, "### `{}`\n", artifact.filename);
        write_markdown_artifact_summary_details(output, artifact);
    }
    let _ = writeln!(output);
}

fn write_markdown_artifact_change_section(
    output: &mut String,
    title: &str,
    changes: &[ArtifactChange],
) {
    if changes.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title} ({})\n", changes.len());
    for change in changes {
        let _ = writeln!(output, "### `{}`\n", change.filename);
        let _ = writeln!(output, "Baseline:\n");
        write_markdown_artifact_summary_details(output, &change.baseline);
        let _ = writeln!(output, "Target:\n");
        write_markdown_artifact_summary_details(output, &change.target);
    }
    let _ = writeln!(output);
}

fn write_markdown_file_record_section(output: &mut String, title: &str, files: &[FileRecord]) {
    if files.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title} ({})\n", files.len());
    let _ = writeln!(output, "| Path | Size | SHA256 | Text |");
    let _ = writeln!(output, "| --- | ---: | --- | --- |");
    for file in files {
        let _ = writeln!(
            output,
            "| `{}` | `{}` | `{}` | `{}` |",
            escape_markdown_table_cell(&file.path),
            file.size_bytes,
            escape_markdown_table_cell(&file.sha256),
            file.text
        );
    }
    let _ = writeln!(output);
}

fn write_markdown_file_record_change_section(
    output: &mut String,
    title: &str,
    changes: &[FileRecordChange],
) {
    if changes.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title} ({})\n", changes.len());
    for change in changes {
        let _ = writeln!(output, "### `{}`\n", change.path);
        let _ = writeln!(output, "| Version | Path | Size | SHA256 | Text |");
        let _ = writeln!(output, "| --- | --- | ---: | --- | --- |");
        let _ = writeln!(
            output,
            "| Baseline | `{}` | `{}` | `{}` | `{}` |",
            escape_markdown_table_cell(&change.baseline.path),
            change.baseline.size_bytes,
            escape_markdown_table_cell(&change.baseline.sha256),
            change.baseline.text
        );
        let _ = writeln!(
            output,
            "| Target | `{}` | `{}` | `{}` | `{}` |\n",
            escape_markdown_table_cell(&change.target.path),
            change.target.size_bytes,
            escape_markdown_table_cell(&change.target.sha256),
            change.target.text
        );
    }
}

fn write_markdown_patch_section(output: &mut String, title: &str, patches: &[FilePatch]) {
    if patches.is_empty() {
        return;
    }

    let _ = writeln!(output, "## {title}\n");
    for patch in patches {
        let _ = writeln!(output, "### `{}` ({})\n", patch.path, patch.change.label());
        if let Some(reason) = &patch.reason {
            let _ = writeln!(output, "- Reason: {reason}\n");
        }
        if let Some(body) = &patch.patch {
            let _ = writeln!(output, "```diff");
            let _ = write!(output, "{body}");
            if !body.ends_with('\n') {
                let _ = writeln!(output);
            }
            let _ = writeln!(output, "```\n");
        }
    }
}

fn format_json_value_inline(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unprintable-json>".to_string())
}

fn format_json_value_pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| format_json_value_inline(value))
}

fn format_hashes_inline(hashes: &ArtifactHashes) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(value) = &hashes.sha256 {
        parts.push(format!("sha256={value}"));
    }
    if let Some(value) = &hashes.sha512 {
        parts.push(format!("sha512={value}"));
    }
    if let Some(value) = &hashes.blake2b_256 {
        parts.push(format!("blake2b_256={value}"));
    }
    if let Some(value) = &hashes.md5 {
        parts.push(format!("md5={value}"));
    }
    if let Some(value) = &hashes.integrity {
        parts.push(format!("integrity={value}"));
    }
    if let Some(value) = &hashes.shasum {
        parts.push(format!("shasum={value}"));
    }
    if let Some(value) = &hashes.checksum {
        parts.push(format!("checksum={value}"));
    }

    (!parts.is_empty()).then(|| parts.join(" | "))
}

fn format_hashes_block(hashes: &ArtifactHashes) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(value) = &hashes.sha256 {
        parts.push(format!("sha256={value}"));
    }
    if let Some(value) = &hashes.sha512 {
        parts.push(format!("sha512={value}"));
    }
    if let Some(value) = &hashes.blake2b_256 {
        parts.push(format!("blake2b_256={value}"));
    }
    if let Some(value) = &hashes.md5 {
        parts.push(format!("md5={value}"));
    }
    if let Some(value) = &hashes.integrity {
        parts.push(format!("integrity={value}"));
    }
    if let Some(value) = &hashes.shasum {
        parts.push(format!("shasum={value}"));
    }
    if let Some(value) = &hashes.checksum {
        parts.push(format!("checksum={value}"));
    }

    (!parts.is_empty()).then(|| parts.join("\n"))
}

fn format_artifact_ref_summary(artifact: &ArtifactRef) -> String {
    let mut parts = vec![artifact.filename.clone()];

    if let Some(kind) = &artifact.kind {
        parts.push(format!("kind={kind}"));
    }
    if let Some(size_bytes) = artifact.size_bytes {
        parts.push(format!("size={size_bytes}"));
    }
    if let Some(uploaded_at) = artifact.uploaded_at {
        parts.push(format!("uploaded_at={}", uploaded_at.to_rfc3339()));
    }
    if let Some(path) = &artifact.path {
        parts.push(format!("path={path}"));
    } else if let Some(url) = &artifact.url {
        parts.push(format!("url={url}"));
    }
    if let Some(hashes) = format_hashes_inline(&artifact.hashes) {
        parts.push(hashes);
    }
    if let Some(value) = artifact.yanked {
        parts.push(format!("yanked={value}"));
    }
    if let Some(path) = &artifact.provenance_path {
        parts.push(format!("provenance={path}"));
    }

    parts.join(" | ")
}

fn format_artifact_summary(artifact: &ArtifactSummary) -> String {
    let mut parts = vec![artifact.filename.clone()];

    if let Some(kind) = &artifact.kind {
        parts.push(format!("kind={kind}"));
    }
    if let Some(size_bytes) = artifact.size_bytes {
        parts.push(format!("size={size_bytes}"));
    }
    if let Some(uploaded_at) = artifact.uploaded_at {
        parts.push(format!("uploaded_at={}", uploaded_at.to_rfc3339()));
    }
    if let Some(path) = &artifact.path {
        parts.push(format!("path={path}"));
    } else if let Some(url) = &artifact.url {
        parts.push(format!("url={url}"));
    }
    if let Some(hashes) = format_hashes_inline(&artifact.hashes) {
        parts.push(hashes);
    }
    if let Some(value) = artifact.yanked {
        parts.push(format!("yanked={value}"));
    }
    if let Some(path) = &artifact.provenance_path {
        parts.push(format!("provenance={path}"));
    }

    parts.join(" | ")
}

fn format_file_record(file: &FileRecord) -> String {
    format!(
        "{} | size={} | sha256={} | text={}",
        file.path, file.size_bytes, file.sha256, file.text
    )
}

fn write_markdown_json_block(output: &mut String, value: &serde_json::Value) {
    let _ = writeln!(output, "```json");
    let _ = writeln!(output, "{}", format_json_value_pretty(value));
    let _ = writeln!(output, "```\n");
}

fn write_markdown_artifact_ref_details(output: &mut String, artifact: &ArtifactRef) {
    let view = MarkdownArtifactView {
        filename: &artifact.filename,
        kind: artifact.kind.as_deref(),
        url: artifact.url.as_deref(),
        path: artifact.path.as_deref(),
        size_bytes: artifact.size_bytes,
        uploaded_at: artifact.uploaded_at,
        yanked: artifact.yanked,
        hashes: &artifact.hashes,
        provenance_path: artifact.provenance_path.as_deref(),
    };
    write_markdown_artifact_common(output, view);
}

fn write_markdown_artifact_summary_details(output: &mut String, artifact: &ArtifactSummary) {
    let view = MarkdownArtifactView {
        filename: &artifact.filename,
        kind: artifact.kind.as_deref(),
        url: artifact.url.as_deref(),
        path: artifact.path.as_deref(),
        size_bytes: artifact.size_bytes,
        uploaded_at: artifact.uploaded_at,
        yanked: artifact.yanked,
        hashes: &artifact.hashes,
        provenance_path: artifact.provenance_path.as_deref(),
    };
    write_markdown_artifact_common(output, view);
}

struct MarkdownArtifactView<'a> {
    filename: &'a str,
    kind: Option<&'a str>,
    url: Option<&'a str>,
    path: Option<&'a str>,
    size_bytes: Option<u64>,
    uploaded_at: Option<DateTime<Utc>>,
    yanked: Option<bool>,
    hashes: &'a ArtifactHashes,
    provenance_path: Option<&'a str>,
}

fn write_markdown_artifact_common(output: &mut String, artifact: MarkdownArtifactView<'_>) {
    let _ = writeln!(output, "- filename: `{}`", artifact.filename);
    if let Some(kind) = artifact.kind {
        let _ = writeln!(output, "- kind: `{kind}`");
    }
    if let Some(size_bytes) = artifact.size_bytes {
        let _ = writeln!(output, "- size_bytes: `{size_bytes}`");
    }
    if let Some(uploaded_at) = artifact.uploaded_at {
        let _ = writeln!(output, "- uploaded_at: `{}`", uploaded_at.to_rfc3339());
    }
    if let Some(path) = artifact.path {
        let _ = writeln!(output, "- path: `{path}`");
    }
    if let Some(url) = artifact.url {
        let _ = writeln!(output, "- url: <{url}>");
    }
    if let Some(yanked) = artifact.yanked {
        let _ = writeln!(output, "- yanked: `{yanked}`");
    }
    if let Some(provenance_path) = artifact.provenance_path {
        let _ = writeln!(output, "- provenance_path: `{provenance_path}`");
    }
    if let Some(hash_block) = format_hashes_block(artifact.hashes) {
        let _ = writeln!(output, "Hashes:\n");
        let _ = writeln!(output, "```text");
        let _ = write!(output, "{hash_block}");
        if !hash_block.ends_with('\n') {
            let _ = writeln!(output);
        }
        let _ = writeln!(output, "```\n");
    } else {
        let _ = writeln!(output);
    }
}

fn escape_markdown_table_cell(value: &str) -> String {
    value.replace('|', "\\|")
}

fn artifact_map(capture: Option<&CapturedRelease>) -> BTreeMap<String, ArtifactView<'_>> {
    capture
        .map(|capture| {
            let local_path = capture_local_artifact_path(capture);
            capture
                .artifacts
                .iter()
                .map(|artifact| {
                    (
                        artifact.filename.clone(),
                        ArtifactView {
                            artifact,
                            local_path,
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Clone, Copy)]
struct ArtifactView<'a> {
    artifact: &'a CapturedArtifact,
    local_path: Option<&'a str>,
}

fn artifact_summary(artifact: ArtifactView<'_>) -> ArtifactSummary {
    ArtifactSummary {
        filename: artifact.artifact.filename.clone(),
        kind: artifact.artifact.kind.clone(),
        url: artifact.artifact.url.clone(),
        path: artifact.local_path.map(str::to_string),
        size_bytes: artifact.artifact.size_bytes,
        uploaded_at: artifact.artifact.uploaded_at,
        yanked: artifact.artifact.yanked,
        hashes: artifact.artifact.hashes.clone(),
        provenance_path: artifact.artifact.provenance_path.clone(),
    }
}

fn artifact_changed(left: ArtifactView<'_>, right: ArtifactView<'_>) -> bool {
    left.artifact.kind != right.artifact.kind
        || left.artifact.url != right.artifact.url
        || left.local_path != right.local_path
        || left.artifact.size_bytes != right.artifact.size_bytes
        || left.artifact.uploaded_at != right.artifact.uploaded_at
        || left.artifact.yanked != right.artifact.yanked
        || left.artifact.hashes.sha256 != right.artifact.hashes.sha256
        || left.artifact.hashes.sha512 != right.artifact.hashes.sha512
        || left.artifact.hashes.blake2b_256 != right.artifact.hashes.blake2b_256
        || left.artifact.hashes.md5 != right.artifact.hashes.md5
        || left.artifact.hashes.integrity != right.artifact.hashes.integrity
        || left.artifact.hashes.shasum != right.artifact.hashes.shasum
        || left.artifact.hashes.checksum != right.artifact.hashes.checksum
        || left.artifact.provenance_path != right.artifact.provenance_path
}

fn capture_local_artifact_path(capture: &CapturedRelease) -> Option<&str> {
    capture
        .details
        .pointer("/local_artifact/path")
        .and_then(serde_json::Value::as_str)
}

fn top_level_keys(value: Option<&serde_json::Value>) -> BTreeSet<String> {
    value
        .and_then(|value| value.as_object())
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

fn unavailable_content_diff(reason: &str) -> ContentDiff {
    ContentDiff {
        available: false,
        reason: Some(reason.to_string()),
        artifact_kind: None,
        baseline_artifact: None,
        target_artifact: None,
        patches_included: false,
        patch_context: None,
        files_added_count: 0,
        files_removed_count: 0,
        files_changed_count: 0,
        files_added: Vec::new(),
        files_removed: Vec::new(),
        files_changed: Vec::new(),
        files_added_detail: Vec::new(),
        files_removed_detail: Vec::new(),
        files_changed_detail: Vec::new(),
        file_patches: Vec::new(),
        npm_install_hook: None,
        crate_repository_commit: None,
    }
}

fn capture_status_label(capture: Option<&CapturedRelease>) -> &'static str {
    match capture.map(|capture| &capture.status) {
        Some(ReleaseStatus::Active) => "active",
        Some(ReleaseStatus::Yanked) => "yanked",
        Some(ReleaseStatus::Removed) => "removed",
        Some(ReleaseStatus::Unknown) => "unknown",
        None => "uncaptured",
    }
}

fn artifact_ref(
    artifact: &CapturedArtifact,
    local_path: Option<&Path>,
    materialized_path: Option<&Path>,
) -> Result<ArtifactRef> {
    let mut hashes = artifact.hashes.clone();
    let mut size_bytes = artifact.size_bytes;
    let should_hash_materialized = local_path.is_some()
        || (size_bytes.is_none()
            && hashes.sha256.is_none()
            && hashes.sha512.is_none()
            && hashes.integrity.is_none()
            && hashes.shasum.is_none()
            && hashes.checksum.is_none()
            && hashes.blake2b_256.is_none()
            && hashes.md5.is_none());
    let digest_source = should_hash_materialized
        .then(|| materialized_path.or(local_path))
        .flatten();

    if let Some(path) = digest_source {
        let digests = hash_file_digests(path)?;
        size_bytes = size_bytes.or(Some(digests.size_bytes));
        hashes.sha256 = hashes.sha256.or(Some(digests.sha256));
        hashes.sha512 = hashes.sha512.or(Some(digests.sha512));
    }

    Ok(ArtifactRef {
        filename: artifact.filename.clone(),
        kind: artifact.kind.clone(),
        url: artifact.url.clone(),
        path: local_path.map(|path| path.display().to_string()),
        size_bytes,
        uploaded_at: artifact.uploaded_at,
        yanked: artifact.yanked,
        hashes,
        provenance_path: artifact.provenance_path.clone(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    NpmTarball,
    CrateTarball,
    TarGz,
    Wheel,
    Zip,
}

impl ArtifactKind {
    fn label(self) -> &'static str {
        match self {
            Self::NpmTarball => "npm-tarball",
            Self::CrateTarball => "crate",
            Self::TarGz => "tar.gz",
            Self::Wheel => "wheel",
            Self::Zip => "zip",
        }
    }
}

fn select_artifact_pair<'a>(
    baseline: &'a CapturedRelease,
    target: &'a CapturedRelease,
) -> Option<(&'a CapturedArtifact, &'a CapturedArtifact, ArtifactKind)> {
    let priorities = [
        ArtifactKind::NpmTarball,
        ArtifactKind::CrateTarball,
        ArtifactKind::TarGz,
        ArtifactKind::Wheel,
        ArtifactKind::Zip,
    ];

    for priority in priorities {
        let baseline_match = baseline
            .artifacts
            .iter()
            .find(|artifact| classify_artifact(artifact) == Some(priority));
        let target_match = target
            .artifacts
            .iter()
            .find(|artifact| classify_artifact(artifact) == Some(priority));
        if let (Some(baseline_match), Some(target_match)) = (baseline_match, target_match) {
            return Some((baseline_match, target_match, priority));
        }
    }

    None
}

fn classify_artifact(artifact: &CapturedArtifact) -> Option<ArtifactKind> {
    match artifact.kind.as_deref() {
        Some("npm-tarball") => Some(ArtifactKind::NpmTarball),
        Some("crate") => Some(ArtifactKind::CrateTarball),
        Some("sdist") => Some(ArtifactKind::TarGz),
        Some("bdist_wheel") => Some(ArtifactKind::Wheel),
        _ => classify_filename(&artifact.filename),
    }
}

fn classify_filename(filename: &str) -> Option<ArtifactKind> {
    let canonical = canonical_archive_name(filename).unwrap_or(filename);
    match canonical {
        value if value.ends_with(".tgz") => Some(ArtifactKind::NpmTarball),
        value if value.ends_with(".crate") => Some(ArtifactKind::CrateTarball),
        value if value.ends_with(".tar.gz") => Some(ArtifactKind::TarGz),
        value if value.ends_with(".whl") => Some(ArtifactKind::Wheel),
        value if value.ends_with(".zip") => Some(ArtifactKind::Zip),
        _ => None,
    }
}

#[derive(Debug)]
struct ComparedContent {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
    added_detail: Vec<FileRecord>,
    removed_detail: Vec<FileRecord>,
    changed_detail: Vec<FileRecordChange>,
    file_patches: Vec<FilePatch>,
    npm_install_hook: Option<NpmInstallHookDiff>,
    crate_repository_commit: Option<CrateRepositoryCommitDiff>,
}

async fn materialize_artifact(
    http: &reqwest::Client,
    source: ArtifactSource<'_>,
    destination: &Path,
) -> Result<()> {
    match source {
        ArtifactSource::Url(url) => download_artifact(http, url, destination).await,
        ArtifactSource::LocalPath(path) => copy_local_artifact(path, destination).await,
    }
}

async fn copy_local_artifact(source: &Path, destination: &Path) -> Result<()> {
    tokio_fs::copy(source, destination).await.with_context(|| {
        format!(
            "failed to copy local artifact {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

async fn download_artifact(http: &reqwest::Client, url: &str, destination: &Path) -> Result<()> {
    let response = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to request artifact {url}"))?
        .error_for_status()
        .with_context(|| format!("artifact download returned an error for {url}"))?;
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("failed to read artifact body from {url}"))?;

    let mut file = tokio_fs::File::create(destination)
        .await
        .with_context(|| format!("failed to create {}", destination.display()))?;
    file.write_all(&bytes)
        .await
        .with_context(|| format!("failed to write {}", destination.display()))?;
    file.flush()
        .await
        .with_context(|| format!("failed to flush {}", destination.display()))?;
    Ok(())
}

async fn extract_artifact(archive: &Path, destination: &Path, kind: ArtifactKind) -> Result<()> {
    let output = match kind {
        ArtifactKind::Wheel | ArtifactKind::Zip => {
            let mut command = Command::new("unzip");
            command.arg("-qq").arg(archive).arg("-d").arg(destination);
            command.output().await
        }
        ArtifactKind::TarGz | ArtifactKind::NpmTarball | ArtifactKind::CrateTarball => {
            let mut command = Command::new("tar");
            command.arg("-xzf").arg(archive).arg("-C").arg(destination);
            command.output().await
        }
    }
    .with_context(|| format!("failed to spawn extractor for {}", archive.display()))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "extractor failed for {}: {}",
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn compare_extracted_dirs(
    baseline_dir: &Path,
    target_dir: &Path,
    include_patches: bool,
    patch_context: usize,
) -> Result<ComparedContent> {
    let baseline_files = collect_files(baseline_dir)?;
    let target_files = collect_files(target_dir)?;
    let all_paths = baseline_files
        .keys()
        .chain(target_files.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut added_detail = Vec::new();
    let mut removed_detail = Vec::new();
    let mut changed_detail = Vec::new();
    let mut file_patches = Vec::new();

    for path in all_paths {
        match (baseline_files.get(&path), target_files.get(&path)) {
            (None, Some(right)) => {
                let target_bytes = fs::read(right)?;
                added_detail.push(build_file_record(&path, &target_bytes));
                if include_patches {
                    file_patches.push(build_file_patch(
                        &path,
                        FileChangeKind::Added,
                        None,
                        None,
                        Some(right),
                        Some(&target_bytes),
                        patch_context,
                    )?);
                }
                added.push(path);
            }
            (Some(left), None) => {
                let baseline_bytes = fs::read(left)?;
                removed_detail.push(build_file_record(&path, &baseline_bytes));
                if include_patches {
                    file_patches.push(build_file_patch(
                        &path,
                        FileChangeKind::Removed,
                        Some(left),
                        Some(&baseline_bytes),
                        None,
                        None,
                        patch_context,
                    )?);
                }
                removed.push(path);
            }
            (Some(left), Some(right)) => {
                let baseline_bytes = fs::read(left)?;
                let target_bytes = fs::read(right)?;
                if baseline_bytes != target_bytes {
                    changed_detail.push(FileRecordChange {
                        path: path.clone(),
                        baseline: build_file_record(&path, &baseline_bytes),
                        target: build_file_record(&path, &target_bytes),
                    });
                    if include_patches {
                        file_patches.push(build_file_patch(
                            &path,
                            FileChangeKind::Changed,
                            Some(left),
                            Some(&baseline_bytes),
                            Some(right),
                            Some(&target_bytes),
                            patch_context,
                        )?);
                    }
                    changed.push(path);
                }
            }
            _ => {}
        }
    }

    let npm_install_hook =
        derive_npm_install_hook_diff(&baseline_files, &target_files, &added, &removed, &changed)?;
    let crate_repository_commit =
        derive_crate_repository_commit_diff(&baseline_files, &target_files)?;

    Ok(ComparedContent {
        added,
        removed,
        changed,
        added_detail,
        removed_detail,
        changed_detail,
        file_patches,
        npm_install_hook,
        crate_repository_commit,
    })
}

fn derive_npm_install_hook_diff(
    baseline_files: &BTreeMap<String, PathBuf>,
    target_files: &BTreeMap<String, PathBuf>,
    added: &[String],
    removed: &[String],
    changed: &[String],
) -> Result<Option<NpmInstallHookDiff>> {
    let baseline_package_json = read_json_file_from_map(baseline_files, "package.json")?;
    let target_package_json = read_json_file_from_map(target_files, "package.json")?;
    if baseline_package_json.is_none() && target_package_json.is_none() {
        return Ok(None);
    }

    let baseline_scripts = baseline_package_json
        .as_ref()
        .map(npm_install_scripts)
        .unwrap_or_default();
    let target_scripts = target_package_json
        .as_ref()
        .map(npm_install_scripts)
        .unwrap_or_default();
    let baseline_has_install_scripts = !baseline_scripts.is_empty();
    let target_has_install_scripts = !target_scripts.is_empty();
    let scripts_changed = baseline_scripts != target_scripts;

    let referenced_files = install_script_file_refs(&baseline_scripts, &target_scripts);
    let changed_paths = added
        .iter()
        .chain(removed.iter())
        .chain(changed.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    let referenced_files_changed = referenced_files
        .iter()
        .filter(|path| changed_paths.contains(*path))
        .cloned()
        .collect::<Vec<_>>();
    let hook_files_changed = !referenced_files_changed.is_empty();
    let effective_changed = scripts_changed || hook_files_changed;
    let longstanding_unchanged =
        target_has_install_scripts && baseline_has_install_scripts && !effective_changed;

    Ok(Some(NpmInstallHookDiff {
        baseline_has_install_scripts,
        target_has_install_scripts,
        scripts_changed,
        hook_files_changed,
        effective_changed,
        longstanding_unchanged,
        baseline_scripts,
        target_scripts,
        referenced_files,
        referenced_files_changed,
    }))
}

fn read_json_file_from_map(
    files: &BTreeMap<String, PathBuf>,
    path: &str,
) -> Result<Option<serde_json::Value>> {
    let Some(file_path) = files.get(path) else {
        return Ok(None);
    };
    let bytes =
        fs::read(file_path).with_context(|| format!("failed to read {}", file_path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", file_path.display()))
        .map(Some)
}

fn read_json_file_by_suffix_from_map(
    files: &BTreeMap<String, PathBuf>,
    suffix: &str,
) -> Result<Option<serde_json::Value>> {
    if let Some(value) = read_json_file_from_map(files, suffix)? {
        return Ok(Some(value));
    }

    let Some((_, file_path)) = files.iter().find(|(path, file_path)| {
        path == &suffix
            || path.ends_with(&format!("/{suffix}"))
            || file_path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name == suffix)
    }) else {
        return Ok(None);
    };

    let bytes =
        fs::read(file_path).with_context(|| format!("failed to read {}", file_path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", file_path.display()))
        .map(Some)
}

fn derive_crate_repository_commit_diff(
    baseline_files: &BTreeMap<String, PathBuf>,
    target_files: &BTreeMap<String, PathBuf>,
) -> Result<Option<CrateRepositoryCommitDiff>> {
    let baseline_commit =
        read_json_file_by_suffix_from_map(baseline_files, ".cargo_vcs_info.json")?
            .as_ref()
            .and_then(crate_vcs_commit_from_value)
            .map(str::to_string);
    let target_commit = read_json_file_by_suffix_from_map(target_files, ".cargo_vcs_info.json")?
        .as_ref()
        .and_then(crate_vcs_commit_from_value)
        .map(str::to_string);

    if baseline_commit.is_none() && target_commit.is_none() {
        return Ok(None);
    }

    Ok(Some(CrateRepositoryCommitDiff {
        commit_changed: baseline_commit != target_commit,
        baseline_commit,
        target_commit,
    }))
}

fn crate_vcs_commit_from_value(value: &serde_json::Value) -> Option<&str> {
    value
        .pointer("/git/sha1")
        .and_then(serde_json::Value::as_str)
}

fn install_script_file_refs(
    baseline_scripts: &BTreeMap<String, String>,
    target_scripts: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut refs = BTreeSet::new();
    for script in baseline_scripts.values().chain(target_scripts.values()) {
        for token in script.split_whitespace() {
            let trimmed = token.trim_matches(|ch: char| {
                matches!(ch, '"' | '\'' | '`' | ';' | ',' | '(' | ')' | '[' | ']')
            });
            if trimmed.is_empty()
                || trimmed.starts_with('-')
                || trimmed.contains("://")
                || trimmed.starts_with('$')
                || trimmed.contains("${")
            {
                continue;
            }

            let normalized = trimmed
                .trim_start_matches("./")
                .trim_start_matches(".\\")
                .replace('\\', "/");
            if !looks_like_local_script_path(&normalized) {
                continue;
            }
            refs.insert(normalized);
        }
    }
    refs.into_iter().collect()
}

fn looks_like_local_script_path(path: &str) -> bool {
    if !(path.contains('/') || path.contains('.')) {
        return false;
    }
    [
        ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".sh", ".bash", ".zsh", ".ps1", ".py",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

fn build_file_patch(
    path: &str,
    change: FileChangeKind,
    baseline_path: Option<&Path>,
    baseline_bytes: Option<&[u8]>,
    target_path: Option<&Path>,
    target_bytes: Option<&[u8]>,
    patch_context: usize,
) -> Result<FilePatch> {
    let baseline_is_text = baseline_bytes.map(is_probably_text).unwrap_or(true);
    let target_is_text = target_bytes.map(is_probably_text).unwrap_or(true);
    if baseline_is_text && target_is_text {
        let patch = render_unified_patch(path, change, baseline_path, target_path, patch_context)?;
        Ok(FilePatch {
            path: path.to_string(),
            change,
            text: true,
            patch: Some(patch),
            reason: None,
        })
    } else {
        Ok(FilePatch {
            path: path.to_string(),
            change,
            text: false,
            patch: None,
            reason: Some(format!("{} file is binary or non-UTF-8", change.label())),
        })
    }
}

fn is_probably_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

fn render_unified_patch(
    path: &str,
    change: FileChangeKind,
    baseline_path: Option<&Path>,
    target_path: Option<&Path>,
    patch_context: usize,
) -> Result<String> {
    let baseline_label = match change {
        FileChangeKind::Added => "/dev/null".to_string(),
        FileChangeKind::Removed | FileChangeKind::Changed => format!("baseline/{path}"),
    };
    let target_label = match change {
        FileChangeKind::Added | FileChangeKind::Changed => format!("target/{path}"),
        FileChangeKind::Removed => "/dev/null".to_string(),
    };
    let left = baseline_path.unwrap_or_else(|| Path::new("/dev/null"));
    let right = target_path.unwrap_or_else(|| Path::new("/dev/null"));
    let output = StdCommand::new("diff")
        .arg("-U")
        .arg(patch_context.to_string())
        .arg("-L")
        .arg(&baseline_label)
        .arg("-L")
        .arg(&target_label)
        .arg(left)
        .arg(right)
        .output()
        .with_context(|| format!("failed to spawn diff for {path}"))?;
    match output.status.code() {
        Some(0) | Some(1) => Ok(String::from_utf8_lossy(&output.stdout).into_owned()),
        Some(code) => Err(anyhow::anyhow!(
            "diff command failed for {path} with exit code {code}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        None => Err(anyhow::anyhow!(
            "diff command terminated by signal for {path}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

fn collect_files(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut relatives = Vec::new();
    collect_files_recursive(root, root, &mut relatives)?;
    let strip_prefix = common_top_level_dir(&relatives);

    let mut files = BTreeMap::new();
    for relative in relatives {
        let normalized = normalize_relative_path(&relative, strip_prefix.as_deref());
        files.insert(normalized, root.join(relative));
    }
    Ok(files)
}

fn collect_files_recursive(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if file_type.is_dir() {
            collect_files_recursive(root, &path, files)?;
        } else if file_type.is_file() {
            files.push(
                path.strip_prefix(root)
                    .with_context(|| format!("failed to relativize {}", path.display()))?
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}

fn common_top_level_dir(files: &[PathBuf]) -> Option<String> {
    let mut candidates = files
        .iter()
        .filter_map(|path| match path.components().next() {
            Some(Component::Normal(value)) => value.to_str().map(str::to_string),
            _ => None,
        });
    let first = candidates.next()?;
    if candidates.all(|candidate| candidate == first) {
        Some(first)
    } else {
        None
    }
}

fn normalize_relative_path(path: &Path, strip_prefix: Option<&str>) -> String {
    let components = path.components().collect::<Vec<_>>();
    let start = match (strip_prefix, components.first()) {
        (Some(prefix), Some(Component::Normal(value))) if *value == OsStr::new(prefix) => 1,
        _ => 0,
    };

    components[start..]
        .iter()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;
    use crate::{capture::CapturedRelease, event::PackageReleaseEvent, ledger::EventLedger};

    #[test]
    fn resolves_previous_release_after_deduping_versions() {
        let entries = vec![
            sample_history_entry("1.0.0", sample_capture("1.0.0")),
            sample_history_entry("1.1.0", sample_capture("1.1.0-old")),
            sample_history_entry("1.1.0", sample_capture("1.1.0-new")),
            sample_history_entry("1.2.0", sample_capture("1.2.0")),
        ];

        let (baseline, target) = resolve_release_pair(entries, "1.2.0", "previous").unwrap();
        assert_eq!(baseline.event.version, "1.1.0");
        assert_eq!(baseline.capture.as_ref().unwrap().version, "1.1.0-new");
        assert_eq!(target.event.version, "1.2.0");
    }

    #[test]
    fn details_diff_tracks_top_level_key_changes() {
        let baseline = sample_capture_with_details(
            "1.0.0",
            serde_json::json!({"publisher": "alice", "downloads": 10}),
        );
        let target = sample_capture_with_details(
            "1.1.0",
            serde_json::json!({"publisher": "bob", "scripts": {"postinstall": "echo hi"}}),
        );

        let diff = build_details_diff(Some(&target), Some(&baseline));
        assert_eq!(diff.added_keys, vec!["scripts".to_string()]);
        assert_eq!(diff.removed_keys, vec!["downloads".to_string()]);
        assert_eq!(diff.changed_keys, vec!["publisher".to_string()]);
        assert_eq!(
            diff.added["scripts"],
            serde_json::json!({"postinstall": "echo hi"})
        );
        assert_eq!(diff.removed["downloads"], serde_json::json!(10));
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].key, "publisher");
        assert_eq!(diff.changed[0].baseline, serde_json::json!("alice"));
        assert_eq!(diff.changed[0].target, serde_json::json!("bob"));
    }

    #[test]
    fn artifact_diff_tracks_added_removed_and_changed_files() {
        let baseline = sample_capture_with_artifacts(
            "1.0.0",
            vec![
                sample_artifact("pkg-1.0.0.tgz", Some("sha-a")),
                sample_artifact("pkg-1.0.0.sig", Some("sig-a")),
            ],
        );
        let target = sample_capture_with_artifacts(
            "1.1.0",
            vec![
                sample_artifact("pkg-1.0.0.tgz", Some("sha-b")),
                sample_artifact("pkg-1.1.0.tgz", Some("sha-c")),
            ],
        );

        let diff = build_artifact_diff(Some(&target), Some(&baseline));
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].filename, "pkg-1.1.0.tgz");
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].filename, "pkg-1.0.0.sig");
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].filename, "pkg-1.0.0.tgz");
    }

    #[test]
    fn strips_common_top_level_directory_when_comparing_archives() {
        let files = vec![
            PathBuf::from("package/src/lib.rs"),
            PathBuf::from("package/Cargo.toml"),
        ];
        assert_eq!(common_top_level_dir(&files), Some("package".to_string()));
        assert_eq!(
            normalize_relative_path(Path::new("package/src/lib.rs"), Some("package")),
            "src/lib.rs"
        );
    }

    #[test]
    fn classifies_quarantined_archive_suffixes() {
        assert_eq!(
            classify_filename("litellm-1.82.8-py3-none-any.whl.malicious"),
            Some(ArtifactKind::Wheel)
        );
        assert_eq!(
            infer_version_from_filename(
                Ecosystem::Pypi,
                "litellm",
                "litellm-1.82.8-py3-none-any.whl.malicious"
            )
            .as_deref(),
            Some("1.82.8")
        );
    }

    #[test]
    fn markdown_renderer_includes_file_lists_and_patches() {
        let diff = ReleaseDiff {
            ecosystem: Ecosystem::Pypi,
            package: "litellm".to_string(),
            baseline_event_id: "pypi:litellm@1.82.6".to_string(),
            target_event_id: "local:pypi:litellm@1.82.8".to_string(),
            baseline_version: "1.82.6".to_string(),
            target_version: "1.82.8".to_string(),
            generated_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
            status: StatusDiff {
                baseline: "active".to_string(),
                target: "unknown".to_string(),
                changed: true,
            },
            artifacts: ArtifactDiff {
                added: Vec::new(),
                removed: Vec::new(),
                changed: Vec::new(),
            },
            details: DetailsDiff {
                added_keys: vec!["local_artifact".to_string()],
                removed_keys: vec!["last_serial".to_string()],
                changed_keys: vec!["publisher".to_string()],
                added: BTreeMap::from([(
                    "local_artifact".to_string(),
                    json!({"path": "/tmp/litellm-1.82.8.whl"}),
                )]),
                removed: BTreeMap::from([("last_serial".to_string(), json!(35435173))]),
                changed: vec![MetadataValueChange {
                    key: "publisher".to_string(),
                    baseline: json!("alice"),
                    target: json!("mallory"),
                }],
            },
            content: ContentDiff {
                available: true,
                reason: None,
                artifact_kind: Some("wheel".to_string()),
                baseline_artifact: Some(ArtifactRef {
                    filename: "litellm-1.82.6-py3-none-any.whl".to_string(),
                    kind: Some("bdist_wheel".to_string()),
                    url: Some("https://files.pythonhosted.org/packages/example".to_string()),
                    path: None,
                    size_bytes: Some(100),
                    uploaded_at: Some(Utc.with_ymd_and_hms(2026, 3, 22, 6, 35, 56).unwrap()),
                    yanked: Some(false),
                    hashes: ArtifactHashes {
                        sha256: Some("baseline-sha".to_string()),
                        ..ArtifactHashes::default()
                    },
                    provenance_path: None,
                }),
                target_artifact: Some(ArtifactRef {
                    filename: "litellm-1.82.8-py3-none-any.whl".to_string(),
                    kind: Some("bdist_wheel".to_string()),
                    url: None,
                    path: Some("/tmp/litellm-1.82.8.whl".to_string()),
                    size_bytes: Some(101),
                    uploaded_at: None,
                    yanked: None,
                    hashes: ArtifactHashes {
                        sha256: Some("target-sha".to_string()),
                        sha512: Some("target-sha512".to_string()),
                        ..ArtifactHashes::default()
                    },
                    provenance_path: None,
                }),
                patches_included: true,
                patch_context: Some(3),
                files_added_count: 2,
                files_removed_count: 0,
                files_changed_count: 1,
                files_added: vec![
                    "litellm_init.pth".to_string(),
                    "litellm-1.82.8.dist-info/entry_points.txt".to_string(),
                ],
                files_removed: Vec::new(),
                files_changed: vec!["litellm/proxy/proxy_server.py".to_string()],
                files_added_detail: vec![
                    FileRecord {
                        path: "litellm_init.pth".to_string(),
                        size_bytes: 10,
                        sha256: "abc".to_string(),
                        text: true,
                    },
                    FileRecord {
                        path: "litellm-1.82.8.dist-info/entry_points.txt".to_string(),
                        size_bytes: 20,
                        sha256: "def".to_string(),
                        text: true,
                    },
                ],
                files_removed_detail: Vec::new(),
                files_changed_detail: vec![FileRecordChange {
                    path: "litellm/proxy/proxy_server.py".to_string(),
                    baseline: FileRecord {
                        path: "litellm/proxy/proxy_server.py".to_string(),
                        size_bytes: 14,
                        sha256: "old".to_string(),
                        text: true,
                    },
                    target: FileRecord {
                        path: "litellm/proxy/proxy_server.py".to_string(),
                        size_bytes: 14,
                        sha256: "new".to_string(),
                        text: true,
                    },
                }],
                file_patches: vec![FilePatch {
                    path: "litellm/proxy/proxy_server.py".to_string(),
                    change: FileChangeKind::Changed,
                    text: true,
                    patch: Some(
                        "--- baseline/litellm/proxy/proxy_server.py\n+++ target/litellm/proxy/proxy_server.py\n@@ -1 +1 @@\n-print(\"safe\")\n+print(\"evil\")\n"
                            .to_string(),
                    ),
                    reason: None,
                }],
                npm_install_hook: None,
                crate_repository_commit: None,
            },
            notes: vec!["target artifact source: /tmp/litellm-1.82.8.whl".to_string()],
        };

        let report = render_release_diff_markdown(&diff);
        assert!(report.contains("## Compared Artifacts"));
        assert!(report.contains("baseline-sha"));
        assert!(report.contains("target-sha512"));
        assert!(report.contains("## Metadata Added"));
        assert!(report.contains("## Metadata Removed"));
        assert!(report.contains("## Metadata Changed"));
        assert!(report.contains("publisher"));
        assert!(report.contains("## Files Added Detail"));
        assert!(report.contains("| Path | Size | SHA256 | Text |"));
        assert!(report.contains("| `litellm_init.pth` | `10` | `abc` | `true` |"));
        assert!(report.contains("## Files Changed Detail"));
        assert!(report.contains("## Files Added (2)"));
        assert!(report.contains("litellm_init.pth"));
        assert!(report.contains("## File Patches"));
        assert!(report.contains("```diff"));
    }

    #[test]
    fn compare_extracted_dirs_builds_unified_patches() {
        let temp = tempdir().unwrap();
        let baseline_dir = temp.path().join("baseline");
        let target_dir = temp.path().join("target");
        std::fs::create_dir_all(baseline_dir.join("pkg")).unwrap();
        std::fs::create_dir_all(target_dir.join("pkg")).unwrap();
        std::fs::write(
            baseline_dir.join("pkg").join("proxy_server.py"),
            "print(\"safe\")\n",
        )
        .unwrap();
        std::fs::write(
            target_dir.join("pkg").join("proxy_server.py"),
            "print(\"evil\")\n",
        )
        .unwrap();
        std::fs::write(
            target_dir.join("pkg").join("litellm_init.pth"),
            "import os\n",
        )
        .unwrap();

        let compared = compare_extracted_dirs(&baseline_dir, &target_dir, true, 2).unwrap();
        assert_eq!(compared.added, vec!["litellm_init.pth".to_string()]);
        assert_eq!(compared.changed, vec!["proxy_server.py".to_string()]);
        assert_eq!(compared.file_patches.len(), 2);
        assert_eq!(compared.added_detail.len(), 1);
        assert_eq!(compared.changed_detail.len(), 1);
        assert_eq!(compared.added_detail[0].path, "litellm_init.pth");
        assert!(!compared.added_detail[0].sha256.is_empty());
        assert_eq!(compared.changed_detail[0].baseline.path, "proxy_server.py");
        assert_eq!(compared.changed_detail[0].target.path, "proxy_server.py");
        let changed_patch = compared
            .file_patches
            .iter()
            .find(|patch| patch.path == "proxy_server.py")
            .unwrap();
        assert_eq!(changed_patch.change, FileChangeKind::Changed);
        assert!(changed_patch.text);
        assert!(
            changed_patch
                .patch
                .as_deref()
                .is_some_and(|patch| patch.contains("@@"))
        );

        let added_patch = compared
            .file_patches
            .iter()
            .find(|patch| patch.path == "litellm_init.pth")
            .unwrap();
        assert_eq!(added_patch.change, FileChangeKind::Added);
        assert!(
            added_patch
                .patch
                .as_deref()
                .is_some_and(|patch| patch.contains("+++ target/litellm_init.pth"))
        );
    }

    #[test]
    fn compare_extracted_dirs_tracks_unchanged_npm_install_hook() {
        let temp = tempdir().unwrap();
        let baseline_dir = temp.path().join("baseline");
        let target_dir = temp.path().join("target");
        std::fs::create_dir_all(baseline_dir.join("package/scripts")).unwrap();
        std::fs::create_dir_all(target_dir.join("package/scripts")).unwrap();
        std::fs::write(
            baseline_dir.join("package").join("package.json"),
            r#"{"name":"demo","version":"1.0.0","scripts":{"postinstall":"node ./scripts/postinstall.mjs"}}"#,
        )
        .unwrap();
        std::fs::write(
            target_dir.join("package").join("package.json"),
            r#"{"name":"demo","version":"1.0.1","scripts":{"postinstall":"node ./scripts/postinstall.mjs"}}"#,
        )
        .unwrap();
        std::fs::write(
            baseline_dir.join("package/scripts").join("postinstall.mjs"),
            "console.log('hi')\n",
        )
        .unwrap();
        std::fs::write(
            target_dir.join("package/scripts").join("postinstall.mjs"),
            "console.log('hi')\n",
        )
        .unwrap();

        let compared = compare_extracted_dirs(&baseline_dir, &target_dir, false, 3).unwrap();
        let hook = compared
            .npm_install_hook
            .expect("npm install hook evidence");
        assert!(hook.baseline_has_install_scripts);
        assert!(hook.target_has_install_scripts);
        assert!(!hook.scripts_changed);
        assert!(!hook.hook_files_changed);
        assert!(hook.longstanding_unchanged);
        assert_eq!(
            hook.referenced_files,
            vec!["scripts/postinstall.mjs".to_string()]
        );
        assert!(hook.referenced_files_changed.is_empty());
    }

    #[test]
    fn compare_extracted_dirs_extracts_crate_vcs_commit() {
        let temp = tempdir().unwrap();
        let baseline_dir = temp.path().join("baseline");
        let target_dir = temp.path().join("target");
        std::fs::create_dir_all(&baseline_dir).unwrap();
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::write(
            baseline_dir.join(".cargo_vcs_info.json"),
            r#"{"git":{"sha1":"49a3f617e6279b711d1a0f6f9e5461b2b931d3f9"}}"#,
        )
        .unwrap();
        std::fs::write(
            target_dir.join(".cargo_vcs_info.json"),
            r#"{"git":{"sha1":"5869fde797bb2bfa6686fabdf8437f0e4d130b9c"}}"#,
        )
        .unwrap();

        let compared = compare_extracted_dirs(&baseline_dir, &target_dir, false, 3).unwrap();
        let commit = compared
            .crate_repository_commit
            .expect("crate vcs commit evidence");
        assert_eq!(
            commit.baseline_commit.as_deref(),
            Some("49a3f617e6279b711d1a0f6f9e5461b2b931d3f9")
        );
        assert_eq!(
            commit.target_commit.as_deref(),
            Some("5869fde797bb2bfa6686fabdf8437f0e4d130b9c")
        );
        assert!(commit.commit_changed);
    }

    #[tokio::test]
    async fn synthesizes_local_wheel_input_with_inferred_version() {
        let temp = tempdir().unwrap();
        let artifact_path = temp.path().join("litellm-1.82.8-py3-none-any.whl");
        fs::write(&artifact_path, b"malicious wheel bytes")
            .await
            .unwrap();

        let input = synthesize_local_input(Ecosystem::Pypi, "litellm", None, &artifact_path)
            .await
            .unwrap();

        assert_eq!(input.entry.event.version, "1.82.8");
        assert_eq!(input.history_lookup_version.as_deref(), Some("1.82.8"));
        let capture = input.entry.capture.as_ref().unwrap();
        assert_eq!(capture.status, ReleaseStatus::Unknown);
        assert_eq!(capture.artifacts[0].kind.as_deref(), Some("bdist_wheel"));
        assert_eq!(
            capture
                .details
                .pointer("/local_artifact/path")
                .and_then(serde_json::Value::as_str),
            Some(artifact_path.to_string_lossy().as_ref())
        );
        assert!(capture.artifacts[0].hashes.sha256.is_some());
        assert!(capture.artifacts[0].hashes.sha512.is_some());
    }

    #[test]
    fn json_diff_omits_missing_optional_fields() {
        let diff = ReleaseDiff {
            ecosystem: Ecosystem::Npm,
            package: "pkg".to_string(),
            baseline_event_id: "npm:pkg@1.0.0".to_string(),
            target_event_id: "npm:pkg@1.1.0".to_string(),
            baseline_version: "1.0.0".to_string(),
            target_version: "1.1.0".to_string(),
            generated_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
            status: StatusDiff {
                baseline: "active".to_string(),
                target: "active".to_string(),
                changed: false,
            },
            artifacts: ArtifactDiff {
                added: vec![ArtifactSummary {
                    filename: "pkg-1.1.0.tgz".to_string(),
                    kind: Some("npm-tarball".to_string()),
                    url: Some("https://example.invalid/pkg-1.1.0.tgz".to_string()),
                    path: None,
                    size_bytes: None,
                    uploaded_at: None,
                    yanked: None,
                    hashes: ArtifactHashes {
                        integrity: Some("sha512-demo".to_string()),
                        ..ArtifactHashes::default()
                    },
                    provenance_path: None,
                }],
                removed: Vec::new(),
                changed: Vec::new(),
            },
            details: DetailsDiff {
                added_keys: Vec::new(),
                removed_keys: Vec::new(),
                changed_keys: Vec::new(),
                added: BTreeMap::new(),
                removed: BTreeMap::new(),
                changed: Vec::new(),
            },
            content: unavailable_content_diff("not available"),
            notes: Vec::new(),
        };

        let value = serde_json::to_value(&diff).unwrap();
        let artifact = &value["artifacts"]["added"][0];
        assert!(artifact.get("path").is_none());
        assert!(artifact.get("size_bytes").is_none());
        assert!(artifact["hashes"].get("sha256").is_none());
        assert_eq!(artifact["hashes"]["integrity"], "sha512-demo");
    }

    #[tokio::test]
    async fn stored_diff_reports_no_baseline_for_first_release() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let ledger = EventLedger::open(crate::ledger::observed_ledger_path(&data_dir))
            .await
            .unwrap();
        ledger
            .append(&PackageReleaseEvent {
                event_id: "npm:pkg@1.0.0".to_string(),
                ecosystem: Ecosystem::Npm,
                package: "pkg".to_string(),
                version: "1.0.0".to_string(),
                published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 11, 0, 0).unwrap()),
                observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
                source: "test".to_string(),
                sequence: None,
                package_url: None,
                release_url: None,
                metadata_url: None,
                priority: None,
            })
            .await
            .unwrap();

        let stored = build_stored_release_diff(StoredReleaseDiffRequest {
            data_dir: &data_dir,
            ecosystem: Ecosystem::Npm,
            package: "pkg",
            target_version: "1.0.0",
            include_patches: false,
            patch_context: 0,
        })
        .await
        .unwrap();

        assert_eq!(stored.status, StoredReleaseDiffStatus::NoBaseline);
        assert!(stored.baseline_event_id.is_none());
        assert!(stored.baseline_version.is_none());
        assert!(stored.diff.is_none());
    }

    fn sample_history_entry(version: &str, capture: CapturedRelease) -> HistoryEntry {
        HistoryEntry {
            event: PackageReleaseEvent {
                event_id: format!("npm:pkg@{version}"),
                ecosystem: Ecosystem::Npm,
                package: "pkg".to_string(),
                version: version.to_string(),
                published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 11, 0, 0).unwrap()),
                observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
                source: "test".to_string(),
                sequence: None,
                package_url: None,
                release_url: None,
                metadata_url: None,
                priority: None,
            },
            capture: Some(capture),
            capture_dir: None,
        }
    }

    fn sample_capture(version: &str) -> CapturedRelease {
        sample_capture_with_artifacts(
            version,
            vec![sample_artifact(
                &format!("pkg-{version}.tgz"),
                Some(version),
            )],
        )
    }

    fn sample_capture_with_details(version: &str, details: serde_json::Value) -> CapturedRelease {
        let mut capture = sample_capture(version);
        capture.details = details;
        capture
    }

    fn sample_capture_with_artifacts(
        version: &str,
        artifacts: Vec<CapturedArtifact>,
    ) -> CapturedRelease {
        CapturedRelease {
            event_id: format!("npm:pkg@{version}"),
            ecosystem: Ecosystem::Npm,
            package: "pkg".to_string(),
            version: version.to_string(),
            observed_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
            published_at: Some(Utc.with_ymd_and_hms(2026, 3, 25, 11, 0, 0).unwrap()),
            captured_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
            status: ReleaseStatus::Active,
            package_url: None,
            release_url: None,
            metadata_url: None,
            raw_metadata_path: None,
            artifacts,
            upstream_repository: None,
            details: serde_json::json!({}),
        }
    }

    fn sample_artifact(filename: &str, sha256: Option<&str>) -> CapturedArtifact {
        CapturedArtifact {
            filename: filename.to_string(),
            kind: Some("npm-tarball".to_string()),
            url: Some(format!("https://example.invalid/{filename}")),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: ArtifactHashes {
                sha256: sha256.map(str::to_string),
                ..ArtifactHashes::default()
            },
            provenance_path: None,
        }
    }
}
