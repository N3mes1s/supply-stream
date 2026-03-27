use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::{LazyLock, Mutex},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::process::Command;

use crate::event::Ecosystem;

const GITHUB_API_BASE: &str = "https://api.github.com";
const GITLAB_API_BASE: &str = "https://gitlab.com/api/v4";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_ACCEPT_HEADER: &str = "application/vnd.github+json";
const GITHUB_USER_AGENT: &str = "supply-stream";

static GITHUB_TAG_CACHE: LazyLock<Mutex<HashMap<String, CachedGithubTags>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static GITHUB_RELEASE_CACHE: LazyLock<Mutex<HashMap<String, bool>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static GITLAB_TAG_CACHE: LazyLock<Mutex<HashMap<String, CachedGitlabTag>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone)]
enum CachedGithubTags {
    Names(Vec<String>),
    NotFound,
    Unknown(String),
}

#[derive(Debug, Clone)]
enum CachedGitlabTag {
    Match { has_release: bool },
    NotFound,
    Unknown(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalArtifactKind {
    Wheel,
    PypiSdist,
    NpmTarball,
    CrateTarball,
}

impl LocalArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wheel => "wheel",
            Self::PypiSdist => "sdist",
            Self::NpmTarball => "npm_tarball",
            Self::CrateTarball => "crate_tarball",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryProvider {
    Github,
    Gitlab,
    Unknown,
}

impl RepositoryProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryMatchKind {
    Tag,
    Release,
    None,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryReleaseProvenance {
    pub provider: RepositoryProvider,
    pub repository_url: String,
    pub normalized_repository_url: String,
    pub package_version: String,
    pub checked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_refs: Vec<String>,
    pub match_kind: RepositoryMatchKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_ref: Option<String>,
    pub suspicious: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageRepositoryIdentity {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub provider: RepositoryProvider,
    pub repository_url: String,
    pub normalized_repository_url: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalArtifactProvenanceReport {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub artifact_path: String,
    pub artifact_kind: LocalArtifactKind,
    pub details: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RepositoryReleaseProvenance>,
}

#[derive(Debug, Clone)]
struct ResolvedRepository {
    provider: RepositoryProvider,
    repository_url: String,
    normalized_repository_url: String,
    owner: String,
    name: String,
}

#[derive(Debug, Clone)]
struct ArtifactMetadata {
    version: String,
    details: Value,
}

pub async fn check_release_provenance(
    http: &reqwest::Client,
    ecosystem: Ecosystem,
    version: &str,
    details: &Value,
) -> Result<Option<RepositoryReleaseProvenance>> {
    check_release_provenance_with_api_bases(
        http,
        ecosystem,
        version,
        details,
        GITHUB_API_BASE,
        GITLAB_API_BASE,
    )
    .await
}

pub fn extract_package_repository_identity(
    ecosystem: Ecosystem,
    package: &str,
    details: &Value,
    source: impl Into<String>,
    confidence: Option<f64>,
) -> Option<PackageRepositoryIdentity> {
    let repository_url = extract_repository_url(ecosystem, details)?;
    let checked_at = Utc::now();
    let source = source.into();
    match resolve_repository(&repository_url) {
        Some(repository) => Some(PackageRepositoryIdentity {
            ecosystem,
            package: package.to_string(),
            provider: repository.provider,
            repository_url: repository.repository_url,
            normalized_repository_url: repository.normalized_repository_url,
            source,
            confidence,
            checked_at,
        }),
        None => Some(PackageRepositoryIdentity {
            ecosystem,
            package: package.to_string(),
            provider: RepositoryProvider::Unknown,
            normalized_repository_url: repository_url.clone(),
            repository_url,
            source,
            confidence,
            checked_at,
        }),
    }
}

pub async fn inspect_local_artifact_provenance(
    http: &reqwest::Client,
    ecosystem: Ecosystem,
    package: &str,
    version_override: Option<&str>,
    artifact_path: &Path,
) -> Result<LocalArtifactProvenanceReport> {
    inspect_local_artifact_provenance_with_api_bases(
        http,
        ecosystem,
        package,
        version_override,
        artifact_path,
        GITHUB_API_BASE,
        GITLAB_API_BASE,
    )
    .await
}

pub async fn inspect_local_artifact_provenance_with_api_bases(
    http: &reqwest::Client,
    ecosystem: Ecosystem,
    package: &str,
    version_override: Option<&str>,
    artifact_path: &Path,
    github_api_base: &str,
    gitlab_api_base: &str,
) -> Result<LocalArtifactProvenanceReport> {
    let artifact_kind = classify_local_artifact(artifact_path).with_context(|| {
        format!(
            "failed to classify local artifact {}",
            artifact_path.display()
        )
    })?;
    let metadata = load_local_artifact_metadata(ecosystem, artifact_path, artifact_kind).await?;
    let version = version_override
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or(metadata.version);
    let repository = check_release_provenance_with_api_bases(
        http,
        ecosystem,
        &version,
        &metadata.details,
        github_api_base,
        gitlab_api_base,
    )
    .await?;

    Ok(LocalArtifactProvenanceReport {
        ecosystem,
        package: package.to_string(),
        version,
        artifact_path: artifact_path.display().to_string(),
        artifact_kind,
        details: metadata.details,
        repository,
    })
}

pub async fn check_release_provenance_with_api_bases(
    http: &reqwest::Client,
    ecosystem: Ecosystem,
    version: &str,
    details: &Value,
    github_api_base: &str,
    gitlab_api_base: &str,
) -> Result<Option<RepositoryReleaseProvenance>> {
    let Some(repository_url) = extract_repository_url(ecosystem, details) else {
        return Ok(None);
    };
    let Some(repository) = resolve_repository(&repository_url) else {
        return Ok(Some(RepositoryReleaseProvenance {
            provider: RepositoryProvider::Unknown,
            repository_url: repository_url.clone(),
            normalized_repository_url: repository_url,
            package_version: version.to_string(),
            checked_at: Utc::now(),
            candidate_refs: candidate_version_refs(version),
            match_kind: RepositoryMatchKind::Unknown,
            matched_ref: None,
            suspicious: false,
            reason: "repository host is not yet supported for release parity checks".to_string(),
        }));
    };

    match repository.provider {
        RepositoryProvider::Github => {
            check_github_release_provenance_with_base(http, &repository, version, github_api_base)
                .await
        }
        RepositoryProvider::Gitlab => {
            check_gitlab_release_provenance_with_base(http, &repository, version, gitlab_api_base)
                .await
        }
        RepositoryProvider::Unknown => Ok(None),
    }
}

fn extract_repository_url(ecosystem: Ecosystem, details: &Value) -> Option<String> {
    match ecosystem {
        Ecosystem::Pypi => extract_pypi_repository_url(details),
        Ecosystem::Npm => extract_npm_repository_url(details),
        Ecosystem::CratesIo => extract_crates_repository_url(details),
    }
}

fn classify_local_artifact(path: &Path) -> Result<LocalArtifactKind> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("artifact path does not contain a valid filename")?;
    let canonical = canonical_archive_name(filename).unwrap_or(filename);
    if canonical.ends_with(".whl") {
        return Ok(LocalArtifactKind::Wheel);
    }
    if canonical.ends_with(".crate") {
        return Ok(LocalArtifactKind::CrateTarball);
    }
    if canonical.ends_with(".tgz") {
        return Ok(LocalArtifactKind::NpmTarball);
    }
    if canonical.ends_with(".tar.gz") {
        return Ok(LocalArtifactKind::PypiSdist);
    }
    anyhow::bail!("unsupported local artifact filename: {filename}");
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

async fn load_local_artifact_metadata(
    ecosystem: Ecosystem,
    artifact_path: &Path,
    artifact_kind: LocalArtifactKind,
) -> Result<ArtifactMetadata> {
    match (ecosystem, artifact_kind) {
        (Ecosystem::Pypi, LocalArtifactKind::Wheel) => {
            let entries = list_archive_entries(artifact_path, artifact_kind).await?;
            let metadata_entry = entries
                .into_iter()
                .find(|entry| entry.ends_with(".dist-info/METADATA"))
                .context("wheel does not contain dist-info/METADATA")?;
            let body = read_archive_entry(artifact_path, artifact_kind, &metadata_entry).await?;
            parse_python_metadata(&body)
        }
        (Ecosystem::Pypi, LocalArtifactKind::PypiSdist) => {
            let entries = list_archive_entries(artifact_path, artifact_kind).await?;
            let metadata_entry = entries
                .into_iter()
                .find(|entry| entry.ends_with("/PKG-INFO") || entry == "PKG-INFO")
                .context("sdist does not contain PKG-INFO")?;
            let body = read_archive_entry(artifact_path, artifact_kind, &metadata_entry).await?;
            parse_python_metadata(&body)
        }
        (Ecosystem::Npm, LocalArtifactKind::NpmTarball) => {
            let entries = list_archive_entries(artifact_path, artifact_kind).await?;
            let package_json = entries
                .into_iter()
                .find(|entry| entry == "package/package.json" || entry.ends_with("/package.json"))
                .context("npm tarball does not contain package.json")?;
            let body = read_archive_entry(artifact_path, artifact_kind, &package_json).await?;
            parse_npm_package_json(&body)
        }
        (Ecosystem::CratesIo, LocalArtifactKind::CrateTarball) => {
            let entries = list_archive_entries(artifact_path, artifact_kind).await?;
            let cargo_toml = entries
                .into_iter()
                .find(|entry| entry.ends_with("/Cargo.toml") || entry == "Cargo.toml")
                .context("crate tarball does not contain Cargo.toml")?;
            let body = read_archive_entry(artifact_path, artifact_kind, &cargo_toml).await?;
            parse_cargo_toml(&body)
        }
        _ => anyhow::bail!(
            "unsupported local provenance inspection for {:?} {}",
            ecosystem,
            artifact_kind.as_str()
        ),
    }
}

async fn list_archive_entries(
    artifact_path: &Path,
    artifact_kind: LocalArtifactKind,
) -> Result<Vec<String>> {
    let mut command = match artifact_kind {
        LocalArtifactKind::Wheel => {
            let mut command = Command::new("unzip");
            command.arg("-Z1").arg(artifact_path);
            command
        }
        LocalArtifactKind::PypiSdist
        | LocalArtifactKind::NpmTarball
        | LocalArtifactKind::CrateTarball => {
            let mut command = Command::new("tar");
            command.arg("-tzf").arg(artifact_path);
            command
        }
    };
    let output = command.output().await.with_context(|| {
        format!(
            "failed to list archive entries for {}",
            artifact_path.display()
        )
    })?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to list archive entries for {}: {}",
            artifact_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

async fn read_archive_entry(
    artifact_path: &Path,
    artifact_kind: LocalArtifactKind,
    entry: &str,
) -> Result<String> {
    let mut command = match artifact_kind {
        LocalArtifactKind::Wheel => {
            let mut command = Command::new("unzip");
            command.arg("-p").arg(artifact_path).arg(entry);
            command
        }
        LocalArtifactKind::PypiSdist
        | LocalArtifactKind::NpmTarball
        | LocalArtifactKind::CrateTarball => {
            let mut command = Command::new("tar");
            command.arg("-xOf").arg(artifact_path).arg(entry);
            command
        }
    };
    let output = command.output().await.with_context(|| {
        format!(
            "failed to read archive entry {} from {}",
            entry,
            artifact_path.display()
        )
    })?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to read archive entry {} from {}: {}",
            entry,
            artifact_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_python_metadata(body: &str) -> Result<ArtifactMetadata> {
    let headers = parse_rfc822_headers(body);
    let version = headers
        .get("Version")
        .cloned()
        .context("python metadata does not contain Version")?;
    let home_page = headers.get("Home-page").cloned();
    let mut project_urls = BTreeMap::new();
    for value in headers.get_all("Project-URL") {
        if let Some((label, url)) = value.split_once(',') {
            let label = label.trim();
            let url = url.trim();
            if !label.is_empty() && !url.is_empty() {
                project_urls.insert(label.to_string(), Value::String(url.to_string()));
            }
        }
    }
    Ok(ArtifactMetadata {
        version,
        details: serde_json::json!({
            "home_page": home_page,
            "project_urls": if project_urls.is_empty() { Value::Null } else { Value::Object(project_urls.into_iter().collect()) }
        }),
    })
}

fn parse_npm_package_json(body: &str) -> Result<ArtifactMetadata> {
    let raw: Value = serde_json::from_str(body).context("failed to decode package.json")?;
    let version = raw
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .context("package.json does not contain version")?;
    Ok(ArtifactMetadata {
        version,
        details: serde_json::json!({
            "repository": raw.get("repository"),
        }),
    })
}

fn parse_cargo_toml(body: &str) -> Result<ArtifactMetadata> {
    let mut in_package = false;
    let mut version = None;
    let mut repository = None;
    let mut homepage = None;

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_package = trimmed == "[package]";
            continue;
        }
        if !in_package || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').to_string();
        match key {
            "version" if !value.is_empty() => version = Some(value),
            "repository" if !value.is_empty() => repository = Some(value),
            "homepage" if !value.is_empty() => homepage = Some(value),
            _ => {}
        }
    }

    Ok(ArtifactMetadata {
        version: version.context("Cargo.toml does not contain package.version")?,
        details: serde_json::json!({
            "crate": {
                "repository": repository,
                "homepage": homepage
            }
        }),
    })
}

#[derive(Default)]
struct MultiHeaders {
    first: BTreeMap<String, String>,
    all: BTreeMap<String, Vec<String>>,
}

impl MultiHeaders {
    fn insert(&mut self, key: String, value: String) {
        self.first
            .entry(key.clone())
            .or_insert_with(|| value.clone());
        self.all.entry(key).or_default().push(value);
    }

    fn get(&self, key: &str) -> Option<&String> {
        self.first.get(key)
    }

    fn get_all(&self, key: &str) -> &[String] {
        self.all.get(key).map(Vec::as_slice).unwrap_or(&[])
    }
}

fn parse_rfc822_headers(body: &str) -> MultiHeaders {
    let mut headers = MultiHeaders::default();
    let mut current_key: Option<String> = None;
    let mut current_value = String::new();

    let flush = |headers: &mut MultiHeaders, key: &mut Option<String>, value: &mut String| {
        if let Some(key) = key.take() {
            headers.insert(key, value.trim().to_string());
            value.clear();
        }
    };

    for line in body.lines() {
        if line.trim().is_empty() {
            flush(&mut headers, &mut current_key, &mut current_value);
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if !current_value.is_empty() {
                current_value.push(' ');
            }
            current_value.push_str(line.trim());
            continue;
        }
        flush(&mut headers, &mut current_key, &mut current_value);
        if let Some((key, value)) = line.split_once(':') {
            current_key = Some(key.trim().to_string());
            current_value.push_str(value.trim());
        }
    }
    flush(&mut headers, &mut current_key, &mut current_value);
    headers
}

fn extract_pypi_repository_url(details: &Value) -> Option<String> {
    let project_urls = details.get("project_urls")?;
    let preferred_keys = [
        "Source",
        "Source Code",
        "Repository",
        "Code",
        "Homepage",
        "Home",
    ];
    for key in preferred_keys {
        if let Some(value) = project_urls.get(key).and_then(Value::as_str)
            && !value.trim().is_empty()
        {
            return Some(value.trim().to_string());
        }
    }

    details
        .get("home_page")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
}

fn extract_npm_repository_url(details: &Value) -> Option<String> {
    let repository = details.get("repository")?;
    if let Some(url) = repository.get("url").and_then(Value::as_str)
        && !url.trim().is_empty()
    {
        return Some(url.trim().to_string());
    }
    repository
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
}

fn extract_crates_repository_url(details: &Value) -> Option<String> {
    details
        .pointer("/crate/repository")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
        .or_else(|| {
            details
                .pointer("/crate/homepage")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(|value| value.trim().to_string())
        })
}

fn resolve_repository(raw: &str) -> Option<ResolvedRepository> {
    let trimmed = raw.trim();
    let without_prefix = trimmed
        .strip_prefix("git+")
        .or_else(|| trimmed.strip_prefix("git://"))
        .unwrap_or(trimmed);
    let without_git_suffix = without_prefix
        .strip_suffix(".git")
        .unwrap_or(without_prefix);
    let candidate = without_git_suffix
        .replace("git@github.com:", "https://github.com/")
        .replace("git@gitlab.com:", "https://gitlab.com/");
    let normalized = candidate
        .strip_prefix("https://")
        .or_else(|| candidate.strip_prefix("http://"))
        .unwrap_or(candidate.as_str());
    let normalized = normalized.strip_prefix("www.").unwrap_or(normalized);

    let mut parts = normalized.split('/');
    let host = parts.next()?.to_ascii_lowercase();
    let owner = parts.next()?.trim();
    let name = parts.next()?.trim();
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    let name = name.strip_suffix(".git").unwrap_or(name);
    let provider = if host == "github.com" {
        RepositoryProvider::Github
    } else if host == "gitlab.com" {
        RepositoryProvider::Gitlab
    } else {
        RepositoryProvider::Unknown
    };

    Some(ResolvedRepository {
        provider,
        repository_url: raw.to_string(),
        normalized_repository_url: format!("https://{host}/{owner}/{name}"),
        owner: owner.to_string(),
        name: name.to_string(),
    })
}

fn candidate_version_refs(version: &str) -> Vec<String> {
    let mut values = Vec::new();
    let normalized = version.trim();
    if !normalized.is_empty() {
        values.push(normalized.to_string());
        if !normalized.starts_with('v') {
            values.push(format!("v{normalized}"));
        } else if let Some(stripped) = normalized.strip_prefix('v')
            && !stripped.is_empty()
        {
            values.push(stripped.to_string());
        }
    }
    values.sort();
    values.dedup();
    values
}

async fn check_github_release_provenance_with_base(
    http: &reqwest::Client,
    repository: &ResolvedRepository,
    version: &str,
    api_base: &str,
) -> Result<Option<RepositoryReleaseProvenance>> {
    let candidates = candidate_version_refs(version);
    let github_token = github_api_token();
    let tags_url = format!(
        "{}/repos/{}/{}/tags?per_page=100",
        api_base, repository.owner, repository.name
    );
    let tags_cache_key = format!("{}|{}|{}", api_base, repository.owner, repository.name);
    let cached_tags = {
        let guard = GITHUB_TAG_CACHE.lock().unwrap();
        guard.get(&tags_cache_key).cloned()
    };
    let tags = match cached_tags {
        Some(CachedGithubTags::Names(names)) => names,
        Some(CachedGithubTags::NotFound) => {
            return Ok(Some(unknown_provenance(
                repository,
                version,
                candidates,
                "GitHub repository or tags endpoint was not found",
            )));
        }
        Some(CachedGithubTags::Unknown(reason)) => {
            return Ok(Some(unknown_provenance(
                repository, version, candidates, &reason,
            )));
        }
        None => {
            let tags_response = github_request(http.get(&tags_url), github_token.as_deref())
                .send()
                .await
                .with_context(|| {
                    format!(
                        "failed to fetch GitHub tags for {}",
                        repository.normalized_repository_url
                    )
                })?;

            if tags_response.status() == StatusCode::NOT_FOUND {
                let reason = "GitHub repository or tags endpoint was not found".to_string();
                GITHUB_TAG_CACHE
                    .lock()
                    .unwrap()
                    .insert(tags_cache_key, CachedGithubTags::NotFound);
                return Ok(Some(unknown_provenance(
                    repository, version, candidates, &reason,
                )));
            }
            if tags_response.status() != StatusCode::OK {
                let reason = format!(
                    "GitHub tags parity check returned status {}",
                    tags_response.status()
                );
                GITHUB_TAG_CACHE
                    .lock()
                    .unwrap()
                    .insert(tags_cache_key, CachedGithubTags::Unknown(reason.clone()));
                return Ok(Some(unknown_provenance(
                    repository, version, candidates, &reason,
                )));
            }
            let names = tags_response
                .json::<Vec<Value>>()
                .await
                .with_context(|| {
                    format!(
                        "failed to decode GitHub tags for {}",
                        repository.normalized_repository_url
                    )
                })?
                .into_iter()
                .filter_map(|tag| tag.get("name").and_then(Value::as_str).map(str::to_string))
                .collect::<Vec<_>>();
            GITHUB_TAG_CACHE
                .lock()
                .unwrap()
                .insert(tags_cache_key, CachedGithubTags::Names(names.clone()));
            names
        }
    };

    for candidate in &candidates {
        if tags.iter().any(|tag| tag == candidate) {
            return Ok(Some(RepositoryReleaseProvenance {
                provider: RepositoryProvider::Github,
                repository_url: repository.repository_url.clone(),
                normalized_repository_url: repository.normalized_repository_url.clone(),
                package_version: version.to_string(),
                checked_at: Utc::now(),
                candidate_refs: candidates.clone(),
                match_kind: RepositoryMatchKind::Tag,
                matched_ref: Some(candidate.clone()),
                suspicious: false,
                reason: "found matching GitHub tag for package version".to_string(),
            }));
        }
    }

    for candidate in &candidates {
        let release_cache_key = format!(
            "{}|{}|{}|{}",
            api_base, repository.owner, repository.name, candidate
        );
        if let Some(found) = GITHUB_RELEASE_CACHE
            .lock()
            .unwrap()
            .get(&release_cache_key)
            .copied()
        {
            if found {
                return Ok(Some(RepositoryReleaseProvenance {
                    provider: RepositoryProvider::Github,
                    repository_url: repository.repository_url.clone(),
                    normalized_repository_url: repository.normalized_repository_url.clone(),
                    package_version: version.to_string(),
                    checked_at: Utc::now(),
                    candidate_refs: candidates.clone(),
                    match_kind: RepositoryMatchKind::Release,
                    matched_ref: Some(candidate.clone()),
                    suspicious: false,
                    reason: "found matching GitHub release for package version".to_string(),
                }));
            }
            continue;
        }
        let release_url = format!(
            "{}/repos/{}/{}/releases/tags/{}",
            api_base,
            repository.owner,
            repository.name,
            urlencoding::encode(candidate)
        );
        let response = github_request(http.get(&release_url), github_token.as_deref())
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to fetch GitHub release for {}",
                    repository.normalized_repository_url
                )
            })?;
        if response.status() == StatusCode::OK {
            GITHUB_RELEASE_CACHE
                .lock()
                .unwrap()
                .insert(release_cache_key, true);
            return Ok(Some(RepositoryReleaseProvenance {
                provider: RepositoryProvider::Github,
                repository_url: repository.repository_url.clone(),
                normalized_repository_url: repository.normalized_repository_url.clone(),
                package_version: version.to_string(),
                checked_at: Utc::now(),
                candidate_refs: candidates.clone(),
                match_kind: RepositoryMatchKind::Release,
                matched_ref: Some(candidate.clone()),
                suspicious: false,
                reason: "found matching GitHub release for package version".to_string(),
            }));
        }
        if response.status() == StatusCode::NOT_FOUND {
            GITHUB_RELEASE_CACHE
                .lock()
                .unwrap()
                .insert(release_cache_key, false);
            continue;
        }
        if response.status() != StatusCode::NOT_FOUND {
            return Ok(Some(unknown_provenance(
                repository,
                version,
                candidates,
                "GitHub release parity check returned an unexpected status",
            )));
        }
    }

    Ok(Some(mismatch_provenance(
        repository,
        version,
        candidates,
        "repository resolved on GitHub but no matching tag or release was found for the package version",
    )))
}

fn github_api_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GH_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}

fn github_request(
    request: reqwest::RequestBuilder,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    let request = request
        .header(USER_AGENT, HeaderValue::from_static(GITHUB_USER_AGENT))
        .header(ACCEPT, HeaderValue::from_static(GITHUB_ACCEPT_HEADER))
        .header(
            "X-GitHub-Api-Version",
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
    match token {
        Some(token) => request.header(AUTHORIZATION, format!("Bearer {token}")),
        None => request,
    }
}

async fn check_gitlab_release_provenance_with_base(
    http: &reqwest::Client,
    repository: &ResolvedRepository,
    version: &str,
    api_base: &str,
) -> Result<Option<RepositoryReleaseProvenance>> {
    let candidates = candidate_version_refs(version);
    let project = format!("{}/{}", repository.owner, repository.name);
    let encoded_project = urlencoding::encode(&project);

    for candidate in &candidates {
        let cache_key = format!("{}|{}|{}", api_base, encoded_project, candidate);
        if let Some(cached) = GITLAB_TAG_CACHE.lock().unwrap().get(&cache_key).cloned() {
            match cached {
                CachedGitlabTag::Match { has_release } => {
                    return Ok(Some(RepositoryReleaseProvenance {
                        provider: RepositoryProvider::Gitlab,
                        repository_url: repository.repository_url.clone(),
                        normalized_repository_url: repository.normalized_repository_url.clone(),
                        package_version: version.to_string(),
                        checked_at: Utc::now(),
                        candidate_refs: candidates.clone(),
                        match_kind: if has_release {
                            RepositoryMatchKind::Release
                        } else {
                            RepositoryMatchKind::Tag
                        },
                        matched_ref: Some(candidate.clone()),
                        suspicious: false,
                        reason: if has_release {
                            "found matching GitLab tag with release metadata for package version"
                                .to_string()
                        } else {
                            "found matching GitLab tag for package version".to_string()
                        },
                    }));
                }
                CachedGitlabTag::NotFound => continue,
                CachedGitlabTag::Unknown(reason) => {
                    return Ok(Some(unknown_provenance(
                        repository, version, candidates, &reason,
                    )));
                }
            }
        }
        let tag_url = format!(
            "{}/projects/{}/repository/tags/{}",
            api_base,
            encoded_project,
            urlencoding::encode(candidate)
        );
        let response = http.get(&tag_url).send().await.with_context(|| {
            format!(
                "failed to fetch GitLab tag for {}",
                repository.normalized_repository_url
            )
        })?;
        if response.status() == StatusCode::OK {
            let body = response.json::<Value>().await.with_context(|| {
                format!(
                    "failed to decode GitLab tag for {}",
                    repository.normalized_repository_url
                )
            })?;
            let has_release = body.get("release").is_some_and(|value| !value.is_null());
            GITLAB_TAG_CACHE
                .lock()
                .unwrap()
                .insert(cache_key, CachedGitlabTag::Match { has_release });
            return Ok(Some(RepositoryReleaseProvenance {
                provider: RepositoryProvider::Gitlab,
                repository_url: repository.repository_url.clone(),
                normalized_repository_url: repository.normalized_repository_url.clone(),
                package_version: version.to_string(),
                checked_at: Utc::now(),
                candidate_refs: candidates.clone(),
                match_kind: if has_release {
                    RepositoryMatchKind::Release
                } else {
                    RepositoryMatchKind::Tag
                },
                matched_ref: Some(candidate.clone()),
                suspicious: false,
                reason: if has_release {
                    "found matching GitLab tag with release metadata for package version"
                        .to_string()
                } else {
                    "found matching GitLab tag for package version".to_string()
                },
            }));
        }
        if response.status() == StatusCode::NOT_FOUND {
            GITLAB_TAG_CACHE
                .lock()
                .unwrap()
                .insert(cache_key, CachedGitlabTag::NotFound);
            continue;
        }
        if response.status() != StatusCode::NOT_FOUND {
            let reason = "GitLab release parity check returned an unexpected status".to_string();
            GITLAB_TAG_CACHE
                .lock()
                .unwrap()
                .insert(cache_key, CachedGitlabTag::Unknown(reason.clone()));
            return Ok(Some(unknown_provenance(
                repository, version, candidates, &reason,
            )));
        }
    }

    Ok(Some(mismatch_provenance(
        repository,
        version,
        candidates,
        "repository resolved on GitLab but no matching tag or release was found for the package version",
    )))
}

fn mismatch_provenance(
    repository: &ResolvedRepository,
    version: &str,
    candidates: Vec<String>,
    reason: &str,
) -> RepositoryReleaseProvenance {
    RepositoryReleaseProvenance {
        provider: repository.provider,
        repository_url: repository.repository_url.clone(),
        normalized_repository_url: repository.normalized_repository_url.clone(),
        package_version: version.to_string(),
        checked_at: Utc::now(),
        candidate_refs: candidates,
        match_kind: RepositoryMatchKind::None,
        matched_ref: None,
        suspicious: true,
        reason: reason.to_string(),
    }
}

fn unknown_provenance(
    repository: &ResolvedRepository,
    version: &str,
    candidates: Vec<String>,
    reason: &str,
) -> RepositoryReleaseProvenance {
    RepositoryReleaseProvenance {
        provider: repository.provider,
        repository_url: repository.repository_url.clone(),
        normalized_repository_url: repository.normalized_repository_url.clone(),
        package_version: version.to_string(),
        checked_at: Utc::now(),
        candidate_refs: candidates,
        match_kind: RepositoryMatchKind::Unknown,
        matched_ref: None,
        suspicious: false,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn extracts_pypi_project_url_repository() {
        let details = json!({
            "project_urls": {
                "Source": "https://github.com/BerriAI/litellm"
            }
        });
        assert_eq!(
            extract_repository_url(Ecosystem::Pypi, &details).as_deref(),
            Some("https://github.com/BerriAI/litellm")
        );
    }

    #[test]
    fn extracts_npm_repository_url_object() {
        let details = json!({
            "repository": {
                "type": "git",
                "url": "git+https://github.com/foo/bar.git"
            }
        });
        assert_eq!(
            extract_repository_url(Ecosystem::Npm, &details).as_deref(),
            Some("git+https://github.com/foo/bar.git")
        );
    }

    #[test]
    fn resolves_github_repository_variants() {
        let resolved = resolve_repository("git+https://github.com/foo/bar.git").unwrap();
        assert_eq!(resolved.provider, RepositoryProvider::Github);
        assert_eq!(
            resolved.normalized_repository_url,
            "https://github.com/foo/bar"
        );
        assert_eq!(resolved.owner, "foo");
        assert_eq!(resolved.name, "bar");
    }

    #[test]
    fn candidate_refs_include_plain_and_v_prefixed_versions() {
        assert_eq!(
            candidate_version_refs("4.87.2"),
            vec!["4.87.2".to_string(), "v4.87.2".to_string()]
        );
        assert_eq!(
            candidate_version_refs("v1.2.3"),
            vec!["1.2.3".to_string(), "v1.2.3".to_string()]
        );
    }

    #[test]
    fn parses_python_metadata_from_wheel_headers() {
        let metadata = parse_python_metadata(
            "Metadata-Version: 2.1\nName: telnyx\nVersion: 4.87.2\nProject-URL: Homepage, https://github.com/team-telnyx/telnyx-python\nProject-URL: Repository, https://github.com/team-telnyx/telnyx-python\n\nbody",
        )
        .unwrap();
        assert_eq!(metadata.version, "4.87.2");
        assert_eq!(
            extract_repository_url(Ecosystem::Pypi, &metadata.details).as_deref(),
            Some("https://github.com/team-telnyx/telnyx-python")
        );
    }

    #[test]
    fn parses_npm_package_json_repository() {
        let metadata = parse_npm_package_json(
            r#"{"name":"pkg-a","version":"1.2.3","repository":{"type":"git","url":"git+https://github.com/foo/bar.git"}}"#,
        )
        .unwrap();
        assert_eq!(metadata.version, "1.2.3");
        assert_eq!(
            extract_repository_url(Ecosystem::Npm, &metadata.details).as_deref(),
            Some("git+https://github.com/foo/bar.git")
        );
    }

    #[test]
    fn github_request_sets_expected_headers() {
        let http = reqwest::Client::builder().build().unwrap();
        let request = github_request(
            http.get("https://api.github.com/repos/foo/bar"),
            Some("test_pat"),
        )
        .build()
        .unwrap();
        assert_eq!(
            request.headers().get(USER_AGENT).unwrap(),
            GITHUB_USER_AGENT
        );
        assert_eq!(request.headers().get(ACCEPT).unwrap(), GITHUB_ACCEPT_HEADER);
        assert_eq!(
            request.headers().get("X-GitHub-Api-Version").unwrap(),
            GITHUB_API_VERSION
        );
        assert_eq!(
            request.headers().get(AUTHORIZATION).unwrap(),
            "Bearer test_pat"
        );
    }

    #[tokio::test]
    async fn github_release_provenance_flags_missing_upstream_release() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 4096];
                let read = socket.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..read]);
                let first_line = request.lines().next().unwrap_or_default();
                let path = first_line.split_whitespace().nth(1).unwrap_or_default();
                let (status, body) = if path == "/repos/team-telnyx/telnyx-python/tags?per_page=100"
                {
                    ("200 OK", r#"[{"name":"v4.87.0"}]"#)
                } else {
                    ("404 Not Found", "{}")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let repository =
            resolve_repository("https://github.com/team-telnyx/telnyx-python").unwrap();
        let http = reqwest::Client::builder().build().unwrap();
        let result = check_github_release_provenance_with_base(
            &http,
            &repository,
            "4.87.2",
            &format!("http://{addr}"),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();

        assert_eq!(result.provider, RepositoryProvider::Github);
        assert_eq!(result.match_kind, RepositoryMatchKind::None);
        assert!(result.suspicious);
        assert_eq!(result.matched_ref, None);
    }

    #[tokio::test]
    async fn github_release_provenance_accepts_matching_tag() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            let body = r#"[{"name":"v4.87.0"}]"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let repository =
            resolve_repository("https://github.com/team-telnyx/telnyx-python").unwrap();
        let http = reqwest::Client::builder().build().unwrap();
        let result = check_github_release_provenance_with_base(
            &http,
            &repository,
            "4.87.0",
            &format!("http://{addr}"),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();

        assert_eq!(result.match_kind, RepositoryMatchKind::Tag);
        assert!(!result.suspicious);
        assert_eq!(result.matched_ref.as_deref(), Some("v4.87.0"));
    }
}
