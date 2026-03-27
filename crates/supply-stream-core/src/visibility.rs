use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};

use crate::event::Ecosystem;

#[derive(Debug, Clone, Serialize)]
pub struct VisibilityReport {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub probes: Vec<ProbeResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub name: String,
    pub url: String,
    pub state: ProbeState,
    pub checked_at: DateTime<Utc>,
    pub marker: Option<String>,
    pub detail: Value,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeState {
    Visible,
    Missing,
    Unsupported,
    Error,
}

impl ProbeResult {
    fn visible(name: &str, url: String, marker: Option<String>, detail: Value) -> Self {
        Self::new(name, url, ProbeState::Visible, marker, detail)
    }

    fn missing(name: &str, url: String, marker: Option<String>, detail: Value) -> Self {
        Self::new(name, url, ProbeState::Missing, marker, detail)
    }

    fn unsupported(name: &str, url: String, detail: Value) -> Self {
        Self::new(name, url, ProbeState::Unsupported, None, detail)
    }

    fn error(name: &str, url: String, detail: Value) -> Self {
        Self::new(name, url, ProbeState::Error, None, detail)
    }

    fn new(
        name: &str,
        url: String,
        state: ProbeState,
        marker: Option<String>,
        detail: Value,
    ) -> Self {
        Self {
            name: name.to_string(),
            url,
            state,
            checked_at: Utc::now(),
            marker,
            detail,
        }
    }
}

pub async fn locate_release(
    ecosystem: Ecosystem,
    package: &str,
    version: Option<&str>,
) -> Result<VisibilityReport> {
    let http = visibility_http_client()?;
    let probes = match ecosystem {
        Ecosystem::Pypi => locate_pypi(&http, package, version).await,
        Ecosystem::Npm => locate_npm(&http, package, version).await,
        Ecosystem::CratesIo => locate_crates_io(&http, package, version).await,
    };

    Ok(VisibilityReport {
        ecosystem,
        package: package.to_string(),
        version: version.map(str::to_string),
        observed_at: Utc::now(),
        probes,
    })
}

fn visibility_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("supply-stream-visibility/0.1.0")
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()
        .context("failed to build visibility HTTP client")
}

async fn locate_pypi(
    http: &reqwest::Client,
    package: &str,
    version: Option<&str>,
) -> Vec<ProbeResult> {
    let mut probes = Vec::new();
    probes.push(probe_pypi_project_json(http, package, version).await);
    probes.push(
        probe_pypi_simple(
            http,
            "pypi.simple",
            format!(
                "https://pypi.org/simple/{}/",
                urlencoding::encode(&normalize_pypi_name(package))
            ),
            package,
            version,
        )
        .await,
    );
    probes.push(
        probe_pypi_simple(
            http,
            "pypi.mirror.aliyun.simple",
            format!(
                "https://mirrors.aliyun.com/pypi/simple/{}/",
                urlencoding::encode(&normalize_pypi_name(package))
            ),
            package,
            version,
        )
        .await,
    );
    probes.push(
        probe_pypi_simple(
            http,
            "pypi.mirror.tuna.simple",
            format!(
                "https://pypi.tuna.tsinghua.edu.cn/simple/{}/",
                urlencoding::encode(&normalize_pypi_name(package))
            ),
            package,
            version,
        )
        .await,
    );
    probes.push(
        probe_pypi_simple(
            http,
            "pypi.mirror.ustc.simple",
            format!(
                "https://pypi.mirrors.ustc.edu.cn/simple/{}/",
                urlencoding::encode(&normalize_pypi_name(package))
            ),
            package,
            version,
        )
        .await,
    );
    probes.push(
        probe_pypi_simple(
            http,
            "pypi.piwheels.simple",
            format!(
                "https://www.piwheels.org/simple/{}/",
                urlencoding::encode(&normalize_pypi_name(package))
            ),
            package,
            version,
        )
        .await,
    );
    probes
}

async fn probe_pypi_project_json(
    http: &reqwest::Client,
    package: &str,
    version: Option<&str>,
) -> ProbeResult {
    let url = format!(
        "https://pypi.org/pypi/{}/json",
        urlencoding::encode(package)
    );
    let response = match http.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return ProbeResult::error(
                "pypi.project-json",
                url,
                json!({ "error": error.to_string() }),
            );
        }
    };

    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ProbeResult::missing(
            "pypi.project-json",
            url,
            None,
            json!({ "http_status": status.as_u16() }),
        );
    }
    if !status.is_success() {
        return ProbeResult::error(
            "pypi.project-json",
            url,
            json!({ "http_status": status.as_u16() }),
        );
    }

    let raw = match response.json::<Value>().await {
        Ok(raw) => raw,
        Err(error) => {
            return ProbeResult::error(
                "pypi.project-json",
                url,
                json!({ "error": error.to_string() }),
            );
        }
    };

    let marker = raw.get("last_serial").map(Value::to_string);
    let releases = raw
        .get("releases")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let version_count = releases.len();

    match version {
        Some(version) => match releases.get(version).and_then(Value::as_array) {
            Some(files) => {
                let published_at = files
                    .iter()
                    .filter_map(|file| {
                        file.get("upload_time_iso_8601")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .min();
                let yanked = files
                    .iter()
                    .any(|file| file.get("yanked").and_then(Value::as_bool) == Some(true));

                ProbeResult::visible(
                    "pypi.project-json",
                    url,
                    marker,
                    json!({
                        "version_count": version_count,
                        "artifact_count": files.len(),
                        "published_at": published_at,
                        "yanked": yanked,
                        "yanked_reason": files.iter().find_map(|file| file.get("yanked_reason").and_then(Value::as_str)),
                        "filenames": files.iter().filter_map(|file| file.get("filename").and_then(Value::as_str)).collect::<Vec<_>>()
                    }),
                )
            }
            None => ProbeResult::missing(
                "pypi.project-json",
                url,
                marker,
                json!({
                    "version_count": version_count,
                    "version": version
                }),
            ),
        },
        None => ProbeResult::visible(
            "pypi.project-json",
            url,
            marker,
            json!({
                "version_count": version_count,
                "project_status": raw.pointer("/project-status/status")
            }),
        ),
    }
}

async fn probe_pypi_simple(
    http: &reqwest::Client,
    name: &str,
    url: String,
    package: &str,
    version: Option<&str>,
) -> ProbeResult {
    let response = match http.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return ProbeResult::error(name, url, json!({ "error": error.to_string() }));
        }
    };

    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ProbeResult::missing(name, url, None, json!({ "http_status": status.as_u16() }));
    }
    if !status.is_success() {
        return ProbeResult::error(name, url, json!({ "http_status": status.as_u16() }));
    }

    let body = match response.text().await {
        Ok(body) => body,
        Err(error) => {
            return ProbeResult::error(name, url, json!({ "error": error.to_string() }));
        }
    };

    let marker = extract_simple_marker(&body);
    let anchor_texts = extract_anchor_texts(&body);
    match version {
        Some(version) => {
            let filenames = anchor_texts
                .iter()
                .filter(|filename| pypi_filename_matches(filename, package, version))
                .cloned()
                .collect::<Vec<_>>();
            if filenames.is_empty() {
                ProbeResult::missing(
                    name,
                    url,
                    marker,
                    json!({
                        "version": version,
                        "link_count": anchor_texts.len()
                    }),
                )
            } else {
                ProbeResult::visible(
                    name,
                    url,
                    marker,
                    json!({
                        "version": version,
                        "link_count": anchor_texts.len(),
                        "filenames": filenames
                    }),
                )
            }
        }
        None => ProbeResult::visible(
            name,
            url,
            marker,
            json!({
                "link_count": anchor_texts.len()
            }),
        ),
    }
}

async fn locate_npm(
    http: &reqwest::Client,
    package: &str,
    version: Option<&str>,
) -> Vec<ProbeResult> {
    vec![
        probe_npm_packument(http, package, version).await,
        probe_npm_package_json(
            http,
            "npm.unpkg.package-json",
            match version {
                Some(version) => format!("https://unpkg.com/{package}@{version}/package.json"),
                None => format!("https://unpkg.com/{package}/package.json"),
            },
        )
        .await,
        probe_npm_package_json(
            http,
            "npm.jsdelivr.package-json",
            match version {
                Some(version) => {
                    format!("https://cdn.jsdelivr.net/npm/{package}@{version}/package.json")
                }
                None => format!("https://cdn.jsdelivr.net/npm/{package}/package.json"),
            },
        )
        .await,
    ]
}

async fn probe_npm_packument(
    http: &reqwest::Client,
    package: &str,
    version: Option<&str>,
) -> ProbeResult {
    let url = format!(
        "https://registry.npmjs.org/{}",
        urlencoding::encode(package)
    );
    let response = match http.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return ProbeResult::error(
                "npm.registry.packument",
                url,
                json!({ "error": error.to_string() }),
            );
        }
    };

    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ProbeResult::missing(
            "npm.registry.packument",
            url,
            None,
            json!({ "http_status": status.as_u16() }),
        );
    }
    if !status.is_success() {
        return ProbeResult::error(
            "npm.registry.packument",
            url,
            json!({ "http_status": status.as_u16() }),
        );
    }

    let raw = match response.json::<Value>().await {
        Ok(raw) => raw,
        Err(error) => {
            return ProbeResult::error(
                "npm.registry.packument",
                url,
                json!({ "error": error.to_string() }),
            );
        }
    };

    let versions = raw
        .get("versions")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let times = raw
        .get("time")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let marker = times
        .get("modified")
        .and_then(Value::as_str)
        .map(str::to_string);

    match version {
        Some(version) => match versions.get(version) {
            Some(version_meta) => ProbeResult::visible(
                "npm.registry.packument",
                url,
                marker,
                json!({
                    "version_count": versions.len(),
                    "published_at": times.get(version),
                    "deprecated": version_meta.get("deprecated"),
                    "integrity": version_meta.pointer("/dist/integrity"),
                    "shasum": version_meta.pointer("/dist/shasum")
                }),
            ),
            None => ProbeResult::missing(
                "npm.registry.packument",
                url,
                marker,
                json!({
                    "version_count": versions.len(),
                    "version": version,
                    "latest": raw.pointer("/dist-tags/latest")
                }),
            ),
        },
        None => ProbeResult::visible(
            "npm.registry.packument",
            url,
            marker,
            json!({
                "version_count": versions.len(),
                "latest": raw.pointer("/dist-tags/latest")
            }),
        ),
    }
}

async fn probe_npm_package_json(http: &reqwest::Client, name: &str, url: String) -> ProbeResult {
    let response = match http.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return ProbeResult::error(name, url, json!({ "error": error.to_string() }));
        }
    };

    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ProbeResult::missing(name, url, None, json!({ "http_status": status.as_u16() }));
    }
    if !status.is_success() {
        return ProbeResult::error(name, url, json!({ "http_status": status.as_u16() }));
    }

    let final_url = response.url().to_string();
    let body = match response.json::<Value>().await {
        Ok(body) => body,
        Err(error) => {
            return ProbeResult::error(name, url, json!({ "error": error.to_string() }));
        }
    };

    ProbeResult::visible(
        name,
        url,
        None,
        json!({
            "resolved_url": final_url,
            "name": body.get("name"),
            "version": body.get("version")
        }),
    )
}

async fn locate_crates_io(
    http: &reqwest::Client,
    package: &str,
    version: Option<&str>,
) -> Vec<ProbeResult> {
    vec![
        probe_crates_api(http, package, version).await,
        probe_crates_index(http, package, version).await,
        probe_crates_download(http, package, version).await,
    ]
}

async fn probe_crates_api(
    http: &reqwest::Client,
    package: &str,
    version: Option<&str>,
) -> ProbeResult {
    let url = format!(
        "https://crates.io/api/v1/crates/{}",
        urlencoding::encode(package)
    );
    let response = match http.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return ProbeResult::error("crates.api", url, json!({ "error": error.to_string() }));
        }
    };

    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ProbeResult::missing("crates.api", url, None, json!({ "http_status": 404 }));
    }
    if !status.is_success() {
        return ProbeResult::error("crates.api", url, json!({ "http_status": status.as_u16() }));
    }

    let raw = match response.json::<Value>().await {
        Ok(raw) => raw,
        Err(error) => {
            return ProbeResult::error("crates.api", url, json!({ "error": error.to_string() }));
        }
    };

    let versions = raw
        .get("versions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let marker = raw
        .pointer("/crate/updated_at")
        .and_then(Value::as_str)
        .map(str::to_string);

    match version {
        Some(version) => {
            let hit = versions
                .iter()
                .find(|item| item.get("num").and_then(Value::as_str) == Some(version));
            match hit {
                Some(item) => ProbeResult::visible(
                    "crates.api",
                    url,
                    marker,
                    json!({
                        "version_count": versions.len(),
                        "published_at": item.get("created_at"),
                        "yanked": item.get("yanked"),
                        "checksum": item.get("checksum")
                    }),
                ),
                None => ProbeResult::missing(
                    "crates.api",
                    url,
                    marker,
                    json!({
                        "version_count": versions.len(),
                        "version": version,
                        "newest": versions.first().and_then(|item| item.get("num"))
                    }),
                ),
            }
        }
        None => ProbeResult::visible(
            "crates.api",
            url,
            marker,
            json!({
                "version_count": versions.len(),
                "newest": versions.first().and_then(|item| item.get("num"))
            }),
        ),
    }
}

async fn probe_crates_index(
    http: &reqwest::Client,
    package: &str,
    version: Option<&str>,
) -> ProbeResult {
    let index_path = crates_index_path(package);
    let url = format!("https://index.crates.io/{index_path}");
    let response = match http.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return ProbeResult::error("crates.index", url, json!({ "error": error.to_string() }));
        }
    };

    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ProbeResult::missing("crates.index", url, None, json!({ "http_status": 404 }));
    }
    if !status.is_success() {
        return ProbeResult::error(
            "crates.index",
            url,
            json!({ "http_status": status.as_u16() }),
        );
    }

    let body = match response.text().await {
        Ok(body) => body,
        Err(error) => {
            return ProbeResult::error("crates.index", url, json!({ "error": error.to_string() }));
        }
    };

    let rows = body
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();

    match version {
        Some(version) => match rows
            .iter()
            .find(|row| row.get("vers").and_then(Value::as_str) == Some(version))
        {
            Some(row) => ProbeResult::visible(
                "crates.index",
                url,
                None,
                json!({
                    "row_count": rows.len(),
                    "yanked": row.get("yanked"),
                    "checksum": row.get("cksum")
                }),
            ),
            None => ProbeResult::missing(
                "crates.index",
                url,
                None,
                json!({
                    "row_count": rows.len(),
                    "version": version
                }),
            ),
        },
        None => ProbeResult::visible(
            "crates.index",
            url,
            None,
            json!({
                "row_count": rows.len()
            }),
        ),
    }
}

async fn probe_crates_download(
    http: &reqwest::Client,
    package: &str,
    version: Option<&str>,
) -> ProbeResult {
    let Some(version) = version else {
        return ProbeResult::unsupported(
            "crates.download",
            format!("https://crates.io/api/v1/crates/{package}/<version>/download"),
            json!({ "reason": "a specific version is required" }),
        );
    };

    let url = format!("https://crates.io/api/v1/crates/{package}/{version}/download");
    let response = match http.head(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return ProbeResult::error(
                "crates.download",
                url,
                json!({ "error": error.to_string() }),
            );
        }
    };

    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ProbeResult::missing("crates.download", url, None, json!({ "http_status": 404 }));
    }
    if !status.is_success() {
        return ProbeResult::error(
            "crates.download",
            url,
            json!({ "http_status": status.as_u16() }),
        );
    }

    ProbeResult::visible(
        "crates.download",
        url,
        None,
        json!({
            "resolved_url": response.url().to_string(),
            "content_length": response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
        }),
    )
}

fn extract_simple_marker(body: &str) -> Option<String> {
    body.lines().rev().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("<!--")
            .and_then(|line| line.strip_suffix("-->"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn extract_anchor_texts(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let (_, tail) = line.split_once('>')?;
            let (text, _) = tail.split_once("</a>")?;
            Some(text.trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .collect()
}

fn pypi_filename_matches(filename: &str, package: &str, version: &str) -> bool {
    let filename = filename.to_ascii_lowercase();
    pypi_distribution_prefixes(package).iter().any(|prefix| {
        filename.strip_prefix(prefix).is_some_and(|rest| {
            rest.starts_with(&format!("-{version}")) || rest.starts_with(&format!("_{version}"))
        })
    })
}

fn pypi_distribution_prefixes(package: &str) -> Vec<String> {
    let package = package.to_ascii_lowercase();
    let normalized = normalize_pypi_name(&package);
    let mut values = Vec::new();
    for value in [
        package.clone(),
        package.replace('-', "_"),
        package.replace('.', "_"),
        package.replace('.', "-"),
        normalized.clone(),
        normalized.replace('-', "_"),
    ] {
        if !values.contains(&value) {
            values.push(value);
        }
    }
    values
}

fn normalize_pypi_name(name: &str) -> String {
    let mut normalized = String::new();
    let mut saw_separator = false;

    for ch in name.chars() {
        let lower = ch.to_ascii_lowercase();
        if matches!(lower, '-' | '_' | '.') {
            if !saw_separator {
                normalized.push('-');
                saw_separator = true;
            }
        } else {
            normalized.push(lower);
            saw_separator = false;
        }
    }

    normalized
}

fn crates_index_path(package: &str) -> String {
    let package = package.to_ascii_lowercase();
    match package.len() {
        1 => format!("1/{package}"),
        2 => format!("2/{package}"),
        3 => format!("3/{}/{}", &package[..1], package),
        _ => format!("{}/{}/{}", &package[..2], &package[2..4], package),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_pypi_names_like_simple_api() {
        assert_eq!(normalize_pypi_name("My_Package.Name"), "my-package-name");
        assert_eq!(normalize_pypi_name("requests"), "requests");
    }

    #[test]
    fn matches_pypi_wheel_and_sdist_filenames() {
        assert!(pypi_filename_matches(
            "my_package-1.2.3-py3-none-any.whl",
            "my-package",
            "1.2.3"
        ));
        assert!(pypi_filename_matches(
            "my-package-1.2.3.tar.gz",
            "my_package",
            "1.2.3"
        ));
        assert!(!pypi_filename_matches(
            "my-package-1.2.4.tar.gz",
            "my_package",
            "1.2.3"
        ));
    }

    #[test]
    fn computes_crates_index_paths() {
        assert_eq!(crates_index_path("a"), "1/a");
        assert_eq!(crates_index_path("ab"), "2/ab");
        assert_eq!(crates_index_path("abc"), "3/a/abc");
        assert_eq!(crates_index_path("serde"), "se/rd/serde");
    }
}
