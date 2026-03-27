use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    event::Ecosystem,
    priority::{PackageCensusRecord, normalize_package_name},
};

const PYPI_SIMPLE_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

#[derive(Debug, Clone)]
pub struct NativeCensusConfig {
    pub pypi_base: String,
    pub npm_all_docs_base: String,
    pub crates_io_base: String,
    pub request_timeout: Duration,
    pub npm_page_size: usize,
    pub npm_limit: usize,
    pub pypi_limit: usize,
    pub crates_page_size: usize,
    pub crates_limit: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeCensusSummary {
    pub ecosystems: Vec<NativeCensusEcosystemSummary>,
    pub emitted_records: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeCensusEcosystemSummary {
    pub ecosystem: Ecosystem,
    pub packages: usize,
}

pub async fn import_native_package_census_live(
    ecosystems: &[Ecosystem],
    config: &NativeCensusConfig,
) -> Result<(Vec<PackageCensusRecord>, NativeCensusSummary)> {
    let http = reqwest::Client::builder()
        .user_agent("supply-stream-census/0.1.0")
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(config.request_timeout)
        .build()
        .context("failed to build native census HTTP client")?;
    import_native_package_census_with_http(&http, ecosystems, config).await
}

async fn import_native_package_census_with_http(
    http: &reqwest::Client,
    ecosystems: &[Ecosystem],
    config: &NativeCensusConfig,
) -> Result<(Vec<PackageCensusRecord>, NativeCensusSummary)> {
    let mut packages = BTreeMap::<(Ecosystem, String), PackageCensusRecord>::new();
    let mut ecosystems_summary = Vec::new();

    for ecosystem in ecosystems {
        let discovered = match ecosystem {
            Ecosystem::Pypi => fetch_pypi_simple_packages(http, config).await?,
            Ecosystem::Npm => fetch_npm_all_docs_packages(http, config).await?,
            Ecosystem::CratesIo => fetch_crates_io_packages(http, config).await?,
        };

        for package in &discovered {
            packages.insert(
                (*ecosystem, package.clone()),
                PackageCensusRecord {
                    ecosystem: *ecosystem,
                    package: package.clone(),
                    discovered_at: None,
                    source: Some(
                        match ecosystem {
                            Ecosystem::Pypi => "pypi_simple_index",
                            Ecosystem::Npm => "npm_all_docs",
                            Ecosystem::CratesIo => "crates_io_native",
                        }
                        .to_string(),
                    ),
                },
            );
        }

        ecosystems_summary.push(NativeCensusEcosystemSummary {
            ecosystem: *ecosystem,
            packages: discovered.len(),
        });
    }

    let records = packages.into_values().collect::<Vec<_>>();
    Ok((
        records.clone(),
        NativeCensusSummary {
            ecosystems: ecosystems_summary,
            emitted_records: records.len(),
        },
    ))
}

#[derive(Debug, Deserialize)]
struct PypiSimpleIndex {
    #[serde(default)]
    projects: Vec<PypiSimpleProject>,
}

#[derive(Debug, Deserialize)]
struct PypiSimpleProject {
    name: String,
}

async fn fetch_pypi_simple_packages(
    http: &reqwest::Client,
    config: &NativeCensusConfig,
) -> Result<Vec<String>> {
    let url = format!("{}/simple/", config.pypi_base.trim_end_matches('/'));
    let payload = http
        .get(url)
        .header(reqwest::header::ACCEPT, PYPI_SIMPLE_ACCEPT)
        .send()
        .await
        .context("failed to fetch PyPI simple index")?
        .error_for_status()
        .context("PyPI simple index returned an error")?
        .json::<PypiSimpleIndex>()
        .await
        .context("failed to decode PyPI simple index")?;

    let limit = if config.pypi_limit == 0 {
        usize::MAX
    } else {
        config.pypi_limit
    };

    Ok(payload
        .projects
        .into_iter()
        .take(limit)
        .map(|project| normalize_package_name(Ecosystem::Pypi, &project.name))
        .collect())
}

#[derive(Debug, Deserialize)]
struct NpmAllDocsResponse {
    #[serde(default)]
    rows: Vec<NpmAllDocsRow>,
}

#[derive(Debug, Deserialize)]
struct NpmAllDocsRow {
    id: String,
}

async fn fetch_npm_all_docs_packages(
    http: &reqwest::Client,
    config: &NativeCensusConfig,
) -> Result<Vec<String>> {
    let limit = if config.npm_limit == 0 {
        usize::MAX
    } else {
        config.npm_limit
    };
    let page_size = config.npm_page_size.max(1);
    let mut packages = Vec::new();
    let mut last_id: Option<String> = None;

    while packages.len() < limit {
        let mut url = format!(
            "{}?limit={}",
            config.npm_all_docs_base.trim_end_matches('/'),
            page_size
        );
        if let Some(last) = &last_id {
            let startkey =
                serde_json::to_string(last).context("failed to encode npm all docs startkey")?;
            url.push_str("&startkey=");
            url.push_str(&urlencoding::encode(&startkey));
        }

        let response = http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failed to fetch npm all docs page from {url}"))?
            .error_for_status()
            .with_context(|| format!("npm all docs returned an error for {url}"))?
            .json::<NpmAllDocsResponse>()
            .await
            .with_context(|| format!("failed to decode npm all docs page from {url}"))?;

        if response.rows.is_empty() {
            break;
        }

        let mut emitted = 0usize;
        for row in response.rows {
            if row.id.starts_with('_') {
                continue;
            }
            if last_id.as_deref() == Some(row.id.as_str()) {
                continue;
            }
            last_id = Some(row.id.clone());
            packages.push(normalize_package_name(Ecosystem::Npm, &row.id));
            emitted += 1;
            if packages.len() >= limit {
                break;
            }
        }

        if emitted == 0 {
            break;
        }
    }

    Ok(packages)
}

#[derive(Debug, Deserialize)]
struct CratesIoIndexResponse {
    #[serde(default)]
    crates: Vec<CratesIoPackage>,
    meta: CratesIoMeta,
}

#[derive(Debug, Deserialize)]
struct CratesIoPackage {
    name: String,
}

#[derive(Debug, Deserialize)]
struct CratesIoMeta {
    next_page: Option<String>,
}

async fn fetch_crates_io_packages(
    http: &reqwest::Client,
    config: &NativeCensusConfig,
) -> Result<Vec<String>> {
    let limit = if config.crates_limit == 0 {
        usize::MAX
    } else {
        config.crates_limit
    };
    let per_page = config.crates_page_size.clamp(1, 100);
    let mut packages = Vec::new();
    let mut page = 1usize;

    while packages.len() < limit {
        let url = format!(
            "{}/api/v1/crates?page={page}&per_page={per_page}",
            config.crates_io_base.trim_end_matches('/')
        );
        let response = http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failed to fetch crates.io page from {url}"))?
            .error_for_status()
            .with_context(|| format!("crates.io returned an error for {url}"))?
            .json::<CratesIoIndexResponse>()
            .await
            .with_context(|| format!("failed to decode crates.io page from {url}"))?;

        if response.crates.is_empty() {
            break;
        }

        for krate in response.crates {
            packages.push(normalize_package_name(Ecosystem::CratesIo, &krate.name));
            if packages.len() >= limit {
                break;
            }
        }

        if packages.len() >= limit || response.meta.next_page.is_none() {
            break;
        }
        page += 1;
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn imports_pypi_npm_and_crates_native_census() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 4096];
                let read = socket.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..read]);
                let (status, body) = if request.starts_with("GET /simple/ ") {
                    (
                        "200 OK",
                        serde_json::json!({
                            "projects": [{"name":"Requests"},{"name":"LiteLLM"}]
                        })
                        .to_string(),
                    )
                } else if request.contains("/registry/_all_docs?limit=2") {
                    (
                        "200 OK",
                        serde_json::json!({
                            "rows": [{"id":"react"},{"id":"vite"}]
                        })
                        .to_string(),
                    )
                } else if request.contains("/api/v1/crates?page=1&per_page=2") {
                    (
                        "200 OK",
                        serde_json::json!({
                            "crates": [{"name":"serde"},{"name":"tokio"}],
                            "meta": {"next_page": null}
                        })
                        .to_string(),
                    )
                } else {
                    ("200 OK", serde_json::json!({"rows":[]}).to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let (records, summary) = import_native_package_census_with_http(
            &reqwest::Client::builder().build().unwrap(),
            &[Ecosystem::Pypi, Ecosystem::Npm, Ecosystem::CratesIo],
            &NativeCensusConfig {
                pypi_base: format!("http://{addr}"),
                npm_all_docs_base: format!("http://{addr}/registry/_all_docs"),
                crates_io_base: format!("http://{addr}"),
                request_timeout: Duration::from_secs(2),
                npm_page_size: 2,
                npm_limit: 2,
                pypi_limit: 2,
                crates_page_size: 2,
                crates_limit: 2,
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.emitted_records, 6);
        assert!(
            records.iter().any(|record| {
                record.ecosystem == Ecosystem::Pypi && record.package == "requests"
            })
        );
        assert!(
            records.iter().any(|record| {
                record.ecosystem == Ecosystem::Pypi && record.package == "litellm"
            })
        );
        assert!(
            records
                .iter()
                .any(|record| { record.ecosystem == Ecosystem::Npm && record.package == "react" })
        );
        assert!(
            records
                .iter()
                .any(|record| { record.ecosystem == Ecosystem::Npm && record.package == "vite" })
        );
        assert!(records.iter().any(|record| {
            record.ecosystem == Ecosystem::CratesIo && record.package == "serde"
        }));
        assert!(records.iter().any(|record| {
            record.ecosystem == Ecosystem::CratesIo && record.package == "tokio"
        }));

        server.await.unwrap();
    }
}
