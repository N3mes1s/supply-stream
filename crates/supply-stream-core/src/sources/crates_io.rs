use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use git2::{DiffOptions, Oid, Repository, Sort};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    config::CratesConfig,
    event::{Ecosystem, PackageReleaseEvent},
    sources::{PackageSource, sleep_or_shutdown},
    state::{FileStateStore, RecentKeys, RecentKeysState},
};

const CRATES_SUMMARY_URL: &str = "https://crates.io/api/v1/summary";
const CRATES_INDEX_GIT_URL: &str = "https://github.com/rust-lang/crates.io-index";
const CRATES_INDEX_DIR: &str = "crates-io-index.git";
const CRATES_INDEX_FETCH_DEPTH: i32 = 256;
const STATE_KEY: &str = "crates-io";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CratesState {
    warmed_up: bool,
    #[serde(default)]
    last_index_head: Option<String>,
    #[serde(default)]
    recent_release_keys: RecentKeysState,
}

#[derive(Debug, Deserialize)]
struct CratesSummaryResponse {
    #[serde(default)]
    just_updated: Vec<CrateSummaryItem>,
    #[serde(default)]
    new_crates: Vec<CrateSummaryItem>,
}

#[derive(Debug, Deserialize, Clone)]
struct CrateSummaryItem {
    name: String,
    max_version: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Clone)]
struct CratesIndexRecord {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "vers")]
    version: String,
}

#[derive(Debug, Clone)]
struct CratesIndexSync {
    head: String,
    events: Vec<PackageReleaseEvent>,
}

#[derive(Debug, Clone)]
struct CratesIndexRemoteHead {
    head: String,
    branch_ref: Option<String>,
}

pub struct CratesIoSource {
    http: reqwest::Client,
    tx: mpsc::Sender<PackageReleaseEvent>,
    state_store: FileStateStore,
    shutdown: CancellationToken,
    config: CratesConfig,
    once: bool,
}

impl CratesIoSource {
    pub fn new(
        http: reqwest::Client,
        tx: mpsc::Sender<PackageReleaseEvent>,
        state_store: FileStateStore,
        shutdown: CancellationToken,
        config: CratesConfig,
        once: bool,
    ) -> Self {
        Self {
            http,
            tx,
            state_store,
            shutdown,
            config,
            once,
        }
    }

    async fn fetch_summary_events(&self) -> Result<Vec<PackageReleaseEvent>> {
        let summary = self
            .http
            .get(CRATES_SUMMARY_URL)
            .send()
            .await
            .context("failed to fetch crates.io summary")?
            .error_for_status()
            .context("crates.io summary returned an error")?
            .json::<CratesSummaryResponse>()
            .await
            .context("failed to decode crates.io summary")?;

        Ok(summary_to_events(summary))
    }

    async fn sync_index(&self, since_head: Option<String>) -> Result<CratesIndexSync> {
        let repo_path = self.state_store.root().join(CRATES_INDEX_DIR);
        tokio::task::spawn_blocking(move || sync_index_blocking(&repo_path, since_head.as_deref()))
            .await
            .context("crates.io index task join failed")?
    }

    async fn fetch_remote_index_head(&self) -> Result<String> {
        tokio::task::spawn_blocking(|| fetch_remote_index_head_blocking().map(|remote| remote.head))
            .await
            .context("crates.io index head task join failed")?
    }
}

#[async_trait]
impl PackageSource for CratesIoSource {
    fn name(&self) -> &'static str {
        "crates-io"
    }

    async fn run(self: Box<Self>) -> Result<()> {
        let mut state = self
            .state_store
            .load::<CratesState>(STATE_KEY)
            .await?
            .unwrap_or_default();
        let mut recent_keys = RecentKeys::from_state(
            state.recent_release_keys.clone(),
            self.config.recent_key_capacity,
        );

        loop {
            if self.shutdown.is_cancelled() {
                return Ok(());
            }

            if !state.warmed_up {
                match self.fetch_remote_index_head().await {
                    Ok(head) => {
                        state.warmed_up = true;
                        state.last_index_head = Some(head);
                        state.recent_release_keys = recent_keys.snapshot();
                        self.state_store.save(STATE_KEY, &state).await?;
                        info!(
                            last_index_head = ?state.last_index_head,
                            "initialized crates.io index journal state"
                        );
                        if self.once {
                            return Ok(());
                        }
                        if sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(error) => {
                        warn!(error = %error, "crates.io index bootstrap failed; falling back to summary");
                    }
                }

                let events = match self.fetch_summary_events().await {
                    Ok(events) => events,
                    Err(error) => {
                        warn!(error = %error, "crates.io summary bootstrap failed");
                        if self.once
                            || sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await
                        {
                            return Ok(());
                        }
                        continue;
                    }
                };

                for event in &events {
                    recent_keys.insert(event.release_key());
                }
                state.warmed_up = true;
                state.recent_release_keys = recent_keys.snapshot();
                self.state_store.save(STATE_KEY, &state).await?;
                info!(
                    primed = recent_keys.len(),
                    "initialized crates.io dedupe window from current summary"
                );
                if self.once {
                    return Ok(());
                }
                if sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await {
                    return Ok(());
                }
                continue;
            }

            if let Some(last_head) = state.last_index_head.clone() {
                match self.sync_index(Some(last_head)).await {
                    Ok(sync) => {
                        let mut emitted = 0usize;
                        for event in sync.events {
                            let release_key = event.release_key();
                            if recent_keys.insert(release_key) {
                                self.tx
                                    .send(event)
                                    .await
                                    .context("crates.io output channel closed")?;
                                emitted += 1;
                            }
                        }

                        state.last_index_head = Some(sync.head);
                        state.recent_release_keys = recent_keys.snapshot();
                        self.state_store.save(STATE_KEY, &state).await?;
                        debug!(emitted, last_index_head = ?state.last_index_head, "processed crates.io index journal");

                        if self.once
                            || sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await
                        {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(error) => {
                        warn!(error = %error, "crates.io index poll failed; falling back to summary");
                    }
                }
            }

            let events = match self.fetch_summary_events().await {
                Ok(events) => events,
                Err(error) => {
                    warn!(error = %error, "crates.io poll failed");
                    if self.once
                        || sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await
                    {
                        return Ok(());
                    }
                    continue;
                }
            };

            let mut emitted = 0usize;
            for event in events {
                let release_key = event.release_key();
                if recent_keys.insert(release_key) {
                    self.tx
                        .send(event)
                        .await
                        .context("crates.io output channel closed")?;
                    emitted += 1;
                }
            }

            debug!(emitted, "processed crates.io summary");
            state.recent_release_keys = recent_keys.snapshot();
            self.state_store.save(STATE_KEY, &state).await?;

            if self.once || sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await {
                return Ok(());
            }
        }
    }
}

fn sync_index_blocking(repo_path: &Path, since_head: Option<&str>) -> Result<CratesIndexSync> {
    let remote = fetch_remote_index_head_blocking()?;
    if since_head.is_some() && since_head == Some(remote.head.as_str()) {
        return Ok(CratesIndexSync {
            head: remote.head,
            events: Vec::new(),
        });
    }

    let repo = open_or_init_index_repo(repo_path)?;
    fetch_index_updates(repo_path, remote.branch_ref.as_deref())?;
    let head = remote.head;
    let head_oid = Oid::from_str(&head).context("invalid crates.io remote head oid")?;
    repo.find_commit(head_oid)
        .with_context(|| format!("fetched crates.io index is missing commit {head}"))?;
    let events = if let Some(since_head) = since_head {
        if since_head == head {
            Vec::new()
        } else {
            collect_index_release_events(&repo, since_head, &head)?
        }
    } else {
        Vec::new()
    };

    Ok(CratesIndexSync { head, events })
}

fn fetch_remote_index_head_blocking() -> Result<CratesIndexRemoteHead> {
    let output = Command::new("git")
        .args(["ls-remote", "--symref", CRATES_INDEX_GIT_URL, "HEAD"])
        .output()
        .context("failed to execute git ls-remote for crates.io index")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git ls-remote crates.io index failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut branch_ref = None;
    let mut head = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("ref: ") {
            if let Some((target, name)) = rest.split_once('\t')
                && name == "HEAD"
            {
                branch_ref = Some(target.trim().to_string());
            }
            continue;
        }
        if let Some((oid, name)) = line.split_once('\t')
            && name == "HEAD"
        {
            head = Some(oid.trim().to_string());
        }
    }

    Ok(CratesIndexRemoteHead {
        head: head.context("git ls-remote did not return crates.io index HEAD")?,
        branch_ref,
    })
}

fn open_or_init_index_repo(path: &Path) -> Result<Repository> {
    if path.exists() {
        return Repository::open_bare(path)
            .or_else(|_| Repository::open(path))
            .with_context(|| format!("failed to open crates.io index repo {}", path.display()));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create index repo dir {}", parent.display()))?;
    }

    let init = Command::new("git")
        .args(["init", "--bare", path.to_string_lossy().as_ref()])
        .output()
        .with_context(|| {
            format!(
                "failed to init bare crates.io index repo {}",
                path.display()
            )
        })?;
    if !init.status.success() {
        anyhow::bail!(
            "git init --bare for crates.io index failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    ensure_index_remote(path)?;
    Repository::open_bare(path)
        .or_else(|_| Repository::open(path))
        .with_context(|| format!("failed to open crates.io index repo {}", path.display()))
}

fn ensure_index_remote(path: &Path) -> Result<()> {
    let remove = Command::new("git")
        .args([
            "--git-dir",
            path.to_string_lossy().as_ref(),
            "remote",
            "remove",
            "origin",
        ])
        .output();
    let _ = remove;

    let add = Command::new("git")
        .args([
            "--git-dir",
            path.to_string_lossy().as_ref(),
            "remote",
            "add",
            "origin",
            CRATES_INDEX_GIT_URL,
        ])
        .output()
        .with_context(|| {
            format!(
                "failed to configure crates.io index remote {}",
                path.display()
            )
        })?;
    if !add.status.success() {
        anyhow::bail!(
            "git remote add origin for crates.io index failed: {}",
            String::from_utf8_lossy(&add.stderr)
        );
    }
    Ok(())
}

fn fetch_index_updates(repo_path: &Path, branch_ref: Option<&str>) -> Result<()> {
    ensure_index_remote(repo_path)?;
    clear_stale_shallow_lock(repo_path)?;

    let branch_ref = branch_ref.unwrap_or("refs/heads/master");
    let branch_name = branch_ref.strip_prefix("refs/heads/").unwrap_or(branch_ref);
    let target_ref = format!("refs/remotes/origin/{branch_name}");
    let refspec = format!("+{branch_ref}:{target_ref}");
    let depth = CRATES_INDEX_FETCH_DEPTH.to_string();

    let output = run_index_fetch(repo_path, depth.as_str(), refspec.as_str())
        .output()
        .with_context(|| {
            format!(
                "failed to fetch crates.io index refs into {}",
                repo_path.display()
            )
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("shallow.lock': File exists") {
        clear_stale_shallow_lock(repo_path)?;
        let retry = run_index_fetch(repo_path, depth.as_str(), refspec.as_str())
            .output()
            .with_context(|| {
                format!(
                    "failed to retry crates.io index refs into {}",
                    repo_path.display()
                )
            })?;
        if retry.status.success() {
            return Ok(());
        }
    }

    if branch_ref != "refs/heads/main" {
        let fallback_refspec = "+refs/heads/main:refs/remotes/origin/main";
        let fallback = run_index_fetch(repo_path, depth.as_str(), fallback_refspec)
            .output()
            .with_context(|| {
                format!(
                    "failed to fetch crates.io main ref into {}",
                    repo_path.display()
                )
            })?;
        if fallback.status.success() {
            return Ok(());
        }
    }

    anyhow::bail!(
        "git fetch crates.io index failed: {}",
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_index_fetch(repo_path: &Path, depth: &str, refspec: &str) -> Command {
    let mut command = Command::new("git");
    command.args([
        "--git-dir",
        repo_path.to_string_lossy().as_ref(),
        "fetch",
        "--depth",
        depth,
        "--no-tags",
        "origin",
        refspec,
    ]);
    command
}

fn clear_stale_shallow_lock(repo_path: &Path) -> Result<()> {
    let lock_path = repo_path.join("shallow.lock");
    if !lock_path.exists() {
        return Ok(());
    }
    if git_process_uses_repo(repo_path)? {
        return Ok(());
    }
    std::fs::remove_file(&lock_path).with_context(|| {
        format!(
            "failed to remove stale crates.io index lock {}",
            lock_path.display()
        )
    })
}

fn git_process_uses_repo(repo_path: &Path) -> Result<bool> {
    let output = Command::new("ps")
        .args(["-axo", "command"])
        .output()
        .context("failed to inspect running processes for crates.io index")?;
    if !output.status.success() {
        return Ok(false);
    }
    let needle = repo_path.to_string_lossy();
    Ok(String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.contains("git") && line.contains(needle.as_ref()) && line.contains("fetch")
    }))
}

fn collect_index_release_events(
    repo: &Repository,
    since_head: &str,
    head: &str,
) -> Result<Vec<PackageReleaseEvent>> {
    let since_oid = Oid::from_str(since_head).context("invalid crates.io index state head")?;
    let head_oid = Oid::from_str(head).context("invalid crates.io index head")?;

    let mut walk = repo
        .revwalk()
        .context("failed to create crates.io revwalk")?;
    walk.set_sorting(Sort::TOPOLOGICAL | Sort::REVERSE)
        .context("failed to sort crates.io revwalk")?;
    walk.push(head_oid)
        .context("failed to push crates.io index head")?;
    walk.hide(since_oid)
        .context("failed to hide previous crates.io index head")?;

    let mut events = Vec::new();
    for oid in walk {
        let oid = oid.context("failed to read crates.io revwalk entry")?;
        let commit = repo
            .find_commit(oid)
            .with_context(|| format!("failed to load crates.io index commit {oid}"))?;
        let current_tree = commit.tree().context("failed to read commit tree")?;
        let parent_tree = if commit.parent_count() > 0 {
            Some(
                commit
                    .parent(0)
                    .context("failed to load parent commit")?
                    .tree()
                    .context("failed to read parent tree")?,
            )
        } else {
            None
        };

        let mut diff_paths = Vec::<PathBuf>::new();
        let diff = repo
            .diff_tree_to_tree(
                parent_tree.as_ref(),
                Some(&current_tree),
                Some(DiffOptions::new().include_untracked(false)),
            )
            .context("failed to diff crates.io index trees")?;
        diff.foreach(
            &mut |delta, _| {
                let path = delta
                    .new_file()
                    .path()
                    .or_else(|| delta.old_file().path())
                    .map(Path::to_path_buf);
                if let Some(path) = path {
                    diff_paths.push(path);
                }
                true
            },
            None,
            None,
            None,
        )
        .context("failed to iterate crates.io index diff")?;

        for path in diff_paths {
            let old_body = parent_tree
                .as_ref()
                .and_then(|tree| read_tree_blob_to_string(repo, tree, &path).transpose())
                .transpose()?;
            let new_body = read_tree_blob_to_string(repo, &current_tree, &path)?;
            events.extend(index_path_added_events(&old_body, &new_body, oid));
        }
    }

    Ok(events)
}

fn read_tree_blob_to_string(
    repo: &Repository,
    tree: &git2::Tree<'_>,
    path: &Path,
) -> Result<Option<String>> {
    let entry = match tree.get_path(path) {
        Ok(entry) => entry,
        Err(_) => return Ok(None),
    };
    let object = entry
        .to_object(repo)
        .with_context(|| format!("failed to load index object for {}", path.display()))?;
    let blob = object
        .as_blob()
        .context("crates.io index object was not a blob")?;
    Ok(Some(String::from_utf8_lossy(blob.content()).into_owned()))
}

fn index_path_added_events(
    old_body: &Option<String>,
    new_body: &Option<String>,
    commit_oid: Oid,
) -> Vec<PackageReleaseEvent> {
    let old_versions = parse_index_versions(old_body.as_deref())
        .into_iter()
        .map(|record| record.version)
        .collect::<std::collections::HashSet<_>>();
    let mut events = Vec::new();

    for record in parse_index_versions(new_body.as_deref()) {
        if record.name.is_empty()
            || record.version.is_empty()
            || old_versions.contains(&record.version)
        {
            continue;
        }
        let package_url = format!("https://crates.io/crates/{}", record.name);
        events.push(PackageReleaseEvent {
            event_id: format!("crates-io:{}@{}", record.name, record.version),
            ecosystem: Ecosystem::CratesIo,
            package: record.name.clone(),
            version: record.version.clone(),
            published_at: None,
            observed_at: Utc::now(),
            source: "crates.index.git".to_string(),
            sequence: Some(commit_oid.to_string()),
            package_url: Some(package_url.clone()),
            release_url: Some(format!("{package_url}/{}", record.version)),
            metadata_url: Some(format!("https://crates.io/api/v1/crates/{}", record.name)),
            priority: None,
        });
    }

    events
}

fn parse_index_versions(body: Option<&str>) -> Vec<CratesIndexRecord> {
    body.into_iter()
        .flat_map(str::lines)
        .filter_map(|line| serde_json::from_str::<CratesIndexRecord>(line).ok())
        .filter(|record| !record.name.is_empty() && !record.version.is_empty())
        .collect()
}

fn summary_to_events(summary: CratesSummaryResponse) -> Vec<PackageReleaseEvent> {
    let mut events = BTreeMap::<String, PackageReleaseEvent>::new();

    for item in summary.new_crates {
        let event = item_to_event(item, "crates.summary.new_crates", Some(SourceKind::New));
        events.insert(event.release_key(), event);
    }

    for item in summary.just_updated {
        let event = item_to_event(
            item,
            "crates.summary.just_updated",
            Some(SourceKind::Updated),
        );
        events.insert(event.release_key(), event);
    }

    let mut events = events.into_values().collect::<Vec<_>>();
    events.sort_by_key(|event| event.published_at);
    events
}

#[derive(Copy, Clone)]
enum SourceKind {
    New,
    Updated,
}

fn item_to_event(
    item: CrateSummaryItem,
    source: &str,
    kind: Option<SourceKind>,
) -> PackageReleaseEvent {
    let published_at = match kind.unwrap_or(SourceKind::Updated) {
        SourceKind::New => Some(item.created_at),
        SourceKind::Updated => Some(item.updated_at),
    };
    let package_url = format!("https://crates.io/crates/{}", item.name);
    let release_url = format!("{package_url}/{}", item.max_version);

    PackageReleaseEvent {
        event_id: format!("crates-io:{}@{}", item.name, item.max_version),
        ecosystem: Ecosystem::CratesIo,
        package: item.name.clone(),
        version: item.max_version,
        published_at,
        observed_at: Utc::now(),
        source: source.to_string(),
        sequence: None,
        package_url: Some(package_url),
        release_url: Some(release_url),
        metadata_url: Some(format!("https://crates.io/api/v1/crates/{}", item.name)),
        priority: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_summary_prefers_updated_entries() {
        let summary = CratesSummaryResponse {
            new_crates: vec![CrateSummaryItem {
                name: "demo".to_string(),
                max_version: "0.1.0".to_string(),
                created_at: DateTime::parse_from_rfc3339("2026-03-25T10:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339("2026-03-25T10:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }],
            just_updated: vec![CrateSummaryItem {
                name: "demo".to_string(),
                max_version: "0.1.0".to_string(),
                created_at: DateTime::parse_from_rfc3339("2026-03-25T10:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339("2026-03-25T10:01:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }],
        };

        let events = summary_to_events(summary);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "crates.summary.just_updated");
    }

    #[test]
    fn index_diff_emits_only_new_versions() {
        let old = Some("{\"name\":\"demo\",\"vers\":\"0.1.0\"}\n".to_string());
        let new = Some(
            "{\"name\":\"demo\",\"vers\":\"0.1.0\"}\n{\"name\":\"demo\",\"vers\":\"0.2.0\"}\n"
                .to_string(),
        );

        let events = index_path_added_events(&old, &new, Oid::zero());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].package, "demo");
        assert_eq!(events[0].version, "0.2.0");
        assert_eq!(events[0].source, "crates.index.git");
    }
}
