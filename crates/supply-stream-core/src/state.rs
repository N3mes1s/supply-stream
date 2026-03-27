use std::{
    collections::{HashSet, VecDeque},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, Clone)]
pub struct FileStateStore {
    root: PathBuf,
}

impl FileStateStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn load<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let path = self.path_for(key);
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read state file {}", path.display()));
            }
        };

        let value = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse state file {}", path.display()))?;
        Ok(Some(value))
    }

    pub async fn save<T>(&self, key: &str, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        tokio::fs::create_dir_all(&self.root)
            .await
            .with_context(|| format!("failed to create state dir {}", self.root.display()))?;

        let path = self.path_for(key);
        let tmp_path = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(value)
            .with_context(|| format!("failed to serialize state file {}", path.display()))?;

        tokio::fs::write(&tmp_path, bytes)
            .await
            .with_context(|| format!("failed to write temp state file {}", tmp_path.display()))?;
        tokio::fs::rename(&tmp_path, &path)
            .await
            .with_context(|| format!("failed to replace state file {}", path.display()))?;
        Ok(())
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(format!("{key}.json"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecentKeysState {
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RecentKeys {
    max_entries: usize,
    queue: VecDeque<String>,
    set: HashSet<String>,
}

impl RecentKeys {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            queue: VecDeque::new(),
            set: HashSet::new(),
        }
    }

    pub fn from_state(state: RecentKeysState, max_entries: usize) -> Self {
        let mut recent = Self::new(max_entries);
        for key in state.keys {
            recent.insert(key);
        }
        recent
    }

    pub fn insert(&mut self, key: impl Into<String>) -> bool {
        let key = key.into();
        if self.set.contains(&key) {
            return false;
        }

        self.queue.push_back(key.clone());
        self.set.insert(key);

        while self.queue.len() > self.max_entries {
            if let Some(oldest) = self.queue.pop_front() {
                self.set.remove(&oldest);
            }
        }

        true
    }

    pub fn snapshot(&self) -> RecentKeysState {
        RecentKeysState {
            keys: self.queue.iter().cloned().collect(),
        }
    }

    pub fn contains(&self, key: &str) -> bool {
        self.set.contains(key)
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

pub fn state_path(root: &Path, key: &str) -> PathBuf {
    root.join(format!("{key}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_keys_evicts_old_entries() {
        let mut recent = RecentKeys::new(2);
        assert!(recent.insert("one"));
        assert!(recent.insert("two"));
        assert!(!recent.insert("two"));
        assert!(recent.insert("three"));
        assert!(!recent.contains("one"));
        assert!(recent.contains("two"));
        assert!(recent.contains("three"));
    }
}
