pub mod crates_io;
pub mod npm;
pub mod pypi;

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{config::AppConfig, event::PackageReleaseEvent, state::FileStateStore};

#[async_trait]
pub trait PackageSource: Send {
    fn name(&self) -> &'static str;
    async fn run(self: Box<Self>) -> Result<()>;
}

pub fn build_sources(
    config: &AppConfig,
    http: &reqwest::Client,
    tx: mpsc::Sender<PackageReleaseEvent>,
    state_store: FileStateStore,
    shutdown: CancellationToken,
) -> Vec<Box<dyn PackageSource>> {
    let mut sources: Vec<Box<dyn PackageSource>> = Vec::new();

    for ecosystem in &config.ecosystems {
        match ecosystem {
            crate::event::Ecosystem::Npm => sources.push(Box::new(npm::NpmSource::new(
                http.clone(),
                tx.clone(),
                state_store.clone(),
                shutdown.clone(),
                config.npm.clone(),
                config.once,
            ))),
            crate::event::Ecosystem::Pypi => sources.push(Box::new(pypi::PypiSource::new(
                http.clone(),
                tx.clone(),
                state_store.clone(),
                shutdown.clone(),
                config.pypi.clone(),
                config.once,
            ))),
            crate::event::Ecosystem::CratesIo => {
                sources.push(Box::new(crates_io::CratesIoSource::new(
                    http.clone(),
                    tx.clone(),
                    state_store.clone(),
                    shutdown.clone(),
                    config.crates_io.clone(),
                    config.once,
                )))
            }
        }
    }

    sources
}

pub async fn sleep_or_shutdown(shutdown: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}
