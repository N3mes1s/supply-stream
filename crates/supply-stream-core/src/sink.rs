use crate::bundle::ReleaseEvidenceBundle;
use anyhow::Result;
use async_trait::async_trait;
use tokio::{
    io::{AsyncWriteExt, BufWriter, Stdout},
    sync::Mutex,
};

use crate::event::{
    EmittedPackageReleaseEvent, EmittedPrioritySignal, EmittedReleaseAssessmentSignal,
    EmittedRepositorySignal,
};

#[async_trait]
pub trait EventSink: Send + Sync {
    async fn publish(&self, event: &EmittedPackageReleaseEvent) -> Result<()>;
    async fn publish_release_bundle(&self, bundle: &ReleaseEvidenceBundle) -> Result<()>;
    async fn publish_priority_signal(&self, signal: &EmittedPrioritySignal) -> Result<()>;
    async fn publish_repository_signal(&self, signal: &EmittedRepositorySignal) -> Result<()>;
    async fn publish_release_assessment(
        &self,
        signal: &EmittedReleaseAssessmentSignal,
    ) -> Result<()>;
}

pub struct StdoutNdjsonSink {
    writer: Mutex<BufWriter<Stdout>>,
}

impl StdoutNdjsonSink {
    pub fn new() -> Self {
        Self {
            writer: Mutex::new(BufWriter::new(tokio::io::stdout())),
        }
    }
}

impl Default for StdoutNdjsonSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventSink for StdoutNdjsonSink {
    async fn publish(&self, event: &EmittedPackageReleaseEvent) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let mut encoded = serde_json::to_vec(event)?;
        encoded.push(b'\n');
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn publish_release_bundle(&self, bundle: &ReleaseEvidenceBundle) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let mut encoded = serde_json::to_vec(bundle)?;
        encoded.push(b'\n');
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn publish_priority_signal(&self, signal: &EmittedPrioritySignal) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let mut encoded = serde_json::to_vec(signal)?;
        encoded.push(b'\n');
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn publish_repository_signal(&self, signal: &EmittedRepositorySignal) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let mut encoded = serde_json::to_vec(signal)?;
        encoded.push(b'\n');
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn publish_release_assessment(
        &self,
        signal: &EmittedReleaseAssessmentSignal,
    ) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let mut encoded = serde_json::to_vec(signal)?;
        encoded.push(b'\n');
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        Ok(())
    }
}
