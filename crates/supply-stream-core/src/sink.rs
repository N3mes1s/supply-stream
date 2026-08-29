use crate::bundle::ReleaseEvidenceBundle;
use anyhow::Result;
use async_trait::async_trait;
use std::time::{Duration, Instant};
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
    writer: Mutex<StdoutWriterState>,
}

struct StdoutWriterState {
    writer: BufWriter<Stdout>,
    pending_flush_messages: usize,
    pending_flush_bytes: usize,
    last_flush_at: Instant,
}

const SINK_FLUSH_MAX_DELAY: Duration = Duration::from_millis(100);
const SINK_FLUSH_MAX_PENDING_MESSAGES: usize = 32;
const SINK_FLUSH_MAX_PENDING_BYTES: usize = 64 * 1024;

impl StdoutNdjsonSink {
    pub fn new() -> Self {
        Self {
            writer: Mutex::new(StdoutWriterState {
                writer: BufWriter::new(tokio::io::stdout()),
                pending_flush_messages: 0,
                pending_flush_bytes: 0,
                last_flush_at: Instant::now(),
            }),
        }
    }

    async fn write_encoded_line(&self, encoded: Vec<u8>) -> Result<()> {
        let mut state = self.writer.lock().await;
        state.writer.write_all(&encoded).await?;
        state.pending_flush_messages += 1;
        state.pending_flush_bytes += encoded.len();
        if state.pending_flush_messages >= SINK_FLUSH_MAX_PENDING_MESSAGES
            || state.pending_flush_bytes >= SINK_FLUSH_MAX_PENDING_BYTES
            || state.last_flush_at.elapsed() >= SINK_FLUSH_MAX_DELAY
        {
            state.writer.flush().await?;
            state.pending_flush_messages = 0;
            state.pending_flush_bytes = 0;
            state.last_flush_at = Instant::now();
        }
        Ok(())
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
        let mut encoded = serde_json::to_vec(event)?;
        encoded.push(b'\n');
        self.write_encoded_line(encoded).await
    }

    async fn publish_release_bundle(&self, bundle: &ReleaseEvidenceBundle) -> Result<()> {
        let mut encoded = serde_json::to_vec(bundle)?;
        encoded.push(b'\n');
        self.write_encoded_line(encoded).await
    }

    async fn publish_priority_signal(&self, signal: &EmittedPrioritySignal) -> Result<()> {
        let mut encoded = serde_json::to_vec(signal)?;
        encoded.push(b'\n');
        self.write_encoded_line(encoded).await
    }

    async fn publish_repository_signal(&self, signal: &EmittedRepositorySignal) -> Result<()> {
        let mut encoded = serde_json::to_vec(signal)?;
        encoded.push(b'\n');
        self.write_encoded_line(encoded).await
    }

    async fn publish_release_assessment(
        &self,
        signal: &EmittedReleaseAssessmentSignal,
    ) -> Result<()> {
        let mut encoded = serde_json::to_vec(signal)?;
        encoded.push(b'\n');
        self.write_encoded_line(encoded).await
    }
}
