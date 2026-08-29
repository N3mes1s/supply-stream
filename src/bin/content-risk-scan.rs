use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use supply_stream_core::{capture::CapturedRelease, content_risk::scan_captured_release};

#[derive(Debug, Parser)]
struct Args {
    /// Path to a captured release JSON file.
    capture_json: PathBuf,
    /// Optional local artifact override for offline scanning.
    #[arg(long)]
    artifact: Option<PathBuf>,
    /// Persist the refreshed content_risk back into capture.json.
    #[arg(long)]
    write: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let capture_json = fs::read_to_string(&args.capture_json)
        .with_context(|| format!("failed to read {}", args.capture_json.display()))?;
    let mut capture = serde_json::from_str::<CapturedRelease>(&capture_json)
        .with_context(|| format!("failed to parse {}", args.capture_json.display()))?;

    if let Some(artifact) = args.artifact {
        capture.details["local_artifact"] =
            serde_json::json!({ "path": artifact.to_string_lossy() });
    }

    let http = reqwest::Client::builder().build()?;
    let capture_dir = args
        .capture_json
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let signal = scan_captured_release(&http, &capture_dir, &capture).await;
    if args.write {
        capture.details["content_risk"] = serde_json::to_value(&signal)?;
        fs::write(&args.capture_json, serde_json::to_vec_pretty(&capture)?)
            .with_context(|| format!("failed to write {}", args.capture_json.display()))?;
    }
    println!("{}", serde_json::to_string_pretty(&signal)?);
    Ok(())
}
