mod config;
mod history_command;
mod priority_command;

use anyhow::Result;
use clap::Parser;
use config::{Cli, Command};
use supply_stream_core::{init_tracing, run};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_filter)?;

    match cli.command {
        Some(Command::History(args)) => history_command::run(args).await,
        Some(Command::Priority(args)) => priority_command::run(args).await,
        None => run(cli.run.into_config()).await,
    }
}
