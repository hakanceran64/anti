use clap::Parser;
use anyhow::Result;
use tracing::info;
mod cli;
mod commands;
use cli::CliApp;
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = CliApp::parse();
    info!("HADRON Antivirus CLI v{}", env!("CARGO_PKG_VERSION"));
    cli.run().await?;
    Ok(())
}