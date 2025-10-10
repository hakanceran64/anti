use anyhow::Result;
use tracing::{info, error};
use tracing_subscriber;
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_level(true)
        .init();
    info!("Starting HADRON Antivirus Service v{}", env!("CARGO_PKG_VERSION"));
    info!("HADRON Antivirus Service started successfully");
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}