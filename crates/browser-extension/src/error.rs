use thiserror::Error;
#[derive(Error, Debug)]
pub enum BrowserExtensionError {
    #[error("Native messaging error: {0}")]
    NativeMessaging(String),
    #[error("URL reputation check failed: {0}")]
    UrlReputation(String),
    #[error("Download scanning failed: {0}")]
    DownloadScanning(String),
    #[error("Browser communication error: {0}")]
    BrowserCommunication(String),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Core engine error: {0}")]
    Core(#[from] core::error::AntivirusError),
}