pub mod native_messaging;
pub mod url_reputation;
pub mod download_scanner;
pub mod browser_agent;
pub mod error;

pub use error::BrowserExtensionError;
pub use native_messaging::NativeMessagingHost;
pub use url_reputation::UrlReputationChecker;
pub use download_scanner::DownloadScanner;
pub use browser_agent::BrowserAgent;

pub type Result<T> = std::result::Result<T, BrowserExtensionError>;