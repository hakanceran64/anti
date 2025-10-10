use crate::{Result, BrowserExtensionError};
use core::types::{ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tracing::{debug, info, warn};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadScanResult {
    pub is_safe: bool,
    pub threat_info: Option<ThreatInfo>,
    pub action_taken: String,
    pub scan_duration_ms: u64,
}
#[derive(Debug, Clone)]
pub struct DownloadScanRequest {
    pub file_path: PathBuf,
    pub download_url: String,
    pub file_size: u64,
    pub mime_type: Option<String>,
}
 Download scanner for browser extension integration
pub struct DownloadScanner {
    scan_engine: Option<core::scan_engine::ScanEngine>,
    quarantine_manager: Option<service::quarantine::QuarantineManager>,
}
impl DownloadScanner {
    pub fn new() -> Self {
        Self {
            scan_engine: None,
            quarantine_manager: None,
        }
    }
    pub async fn initialize(&mut self) -> Result<()> {
        self.scan_engine = Some(core::scan_engine::ScanEngine::new().await
            .map_err(|e| BrowserExtensionError::Core(e))?);
        self.quarantine_manager = Some(service::quarantine::QuarantineManager::new().await
            .map_err(|e| BrowserExtensionError::DownloadScanning(format!("Failed to initialize quarantine: {}", e)))?);
        info!("Download scanner initialized successfully");
        Ok(())
    }
    pub async fn scan_download(&self, file_path: &str, download_url: &str) -> Result<DownloadScanResult> {
        let start_time = SystemTime::now();
        let path = PathBuf::from(file_path);
        debug!("Scanning download: {} from {}", file_path, download_url);
        if !path.exists() {
            return Err(BrowserExtensionError::DownloadScanning(
                format!("File not found: {}", file_path)
            ));
        }
        let metadata = fs::metadata(&path).await?;
        let file_size = metadata.len();
        if let Some(pre_scan_result) = self.perform_pre_scan_checks(&path, download_url, file_size).await? {
            return Ok(pre_scan_result);
        }
        let scan_result = self.perform_file_scan(&path).await?;
        let scan_duration = start_time.elapsed()
            .unwrap_or_default()
            .as_millis() as u64;
        let result = if let Some(threat_info) = scan_result {
            let action = self.handle_threat_detection(&path, &threat_info).await?;
            DownloadScanResult {
                is_safe: false,
                threat_info: Some(threat_info),
                action_taken: action,
                scan_duration_ms: scan_duration,
            }
        } else {
            DownloadScanResult {
                is_safe: true,
                threat_info: None,
                action_taken: "allowed".to_string(),
                scan_duration_ms: scan_duration,
            }
        };
        debug!("Download scan completed: {:?}", result);
        Ok(result)
    }
    async fn perform_pre_scan_checks(
        &self,
        path: &Path,
        download_url: &str,
        file_size: u64,
    ) -> Result<Option<DownloadScanResult>> {
        if file_size > 100 * 1024 * 1024 {
            warn!("File too large for scanning: {} bytes", file_size);
            return Ok(Some(DownloadScanResult {
                is_safe: true,
                threat_info: None,
                action_taken: "skipped_large_file".to_string(),
                scan_duration_ms: 0,
            }));
        }
        if let Some(extension) = path.extension() {
            let ext = extension.to_string_lossy().to_lowercase();
            if self.is_dangerous_extension(&ext) {
                let threat_info = ThreatInfo {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: format!("Dangerous file extension: .{}", ext),
                    threat_type: ThreatType::PotentiallyUnwanted,
                    severity: ThreatSeverity::High,
                    file_path: path.to_path_buf(),
                    file_hash: "".to_string(),
                    detection_method: DetectionMethod::Heuristic,
                    timestamp: SystemTime::now(),
                    additional_info: std::collections::HashMap::from([
                        ("download_url".to_string(), download_url.to_string()),
                        ("file_extension".to_string(), ext),
                    ]),
                };
                let action = self.handle_threat_detection(path, &threat_info).await?;
                return Ok(Some(DownloadScanResult {
                    is_safe: false,
                    threat_info: Some(threat_info),
                    action_taken: action,
                    scan_duration_ms: 0,
                }));
            }
            if self.is_safe_extension(&ext) {
                return Ok(Some(DownloadScanResult {
                    is_safe: true,
                    threat_info: None,
                    action_taken: "skipped_safe_extension".to_string(),
                    scan_duration_ms: 0,
                }));
            }
        }
        if self.is_suspicious_download_url(download_url) {
            let threat_info = ThreatInfo {
                id: uuid::Uuid::new_v4().to_string(),
                name: "Download from suspicious URL".to_string(),
                threat_type: ThreatType::Suspicious,
                severity: ThreatSeverity::Medium,
                file_path: path.to_path_buf(),
                file_hash: "".to_string(),
                detection_method: DetectionMethod::Heuristic,
                timestamp: SystemTime::now(),
                additional_info: std::collections::HashMap::from([
                    ("download_url".to_string(), download_url.to_string()),
                    ("reason".to_string(), "suspicious_url".to_string()),
                ]),
            };
            return Ok(Some(DownloadScanResult {
                is_safe: false,
                threat_info: Some(threat_info),
                action_taken: "blocked_suspicious_url".to_string(),
                scan_duration_ms: 0,
            }));
        }
        Ok(None)
    }
    async fn perform_file_scan(&self, path: &Path) -> Result<Option<ThreatInfo>> {
        if let Some(scan_engine) = &self.scan_engine {
            match scan_engine.scan_file(path).await {
                Ok(scan_result) => {
                    if let Some(threat) = scan_result.threats.first() {
                        Ok(Some(threat.clone()))
                    } else {
                        Ok(None)
                    }
                }
                Err(e) => {
                    warn!("Scan engine error: {}", e);
                    Ok(None)
                }
            }
        } else {
            self.perform_basic_heuristic_scan(path).await
        }
    }
    async fn perform_basic_heuristic_scan(&self, path: &Path) -> Result<Option<ThreatInfo>> {
        let mut file = fs::File::open(path).await?;
        let mut buffer = vec![0u8; 1024];
        use tokio::io::AsyncReadExt;
        let bytes_read = file.read(&mut buffer).await?;
        buffer.truncate(bytes_read);
        if self.contains_suspicious_patterns(&buffer) {
            let threat_info = ThreatInfo {
                id: uuid::Uuid::new_v4().to_string(),
                name: "Suspicious file content detected".to_string(),
                threat_type: ThreatType::Suspicious,
                severity: ThreatSeverity::Medium,
                file_path: path.to_path_buf(),
                file_hash: self.calculate_file_hash(&buffer),
                detection_method: DetectionMethod::Heuristic,
                timestamp: SystemTime::now(),
                additional_info: std::collections::HashMap::new(),
            };
            return Ok(Some(threat_info));
        }
        Ok(None)
    }
    async fn handle_threat_detection(&self, path: &Path, threat_info: &ThreatInfo) -> Result<String> {
        match threat_info.severity {
            ThreatSeverity::Critical | ThreatSeverity::High => {
                if let Some(quarantine_manager) = &self.quarantine_manager {
                    match quarantine_manager.quarantine_file(path, threat_info).await {
                        Ok(_) => {
                            info!("File quarantined: {}", path.display());
                            Ok("quarantined".to_string())
                        }
                        Err(e) => {
                            warn!("Failed to quarantine file: {}", e);
                            if let Err(delete_err) = fs::remove_file(path).await {
                                warn!("Failed to delete file: {}", delete_err);
                                Ok("blocked_in_place".to_string())
                            } else {
                                Ok("deleted".to_string())
                            }
                        }
                    }
                } else {
                    if let Err(e) = fs::remove_file(path).await {
                        warn!("Failed to delete file: {}", e);
                        Ok("blocked_in_place".to_string())
                    } else {
                        Ok("deleted".to_string())
                    }
                }
            }
            ThreatSeverity::Medium => {
                Ok("blocked".to_string())
            }
            ThreatSeverity::Low => {
                Ok("allowed_with_warning".to_string())
            }
        }
    }
    fn is_dangerous_extension(&self, extension: &str) -> bool {
        let dangerous_extensions = [
            "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe",
            "js", "jse", "wsf", "wsh", "msi", "msp", "hta", "cpl",
            "jar", "app", "deb", "pkg", "dmg", "run"
        ];
        dangerous_extensions.contains(&extension)
    }
    fn is_safe_extension(&self, extension: &str) -> bool {
        let safe_extensions = [
            "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "jpg", "jpeg", "png", "gif", "bmp", "svg", "webp",
            "mp3", "mp4", "avi", "mov", "wmv", "flv", "webm",
            "zip", "rar", "7z", "tar", "gz"
        ];
        safe_extensions.contains(&extension)
    }
    fn is_suspicious_download_url(&self, url: &str) -> bool {
        let suspicious_patterns = [
            r"(?i)(malware|virus|trojan|keylogger)",
            r"(?i)(crack|keygen|patch|serial)",
            r"(?i)(free.*download.*exe)",
            r"(?i)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        ];
        for pattern in &suspicious_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if regex.is_match(url) {
                    return true;
                }
            }
        }
        false
    }
    fn contains_suspicious_patterns(&self, content: &[u8]) -> bool {
        let content_str = String::from_utf8_lossy(content);
        let suspicious_patterns = [
            r"(?i)(virus|malware|trojan|backdoor)",
            r"(?i)(keylogger|password.*steal)",
            r"(?i)(ransomware|encrypt.*files)",
            r"(?i)(bitcoin|cryptocurrency|mining)",
        ];
        for pattern in &suspicious_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if regex.is_match(&content_str) {
                    return true;
                }
            }
        }
        if content.len() >= 2 {
            if content[0] == 0x4D && content[1] == 0x5A {
                return true;
            }
        }
        false
    }
    fn calculate_file_hash(&self, content: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }
}
impl Default for DownloadScanner {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;
    use std::io::Write;
    #[tokio::test]
    async fn test_dangerous_extension_detection() {
        let scanner = DownloadScanner::new();
        assert!(scanner.is_dangerous_extension("exe"));
        assert!(scanner.is_dangerous_extension("scr"));
        assert!(!scanner.is_dangerous_extension("txt"));
    }
    #[tokio::test]
    async fn test_safe_extension_detection() {
        let scanner = DownloadScanner::new();
        assert!(scanner.is_safe_extension("pdf"));
        assert!(scanner.is_safe_extension("jpg"));
        assert!(!scanner.is_safe_extension("exe"));
    }
    #[tokio::test]
    async fn test_suspicious_url_detection() {
        let scanner = DownloadScanner::new();
        assert!(scanner.is_suspicious_download_url("http:
        assert!(scanner.is_suspicious_download_url("http:
        assert!(!scanner.is_suspicious_download_url("https:
    }
    #[tokio::test]
    async fn test_suspicious_content_detection() {
        let scanner = DownloadScanner::new();
        let suspicious_content = b"This is a virus that will steal your passwords";
        assert!(scanner.contains_suspicious_patterns(suspicious_content));
        let safe_content = b"This is a normal text file with safe content";
        assert!(!scanner.contains_suspicious_patterns(safe_content));
    }
    #[tokio::test]
    async fn test_file_hash_calculation() {
        let scanner = DownloadScanner::new();
        let content = b"test content";
        let hash1 = scanner.calculate_file_hash(content);
        let hash2 = scanner.calculate_file_hash(content);
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }
}