use crate::error::AntivirusError;
use crate::types::{ScanResult, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
use crate::traits::Scanner;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, info, warn};
use uuid::Uuid;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttachment {
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub temp_path: PathBuf,
    pub email_subject: String,
    pub sender: String,
    pub recipient: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailScanConfig {
    pub enabled: bool,
    pub scan_attachments: bool,
    pub scan_embedded_objects: bool,
    pub max_attachment_size_mb: u64,
    pub quarantine_infected: bool,
    pub block_suspicious_types: bool,
    pub allowed_extensions: Vec<String>,
    pub blocked_extensions: Vec<String>,
}
impl Default for EmailScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_attachments: true,
            scan_embedded_objects: true,
            max_attachment_size_mb: 50,
            quarantine_infected: true,
            block_suspicious_types: true,
            allowed_extensions: vec![
                "txt".to_string(),
                "pdf".to_string(),
                "doc".to_string(),
                "docx".to_string(),
                "xls".to_string(),
                "xlsx".to_string(),
                "ppt".to_string(),
                "pptx".to_string(),
            ],
            blocked_extensions: vec![
                "exe".to_string(),
                "scr".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "com".to_string(),
                "pif".to_string(),
                "vbs".to_string(),
                "js".to_string(),
            ],
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailScanResult {
    pub attachment: EmailAttachment,
    pub scan_result: ScanResult,
    pub action_taken: EmailAction,
    pub scan_duration_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailAction {
    Allow,
    Block,
    Quarantine,
    StripAttachment,
    Warn,
}
#[async_trait]
pub trait EmailScanner: Send + Sync {
    async fn scan_attachment(&self, attachment: &EmailAttachment) -> Result<EmailScanResult, AntivirusError>;
    async fn extract_attachments(&self, email_path: &PathBuf) -> Result<Vec<EmailAttachment>, AntivirusError>;
    fn is_attachment_allowed(&self, attachment: &EmailAttachment) -> bool;
    fn get_config(&self) -> &EmailScanConfig;
    fn update_config(&mut self, config: EmailScanConfig);
}
pub struct EmailScannerImpl {
    config: EmailScanConfig,
    scan_engine: Arc<dyn Scanner + Send + Sync>,
}
impl EmailScannerImpl {
    pub fn new(scan_engine: Arc<dyn Scanner + Send + Sync>) -> Self {
        Self {
            config: EmailScanConfig::default(),
            scan_engine,
        }
    }
    pub fn with_config(scan_engine: Arc<dyn Scanner + Send + Sync>, config: EmailScanConfig) -> Self {
        Self {
            config,
            scan_engine,
        }
    }
    fn is_extension_blocked(&self, filename: &str) -> bool {
        if let Some(extension) = std::path::Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            self.config.blocked_extensions.contains(&extension.to_lowercase())
        } else {
            false
        }
    }
    fn is_extension_allowed(&self, filename: &str) -> bool {
        if let Some(extension) = std::path::Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            self.config.allowed_extensions.contains(&extension.to_lowercase())
        } else {
            false
        }
    }
    fn determine_action(&self, attachment: &EmailAttachment, scan_result: &ScanResult) -> EmailAction {
        if !scan_result.threats_found.is_empty() {
            if self.config.quarantine_infected {
                return EmailAction::Quarantine;
            } else {
                return EmailAction::Block;
            }
        }
        if self.config.block_suspicious_types && self.is_extension_blocked(&attachment.filename) {
            return EmailAction::Block;
        }
        if attachment.size > self.config.max_attachment_size_mb * 1024 * 1024 {
            return EmailAction::Warn;
        }
        if !scan_result.errors.is_empty() {
            return EmailAction::Warn;
        }
        EmailAction::Allow
    }
}
#[async_trait]
impl EmailScanner for EmailScannerImpl {
    async fn scan_attachment(&self, attachment: &EmailAttachment) -> Result<EmailScanResult, AntivirusError> {
        let start_time = std::time::Instant::now();
        info!("Scanning email attachment: {}", attachment.filename);
        debug!("Attachment details: {:?}", attachment);
        if !self.config.enabled || !self.config.scan_attachments {
            let clean_result = ScanResult::new(uuid::Uuid::new_v4());
            return Ok(EmailScanResult {
                attachment: attachment.clone(),
                scan_result: clean_result,
                action_taken: EmailAction::Allow,
                scan_duration_ms: start_time.elapsed().as_millis() as u64,
            });
        }
        if attachment.size > self.config.max_attachment_size_mb * 1024 * 1024 {
            warn!("Attachment {} exceeds size limit: {} bytes", 
                  attachment.filename, attachment.size);
            let clean_result = ScanResult::new(uuid::Uuid::new_v4());
            return Ok(EmailScanResult {
                attachment: attachment.clone(),
                scan_result: clean_result,
                action_taken: EmailAction::Warn,
                scan_duration_ms: start_time.elapsed().as_millis() as u64,
            });
        }
        let scan_result = self.scan_engine.scan_file(&attachment.temp_path).await?;
        let action = self.determine_action(attachment, &scan_result);
        let duration = start_time.elapsed().as_millis() as u64;
        info!("Email attachment scan completed: {} - Action: {:?} - Duration: {}ms", 
              attachment.filename, action, duration);
        Ok(EmailScanResult {
            attachment: attachment.clone(),
            scan_result,
            action_taken: action,
            scan_duration_ms: duration,
        })
    }
    async fn extract_attachments(&self, email_path: &PathBuf) -> Result<Vec<EmailAttachment>, AntivirusError> {
        debug!("Extracting attachments from email: {:?}", email_path);
        let mut attachments = Vec::new();
        if !email_path.exists() {
            return Err(AntivirusError::FileNotFound(email_path.clone()));
        }
        let email_content = fs::read_to_string(email_path).await
            .map_err(|e| AntivirusError::IoError(e))?;
        if email_content.contains("Content-Disposition: attachment") {
            let attachment = EmailAttachment {
                filename: "extracted_attachment.bin".to_string(),
                content_type: "application/octet-stream".to_string(),
                size: 1024,
                temp_path: email_path.clone(),
                email_subject: "Test Email".to_string(),
                sender: "unknown@example.com".to_string(),
                recipient: "user@example.com".to_string(),
            };
            attachments.push(attachment);
        }
        debug!("Extracted {} attachments", attachments.len());
        Ok(attachments)
    }
    fn is_attachment_allowed(&self, attachment: &EmailAttachment) -> bool {
        if self.is_extension_blocked(&attachment.filename) {
            return false;
        }
        if !self.config.allowed_extensions.is_empty() && !self.is_extension_allowed(&attachment.filename) {
            return false;
        }
        if attachment.size > self.config.max_attachment_size_mb * 1024 * 1024 {
            return false;
        }
        true
    }
    fn get_config(&self) -> &EmailScanConfig {
        &self.config
    }
    fn update_config(&mut self, config: EmailScanConfig) {
        self.config = config;
        info!("Email scanner configuration updated");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ThreatType;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;
    struct MockScanner;
    #[async_trait]
    impl crate::traits::Scanner for MockScanner {
        async fn scan_file(&self, _path: &PathBuf) -> Result<ScanResult, AntivirusError> {
            Ok(ScanResult::clean())
        }
        async fn scan_memory(&self, _process_id: u32) -> Result<ScanResult, AntivirusError> {
            Ok(ScanResult::clean())
        }
    }
    #[tokio::test]
    async fn test_email_scanner_creation() {
        let scanner = EmailScannerImpl::new(Box::new(MockScanner));
        assert!(scanner.get_config().enabled);
        assert!(scanner.get_config().scan_attachments);
    }
    #[tokio::test]
    async fn test_attachment_allowed() {
        let scanner = EmailScannerImpl::new(Box::new(MockScanner));
        let allowed_attachment = EmailAttachment {
            filename: "document.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            size: 1024,
            temp_path: PathBuf::from("/tmp/test.pdf"),
            email_subject: "Test".to_string(),
            sender: "test@example.com".to_string(),
            recipient: "user@example.com".to_string(),
        };
        let blocked_attachment = EmailAttachment {
            filename: "malware.exe".to_string(),
            content_type: "application/octet-stream".to_string(),
            size: 1024,
            temp_path: PathBuf::from("/tmp/test.exe"),
            email_subject: "Test".to_string(),
            sender: "test@example.com".to_string(),
            recipient: "user@example.com".to_string(),
        };
        assert!(scanner.is_attachment_allowed(&allowed_attachment));
        assert!(!scanner.is_attachment_allowed(&blocked_attachment));
    }
    #[tokio::test]
    async fn test_scan_attachment() {
        let scanner = EmailScannerImpl::new(Box::new(MockScanner));
        let temp_file = NamedTempFile::new().unwrap();
        let attachment = EmailAttachment {
            filename: "test.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 100,
            temp_path: temp_file.path().to_path_buf(),
            email_subject: "Test Email".to_string(),
            sender: "test@example.com".to_string(),
            recipient: "user@example.com".to_string(),
        };
        let result = scanner.scan_attachment(&attachment).await.unwrap();
        assert!(matches!(result.action_taken, EmailAction::Allow));
        assert!(result.scan_result.threats.is_empty());
    }
    #[test]
    fn test_extension_checking() {
        let scanner = EmailScannerImpl::new(Box::new(MockScanner));
        assert!(scanner.is_extension_blocked("malware.exe"));
        assert!(scanner.is_extension_blocked("script.vbs"));
        assert!(!scanner.is_extension_blocked("document.pdf"));
        assert!(scanner.is_extension_allowed("document.pdf"));
        assert!(scanner.is_extension_allowed("spreadsheet.xlsx"));
        assert!(!scanner.is_extension_allowed("unknown.xyz"));
    }
    #[test]
    fn test_config_update() {
        let mut scanner = EmailScannerImpl::new(Box::new(MockScanner));
        let mut new_config = EmailScanConfig::default();
        new_config.enabled = false;
        new_config.max_attachment_size_mb = 100;
        scanner.update_config(new_config);
        assert!(!scanner.get_config().enabled);
        assert_eq!(scanner.get_config().max_attachment_size_mb, 100);
    }
}