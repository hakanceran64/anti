use hadron_core::{
    EmailScanner, EmailScannerImpl, EmailMonitor, MapiIntegration, MapiOperations,
    EmailAttachment, EmailScanResult, EmailScanConfig, OutlookConfig,
    AntivirusError, Scanner
};
use crate::minimal_scan_engine::MinimalScanEngine;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailScanStats {
    pub total_emails_processed: u64,
    pub total_attachments_scanned: u64,
    pub threats_detected: u64,
    pub attachments_quarantined: u64,
    pub attachments_blocked: u64,
    pub average_scan_time_ms: f64,
    pub last_scan_time: Option<chrono::DateTime<chrono::Utc>>,
}
impl Default for EmailScanStats {
    fn default() -> Self {
        Self {
            total_emails_processed: 0,
            total_attachments_scanned: 0,
            threats_detected: 0,
            attachments_quarantined: 0,
            attachments_blocked: 0,
            average_scan_time_ms: 0.0,
            last_scan_time: None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailServiceConfig {
    pub email_scan_config: EmailScanConfig,
    pub outlook_config: OutlookConfig,
    pub monitoring_interval_seconds: u64,
    pub max_concurrent_scans: u32,
    pub enable_statistics: bool,
}
impl Default for EmailServiceConfig {
    fn default() -> Self {
        Self {
            email_scan_config: EmailScanConfig::default(),
            outlook_config: OutlookConfig::default(),
            monitoring_interval_seconds: 30,
            max_concurrent_scans: 10,
            enable_statistics: true,
        }
    }
}
pub struct EmailScanService {
    config: Arc<RwLock<EmailServiceConfig>>,
    scanner: Arc<Mutex<Box<dyn EmailScanner>>>,
    monitor: Arc<Mutex<Option<EmailMonitor>>>,
    stats: Arc<RwLock<EmailScanStats>>,
    running: Arc<std::sync::atomic::AtomicBool>,
}
impl EmailScanService {
    pub fn new(scan_engine: Arc<dyn Scanner + Send + Sync>) -> Self {
        let email_scanner = Box::new(EmailScannerImpl::new(scan_engine));
        Self {
            config: Arc::new(RwLock::new(EmailServiceConfig::default())),
            scanner: Arc::new(Mutex::new(email_scanner)),
            monitor: Arc::new(Mutex::new(None)),
            stats: Arc::new(RwLock::new(EmailScanStats::default())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    pub fn with_config(scan_engine: Arc<dyn Scanner + Send + Sync>, config: EmailServiceConfig) -> Self {
        let email_scanner = Box::new(EmailScannerImpl::with_config(
            scan_engine,
            config.email_scan_config.clone()
        ));
        Self {
            config: Arc::new(RwLock::new(config)),
            scanner: Arc::new(Mutex::new(email_scanner)),
            monitor: Arc::new(Mutex::new(None)),
            stats: Arc::new(RwLock::new(EmailScanStats::default())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    pub async fn start(&self) -> Result<(), AntivirusError> {
        info!("Starting email scanning service");
        let config = self.config.read().await;
        if !config.email_scan_config.enabled {
            warn!("Email scanning is disabled in configuration");
            return Ok(());
        }
        let mapi = Box::new(MapiIntegration::with_config(config.outlook_config.clone()));
        let scanner = self.scanner.lock().await;
        let monitor_scanner = Box::new(EmailScannerImpl::with_config(
            Arc::new(crate::minimal_scan_engine::MinimalScanEngine::new()?),
            config.email_scan_config.clone()
        ));
        let email_monitor = EmailMonitor::with_config(
            mapi,
            monitor_scanner,
            config.outlook_config.clone()
        );
        drop(scanner);
        drop(config);
        let mut monitor_guard = self.monitor.lock().await;
        *monitor_guard = Some(email_monitor);
        drop(monitor_guard);
        if let Some(ref mut monitor) = self.monitor.lock().await.as_mut() {
            monitor.start_monitoring().await?;
        }
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);
        self.start_background_monitoring().await;
        info!("Email scanning service started");
        Ok(())
    }
    pub async fn stop(&self) -> Result<(), AntivirusError> {
        info!("Stopping email scanning service");
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(ref mut monitor) = self.monitor.lock().await.as_mut() {
            monitor.stop_monitoring().await?;
        }
        info!("Email scanning service stopped");
        Ok(())
    }
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub async fn scan_attachment(&self, attachment: &EmailAttachment) -> Result<EmailScanResult, AntivirusError> {
        let scanner = self.scanner.lock().await;
        let result = scanner.scan_attachment(attachment).await?;
        drop(scanner);
        self.update_stats(&result).await;
        Ok(result)
    }
    pub async fn get_statistics(&self) -> EmailScanStats {
        self.stats.read().await.clone()
    }
    pub async fn update_config(&self, config: EmailServiceConfig) -> Result<(), AntivirusError> {
        info!("Updating email scanning service configuration");
        let mut scanner = self.scanner.lock().await;
        scanner.update_config(config.email_scan_config.clone());
        drop(scanner);
        let mut service_config = self.config.write().await;
        *service_config = config;
        drop(service_config);
        info!("Email scanning service configuration updated");
        Ok(())
    }
    pub async fn get_config(&self) -> EmailServiceConfig {
        self.config.read().await.clone()
    }
    async fn start_background_monitoring(&self) {
        let monitor = self.monitor.clone();
        let stats = self.stats.clone();
        let running = self.running.clone();
        let config = self.config.clone();
        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                let interval = {
                    let config_guard = config.read().await;
                    config_guard.monitoring_interval_seconds
                };
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                if let Some(ref mut email_monitor) = monitor.lock().await.as_mut() {
                    match email_monitor.check_and_scan_messages().await {
                        Ok(results) => {
                            debug!("Background email scan completed: {} results", results.len());
                            if !results.is_empty() {
                                let mut stats_guard = stats.write().await;
                                for result in &results {
                                    Self::update_stats_internal(&mut stats_guard, result);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Background email scanning failed: {}", e);
                        }
                    }
                }
            }
        });
    }
    async fn update_stats(&self, result: &EmailScanResult) {
        if self.config.read().await.enable_statistics {
            let mut stats = self.stats.write().await;
            Self::update_stats_internal(&mut stats, result);
        }
    }
    fn update_stats_internal(stats: &mut EmailScanStats, result: &EmailScanResult) {
        stats.total_attachments_scanned += 1;
        stats.last_scan_time = Some(chrono::Utc::now());
        if !result.scan_result.threats_found.is_empty() {
            stats.threats_detected += 1;
        }
        match result.action_taken {
            hadron_core::EmailAction::Quarantine => stats.attachments_quarantined += 1,
            hadron_core::EmailAction::Block => stats.attachments_blocked += 1,
            _ => {}
        }
        let total_scans = stats.total_attachments_scanned as f64;
        stats.average_scan_time_ms = 
            (stats.average_scan_time_ms * (total_scans - 1.0) + result.scan_duration_ms as f64) / total_scans;
    }
    pub async fn force_scan_check(&self) -> Result<Vec<EmailScanResult>, AntivirusError> {
        info!("Forcing manual email scan check");
        if let Some(ref mut monitor) = self.monitor.lock().await.as_mut() {
            let results = monitor.check_and_scan_messages().await?;
            for result in &results {
                self.update_stats(result).await;
            }
            info!("Manual email scan check completed: {} results", results.len());
            Ok(results)
        } else {
            Err(AntivirusError::Internal("Email monitor not initialized".to_string()))
        }
    }
    pub async fn reset_statistics(&self) {
        info!("Resetting email scanning statistics");
        let mut stats = self.stats.write().await;
        *stats = EmailScanStats::default();
    }
}
#[async_trait]
pub trait EmailScanServiceOperations: Send + Sync {
    async fn start(&self) -> Result<(), AntivirusError>;
    async fn stop(&self) -> Result<(), AntivirusError>;
    fn is_running(&self) -> bool;
    async fn scan_attachment(&self, attachment: &EmailAttachment) -> Result<EmailScanResult, AntivirusError>;
    async fn get_statistics(&self) -> EmailScanStats;
    async fn update_config(&self, config: EmailServiceConfig) -> Result<(), AntivirusError>;
    async fn force_scan_check(&self) -> Result<Vec<EmailScanResult>, AntivirusError>;
}
#[async_trait]
impl EmailScanServiceOperations for EmailScanService {
    async fn start(&self) -> Result<(), AntivirusError> {
        self.start().await
    }
    async fn stop(&self) -> Result<(), AntivirusError> {
        self.stop().await
    }
    fn is_running(&self) -> bool {
        self.is_running()
    }
    async fn scan_attachment(&self, attachment: &EmailAttachment) -> Result<EmailScanResult, AntivirusError> {
        self.scan_attachment(attachment).await
    }
    async fn get_statistics(&self) -> EmailScanStats {
        self.get_statistics().await
    }
    async fn update_config(&self, config: EmailServiceConfig) -> Result<(), AntivirusError> {
        self.update_config(config).await
    }
    async fn force_scan_check(&self) -> Result<Vec<EmailScanResult>, AntivirusError> {
        self.force_scan_check().await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hadron_core::{ScanResult, ThreatInfo, ThreatType, ThreatSeverity};
    use std::path::PathBuf;
    use tempfile::NamedTempFile;
    struct MockScanner;
    #[async_trait]
    impl Scanner for MockScanner {
        async fn scan_file(&self, _path: &PathBuf) -> Result<ScanResult, AntivirusError> {
            Ok(ScanResult::clean())
        }
        async fn scan_memory(&self, _process_id: u32) -> Result<ScanResult, AntivirusError> {
            Ok(ScanResult::clean())
        }
    }
    #[tokio::test]
    async fn test_email_service_creation() {
        let service = EmailScanService::new(Box::new(MockScanner));
        assert!(!service.is_running());
        let stats = service.get_statistics().await;
        assert_eq!(stats.total_attachments_scanned, 0);
    }
    #[tokio::test]
    async fn test_email_service_lifecycle() {
        let service = EmailScanService::new(Box::new(MockScanner));
        service.start().await.unwrap();
        assert!(service.is_running());
        service.stop().await.unwrap();
        assert!(!service.is_running());
    }
    #[tokio::test]
    async fn test_attachment_scanning() {
        let service = EmailScanService::new(Box::new(MockScanner));
        service.start().await.unwrap();
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
        let result = service.scan_attachment(&attachment).await.unwrap();
        assert!(result.scan_result.threats.is_empty());
        let stats = service.get_statistics().await;
        assert_eq!(stats.total_attachments_scanned, 1);
        service.stop().await.unwrap();
    }
    #[tokio::test]
    async fn test_config_update() {
        let service = EmailScanService::new(Box::new(MockScanner));
        let mut new_config = EmailServiceConfig::default();
        new_config.monitoring_interval_seconds = 60;
        new_config.max_concurrent_scans = 20;
        service.update_config(new_config.clone()).await.unwrap();
        let current_config = service.get_config().await;
        assert_eq!(current_config.monitoring_interval_seconds, 60);
        assert_eq!(current_config.max_concurrent_scans, 20);
    }
    #[tokio::test]
    async fn test_statistics_reset() {
        let service = EmailScanService::new(Box::new(MockScanner));
        service.start().await.unwrap();
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
        service.scan_attachment(&attachment).await.unwrap();
        let stats_before = service.get_statistics().await;
        assert_eq!(stats_before.total_attachments_scanned, 1);
        service.reset_statistics().await;
        let stats_after = service.get_statistics().await;
        assert_eq!(stats_after.total_attachments_scanned, 0);
        service.stop().await.unwrap();
    }
}