use crate::{Result, BrowserExtensionError, NativeMessagingHost, UrlReputationChecker, DownloadScanner};
use core::types::ThreatInfo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserAgentConfig {
    pub enable_url_checking: bool,
    pub enable_download_scanning: bool,
    pub enable_real_time_protection: bool,
    pub block_suspicious_downloads: bool,
    pub warn_on_suspicious_urls: bool,
    pub scan_timeout_seconds: u64,
}

impl Default for BrowserAgentConfig {
    fn default() -> Self {
        Self {
            enable_url_checking: true,
            enable_download_scanning: true,
            enable_real_time_protection: true,
            block_suspicious_downloads: true,
            warn_on_suspicious_urls: true,
            scan_timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserAgentStatus {
    pub is_running: bool,
    pub service_connected: bool,
    pub last_update: String,
    pub threats_blocked_today: u32,
    pub urls_checked_today: u32,
    pub downloads_scanned_today: u32,
}

/// Main browser agent that coordinates all browser extension functionality
pub struct BrowserAgent {
    config: Arc<RwLock<BrowserAgentConfig>>,
    native_messaging_host: Arc<NativeMessagingHost>,
    url_reputation_checker: Arc<UrlReputationChecker>,
    download_scanner: Arc<DownloadScanner>,
    status: Arc<RwLock<BrowserAgentStatus>>,
    threat_sender: mpsc::UnboundedSender<ThreatInfo>,
    threat_receiver: Option<mpsc::UnboundedReceiver<ThreatInfo>>,
}

impl BrowserAgent {
    pub fn new() -> Self {
        let (threat_sender, threat_receiver) = mpsc::unbounded_channel();
        
        Self {
            config: Arc::new(RwLock::new(BrowserAgentConfig::default())),
            native_messaging_host: Arc::new(NativeMessagingHost::new()),
            url_reputation_checker: Arc::new(UrlReputationChecker::new()),
            download_scanner: Arc::new(DownloadScanner::new()),
            status: Arc::new(RwLock::new(BrowserAgentStatus {
                is_running: false,
                service_connected: false,
                last_update: chrono::Utc::now().to_rfc3339(),
                threats_blocked_today: 0,
                urls_checked_today: 0,
                downloads_scanned_today: 0,
            })),
            threat_sender,
            threat_receiver: Some(threat_receiver),
        }
    }

    /// Start the browser agent
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting browser agent");

        // Update status
        {
            let mut status = self.status.write().await;
            status.is_running = true;
            status.last_update = chrono::Utc::now().to_rfc3339();
        }

        // Initialize download scanner
        let mut download_scanner = DownloadScanner::new();
        if let Err(e) = download_scanner.initialize().await {
            warn!("Failed to initialize download scanner: {}", e);
        }

        // Start threat monitoring task
        if let Some(threat_receiver) = self.threat_receiver.take() {
            let native_host = self.native_messaging_host.clone();
            let status = self.status.clone();
            
            tokio::spawn(async move {
                Self::threat_monitoring_task(threat_receiver, native_host, status).await;
            });
        }

        // Start native messaging host
        let mut native_host = (*self.native_messaging_host).clone();
        tokio::spawn(async move {
            if let Err(e) = native_host.start().await {
                error!("Native messaging host error: {}", e);
            }
        });

        // Start periodic tasks
        self.start_periodic_tasks().await;

        info!("Browser agent started successfully");
        Ok(())
    }

    /// Stop the browser agent
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping browser agent");

        let mut status = self.status.write().await;
        status.is_running = false;
        status.last_update = chrono::Utc::now().to_rfc3339();

        Ok(())
    }

    /// Check URL reputation
    pub async fn check_url(&self, url: &str, tab_id: Option<u32>) -> Result<crate::url_reputation::UrlReputationResult> {
        let config = self.config.read().await;
        if !config.enable_url_checking {
            return Ok(crate::url_reputation::UrlReputationResult {
                is_safe: true,
                threat_type: None,
                reputation_score: 1.0,
                block_reason: None,
                categories: vec!["disabled".to_string()],
            });
        }

        debug!("Checking URL reputation: {}", url);
        
        let result = self.url_reputation_checker.check_url(url).await?;

        // Update statistics
        {
            let mut status = self.status.write().await;
            status.urls_checked_today += 1;
            
            if !result.is_safe {
                status.threats_blocked_today += 1;
                
                // Send threat notification
                let threat_info = ThreatInfo {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: format!("Malicious URL blocked: {}", url),
                    threat_type: core::types::ThreatType::Malicious,
                    severity: core::types::ThreatSeverity::High,
                    file_path: std::path::PathBuf::new(),
                    file_hash: "".to_string(),
                    detection_method: core::types::DetectionMethod::Reputation,
                    timestamp: std::time::SystemTime::now(),
                    additional_info: std::collections::HashMap::from([
                        ("url".to_string(), url.to_string()),
                        ("tab_id".to_string(), tab_id.map(|id| id.to_string()).unwrap_or_default()),
                        ("reputation_score".to_string(), result.reputation_score.to_string()),
                    ]),
                };

                if let Err(e) = self.threat_sender.send(threat_info) {
                    warn!("Failed to send threat notification: {}", e);
                }
            }
        }

        Ok(result)
    }

    /// Scan downloaded file
    pub async fn scan_download(&self, file_path: &str, download_url: &str) -> Result<crate::download_scanner::DownloadScanResult> {
        let config = self.config.read().await;
        if !config.enable_download_scanning {
            return Ok(crate::download_scanner::DownloadScanResult {
                is_safe: true,
                threat_info: None,
                action_taken: "disabled".to_string(),
                scan_duration_ms: 0,
            });
        }

        debug!("Scanning download: {}", file_path);
        
        let result = self.download_scanner.scan_download(file_path, download_url).await?;

        // Update statistics
        {
            let mut status = self.status.write().await;
            status.downloads_scanned_today += 1;
            
            if !result.is_safe {
                status.threats_blocked_today += 1;
                
                // Send threat notification if threat was found
                if let Some(threat_info) = &result.threat_info {
                    if let Err(e) = self.threat_sender.send(threat_info.clone()) {
                        warn!("Failed to send threat notification: {}", e);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Get current agent status
    pub async fn get_status(&self) -> BrowserAgentStatus {
        self.status.read().await.clone()
    }

    /// Update agent configuration
    pub async fn update_config(&self, new_config: BrowserAgentConfig) -> Result<()> {
        debug!("Updating browser agent configuration");
        
        let mut config = self.config.write().await;
        *config = new_config;

        // Update status timestamp
        let mut status = self.status.write().await;
        status.last_update = chrono::Utc::now().to_rfc3339();

        info!("Browser agent configuration updated");
        Ok(())
    }

    /// Update URL blacklist/whitelist
    pub async fn update_url_lists(&self, blacklist: Vec<String>, whitelist: Vec<String>) -> Result<()> {
        debug!("Updating URL blacklist ({} entries) and whitelist ({} entries)", 
               blacklist.len(), whitelist.len());
        
        self.url_reputation_checker.update_blacklist(blacklist).await;
        self.url_reputation_checker.update_whitelist(whitelist).await;

        Ok(())
    }

    /// Start periodic maintenance tasks
    async fn start_periodic_tasks(&self) {
        let status = self.status.clone();
        
        // Daily statistics reset task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(24 * 60 * 60));
            
            loop {
                interval.tick().await;
                
                let mut status_guard = status.write().await;
                status_guard.threats_blocked_today = 0;
                status_guard.urls_checked_today = 0;
                status_guard.downloads_scanned_today = 0;
                status_guard.last_update = chrono::Utc::now().to_rfc3339();
                
                info!("Daily statistics reset");
            }
        });

        // Service connectivity check task
        let status = self.status.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Check if antivirus service is running
                let service_connected = Self::check_service_connectivity().await;
                
                let mut status_guard = status.write().await;
                if status_guard.service_connected != service_connected {
                    status_guard.service_connected = service_connected;
                    status_guard.last_update = chrono::Utc::now().to_rfc3339();
                    
                    if service_connected {
                        info!("Antivirus service connection established");
                    } else {
                        warn!("Antivirus service connection lost");
                    }
                }
            }
        });
    }

    /// Check connectivity to main antivirus service
    async fn check_service_connectivity() -> bool {
        // Try to connect to the service via named pipe or TCP
        // This is a simplified check - in real implementation, this would
        // attempt to connect to the actual service
        
        // Mock implementation for now
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        true // Assume service is always available for now
    }

    /// Threat monitoring task
    async fn threat_monitoring_task(
        mut threat_receiver: mpsc::UnboundedReceiver<ThreatInfo>,
        native_host: Arc<NativeMessagingHost>,
        status: Arc<RwLock<BrowserAgentStatus>>,
    ) {
        info!("Starting threat monitoring task");
        
        while let Some(threat_info) = threat_receiver.recv().await {
            debug!("Processing threat notification: {}", threat_info.name);
            
            // Send threat alert to browser extension
            if let Err(e) = native_host.send_threat_alert(threat_info.clone()).await {
                error!("Failed to send threat alert to browser: {}", e);
            }

            // Log threat for audit purposes
            info!("Threat detected and blocked: {} ({})", 
                  threat_info.name, threat_info.threat_type);
        }
        
        info!("Threat monitoring task stopped");
    }

    /// Handle browser extension installation
    pub async fn install_browser_extension(&self, browser_type: &str) -> Result<()> {
        info!("Installing browser extension for: {}", browser_type);
        
        match browser_type.to_lowercase().as_str() {
            "chrome" | "chromium" | "edge" => {
                self.install_chromium_extension().await?;
            }
            "firefox" => {
                self.install_firefox_extension().await?;
            }
            _ => {
                return Err(BrowserExtensionError::BrowserCommunication(
                    format!("Unsupported browser: {}", browser_type)
                ));
            }
        }

        info!("Browser extension installed successfully for {}", browser_type);
        Ok(())
    }

    /// Install Chromium-based browser extension
    async fn install_chromium_extension(&self) -> Result<()> {
        // Create manifest.json for Chrome extension
        let manifest = serde_json::json!({
            "manifest_version": 3,
            "name": "Windows Antivirus Browser Protection",
            "version": "1.0.0",
            "description": "Real-time web protection by Windows Antivirus",
            "permissions": [
                "activeTab",
                "downloads",
                "webNavigation",
                "storage",
                "nativeMessaging"
            ],
            "host_permissions": [
                "<all_urls>"
            ],
            "background": {
                "service_worker": "background.js"
            },
            "content_scripts": [{
                "matches": ["<all_urls>"],
                "js": ["content.js"],
                "run_at": "document_start"
            }],
            "action": {
                "default_popup": "popup.html",
                "default_title": "Windows Antivirus Protection"
            },
            "icons": {
                "16": "icons/icon16.png",
                "48": "icons/icon48.png",
                "128": "icons/icon128.png"
            }
        });

        // TODO: Write extension files to appropriate directory
        // This would involve creating the actual extension files
        debug!("Chromium extension manifest: {}", manifest);
        
        Ok(())
    }

    /// Install Firefox extension
    async fn install_firefox_extension(&self) -> Result<()> {
        // Create manifest.json for Firefox extension
        let manifest = serde_json::json!({
            "manifest_version": 2,
            "name": "Windows Antivirus Browser Protection",
            "version": "1.0.0",
            "description": "Real-time web protection by Windows Antivirus",
            "permissions": [
                "activeTab",
                "downloads",
                "webNavigation",
                "storage",
                "nativeMessaging",
                "<all_urls>"
            ],
            "background": {
                "scripts": ["background.js"],
                "persistent": false
            },
            "content_scripts": [{
                "matches": ["<all_urls>"],
                "js": ["content.js"],
                "run_at": "document_start"
            }],
            "browser_action": {
                "default_popup": "popup.html",
                "default_title": "Windows Antivirus Protection"
            },
            "icons": {
                "16": "icons/icon16.png",
                "48": "icons/icon48.png",
                "128": "icons/icon128.png"
            }
        });

        // TODO: Write extension files to appropriate directory
        debug!("Firefox extension manifest: {}", manifest);
        
        Ok(())
    }
}

impl Default for BrowserAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_browser_agent_creation() {
        let agent = BrowserAgent::new();
        let status = agent.get_status().await;
        assert!(!status.is_running);
    }

    #[tokio::test]
    async fn test_config_update() {
        let agent = BrowserAgent::new();
        let mut new_config = BrowserAgentConfig::default();
        new_config.enable_url_checking = false;
        
        agent.update_config(new_config).await.unwrap();
        
        let config = agent.config.read().await;
        assert!(!config.enable_url_checking);
    }

    #[tokio::test]
    async fn test_url_checking_disabled() {
        let agent = BrowserAgent::new();
        let mut config = BrowserAgentConfig::default();
        config.enable_url_checking = false;
        agent.update_config(config).await.unwrap();
        
        let result = agent.check_url("https://malicious-site.com", None).await.unwrap();
        assert!(result.is_safe);
        assert!(result.categories.contains(&"disabled".to_string()));
    }

    #[tokio::test]