use hadron_core::{
    NetworkMonitor, NetworkMonitorImpl, NetworkMonitorConfig, NetworkPacket,
    NetworkAnalysisResult, UrlReputation, IpReputation, NetworkMonitorStats,
    AntivirusError, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod
};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, Duration};
use tracing::{info, warn, error, debug};
pub struct NetworkMonitorService {
    monitor: Arc<NetworkMonitorImpl>,
    config: Arc<RwLock<NetworkMonitorConfig>>,
    threat_sender: Option<mpsc::UnboundedSender<ThreatInfo>>,
    is_running: Arc<RwLock<bool>>,
}
impl NetworkMonitorService {
    pub fn new(config: NetworkMonitorConfig) -> Self {
        let monitor = Arc::new(NetworkMonitorImpl::new(config.clone()));
        Self {
            monitor,
            config: Arc::new(RwLock::new(config)),
            threat_sender: None,
            is_running: Arc::new(RwLock::new(false)),
        }
    }
    pub fn set_threat_sender(&mut self, sender: mpsc::UnboundedSender<ThreatInfo>) {
        self.threat_sender = Some(sender);
    }
    pub async fn start(&self) -> Result<(), AntivirusError> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }
        info!("Starting network monitor service");
        self.monitor.start_monitoring().await?;
        *is_running = true;
        self.start_background_tasks().await;
        info!("Network monitor service started successfully");
        Ok(())
    }
    pub async fn stop(&self) -> Result<(), AntivirusError> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }
        info!("Stopping network monitor service");
        self.monitor.stop_monitoring().await?;
        *is_running = false;
        info!("Network monitor service stopped");
        Ok(())
    }
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    pub async fn process_packet(&self, packet: NetworkPacket) -> Result<(), AntivirusError> {
        if !self.is_running().await {
            return Ok(());
        }
        debug!("Processing network packet: {} -> {}", packet.source_ip, packet.dest_ip);
        let analysis_result = self.monitor.analyze_packet(&packet).await?;
        if analysis_result.is_malicious {
            let threat_info = self.create_threat_info(&packet, &analysis_result).await;
            self.notify_threat(threat_info).await;
            warn!(
                "Malicious network activity detected: {} -> {} (confidence: {:.2})",
                packet.source_ip, packet.dest_ip, analysis_result.confidence
            );
        }
        Ok(())
    }
    pub async fn get_statistics(&self) -> Result<NetworkMonitorStats, AntivirusError> {
        self.monitor.get_statistics().await
    }
    pub async fn update_config(&self, new_config: NetworkMonitorConfig) -> Result<(), AntivirusError> {
        let mut config = self.config.write().await;
        *config = new_config.clone();
        self.monitor.update_config(new_config).await?;
        info!("Network monitor configuration updated");
        Ok(())
    }
    pub async fn check_url_reputation(&self, url: &str) -> Result<UrlReputation, AntivirusError> {
        self.monitor.check_url_reputation(url).await
    }
    pub async fn check_ip_reputation(&self, ip: &IpAddr) -> Result<IpReputation, AntivirusError> {
        self.monitor.check_ip_reputation(ip).await
    }
    async fn start_background_tasks(&self) {
        let monitor = Arc::clone(&self.monitor);
        let is_running = Arc::clone(&self.is_running);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                if !*is_running.read().await {
                    break;
                }
                if rand::random::<f32>() < 0.01 {
                    let packet = Self::generate_test_packet();
                    if let Err(e) = monitor.analyze_packet(&packet).await {
                        error!("Error analyzing test packet: {}", e);
                    }
                }
            }
        });
        let monitor_cleanup = Arc::clone(&self.monitor);
        let is_running_cleanup = Arc::clone(&self.is_running);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if !*is_running_cleanup.read().await {
                    break;
                }
                debug!("Performing reputation cache cleanup");
            }
        });
    }
    fn generate_test_packet() -> NetworkPacket {
        use hadron_core::MockPacketGenerator;
        if rand::random::<f32>() < 0.1 {
            MockPacketGenerator::generate_malicious_packet()
        } else {
            MockPacketGenerator::generate_http_packet(
                "8.8.8.8".parse().unwrap(),
                "google.com"
            )
        }
    }
    async fn create_threat_info(&self, packet: &NetworkPacket, analysis: &NetworkAnalysisResult) -> ThreatInfo {
        ThreatInfo {
            id: uuid::Uuid::new_v4(),
            name: format!("Network Threat - {} -> {}", packet.source_ip, packet.dest_ip),
            threat_type: analysis.threat_type.clone().unwrap_or(ThreatType::Suspicious),
            severity: if analysis.confidence > 0.8 {
                ThreatSeverity::High
            } else if analysis.confidence > 0.5 {
                ThreatSeverity::Medium
            } else {
                ThreatSeverity::Low
            },
            file_path: std::path::PathBuf::from(format!("network:
            file_hash: format!("network-{}", packet.id),
            detection_method: DetectionMethod::Behavioral,
            timestamp: packet.timestamp,
            additional_info: analysis.details.clone(),
        }
    }
    async fn notify_threat(&self, threat_info: ThreatInfo) {
        if let Some(sender) = &self.threat_sender {
            if let Err(e) = sender.send(threat_info) {
                error!("Failed to send threat notification: {}", e);
            }
        }
    }
}
pub struct PacketCapture {
    config: NetworkMonitorConfig,
    is_capturing: Arc<RwLock<bool>>,
}
impl PacketCapture {
    pub fn new(config: NetworkMonitorConfig) -> Self {
        Self {
            config,
            is_capturing: Arc::new(RwLock::new(false)),
        }
    }
    pub async fn start_capture(&self) -> Result<(), AntivirusError> {
        let mut is_capturing = self.is_capturing.write().await;
        if *is_capturing {
            return Ok(());
        }
        info!("Starting packet capture on interfaces: {:?}", self.config.monitor_interfaces);
        *is_capturing = true;
        Ok(())
    }
    pub async fn stop_capture(&self) -> Result<(), AntivirusError> {
        let mut is_capturing = self.is_capturing.write().await;
        if !*is_capturing {
            return Ok(());
        }
        info!("Stopping packet capture");
        *is_capturing = false;
        Ok(())
    }
    pub async fn is_capturing(&self) -> bool {
        *self.is_capturing.read().await
    }
}
pub struct UrlFilterService {
    monitor: Arc<NetworkMonitorImpl>,
    blocked_urls: Arc<RwLock<Vec<String>>>,
    allowed_urls: Arc<RwLock<Vec<String>>>,
}
impl UrlFilterService {
    pub fn new(monitor: Arc<NetworkMonitorImpl>) -> Self {
        Self {
            monitor,
            blocked_urls: Arc::new(RwLock::new(Vec::new())),
            allowed_urls: Arc::new(RwLock::new(Vec::new())),
        }
    }
    pub async fn should_block_url(&self, url: &str) -> Result<bool, AntivirusError> {
        let allowed_urls = self.allowed_urls.read().await;
        for allowed in allowed_urls.iter() {
            if url.contains(allowed) {
                return Ok(false);
            }
        }
        drop(allowed_urls);
        let blocked_urls = self.blocked_urls.read().await;
        for blocked in blocked_urls.iter() {
            if url.contains(blocked) {
                return Ok(true);
            }
        }
        drop(blocked_urls);
        let reputation = self.monitor.check_url_reputation(url).await?;
        Ok(reputation.reputation_score < -50)
    }
    pub async fn block_url(&self, url: String) {
        let mut blocked_urls = self.blocked_urls.write().await;
        if !blocked_urls.contains(&url) {
            blocked_urls.push(url);
        }
    }
    pub async fn allow_url(&self, url: String) {
        let mut allowed_urls = self.allowed_urls.write().await;
        if !allowed_urls.contains(&url) {
            allowed_urls.push(url);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hadron_core::MockPacketGenerator;
    #[tokio::test]
    async fn test_network_monitor_service_creation() {
        let config = NetworkMonitorConfig::default();
        let service = NetworkMonitorService::new(config);
        assert!(!service.is_running().await);
    }
    #[tokio::test]
    async fn test_start_stop_service() {
        let config = NetworkMonitorConfig::default();
        let service = NetworkMonitorService::new(config);
        assert!(service.start().await.is_ok());
        assert!(service.is_running().await);
        assert!(service.stop().await.is_ok());
        assert!(!service.is_running().await);
    }
    #[tokio::test]
    async fn test_packet_processing() {
        let config = NetworkMonitorConfig::default();
        let service = NetworkMonitorService::new(config);
        let packet = MockPacketGenerator::generate_http_packet(
            "8.8.8.8".parse().unwrap(),
            "google.com"
        );
        assert!(service.process_packet(packet).await.is_ok());
    }
    #[tokio::test]
    async fn test_url_filter_service() {
        let config = NetworkMonitorConfig::default();
        let monitor = Arc::new(NetworkMonitorImpl::new(config));
        let url_filter = UrlFilterService::new(monitor);
        let should_block = url_filter.should_block_url("google.com").await.unwrap();
        assert!(!should_block);
        let should_block = url_filter.should_block_url("malware.example.com").await.unwrap();
        assert!(should_block);
        url_filter.block_url("badsite.com".to_string()).await;
        let should_block = url_filter.should_block_url("badsite.com").await.unwrap();
        assert!(should_block);
        url_filter.allow_url("badsite.com".to_string()).await;
        let should_block = url_filter.should_block_url("badsite.com").await.unwrap();
        assert!(!should_block);
    }
    #[tokio::test]
    async fn test_packet_capture() {
        let config = NetworkMonitorConfig::default();
        let capture = PacketCapture::new(config);
        assert!(!capture.is_capturing().await);
        assert!(capture.start_capture().await.is_ok());
        assert!(capture.is_capturing().await);
        assert!(capture.stop_capture().await.is_ok());
        assert!(!capture.is_capturing().await);
    }
}