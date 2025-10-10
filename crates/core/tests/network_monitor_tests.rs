use hadron_core::{
    NetworkMonitor, NetworkMonitorImpl, NetworkMonitorConfig, NetworkPacket,
    NetworkProtocol, MockPacketGenerator, ThreatType
};
use std::net::IpAddr;
use tokio;
#[tokio::test]
async fn test_network_monitor_creation() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    assert!(!monitor.is_monitoring().await);
}
#[tokio::test]
async fn test_start_stop_monitoring() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    assert!(monitor.start_monitoring().await.is_ok());
    assert!(monitor.is_monitoring().await);
    assert!(monitor.stop_monitoring().await.is_ok());
    assert!(!monitor.is_monitoring().await);
}
#[tokio::test]
async fn test_packet_analysis_clean() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let packet = MockPacketGenerator::generate_http_packet(
        "8.8.8.8".parse().unwrap(),
        "google.com"
    );
    let result = monitor.analyze_packet(&packet).await.unwrap();
    assert_eq!(result.packet_id, packet.id);
    assert!(!result.is_malicious);
    assert!(!result.blocked);
    assert!(result.confidence < 0.5);
}
#[tokio::test]
async fn test_packet_analysis_malicious() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let packet = MockPacketGenerator::generate_malicious_packet();
    let result = monitor.analyze_packet(&packet).await.unwrap();
    assert!(result.is_malicious);
    assert!(result.confidence > 0.5);
    assert!(result.blocked);
    assert!(result.threat_type.is_some());
}
#[tokio::test]
async fn test_url_reputation_clean() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let reputation = monitor.check_url_reputation("google.com").await.unwrap();
    assert!(reputation.reputation_score > 0);
    assert_eq!(reputation.url, "google.com");
    assert!(reputation.categories.contains(&"clean".to_string()));
}
#[tokio::test]
async fn test_url_reputation_malicious() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let reputation = monitor.check_url_reputation("malware.example.com").await.unwrap();
    assert!(reputation.reputation_score < 0);
    assert_eq!(reputation.url, "malware.example.com");
    assert!(reputation.categories.contains(&"malware".to_string()));
}
#[tokio::test]
async fn test_ip_reputation_clean() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let clean_ip: IpAddr = "8.8.8.8".parse().unwrap();
    let reputation = monitor.check_ip_reputation(&clean_ip).await.unwrap();
    assert!(reputation.reputation_score >= 0);
    assert_eq!(reputation.ip, clean_ip);
}
#[tokio::test]
async fn test_ip_reputation_malicious() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let malicious_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let reputation = monitor.check_ip_reputation(&malicious_ip).await.unwrap();
    assert!(reputation.reputation_score < 0);
    assert_eq!(reputation.ip, malicious_ip);
}
#[tokio::test]
async fn test_ip_reputation_private() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let private_ip: IpAddr = "192.168.1.10".parse().unwrap();
    let reputation = monitor.check_ip_reputation(&private_ip).await.unwrap();
    assert!(reputation.reputation_score > 0);
    assert_eq!(reputation.ip, private_ip);
}
#[tokio::test]
async fn test_statistics_tracking() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let initial_stats = monitor.get_statistics().await.unwrap();
    assert_eq!(initial_stats.packets_analyzed, 0);
    assert_eq!(initial_stats.threats_detected, 0);
    let clean_packet = MockPacketGenerator::generate_http_packet(
        "8.8.8.8".parse().unwrap(),
        "google.com"
    );
    let _ = monitor.analyze_packet(&clean_packet).await.unwrap();
    let stats_after_clean = monitor.get_statistics().await.unwrap();
    assert_eq!(stats_after_clean.packets_analyzed, 1);
    assert_eq!(stats_after_clean.threats_detected, 0);
    assert!(stats_after_clean.bytes_processed > 0);
    let malicious_packet = MockPacketGenerator::generate_malicious_packet();
    let _ = monitor.analyze_packet(&malicious_packet).await.unwrap();
    let stats_after_malicious = monitor.get_statistics().await.unwrap();
    assert_eq!(stats_after_malicious.packets_analyzed, 2);
    assert_eq!(stats_after_malicious.threats_detected, 1);
    assert_eq!(stats_after_malicious.connections_blocked, 1);
}
#[tokio::test]
async fn test_configuration_update() {
    let mut config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config.clone());
    config.analysis_enabled = false;
    assert!(monitor.update_config(config).await.is_ok());
    let packet = MockPacketGenerator::generate_malicious_packet();
    let result = monitor.analyze_packet(&packet).await.unwrap();
    assert!(!result.is_malicious);
}
#[tokio::test]
async fn test_url_extraction_from_packet() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let payload = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n";
    let packet = NetworkPacket {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        source_ip: "192.168.1.10".parse().unwrap(),
        dest_ip: "93.184.216.34".parse().unwrap(),
        source_port: 12345,
        dest_port: 80,
        protocol: NetworkProtocol::HTTP,
        payload: payload.as_bytes().to_vec(),
        size: payload.len(),
    };
    let result = monitor.analyze_packet(&packet).await.unwrap();
    assert_eq!(result.packet_id, packet.id);
    assert!(result.details.contains_key("source_ip"));
    assert!(result.details.contains_key("dest_ip"));
}
#[tokio::test]
async fn test_suspicious_pattern_detection() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let payload = r#"
        <html>
        <script>
            eval(atob('bWFsaWNpb3VzIGNvZGU='));
            document.write('<iframe src="http:
        </script>
        </html>
    "#;
    let packet = NetworkPacket {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        source_ip: "192.168.1.10".parse().unwrap(),
        dest_ip: "8.8.8.8".parse().unwrap(),
        source_port: 12345,
        dest_port: 80,
        protocol: NetworkProtocol::HTTP,
        payload: payload.as_bytes().to_vec(),
        size: payload.len(),
    };
    let result = monitor.analyze_packet(&packet).await.unwrap();
    assert!(result.is_malicious);
    assert!(result.confidence >= 0.6);
    assert_eq!(result.threat_type, Some(ThreatType::Suspicious));
}
#[tokio::test]
async fn test_disabled_monitoring() {
    let mut config = NetworkMonitorConfig::default();
    config.enabled = false;
    let monitor = NetworkMonitorImpl::new(config);
    let result = monitor.start_monitoring().await;
    assert!(result.is_err());
}
#[tokio::test]
async fn test_reputation_caching() {
    let config = NetworkMonitorConfig::default();
    let monitor = NetworkMonitorImpl::new(config);
    let url = "test-cache.com";
    let reputation1 = monitor.check_url_reputation(url).await.unwrap();
    let reputation2 = monitor.check_url_reputation(url).await.unwrap();
    assert_eq!(reputation1.url, reputation2.url);
    assert_eq!(reputation1.reputation_score, reputation2.reputation_score);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let ip_reputation1 = monitor.check_ip_reputation(&ip).await.unwrap();
    let ip_reputation2 = monitor.check_ip_reputation(&ip).await.unwrap();
    assert_eq!(ip_reputation1.ip, ip_reputation2.ip);
    assert_eq!(ip_reputation1.reputation_score, ip_reputation2.reputation_score);
}