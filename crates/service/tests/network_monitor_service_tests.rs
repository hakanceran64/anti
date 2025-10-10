use av_service::{NetworkMonitorService, UrlFilterService, PacketCapture};
use hadron_core::{NetworkMonitorConfig, NetworkMonitorImpl, MockPacketGenerator};
use std::sync::Arc;
use tokio;
#[tokio::test]
async fn test_network_monitor_service_lifecycle() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    assert!(!service.is_running().await);
    assert!(service.start().await.is_ok());
    assert!(service.is_running().await);
    assert!(service.stop().await.is_ok());
    assert!(!service.is_running().await);
}
#[tokio::test]
async fn test_packet_processing() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    assert!(service.start().await.is_ok());
    let clean_packet = MockPacketGenerator::generate_http_packet(
        "8.8.8.8".parse().unwrap(),
        "google.com"
    );
    assert!(service.process_packet(clean_packet).await.is_ok());
    let malicious_packet = MockPacketGenerator::generate_malicious_packet();
    assert!(service.process_packet(malicious_packet).await.is_ok());
    let stats = service.get_statistics().await.unwrap();
    assert!(stats.packets_analyzed >= 2);
    assert!(service.stop().await.is_ok());
}
#[tokio::test]
async fn test_configuration_update() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    let mut new_config = NetworkMonitorConfig::default();
    new_config.analysis_enabled = false;
    new_config.max_packet_size = 32768;
    assert!(service.update_config(new_config).await.is_ok());
}
#[tokio::test]
async fn test_reputation_checking() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    let clean_url_reputation = service.check_url_reputation("google.com").await.unwrap();
    assert!(clean_url_reputation.reputation_score > 0);
    let malicious_url_reputation = service.check_url_reputation("malware.example.com").await.unwrap();
    assert!(malicious_url_reputation.reputation_score < 0);
    let clean_ip = "8.8.8.8".parse().unwrap();
    let clean_ip_reputation = service.check_ip_reputation(&clean_ip).await.unwrap();
    assert!(clean_ip_reputation.reputation_score >= 0);
    let malicious_ip = "192.168.1.100".parse().unwrap();
    let malicious_ip_reputation = service.check_ip_reputation(&malicious_ip).await.unwrap();
    assert!(malicious_ip_reputation.reputation_score < 0);
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
async fn test_packet_capture_interface() {
    let config = NetworkMonitorConfig::default();
    let capture = PacketCapture::new(config);
    assert!(!capture.is_capturing().await);
    assert!(capture.start_capture().await.is_ok());
    assert!(capture.is_capturing().await);
    assert!(capture.stop_capture().await.is_ok());
    assert!(!capture.is_capturing().await);
}
#[tokio::test]
async fn test_service_with_threat_notifications() {
    let config = NetworkMonitorConfig::default();
    let mut service = NetworkMonitorService::new(config);
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    service.set_threat_sender(sender);
    assert!(service.start().await.is_ok());
    let malicious_packet = MockPacketGenerator::generate_malicious_packet();
    assert!(service.process_packet(malicious_packet).await.is_ok());
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    if let Ok(threat_info) = receiver.try_recv() {
        assert!(threat_info.name.contains("Network Threat"));
        assert!(!threat_info.file_path.to_string_lossy().is_empty());
    }
    assert!(service.stop().await.is_ok());
}
#[tokio::test]
async fn test_multiple_packet_processing() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    assert!(service.start().await.is_ok());
    for i in 0..10 {
        let packet = if i % 3 == 0 {
            MockPacketGenerator::generate_malicious_packet()
        } else {
            MockPacketGenerator::generate_http_packet(
                "8.8.8.8".parse().unwrap(),
                "google.com"
            )
        };
        assert!(service.process_packet(packet).await.is_ok());
    }
    let stats = service.get_statistics().await.unwrap();
    assert_eq!(stats.packets_analyzed, 10);
    assert!(stats.threats_detected >= 3);
    assert!(stats.bytes_processed > 0);
    assert!(service.stop().await.is_ok());
}
#[tokio::test]
async fn test_service_disabled_processing() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    assert!(!service.is_running().await);
    let packet = MockPacketGenerator::generate_http_packet(
        "8.8.8.8".parse().unwrap(),
        "google.com"
    );
    assert!(service.process_packet(packet).await.is_ok());
    let stats = service.get_statistics().await.unwrap();
    assert_eq!(stats.packets_analyzed, 0);
}
#[tokio::test]
async fn test_url_filter_reputation_integration() {
    let config = NetworkMonitorConfig::default();
    let monitor = Arc::new(NetworkMonitorImpl::new(config));
    let url_filter = UrlFilterService::new(monitor);
    let should_block = url_filter.should_block_url("suspicious.badsite.com").await.unwrap();
    assert!(should_block);
    let should_block = url_filter.should_block_url("clean.goodsite.com").await.unwrap();
    assert!(!should_block);
}
#[tokio::test]
async fn test_concurrent_packet_processing() {
    let config = NetworkMonitorConfig::default();
    let service = Arc::new(NetworkMonitorService::new(config));
    assert!(service.start().await.is_ok());
    let mut handles = Vec::new();
    for i in 0..5 {
        let service_clone = Arc::clone(&service);
        let handle = tokio::spawn(async move {
            let packet = MockPacketGenerator::generate_http_packet(
                format!("192.168.1.{}", i + 10).parse().unwrap(),
                "google.com"
            );
            service_clone.process_packet(packet).await
        });
        handles.push(handle);
    }
    for handle in handles {
        assert!(handle.await.unwrap().is_ok());
    }
    let stats = service.get_statistics().await.unwrap();
    assert_eq!(stats.packets_analyzed, 5);
    assert!(service.stop().await.is_ok());
}