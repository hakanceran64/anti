use av_service::{NetworkMonitorService, UrlFilterService, PacketCapture};
use hadron_core::{NetworkMonitorConfig, NetworkMonitorImpl, MockPacketGenerator};
use std::sync::Arc;
use tokio;

#[tokio::test]
async fn test_network_monitor_service_lifecycle() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    
    // Test initial state
    assert!(!service.is_running().await);
    
    // Test starting service
    assert!(service.start().await.is_ok());
    assert!(service.is_running().await);
    
    // Test stopping service
    assert!(service.stop().await.is_ok());
    assert!(!service.is_running().await);
}

#[tokio::test]
async fn test_packet_processing() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    
    // Start service
    assert!(service.start().await.is_ok());
    
    // Process a clean packet
    let clean_packet = MockPacketGenerator::generate_http_packet(
        "8.8.8.8".parse().unwrap(),
        "google.com"
    );
    
    assert!(service.process_packet(clean_packet).await.is_ok());
    
    // Process a malicious packet
    let malicious_packet = MockPacketGenerator::generate_malicious_packet();
    assert!(service.process_packet(malicious_packet).await.is_ok());
    
    // Check statistics
    let stats = service.get_statistics().await.unwrap();
    assert!(stats.packets_analyzed >= 2);
    
    // Stop service
    assert!(service.stop().await.is_ok());
}

#[tokio::test]
async fn test_configuration_update() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    
    // Update configuration
    let mut new_config = NetworkMonitorConfig::default();
    new_config.analysis_enabled = false;
    new_config.max_packet_size = 32768;
    
    assert!(service.update_config(new_config).await.is_ok());
}

#[tokio::test]
async fn test_reputation_checking() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    
    // Test URL reputation
    let clean_url_reputation = service.check_url_reputation("google.com").await.unwrap();
    assert!(clean_url_reputation.reputation_score > 0);
    
    let malicious_url_reputation = service.check_url_reputation("malware.example.com").await.unwrap();
    assert!(malicious_url_reputation.reputation_score < 0);
    
    // Test IP reputation
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
    
    // Test clean URL
    let should_block = url_filter.should_block_url("google.com").await.unwrap();
    assert!(!should_block);
    
    // Test malicious URL
    let should_block = url_filter.should_block_url("malware.example.com").await.unwrap();
    assert!(should_block);
    
    // Test manual blocking
    url_filter.block_url("badsite.com".to_string()).await;
    let should_block = url_filter.should_block_url("badsite.com").await.unwrap();
    assert!(should_block);
    
    // Test manual allowing (whitelist overrides blacklist)
    url_filter.allow_url("badsite.com".to_string()).await;
    let should_block = url_filter.should_block_url("badsite.com").await.unwrap();
    assert!(!should_block);
}

#[tokio::test]
async fn test_packet_capture_interface() {
    let config = NetworkMonitorConfig::default();
    let capture = PacketCapture::new(config);
    
    // Test initial state
    assert!(!capture.is_capturing().await);
    
    // Test starting capture
    assert!(capture.start_capture().await.is_ok());
    assert!(capture.is_capturing().await);
    
    // Test stopping capture
    assert!(capture.stop_capture().await.is_ok());
    assert!(!capture.is_capturing().await);
}

#[tokio::test]
async fn test_service_with_threat_notifications() {
    let config = NetworkMonitorConfig::default();
    let mut service = NetworkMonitorService::new(config);
    
    // Set up threat notification channel
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    service.set_threat_sender(sender);
    
    // Start service
    assert!(service.start().await.is_ok());
    
    // Process a malicious packet
    let malicious_packet = MockPacketGenerator::generate_malicious_packet();
    assert!(service.process_packet(malicious_packet).await.is_ok());
    
    // Check if threat notification was sent
    // Note: In a real test, we might need to add a small delay to allow async processing
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    
    // Try to receive threat notification (non-blocking)
    if let Ok(threat_info) = receiver.try_recv() {
        assert!(threat_info.name.contains("Network Threat"));
        assert!(!threat_info.file_path.to_string_lossy().is_empty());
    }
    
    // Stop service
    assert!(service.stop().await.is_ok());
}

#[tokio::test]
async fn test_multiple_packet_processing() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    
    assert!(service.start().await.is_ok());
    
    // Process multiple packets
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
    
    // Check statistics
    let stats = service.get_statistics().await.unwrap();
    assert_eq!(stats.packets_analyzed, 10);
    assert!(stats.threats_detected >= 3); // At least 3 malicious packets
    assert!(stats.bytes_processed > 0);
    
    assert!(service.stop().await.is_ok());
}

#[tokio::test]
async fn test_service_disabled_processing() {
    let config = NetworkMonitorConfig::default();
    let service = NetworkMonitorService::new(config);
    
    // Don't start the service
    assert!(!service.is_running().await);
    
    // Try to process packet while service is not running
    let packet = MockPacketGenerator::generate_http_packet(
        "8.8.8.8".parse().unwrap(),
        "google.com"
    );
    
    // Should succeed but not actually process
    assert!(service.process_packet(packet).await.is_ok());
    
    // Statistics should show no processing
    let stats = service.get_statistics().await.unwrap();
    assert_eq!(stats.packets_analyzed, 0);
}

#[tokio::test]
async fn test_url_filter_reputation_integration() {
    let config = NetworkMonitorConfig::default();
    let monitor = Arc::new(NetworkMonitorImpl::new(config));
    let url_filter = UrlFilterService::new(monitor);
    
    // Test URL with negative reputation
    let should_block = url_filter.should_block_url("suspicious.badsite.com").await.unwrap();
    assert!(should_block); // Should be blocked due to "suspicious" in URL
    
    // Test URL with positive reputation
    let should_block = url_filter.should_block_url("clean.goodsite.com").await.unwrap();
    assert!(!should_block);
}

#[tokio::test]
async fn test_concurrent_packet_processing() {
    let config = NetworkMonitorConfig::default();
    let service = Arc::new(NetworkMonitorService::new(config));
    
    assert!(service.start().await.is_ok());
    
    // Process packets concurrently
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
    
    // Wait for all tasks to complete
    for handle in handles {
        assert!(handle.await.unwrap().is_ok());
    }
    
    // Check statistics
    let stats = service.get_statistics().await.unwrap();
    assert_eq!(stats.packets_analyzed, 5);
    
    assert!(service.stop().await.is_ok());
}