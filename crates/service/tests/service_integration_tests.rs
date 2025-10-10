/// Integration tests for the main antivirus service

use av_service::*;
use hadron_core::*;
use std::sync::Arc;

#[tokio::test]
async fn test_service_creation() {
    let config = AntivirusConfig::default();
    let service = AntivirusService::new(config).await;
    assert!(service.is_ok());
}

#[tokio::test]
async fn test_service_lifecycle() {
    let config = AntivirusConfig::default();
    let service = AntivirusService::new(config).await.unwrap();
    
    // Initially not running
    assert!(!service.is_running().await);
    
    // Start service
    service.start().await.unwrap();
    assert!(service.is_running().await);
    
    // Stop service
    service.stop().await.unwrap();
    assert!(!service.is_running().await);
}

#[tokio::test]
async fn test_windows_service_wrapper() {
    let config = AntivirusConfig::default();
    let service = Arc::new(AntivirusService::new(config).await.unwrap());
    let wrapper = WindowsServiceWrapper::new(service).unwrap();
    
    // Test lifecycle
    assert!(!wrapper.is_running().await);
    
    wrapper.start_service().await.unwrap();
    assert!(wrapper.is_running().await);
    
    wrapper.stop_service().await.unwrap();
    assert!(!wrapper.is_running().await);
}

#[tokio::test]
async fn test_api_server_creation() {
    let config = AntivirusConfig::default();
    let service = Arc::new(AntivirusService::new(config).await.unwrap());
    let api_server = ApiServer::new("test_pipe".to_string(), service);
    
    // Test start/stop
    api_server.start().await.unwrap();
    api_server.stop().await.unwrap();
}

#[tokio::test]
async fn test_api_client_creation() {
    let client = ApiClient::new("test_pipe".to_string());
    
    // Test connection attempt (will fail but shouldn't panic)
    let result = client.connect().await;
    // Connection will fail since no server is running, but it should handle gracefully
    assert!(result.is_err());
}

#[tokio::test]
async fn test_service_lifecycle_manager() {
    let config = AntivirusConfig::default();
    let service = Arc::new(AntivirusService::new(config).await.unwrap());
    let manager = ServiceLifecycleManager::new(service);
    
    // Test state transitions
    assert_eq!(manager.get_state().await, ServiceState::Stopped);
    
    manager.start().await.unwrap();
    assert_eq!(manager.get_state().await, ServiceState::Running);
    
    manager.pause().await.unwrap();
    assert_eq!(manager.get_state().await, ServiceState::Paused);
    
    manager.resume().await.unwrap();
    assert_eq!(manager.get_state().await, ServiceState::Running);
    
    manager.stop().await.unwrap();
    assert_eq!(manager.get_state().await, ServiceState::Stopped);
}

#[tokio::test]
async fn test_service_configuration_update() {
    let config = AntivirusConfig::default();
    let service = AntivirusService::new(config).await.unwrap();
    
    // Update configuration
    let mut new_config = AntivirusConfig::default();
    new_config.realtime_protection.enabled = false;
    
    service.update_config(new_config).await.unwrap();
}

#[tokio::test]
async fn test_service_health_check() {
    let config = AntivirusConfig::default();
    let service = Arc::new(AntivirusService::new(config).await.unwrap());
    let manager = ServiceLifecycleManager::new(service);
    
    // Health check when stopped
    assert!(!manager.health_check().await.unwrap());
    
    // Start and check health
    manager.start().await.unwrap();
    assert!(manager.health_check().await.unwrap());
}