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
    assert!(!service.is_running().await);
    service.start().await.unwrap();
    assert!(service.is_running().await);
    service.stop().await.unwrap();
    assert!(!service.is_running().await);
}
#[tokio::test]
async fn test_windows_service_wrapper() {
    let config = AntivirusConfig::default();
    let service = Arc::new(AntivirusService::new(config).await.unwrap());
    let wrapper = WindowsServiceWrapper::new(service).unwrap();
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
    api_server.start().await.unwrap();
    api_server.stop().await.unwrap();
}
#[tokio::test]
async fn test_api_client_creation() {
    let client = ApiClient::new("test_pipe".to_string());
    let result = client.connect().await;
    assert!(result.is_err());
}
#[tokio::test]
async fn test_service_lifecycle_manager() {
    let config = AntivirusConfig::default();
    let service = Arc::new(AntivirusService::new(config).await.unwrap());
    let manager = ServiceLifecycleManager::new(service);
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
    let mut new_config = AntivirusConfig::default();
    new_config.realtime_protection.enabled = false;
    service.update_config(new_config).await.unwrap();
}
#[tokio::test]
async fn test_service_health_check() {
    let config = AntivirusConfig::default();
    let service = Arc::new(AntivirusService::new(config).await.unwrap());
    let manager = ServiceLifecycleManager::new(service);
    assert!(!manager.health_check().await.unwrap());
    manager.start().await.unwrap();
    assert!(manager.health_check().await.unwrap());
}