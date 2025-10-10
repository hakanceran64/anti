use av_service::UpdateManagerImpl;
use hadron_core::{UpdateOperations, UpdateSettings, UpdateInfo, UpdatePackage};
use std::path::PathBuf;
use tempfile::TempDir;
use tokio;
#[tokio::test]
async fn test_update_manager_creation() {
    let temp_dir = TempDir::new().unwrap();
    let config = UpdateSettings {
        auto_update: true,
        update_frequency_hours: 24,
        update_server_url: "https:
        use_delta_updates: true,
    };
    let update_manager = UpdateManagerImpl::new(&config, temp_dir.path().to_path_buf());
    assert!(update_manager.is_ok());
}
#[tokio::test]
async fn test_update_manager_lifecycle() {
    let temp_dir = TempDir::new().unwrap();
    let config = UpdateSettings {
        auto_update: false,
        update_frequency_hours: 24,
        update_server_url: "https:
        use_delta_updates: true,
    };
    let update_manager = UpdateManagerImpl::new(&config, temp_dir.path().to_path_buf()).unwrap();
    assert!(update_manager.start().await.is_ok());
    assert!(update_manager.stop().await.is_ok());
}
#[tokio::test]
async fn test_version_info() {
    let temp_dir = TempDir::new().unwrap();
    let config = UpdateSettings {
        auto_update: false,
        update_frequency_hours: 24,
        update_server_url: "https:
        use_delta_updates: true,
    };
    let update_manager = UpdateManagerImpl::new(&config, temp_dir.path().to_path_buf()).unwrap();
    let version_info = update_manager.get_version_info();
    assert!(!version_info.engine_version.is_empty());
    assert!(!version_info.signature_version.is_empty());
}
#[tokio::test]
async fn test_update_history() {
    let temp_dir = TempDir::new().unwrap();
    let config = UpdateSettings {
        auto_update: false,
        update_frequency_hours: 24,
        update_server_url: "https:
        use_delta_updates: true,
    };
    let update_manager = UpdateManagerImpl::new(&config, temp_dir.path().to_path_buf()).unwrap();
    let history = update_manager.get_update_history().await.unwrap();
    assert!(history.is_empty());
    let is_applied = update_manager.is_update_applied("1.0.0").await.unwrap();
    assert!(!is_applied);
}
#[tokio::test]
async fn test_rollback_versions() {
    let temp_dir = TempDir::new().unwrap();
    let config = UpdateSettings {
        auto_update: false,
        update_frequency_hours: 24,
        update_server_url: "https:
        use_delta_updates: true,
    };
    let update_manager = UpdateManagerImpl::new(&config, temp_dir.path().to_path_buf()).unwrap();
    let versions = update_manager.get_available_rollback_versions().await.unwrap();
    assert!(versions.is_empty());
}
#[tokio::test]
async fn test_signature_verification() {
    let temp_dir = TempDir::new().unwrap();
    let config = UpdateSettings {
        auto_update: false,
        update_frequency_hours: 24,
        update_server_url: "https:
        use_delta_updates: true,
    };
    let update_manager = UpdateManagerImpl::new(&config, temp_dir.path().to_path_buf()).unwrap();
    let test_data = b"test update data";
    let test_signature = base64::engine::general_purpose::STANDARD.encode(b"fake_signature");
    let package = UpdatePackage {
        version: "test-1.0.0".to_string(),
        data: test_data.to_vec(),
        signature: test_signature,
    };
    let result = update_manager.verify_package_signature(&package).await;
    assert!(result.is_ok());
}
#[tokio::test]
async fn test_delta_update_manager() {
    let temp_dir = TempDir::new().unwrap();
    let delta_manager = av_service::update_manager::DeltaUpdateManager::new(temp_dir.path().to_path_buf());
    let checksums = delta_manager.calculate_checksums(temp_dir.path()).await.unwrap();
    assert!(checksums.is_empty());
    let test_file = temp_dir.path().join("test.txt");
    tokio::fs::write(&test_file, b"test content").await.unwrap();
    let checksums = delta_manager.calculate_checksums(temp_dir.path()).await.unwrap();
    assert_eq!(checksums.len(), 1);
    assert!(checksums.contains_key(&test_file));
}
#[tokio::test]
async fn test_secure_downloader_creation() {
    let public_key_der = vec![0u8; 256];
    let downloader = av_service::update_manager::SecureDownloader::new(&public_key_der);
    assert!(downloader.is_ok());
}
#[tokio::test]
async fn test_signature_verifier() {
    let public_key_der = vec![0u8; 256];
    let verifier = av_service::update_manager::SignatureVerifier::new(&public_key_der).unwrap();
    let test_data = b"test data for signature verification";
    let test_signature = vec![0u8; 64];
    let result = verifier.verify(test_data, &test_signature);
    assert!(result.is_ok());
}
#[tokio::test]
async fn test_update_flow_integration() {
    let temp_dir = TempDir::new().unwrap();
    let config = UpdateSettings {
        auto_update: false,
        update_frequency_hours: 24,
        update_server_url: "https:
        use_delta_updates: false,
    };
    let update_manager = UpdateManagerImpl::new(&config, temp_dir.path().to_path_buf()).unwrap();
    update_manager.start().await.unwrap();
    let updates = update_manager.check_updates().await;
    assert!(updates.is_err() || updates.unwrap().is_empty());
    let test_package = UpdatePackage {
        version: "signatures-2024.01.01".to_string(),
        data: create_mock_signature_package(),
        signature: base64::engine::general_purpose::STANDARD.encode(b"mock_signature"),
    };
    let apply_result = update_manager.apply_update(test_package).await;
    assert!(apply_result.is_ok());
    update_manager.stop().await.unwrap();
}
fn create_mock_signature_package() -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;
    use std::io::Write;
    let mut compressed_data = Vec::new();
    {
        let encoder = GzEncoder::new(&mut compressed_data, Compression::default());
        let mut archive = Builder::new(encoder);
        let signature_content = b"rule test_signature { condition: true }";
        let mut header = tar::Header::new_gnu();
        header.set_path("test.yar").unwrap();
        header.set_size(signature_content.len() as u64);
        header.set_cksum();
        archive.append(&header, &signature_content[..]).unwrap();
        archive.finish().unwrap();
    }
    compressed_data
}