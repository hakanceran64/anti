use av_service::quarantine::QuarantineManagerImpl;
use hadron_core::{QuarantineOperations, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
use hadron_core::config::QuarantineConfig;
use std::path::PathBuf;
use tempfile::TempDir;
#[tokio::test]
async fn test_quarantine_basic_operations() {
    let temp_dir = TempDir::new().unwrap();
    let quarantine_path = temp_dir.path().join("quarantine");
    let key_path = temp_dir.path().join("quarantine.key");
    let config = QuarantineConfig {
        quarantine_path,
        max_quarantine_size_mb: 100,
        auto_delete_after_days: 30,
        encryption_key_path: key_path,
    };
    let quarantine_manager = QuarantineManagerImpl::new(&config).await.unwrap();
    let test_file = temp_dir.path().join("test_malware.exe");
    std::fs::write(&test_file, b"This is a test malware file").unwrap();
    let threat_info = ThreatInfo::new(
        "Test.Malware".to_string(),
        ThreatType::Virus,
        ThreatSeverity::High,
        test_file.clone(),
        "a".repeat(64),
        DetectionMethod::Signature,
    ).unwrap();
    let quarantine_id = quarantine_manager.quarantine_file(&test_file, &threat_info).await.unwrap();
    assert!(!test_file.exists());
    let quarantined_files = quarantine_manager.list_quarantined().await.unwrap();
    assert_eq!(quarantined_files.len(), 1);
    assert_eq!(quarantined_files[0].id, quarantine_id);
    quarantine_manager.restore_file(quarantine_id).await.unwrap();
    assert!(test_file.exists());
    let restored_content = std::fs::read_to_string(&test_file).unwrap();
    assert_eq!(restored_content, "This is a test malware file");
    let quarantined_files = quarantine_manager.list_quarantined().await.unwrap();
    assert_eq!(quarantined_files.len(), 0);
}
#[tokio::test]
async fn test_quarantine_delete_operation() {
    let temp_dir = TempDir::new().unwrap();
    let quarantine_path = temp_dir.path().join("quarantine");
    let key_path = temp_dir.path().join("quarantine.key");
    let config = QuarantineConfig {
        quarantine_path,
        max_quarantine_size_mb: 100,
        auto_delete_after_days: 30,
        encryption_key_path: key_path,
    };
    let quarantine_manager = QuarantineManagerImpl::new(&config).await.unwrap();
    let test_file = temp_dir.path().join("test_malware2.exe");
    std::fs::write(&test_file, b"Another test malware file").unwrap();
    let threat_info = ThreatInfo::new(
        "Test.Malware2".to_string(),
        ThreatType::Trojan,
        ThreatSeverity::Critical,
        test_file.clone(),
        "b".repeat(64),
        DetectionMethod::Heuristic,
    ).unwrap();
    let quarantine_id = quarantine_manager.quarantine_file(&test_file, &threat_info).await.unwrap();
    assert!(!test_file.exists());
    quarantine_manager.delete_quarantined(quarantine_id).await.unwrap();
    let quarantined_files = quarantine_manager.list_quarantined().await.unwrap();
    assert_eq!(quarantined_files.len(), 0);
    assert!(!test_file.exists());
}
#[tokio::test]
async fn test_quarantine_encryption() {
    let temp_dir = TempDir::new().unwrap();
    let quarantine_path = temp_dir.path().join("quarantine");
    let key_path = temp_dir.path().join("quarantine.key");
    let config = QuarantineConfig {
        quarantine_path: quarantine_path.clone(),
        max_quarantine_size_mb: 100,
        auto_delete_after_days: 30,
        encryption_key_path: key_path,
    };
    let quarantine_manager = QuarantineManagerImpl::new(&config).await.unwrap();
    let test_file = temp_dir.path().join("test_encryption.txt");
    let original_content = "This is sensitive malware content that should be encrypted";
    std::fs::write(&test_file, original_content).unwrap();
    let threat_info = ThreatInfo::new(
        "Test.Encryption".to_string(),
        ThreatType::Spyware,
        ThreatSeverity::Medium,
        test_file.clone(),
        "c".repeat(64),
        DetectionMethod::MachineLearning,
    ).unwrap();
    let quarantine_id = quarantine_manager.quarantine_file(&test_file, &threat_info).await.unwrap();
    let entry = quarantine_manager.get_quarantine_entry(quarantine_id).await.unwrap();
    assert!(entry.encrypted_path.exists());
    let encrypted_content = std::fs::read(&entry.encrypted_path).unwrap();
    assert_ne!(encrypted_content, original_content.as_bytes());
    assert!(encrypted_content.len() > original_content.len());
    quarantine_manager.restore_file(quarantine_id).await.unwrap();
    let restored_content = std::fs::read_to_string(&test_file).unwrap();
    assert_eq!(restored_content, original_content);
}