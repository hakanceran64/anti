use av_service::quarantine::QuarantineManagerImpl;
use hadron_core::{QuarantineOperations, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
use hadron_core::config::QuarantineConfig;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_quarantine_basic_operations() {
    // Create temporary directory for testing
    let temp_dir = TempDir::new().unwrap();
    let quarantine_path = temp_dir.path().join("quarantine");
    let key_path = temp_dir.path().join("quarantine.key");
    
    // Create test configuration
    let config = QuarantineConfig {
        quarantine_path,
        max_quarantine_size_mb: 100,
        auto_delete_after_days: 30,
        encryption_key_path: key_path,
    };
    
    // Create quarantine manager
    let quarantine_manager = QuarantineManagerImpl::new(&config).await.unwrap();
    
    // Create a test file
    let test_file = temp_dir.path().join("test_malware.exe");
    std::fs::write(&test_file, b"This is a test malware file").unwrap();
    
    // Create threat info
    let threat_info = ThreatInfo::new(
        "Test.Malware".to_string(),
        ThreatType::Virus,
        ThreatSeverity::High,
        test_file.clone(),
        "a".repeat(64), // Valid SHA-256 hash
        DetectionMethod::Signature,
    ).unwrap();
    
    // Test quarantine operation
    let quarantine_id = quarantine_manager.quarantine_file(&test_file, &threat_info).await.unwrap();
    
    // Verify file was quarantined (original should be gone)
    assert!(!test_file.exists());
    
    // List quarantined files
    let quarantined_files = quarantine_manager.list_quarantined().await.unwrap();
    assert_eq!(quarantined_files.len(), 1);
    assert_eq!(quarantined_files[0].id, quarantine_id);
    
    // Test restore operation
    quarantine_manager.restore_file(quarantine_id).await.unwrap();
    
    // Verify file was restored
    assert!(test_file.exists());
    let restored_content = std::fs::read_to_string(&test_file).unwrap();
    assert_eq!(restored_content, "This is a test malware file");
    
    // Verify quarantine is empty
    let quarantined_files = quarantine_manager.list_quarantined().await.unwrap();
    assert_eq!(quarantined_files.len(), 0);
}

#[tokio::test]
async fn test_quarantine_delete_operation() {
    // Create temporary directory for testing
    let temp_dir = TempDir::new().unwrap();
    let quarantine_path = temp_dir.path().join("quarantine");
    let key_path = temp_dir.path().join("quarantine.key");
    
    // Create test configuration
    let config = QuarantineConfig {
        quarantine_path,
        max_quarantine_size_mb: 100,
        auto_delete_after_days: 30,
        encryption_key_path: key_path,
    };
    
    // Create quarantine manager
    let quarantine_manager = QuarantineManagerImpl::new(&config).await.unwrap();
    
    // Create a test file
    let test_file = temp_dir.path().join("test_malware2.exe");
    std::fs::write(&test_file, b"Another test malware file").unwrap();
    
    // Create threat info
    let threat_info = ThreatInfo::new(
        "Test.Malware2".to_string(),
        ThreatType::Trojan,
        ThreatSeverity::Critical,
        test_file.clone(),
        "b".repeat(64), // Valid SHA-256 hash
        DetectionMethod::Heuristic,
    ).unwrap();
    
    // Test quarantine operation
    let quarantine_id = quarantine_manager.quarantine_file(&test_file, &threat_info).await.unwrap();
    
    // Verify file was quarantined
    assert!(!test_file.exists());
    
    // Test delete operation
    quarantine_manager.delete_quarantined(quarantine_id).await.unwrap();
    
    // Verify quarantine is empty
    let quarantined_files = quarantine_manager.list_quarantined().await.unwrap();
    assert_eq!(quarantined_files.len(), 0);
    
    // Verify original file is still gone
    assert!(!test_file.exists());
}

#[tokio::test]
async fn test_quarantine_encryption() {
    // Create temporary directory for testing
    let temp_dir = TempDir::new().unwrap();
    let quarantine_path = temp_dir.path().join("quarantine");
    let key_path = temp_dir.path().join("quarantine.key");
    
    // Create test configuration
    let config = QuarantineConfig {
        quarantine_path: quarantine_path.clone(),
        max_quarantine_size_mb: 100,
        auto_delete_after_days: 30,
        encryption_key_path: key_path,
    };
    
    // Create quarantine manager
    let quarantine_manager = QuarantineManagerImpl::new(&config).await.unwrap();
    
    // Create a test file with specific content
    let test_file = temp_dir.path().join("test_encryption.txt");
    let original_content = "This is sensitive malware content that should be encrypted";
    std::fs::write(&test_file, original_content).unwrap();
    
    // Create threat info
    let threat_info = ThreatInfo::new(
        "Test.Encryption".to_string(),
        ThreatType::Spyware,
        ThreatSeverity::Medium,
        test_file.clone(),
        "c".repeat(64), // Valid SHA-256 hash
        DetectionMethod::MachineLearning,
    ).unwrap();
    
    // Test quarantine operation
    let quarantine_id = quarantine_manager.quarantine_file(&test_file, &threat_info).await.unwrap();
    
    // Get quarantine entry to check encrypted file
    let entry = quarantine_manager.get_quarantine_entry(quarantine_id).await.unwrap();
    
    // Verify encrypted file exists and is different from original
    assert!(entry.encrypted_path.exists());
    let encrypted_content = std::fs::read(&entry.encrypted_path).unwrap();
    
    // Encrypted content should be different from original
    assert_ne!(encrypted_content, original_content.as_bytes());
    
    // Encrypted content should be larger (due to nonce and auth tag)
    assert!(encrypted_content.len() > original_content.len());
    
    // Test restore to verify decryption works
    quarantine_manager.restore_file(quarantine_id).await.unwrap();
    
    // Verify restored content matches original
    let restored_content = std::fs::read_to_string(&test_file).unwrap();
    assert_eq!(restored_content, original_content);
}