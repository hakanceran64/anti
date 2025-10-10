use av_service::config_manager::{ConfigurationManager, PolicyValidationRules, WhitelistOperationType};
use hadron_core::traits::{
    EnterprisePolicy, PolicyRestrictions, ScanSettings, RealtimeSettings, 
    UpdateSettings, WhitelistEntry, ConfigOperations
};
use tempfile::TempDir;
use std::path::PathBuf;
use chrono::{Utc, Duration};
fn create_test_config_manager() -> (ConfigurationManager, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test_config.toml");
    let manager = ConfigurationManager::new(config_path).unwrap();
    (manager, temp_dir)
}
fn create_test_policy() -> EnterprisePolicy {
    EnterprisePolicy {
        policy_version: "1.0".to_string(),
        scan_settings: ScanSettings {
            scan_archives: true,
            scan_email: true,
            scan_network_drives: false,
            max_file_size_mb: 100,
            timeout_seconds: 30,
            heuristic_level: 2,
        },
        realtime_settings: RealtimeSettings {
            enabled: true,
            scan_on_access: true,
            scan_on_write: true,
            scan_downloads: true,
            scan_removable_media: true,
        },
        update_settings: UpdateSettings {
            auto_update: true,
            update_frequency_hours: 4,
            update_server_url: "https:
            use_delta_updates: true,
        },
        restrictions: PolicyRestrictions {
            allow_user_whitelist: false,
            allow_disable_realtime: false,
            allow_quarantine_restore: true,
            require_admin_for_settings: true,
        },
    }
}
#[test]
fn test_configuration_manager_creation() {
    let (manager, _temp_dir) = create_test_config_manager();
    let config = manager.get_config();
    assert!(config.validate().is_ok());
    assert_eq!(config.service.service_name, "WindowsAntivirusService");
}
#[test]
fn test_configuration_manager_with_custom_validation_rules() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test_config.toml");
    let custom_rules = PolicyValidationRules {
        max_scan_timeout: 1800,
        min_update_frequency: 2,
        max_update_frequency: 48,
        allowed_heuristic_levels: vec![1, 2, 3],
        required_scan_settings: vec!["scan_archives".to_string()],
    };
    let manager = ConfigurationManager::with_validation_rules(config_path, custom_rules).unwrap();
    let config = manager.get_config();
    assert!(config.validate().is_ok());
}
#[test]
fn test_enterprise_policy_application() {
    let (manager, _temp_dir) = create_test_config_manager();
    let policy = create_test_policy();
    let result = manager.apply_enterprise_policy(policy.clone()).unwrap();
    assert!(result.success);
    assert!(!result.applied_settings.is_empty());
    assert!(result.failed_settings.is_empty());
    let config = manager.get_config();
    assert!(config.has_enterprise_policy());
    assert_eq!(config.enterprise_policy.as_ref().unwrap().policy_version, "1.0");
}
#[test]
fn test_enterprise_policy_validation_failure() {
    let (manager, _temp_dir) = create_test_config_manager();
    let mut policy = create_test_policy();
    policy.scan_settings.heuristic_level = 10;
    let result = manager.validate_enterprise_policy(&policy).unwrap();
    assert!(!result.success);
    assert!(!result.failed_settings.is_empty());
    assert!(result.failed_settings[0].contains("heuristic_level"));
}
#[test]
fn test_enterprise_policy_validation_timeout_failure() {
    let (manager, _temp_dir) = create_test_config_manager();
    let mut policy = create_test_policy();
    policy.scan_settings.timeout_seconds = 10000;
    let result = manager.validate_enterprise_policy(&policy).unwrap();
    assert!(!result.success);
    assert!(!result.failed_settings.is_empty());
    assert!(result.failed_settings[0].contains("scan_timeout"));
}
#[test]
fn test_enterprise_policy_validation_update_frequency_failure() {
    let (manager, _temp_dir) = create_test_config_manager();
    let mut policy = create_test_policy();
    policy.update_settings.update_frequency_hours = 0;
    let result = manager.validate_enterprise_policy(&policy).unwrap();
    assert!(!result.success);
    assert!(!result.failed_settings.is_empty());
    assert!(result.failed_settings[0].contains("update_frequency_hours"));
}
#[test]
fn test_enterprise_policy_removal() {
    let (manager, _temp_dir) = create_test_config_manager();
    let policy = create_test_policy();
    manager.apply_enterprise_policy(policy).unwrap();
    assert!(manager.get_config().has_enterprise_policy());
    let change_event = manager.remove_enterprise_policy().unwrap();
    assert!(!manager.get_config().has_enterprise_policy());
    assert_eq!(change_event.new_value, "null");
}
#[test]
fn test_whitelist_entry_addition() {
    let (manager, temp_dir) = create_test_config_manager();
    let test_file = temp_dir.path().join("test.exe");
    std::fs::write(&test_file, b"test content").unwrap();
    let entry = WhitelistEntry {
        path: test_file.clone(),
        hash: Some("a1b2c3d4e5f67890123456789abcdef0".to_string()),
        expiry: Some(Utc::now() + Duration::hours(24)),
        reason: "Test entry".to_string(),
    };
    let operation = manager.add_whitelist_entry(entry.clone()).unwrap();
    assert!(matches!(operation.operation_type, WhitelistOperationType::Add));
    assert_eq!(operation.entry.path, test_file);
    let entries = manager.get_whitelist_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, test_file);
    assert_eq!(entries[0].reason, "Test entry");
}
#[test]
fn test_whitelist_entry_duplicate_addition() {
    let (manager, temp_dir) = create_test_config_manager();
    let test_file = temp_dir.path().join("test.exe");
    std::fs::write(&test_file, b"test content").unwrap();
    let entry = WhitelistEntry {
        path: test_file.clone(),
        hash: None,
        expiry: None,
        reason: "Test entry".to_string(),
    };
    manager.add_whitelist_entry(entry.clone()).unwrap();
    let result = manager.add_whitelist_entry(entry);
    assert!(result.is_err());
}
#[test]
fn test_whitelist_entry_removal() {
    let (manager, temp_dir) = create_test_config_manager();
    let test_file = temp_dir.path().join("test.exe");
    std::fs::write(&test_file, b"test content").unwrap();
    let entry = WhitelistEntry {
        path: test_file.clone(),
        hash: None,
        expiry: None,
        reason: "Test entry".to_string(),
    };
    manager.add_whitelist_entry(entry).unwrap();
    assert_eq!(manager.get_whitelist_entries().len(), 1);
    let operation = manager.remove_whitelist_entry(&test_file).unwrap();
    assert!(matches!(operation.operation_type, WhitelistOperationType::Remove));
    let entries = manager.get_whitelist_entries();
    assert_eq!(entries.len(), 0);
}
#[test]
fn test_whitelist_entry_removal_not_found() {
    let (manager, _temp_dir) = create_test_config_manager();
    let test_file = PathBuf::from("nonexistent.exe");
    let result = manager.remove_whitelist_entry(&test_file);
    assert!(result.is_err());
}
#[test]
fn test_whitelist_entry_update() {
    let (manager, temp_dir) = create_test_config_manager();
    let test_file = temp_dir.path().join("test.exe");
    std::fs::write(&test_file, b"test content").unwrap();
    let entry = WhitelistEntry {
        path: test_file.clone(),
        hash: None,
        expiry: None,
        reason: "Original reason".to_string(),
    };
    manager.add_whitelist_entry(entry).unwrap();
    let updated_entry = WhitelistEntry {
        path: test_file.clone(),
        hash: Some("abcdef1234567890abcdef1234567890".to_string()),
        expiry: Some(Utc::now() + Duration::hours(48)),
        reason: "Updated reason".to_string(),
    };
    let operation = manager.update_whitelist_entry(&test_file, updated_entry.clone()).unwrap();
    assert!(matches!(operation.operation_type, WhitelistOperationType::Update));
    let entries = manager.get_whitelist_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].reason, "Updated reason");
    assert!(entries[0].hash.is_some());
}
#[test]
fn test_whitelist_validation_invalid_hash_length() {
    let (manager, _temp_dir) = create_test_config_manager();
    let entry = WhitelistEntry {
        path: PathBuf::from("test.exe"),
        hash: Some("invalid".to_string()),
        expiry: None,
        reason: "Test".to_string(),
    };
    let result = manager.add_whitelist_entry(entry);
    assert!(result.is_err());
}
#[test]
fn test_whitelist_validation_invalid_hash_characters() {
    let (manager, _temp_dir) = create_test_config_manager();
    let entry = WhitelistEntry {
        path: PathBuf::from("test.exe"),
        hash: Some("gggggggggggggggggggggggggggggggg".to_string()),
        expiry: None,
        reason: "Test".to_string(),
    };
    let result = manager.add_whitelist_entry(entry);
    assert!(result.is_err());
}
#[test]
fn test_whitelist_validation_past_expiry() {
    let (manager, _temp_dir) = create_test_config_manager();
    let entry = WhitelistEntry {
        path: PathBuf::from("test.exe"),
        hash: None,
        expiry: Some(Utc::now() - Duration::hours(1)),
        reason: "Test".to_string(),
    };
    let result = manager.add_whitelist_entry(entry);
    assert!(result.is_err());
}
#[test]
fn test_whitelist_validation_empty_reason() {
    let (manager, _temp_dir) = create_test_config_manager();
    let entry = WhitelistEntry {
        path: PathBuf::from("test.exe"),
        hash: None,
        expiry: None,
        reason: "".to_string(),
    };
    let result = manager.add_whitelist_entry(entry);
    assert!(result.is_err());
}
#[test]
fn test_whitelist_validation_valid_hashes() {
    let (manager, temp_dir) = create_test_config_manager();
    let test_file = temp_dir.path().join("test.exe");
    std::fs::write(&test_file, b"test content").unwrap();
    let entry_md5 = WhitelistEntry {
        path: test_file.clone(),
        hash: Some("abcdef1234567890abcdef1234567890".to_string()),
        expiry: None,
        reason: "MD5 test".to_string(),
    };
    let result = manager.add_whitelist_entry(entry_md5);
    assert!(result.is_ok());
    manager.remove_whitelist_entry(&test_file).unwrap();
    let entry_sha1 = WhitelistEntry {
        path: test_file.clone(),
        hash: Some("abcdef1234567890abcdef1234567890abcdef12".to_string()),
        expiry: None,
        reason: "SHA1 test".to_string(),
    };
    let result = manager.add_whitelist_entry(entry_sha1);
    assert!(result.is_ok());
    manager.remove_whitelist_entry(&test_file).unwrap();
    let entry_sha256 = WhitelistEntry {
        path: test_file.clone(),
        hash: Some("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string()),
        expiry: None,
        reason: "SHA256 test".to_string(),
    };
    let result = manager.add_whitelist_entry(entry_sha256);
    assert!(result.is_ok());
}
#[test]
fn test_expired_whitelist_cleanup() {
    let (manager, temp_dir) = create_test_config_manager();
    let test_file1 = temp_dir.path().join("test1.exe");
    let test_file2 = temp_dir.path().join("test2.exe");
    std::fs::write(&test_file1, b"test content 1").unwrap();
    std::fs::write(&test_file2, b"test content 2").unwrap();
    let expired_entry = WhitelistEntry {
        path: test_file1.clone(),
        hash: None,
        expiry: Some(Utc::now() - Duration::hours(1)),
        reason: "Expired entry".to_string(),
    };
    let valid_entry = WhitelistEntry {
        path: test_file2.clone(),
        hash: None,
        expiry: Some(Utc::now() + Duration::hours(1)),
        reason: "Valid entry".to_string(),
    };
    {
        let mut whitelist = manager.whitelist_cache.write().unwrap();
        whitelist.push(expired_entry);
        whitelist.push(valid_entry);
    }
    let operations = manager.clean_expired_whitelist_entries().unwrap();
    assert_eq!(operations.len(), 1);
    assert!(matches!(operations[0].operation_type, WhitelistOperationType::Expire));
    assert_eq!(operations[0].entry.path, test_file1);
    let entries = manager.get_whitelist_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, test_file2);
}
#[test]
fn test_config_export_import_json() {
    let (manager, _temp_dir) = create_test_config_manager();
    let json_config = manager.export_config_json().unwrap();
    assert!(!json_config.is_empty());
    assert!(json_config.contains("WindowsAntivirusService"));
    let result = manager.import_config_json(&json_config);
    assert!(result.is_ok());
    let change_event = result.unwrap();
    assert!(matches!(change_event.change_type, av_service::config_manager::ConfigChangeType::SettingsChange));
}
#[test]
fn test_config_export_import_toml() {
    let (manager, _temp_dir) = create_test_config_manager();
    let toml_config = manager.export_config_toml().unwrap();
    assert!(!toml_config.is_empty());
    assert!(toml_config.contains("WindowsAntivirusService"));
    let result = manager.import_config_toml(&toml_config);
    assert!(result.is_ok());
    let change_event = result.unwrap();
    assert!(matches!(change_event.change_type, av_service::config_manager::ConfigChangeType::SettingsChange));
}
#[test]
fn test_config_operations_trait() {
    let (manager, _temp_dir) = create_test_config_manager();
    let scan_settings = manager.get_scan_settings();
    assert!(scan_settings.scan_archives);
    let realtime_settings = manager.get_realtime_settings();
    assert!(realtime_settings.enabled);
    let test_entries = vec![
        WhitelistEntry {
            path: PathBuf::from("test1.exe"),
            hash: None,
            expiry: None,
            reason: "Test entry 1".to_string(),
        },
        WhitelistEntry {
            path: PathBuf::from("test2.exe"),
            hash: None,
            expiry: None,
            reason: "Test entry 2".to_string(),
        },
    ];
    let result = manager.update_whitelist(test_entries);
    assert!(result.is_ok());
    let entries = manager.get_whitelist_entries();
    assert_eq!(entries.len(), 2);
    let policy = create_test_policy();
    let result = manager.apply_enterprise_policy(policy);
    assert!(result.is_ok());
    let result = manager.save_config();
    assert!(result.is_ok());
}
#[test]
fn test_config_reload() {
    let (manager, _temp_dir) = create_test_config_manager();
    let result = manager.reload_config();
    assert!(result.is_ok());
    let change_event = result.unwrap();
    assert!(matches!(change_event.change_type, av_service::config_manager::ConfigChangeType::Reload));
    assert_eq!(change_event.section, "all");
}
#[tokio::test]
async fn test_config_change_notification() {
    let (manager, _temp_dir) = create_test_config_manager();
    let manager_clone = std::sync::Arc::new(manager);
    let manager_wait = manager_clone.clone();
    let wait_task = tokio::spawn(async move {
        manager_wait.wait_for_config_change().await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    let policy = create_test_policy();
    manager_clone.apply_enterprise_policy(policy).unwrap();
    let result = tokio::time::timeout(tokio::time::Duration::from_secs(1), wait_task).await;
    assert!(result.is_ok());
}