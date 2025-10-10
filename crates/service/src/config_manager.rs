use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::Notify;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use hadron_core::{
    config::{AntivirusConfig, ConfigurationManager as CoreConfigManager},
    traits::{
        ConfigOperations, ScanSettings, RealtimeSettings, WhitelistEntry, 
        EnterprisePolicy, PolicyRestrictions, UpdateSettings
    },
    Result, ConfigError
};
pub struct ConfigurationManager {
    core_manager: Arc<RwLock<CoreConfigManager>>,
    policy_cache: Arc<RwLock<HashMap<String, EnterprisePolicy>>>,
    whitelist_cache: Arc<RwLock<Vec<WhitelistEntry>>>,
    config_change_notify: Arc<Notify>,
    policy_validation_rules: PolicyValidationRules,
}
#[derive(Debug, Clone)]
pub struct PolicyValidationRules {
    pub max_scan_timeout: u32,
    pub min_update_frequency: u32,
    pub max_update_frequency: u32,
    pub allowed_heuristic_levels: Vec<u8>,
    pub required_scan_settings: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApplicationResult {
    pub success: bool,
    pub applied_settings: Vec<String>,
    pub failed_settings: Vec<String>,
    pub warnings: Vec<String>,
    pub timestamp: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistOperation {
    pub operation_type: WhitelistOperationType,
    pub entry: WhitelistEntry,
    pub timestamp: DateTime<Utc>,
    pub user: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhitelistOperationType {
    Add,
    Remove,
    Update,
    Expire,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChangeEvent {
    pub change_type: ConfigChangeType,
    pub section: String,
    pub old_value: Option<String>,
    pub new_value: String,
    pub timestamp: DateTime<Utc>,
    pub user: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigChangeType {
    PolicyUpdate,
    WhitelistChange,
    SettingsChange,
    Reload,
}
impl Default for PolicyValidationRules {
    fn default() -> Self {
        Self {
            max_scan_timeout: 7200, 
            min_update_frequency: 1, 
            max_update_frequency: 168, 
            allowed_heuristic_levels: vec![0, 1, 2, 3, 4, 5],
            required_scan_settings: vec![
                "scan_archives".to_string(),
                "scan_email".to_string(),
                "max_file_size_mb".to_string(),
            ],
        }
    }
}
impl ConfigurationManager {
    pub fn new(config_path: PathBuf) -> Result<Self> {
        let core_manager = CoreConfigManager::new(config_path)
            .map_err(|e| ConfigError::InvalidFormat(format!("Failed to create config manager: {}", e)))?;
        let config = core_manager.get_config();
        let policy_cache = Arc::new(RwLock::new(HashMap::new()));
        if let Some(ref policy) = config.enterprise_policy {
            let mut cache = policy_cache.write().unwrap();
            cache.insert(policy.policy_version.clone(), policy.clone());
        }
        let whitelist_cache = Arc::new(RwLock::new(config.whitelist.clone()));
        Ok(Self {
            core_manager: Arc::new(RwLock::new(core_manager)),
            policy_cache,
            whitelist_cache,
            config_change_notify: Arc::new(Notify::new()),
            policy_validation_rules: PolicyValidationRules::default(),
        })
    }
     pub fn with_validation_rules(config_path: PathBuf, rules: PolicyValidationRules) -> Result<Self> {
        let mut manager = Self::new(config_path)?;
        manager.policy_validation_rules = rules;
        Ok(manager)
    }
     pub fn get_config(&self) -> AntivirusConfig {
        let core_manager = self.core_manager.read().unwrap();
        core_manager.get_config().clone()
    }
    pub fn update_config(&self, new_config: AntivirusConfig) -> Result<ConfigChangeEvent> {
        new_config.validate()?;
        let old_config = {
            let core_manager = self.core_manager.read().unwrap();
            core_manager.get_config().clone()
        };
         {
            let mut core_manager = self.core_manager.write().unwrap();
            core_manager.update_config(new_config.clone())
                .map_err(|e| ConfigError::InvalidFormat(format!("Failed to update config: {}", e)))?;
        }
        self.update_caches(&new_config)?;
        let change_event = ConfigChangeEvent {
            change_type: ConfigChangeType::SettingsChange,
            section: "global".to_string(),
            old_value: Some(serde_json::to_string(&old_config).unwrap_or_default()),
            new_value: serde_json::to_string(&new_config).unwrap_or_default(),
            timestamp: Utc::now(),
            user: None,
        };
        self.config_change_notify.notify_waiters();
        Ok(change_event)
    }
    pub fn apply_enterprise_policy(&self, policy: EnterprisePolicy) -> Result<PolicyApplicationResult> {
        let validation_result = self.validate_enterprise_policy(&policy)?;
        if !validation_result.success {
            return Ok(validation_result);
        }
        let mut config = self.get_config();
        config.enterprise_policy = Some(policy.clone());
        let change_event = self.update_config(config)?;
        {
            let mut cache = self.policy_cache.write().unwrap();
            cache.insert(policy.policy_version.clone(), policy);
        }
        Ok(PolicyApplicationResult {
            success: true,
            applied_settings: vec![
                "scan_settings".to_string(),
                "realtime_settings".to_string(),
                "update_settings".to_string(),
                "restrictions".to_string(),
            ],
            failed_settings: vec![],
            warnings: vec![],
            timestamp: change_event.timestamp,
        })
    }
    pub fn validate_enterprise_policy(&self, policy: &EnterprisePolicy) -> Result<PolicyApplicationResult> {
        let mut warnings = Vec::new();
        let mut failed_settings = Vec::new();
        if policy.scan_settings.timeout_seconds > self.policy_validation_rules.max_scan_timeout {
            failed_settings.push(format!(
                "scan_timeout exceeds maximum allowed value of {} seconds",
                self.policy_validation_rules.max_scan_timeout
            ));
        }
        if !self.policy_validation_rules.allowed_heuristic_levels.contains(&policy.scan_settings.heuristic_level) {
            failed_settings.push(format!(
                "heuristic_level {} is not in allowed values: {:?}",
                policy.scan_settings.heuristic_level,
                self.policy_validation_rules.allowed_heuristic_levels
            ));
        }
        if policy.update_settings.update_frequency_hours < self.policy_validation_rules.min_update_frequency {
            failed_settings.push(format!(
                "update_frequency_hours {} is below minimum of {}",
                policy.update_settings.update_frequency_hours,
                self.policy_validation_rules.min_update_frequency
            ));
        }
        if policy.update_settings.update_frequency_hours > self.policy_validation_rules.max_update_frequency {
            failed_settings.push(format!(
                "update_frequency_hours {} exceeds maximum of {}",
                policy.update_settings.update_frequency_hours,
                self.policy_validation_rules.max_update_frequency
            ));
        }
        for required_setting in &self.policy_validation_rules.required_scan_settings {
            match required_setting.as_str() {
                "scan_archives" => {
                    if !policy.scan_settings.scan_archives {
                        warnings.push("scan_archives is disabled but recommended for security".to_string());
                    }
                }
                "scan_email" => {
                    if !policy.scan_settings.scan_email {
                        warnings.push("scan_email is disabled but recommended for security".to_string());
                    }
                }
                "max_file_size_mb" => {
                    if policy.scan_settings.max_file_size_mb == 0 {
                        failed_settings.push("max_file_size_mb cannot be zero".to_string());
                    }
                }
                _ => {}
            }
        }
        Ok(PolicyApplicationResult {
            success: failed_settings.is_empty(),
            applied_settings: if failed_settings.is_empty() {
                vec!["policy_validation_passed".to_string()]
            } else {
                vec![]
            },
            failed_settings,
            warnings,
            timestamp: Utc::now(),
        })
    }
    pub fn remove_enterprise_policy(&self) -> Result<ConfigChangeEvent> {
        let mut config = self.get_config();
        let old_policy = config.enterprise_policy.clone();
        config.enterprise_policy = None;
        let change_event = self.update_config(config)?;
        {
            let mut cache = self.policy_cache.write().unwrap();
            cache.clear();
        }
        Ok(ConfigChangeEvent {
            change_type: ConfigChangeType::PolicyUpdate,
            section: "enterprise_policy".to_string(),
            old_value: old_policy.map(|p| serde_json::to_string(&p).unwrap_or_default()),
            new_value: "null".to_string(),
            timestamp: change_event.timestamp,
            user: change_event.user,
        })
    }
    pub fn add_whitelist_entry(&self, entry: WhitelistEntry) -> Result<WhitelistOperation> {
        self.validate_whitelist_entry(&entry)?;
        {
            let whitelist = self.whitelist_cache.read().unwrap();
            if whitelist.iter().any(|e| e.path == entry.path) {
                return Err(ConfigError::ValidationFailed(
                    format!("Whitelist entry for path {:?} already exists", entry.path)
                ).into());
            }
        }
        {
            let mut whitelist = self.whitelist_cache.write().unwrap();
            whitelist.push(entry.clone());
        }
        let mut config = self.get_config();
        config.whitelist = self.whitelist_cache.read().unwrap().clone();
        self.update_config(config)?;
        Ok(WhitelistOperation {
            operation_type: WhitelistOperationType::Add,
            entry,
            timestamp: Utc::now(),
            user: "system".to_string(),
        })
    }
    pub fn remove_whitelist_entry(&self, path: &Path) -> Result<WhitelistOperation> {
        let removed_entry = {
            let mut whitelist = self.whitelist_cache.write().unwrap();
            let initial_len = whitelist.len();
            whitelist.retain(|e| e.path != path);
            if whitelist.len() == initial_len {
                return Err(ConfigError::ValidationFailed(
                    format!("Whitelist entry for path {:?} not found", path)
                ).into());
            }
            WhitelistEntry {
                path: path.to_path_buf(),
                hash: None,
                expiry: None,
                reason: "Removed by user".to_string(),
            }
        };
        let mut config = self.get_config();
        config.whitelist = self.whitelist_cache.read().unwrap().clone();
        self.update_config(config)?;
        Ok(WhitelistOperation {
            operation_type: WhitelistOperationType::Remove,
            entry: removed_entry,
            timestamp: Utc::now(),
            user: "system".to_string(),
        })
    }
    pub fn update_whitelist_entry(&self, path: &Path, new_entry: WhitelistEntry) -> Result<WhitelistOperation> {
        self.validate_whitelist_entry(&new_entry)?;
        {
            let mut whitelist = self.whitelist_cache.write().unwrap();
            let entry_index = whitelist.iter().position(|e| e.path == path)
                .ok_or_else(|| ConfigError::ValidationFailed(
                    format!("Whitelist entry for path {:?} not found", path)
                ))?;
            whitelist[entry_index] = new_entry.clone();
        }
        let mut config = self.get_config();
        config.whitelist = self.whitelist_cache.read().unwrap().clone();
        self.update_config(config)?;
        Ok(WhitelistOperation {
            operation_type: WhitelistOperationType::Update,
            entry: new_entry,
            timestamp: Utc::now(),
            user: "system".to_string(),
        })
    }
    pub fn get_whitelist_entries(&self) -> Vec<WhitelistEntry> {
        self.whitelist_cache.read().unwrap().clone()
    }
    pub fn clean_expired_whitelist_entries(&self) -> Result<Vec<WhitelistOperation>> {
        let now = Utc::now();
        let mut operations = Vec::new();
        let expired_entries: Vec<WhitelistEntry> = {
            let whitelist = self.whitelist_cache.read().unwrap();
            whitelist.iter()
                .filter(|entry| {
                    if let Some(expiry) = entry.expiry {
                        expiry <= now
                    } else {
                        false
                    }
                })
                .cloned()
                .collect()
        };
        for entry in expired_entries {
            {
                let mut whitelist = self.whitelist_cache.write().unwrap();
                whitelist.retain(|e| e.path != entry.path);
            }
            operations.push(WhitelistOperation {
                operation_type: WhitelistOperationType::Expire,
                entry,
                timestamp: now,
                user: "system".to_string(),
            });
        }
        if !operations.is_empty() {
            let mut config = self.get_config();
            config.whitelist = self.whitelist_cache.read().unwrap().clone();
            self.update_config(config)?;
        }
        Ok(operations)
    }
    fn validate_whitelist_entry(&self, entry: &WhitelistEntry) -> Result<()> {
        if !entry.path.exists() {
            tracing::warn!("Whitelist entry path does not exist: {:?}", entry.path);
        }
        if let Some(ref hash) = entry.hash {
            if hash.len() != 64 && hash.len() != 40 && hash.len() != 32 {
                return Err(ConfigError::ValidationFailed(
                    "Hash must be MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars)".to_string()
                ).into());
            }
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ConfigError::ValidationFailed(
                    "Hash must contain only hexadecimal characters".to_string()
                ).into());
            }
        }
        if let Some(expiry) = entry.expiry {
            if expiry <= Utc::now() {
                return Err(ConfigError::ValidationFailed(
                    "Expiry date must be in the future".to_string()
                ).into());
            }
        }
        if entry.reason.trim().is_empty() {
            return Err(ConfigError::ValidationFailed(
                "Reason cannot be empty".to_string()
            ).into());
        }
        Ok(())
    }
    fn update_caches(&self, config: &AntivirusConfig) -> Result<()> {
        if let Some(ref policy) = config.enterprise_policy {
            let mut cache = self.policy_cache.write().unwrap();
            cache.insert(policy.policy_version.clone(), policy.clone());
        }
        {
            let mut cache = self.whitelist_cache.write().unwrap();
            *cache = config.whitelist.clone();
        }
        Ok(())
    }
    pub async fn wait_for_config_change(&self) {
        self.config_change_notify.notified().await;
    }
    pub fn reload_config(&self) -> Result<ConfigChangeEvent> {
        {
            let mut core_manager = self.core_manager.write().unwrap();
            core_manager.reload_config()
                .map_err(|e| ConfigError::InvalidFormat(format!("Failed to reload config: {}", e)))?;
        }
        let config = self.get_config();
        self.update_caches(&config)?;
        let change_event = ConfigChangeEvent {
            change_type: ConfigChangeType::Reload,
            section: "all".to_string(),
            old_value: None,
            new_value: serde_json::to_string(&config).unwrap_or_default(),
            timestamp: Utc::now(),
            user: None,
        };
        self.config_change_notify.notify_waiters();
        Ok(change_event)
    }
    pub fn export_config_json(&self) -> Result<String> {
        let config = self.get_config();
        serde_json::to_string_pretty(&config)
            .map_err(|e| ConfigError::InvalidFormat(format!("Failed to serialize config: {}", e)).into())
    }
    pub fn export_config_toml(&self) -> Result<String> {
        let config = self.get_config();
        toml::to_string_pretty(&config)
            .map_err(|e| ConfigError::InvalidFormat(format!("Failed to serialize config: {}", e)).into())
    }
    pub fn import_config_json(&self, json_data: &str) -> Result<ConfigChangeEvent> {
        let config: AntivirusConfig = serde_json::from_str(json_data)
            .map_err(|e| ConfigError::InvalidFormat(format!("Failed to parse JSON config: {}", e)))?;
        self.update_config(config)
    }
    pub fn import_config_toml(&self, toml_data: &str) -> Result<ConfigChangeEvent> {
        let config: AntivirusConfig = toml::from_str(toml_data)
            .map_err(|e| ConfigError::InvalidFormat(format!("Failed to parse TOML config: {}", e)))?;
        self.update_config(config)
    }
}
impl ConfigOperations for ConfigurationManager {
    fn get_scan_settings(&self) -> ScanSettings {
        let config = self.get_config();
        config.get_effective_scan_settings().clone()
    }
    fn get_realtime_settings(&self) -> RealtimeSettings {
        let config = self.get_config();
        config.get_effective_realtime_settings().clone()
    }
    fn update_whitelist(&self, entries: Vec<WhitelistEntry>) -> Result<()> {
        for entry in &entries {
            self.validate_whitelist_entry(entry)?;
        }
        {
            let mut whitelist = self.whitelist_cache.write().unwrap();
            *whitelist = entries;
        }
        let mut config = self.get_config();
        config.whitelist = self.whitelist_cache.read().unwrap().clone();
        self.update_config(config)?;
        Ok(())
    }
    fn apply_enterprise_policy(&self, policy: EnterprisePolicy) -> Result<()> {
        let result = self.apply_enterprise_policy(policy)?;
        if !result.success {
            return Err(ConfigError::ValidationFailed(
                format!("Policy validation failed: {:?}", result.failed_settings)
            ).into());
        }
        Ok(())
    }
    fn save_config(&self) -> Result<()> {
        let core_manager = self.core_manager.read().unwrap();
        core_manager.save_config()
            .map_err(|e| ConfigError::InvalidFormat(format!("Failed to save config: {}", e)).into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::path::PathBuf;
    fn create_test_config_manager() -> (ConfigurationManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");
        let manager = ConfigurationManager::new(config_path).unwrap();
        (manager, temp_dir)
    }
    #[test]
    fn test_configuration_manager_creation() {
        let (manager, _temp_dir) = create_test_config_manager();
        let config = manager.get_config();
        assert!(config.validate().is_ok());
    }
    #[test]
    fn test_enterprise_policy_validation() {
        let (manager, _temp_dir) = create_test_config_manager();
        let mut policy = EnterprisePolicy {
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
        };
        let result = manager.validate_enterprise_policy(&policy).unwrap();
        assert!(result.success);
        policy.scan_settings.heuristic_level = 10;
        let result = manager.validate_enterprise_policy(&policy).unwrap();
        assert!(!result.success);
        assert!(!result.failed_settings.is_empty());
    }
    #[test]
    fn test_whitelist_management() {
        let (manager, temp_dir) = create_test_config_manager();
        let test_file = temp_dir.path().join("test.exe");
        std::fs::write(&test_file, b"test content").unwrap();
        let entry = WhitelistEntry {
            path: test_file.clone(),
            hash: Some("a1b2c3d4e5f6".to_string()),
            expiry: Some(Utc::now() + chrono::Duration::hours(24)),
            reason: "Test entry".to_string(),
        };
        let operation = manager.add_whitelist_entry(entry.clone()).unwrap();
        assert!(matches!(operation.operation_type, WhitelistOperationType::Add));
        let entries = manager.get_whitelist_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, test_file);
        let operation = manager.remove_whitelist_entry(&test_file).unwrap();
        assert!(matches!(operation.operation_type, WhitelistOperationType::Remove));
        let entries = manager.get_whitelist_entries();
        assert_eq!(entries.len(), 0);
    }
    #[test]
    fn test_whitelist_validation() {
        let (manager, _temp_dir) = create_test_config_manager();
        let entry = WhitelistEntry {
            path: PathBuf::from("test.exe"),
            hash: Some("invalid".to_string()),
            expiry: None,
            reason: "Test".to_string(),
        };
        assert!(manager.validate_whitelist_entry(&entry).is_err());
        let entry = WhitelistEntry {
            path: PathBuf::from("test.exe"),
            hash: Some("gggggggggggggggggggggggggggggggg".to_string()),
            expiry: None,
            reason: "Test".to_string(),
        };
        assert!(manager.validate_whitelist_entry(&entry).is_err());
        let entry = WhitelistEntry {
            path: PathBuf::from("test.exe"),
            hash: None,
            expiry: Some(Utc::now() - chrono::Duration::hours(1)),
            reason: "Test".to_string(),
        };
        assert!(manager.validate_whitelist_entry(&entry).is_err());
        let entry = WhitelistEntry {
            path: PathBuf::from("test.exe"),
            hash: None,
            expiry: None,
            reason: "".to_string(),
        };
        assert!(manager.validate_whitelist_entry(&entry).is_err());
    }
    #[test]
    fn test_config_export_import() {
        let (manager, _temp_dir) = create_test_config_manager();
        let json_config = manager.export_config_json().unwrap();
        assert!(!json_config.is_empty());
        let toml_config = manager.export_config_toml().unwrap();
        assert!(!toml_config.is_empty());
        let result = manager.import_config_json(&json_config);
        assert!(result.is_ok());
        let result = manager.import_config_toml(&toml_config);
        assert!(result.is_ok());
    }
    #[test]
    fn test_expired_whitelist_cleanup() {
        let (manager, temp_dir) = create_test_config_manager();
        let test_file = temp_dir.path().join("test.exe");
        std::fs::write(&test_file, b"test content").unwrap();
        let expired_entry = WhitelistEntry {
            path: test_file.clone(),
            hash: None,
            expiry: Some(Utc::now() - chrono::Duration::hours(1)),
            reason: "Expired test entry".to_string(),
        };
        {
            let mut whitelist = manager.whitelist_cache.write().unwrap();
            whitelist.push(expired_entry);
        }
        let operations = manager.clean_expired_whitelist_entries().unwrap();
        assert_eq!(operations.len(), 1);
        assert!(matches!(operations[0].operation_type, WhitelistOperationType::Expire));
        let entries = manager.get_whitelist_entries();
        assert_eq!(entries.len(), 0);
    }
}