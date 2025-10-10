use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::traits::{ScanSettings, RealtimeSettings, UpdateSettings, UISettings, NotificationLevel, UITheme};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusConfig {
    pub service: ServiceConfig,
    pub realtime_protection: RealtimeSettings,
    pub scan_settings: ScanSettings,
    pub quarantine: QuarantineConfig,
    pub update: UpdateSettings,
    pub logging: LoggingConfig,
    pub ui: UISettings,
    pub whitelist: Vec<crate::traits::WhitelistEntry>,
    pub enterprise_policy: Option<crate::traits::EnterprisePolicy>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub service_name: String,
    pub pipe_name: String,
    pub max_concurrent_scans: u32,
    pub scan_timeout_seconds: u32,
    pub memory_limit_mb: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub quarantine_path: PathBuf,
    pub max_quarantine_size_mb: u64,
    pub auto_delete_after_days: u32,
    pub encryption_key_path: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub log_level: String,
    pub log_file_path: PathBuf,
    pub max_log_file_size_mb: u64,
    pub max_log_files: u32,
    pub enable_console_logging: bool,
    pub enable_windows_event_log: bool,
    pub enable_json_logging: bool,
}
impl Default for AntivirusConfig {
    fn default() -> Self {
        Self {
            service: ServiceConfig::default(),
            realtime_protection: RealtimeSettings::default(),
            scan_settings: ScanSettings::default(),
            quarantine: QuarantineConfig::default(),
            update: UpdateSettings::default(),
            logging: LoggingConfig::default(),
            ui: UISettings::default(),
            whitelist: Vec::new(),
            enterprise_policy: None,
        }
    }
}
impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            service_name: "WindowsAntivirusService".to_string(),
            pipe_name: "\\\\.\\pipe\\av_service".to_string(),
            max_concurrent_scans: 4,
            scan_timeout_seconds: 3600,
            memory_limit_mb: 1024,
        }
    }
}
impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            quarantine_path: PathBuf::from("C:\\ProgramData\\WindowsAntivirus\\Quarantine"),
            max_quarantine_size_mb: 10240,
            auto_delete_after_days: 30,
            encryption_key_path: PathBuf::from("C:\\ProgramData\\WindowsAntivirus\\quarantine.key"),
        }
    }
}
impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            log_file_path: PathBuf::from("C:\\ProgramData\\WindowsAntivirus\\Logs\\antivirus.log"),
            max_log_file_size_mb: 100,
            max_log_files: 10,
            enable_console_logging: false,
            enable_windows_event_log: true,
            enable_json_logging: true,
        }
    }
}
impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            scan_archives: true,
            scan_email: true,
            scan_network_drives: false,
            max_file_size_mb: 100,
            timeout_seconds: 30,
            heuristic_level: 2,
        }
    }
}
impl Default for RealtimeSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_on_access: true,
            scan_on_write: true,
            scan_downloads: true,
            scan_removable_media: true,
        }
    }
}
impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto_update: true,
            update_frequency_hours: 4,
            update_server_url: "https:
            use_delta_updates: true,
        }
    }
}
impl Default for UISettings {
    fn default() -> Self {
        Self {
            language: "en".to_string(),
            show_notifications: true,
            notification_level: NotificationLevel::ThreatsOnly,
            theme: UITheme::System,
        }
    }
}
impl AntivirusConfig {
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        if self.service.max_concurrent_scans == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_concurrent_scans must be greater than 0".to_string()
            ));
        }
        if self.service.scan_timeout_seconds == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "scan_timeout_seconds must be greater than 0".to_string()
            ));
        }
        if self.quarantine.max_quarantine_size_mb == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_quarantine_size_mb must be greater than 0".to_string()
            ));
        }
        if self.scan_settings.max_file_size_mb == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_file_size_mb must be greater than 0".to_string()
            ));
        }
        if self.scan_settings.heuristic_level > 5 {
            return Err(crate::ConfigError::ValidationFailed(
                "heuristic_level must be between 0 and 5".to_string()
            ));
        }
        if self.update.update_frequency_hours == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "update_frequency_hours must be greater than 0".to_string()
            ));
        }
        if self.logging.max_log_file_size_mb == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_log_file_size_mb must be greater than 0".to_string()
            ));
        }
        if self.logging.max_log_files == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_log_files must be greater than 0".to_string()
            ));
        }
        Ok(())
    }
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
    pub fn merge_with(&mut self, other: &AntivirusConfig) {
        if other.service.max_concurrent_scans != self.service.max_concurrent_scans {
            self.service.max_concurrent_scans = other.service.max_concurrent_scans;
        }
        self.realtime_protection = other.realtime_protection.clone();
        self.scan_settings = other.scan_settings.clone();
        if other.enterprise_policy.is_some() {
            self.enterprise_policy = other.enterprise_policy.clone();
        }
        for entry in &other.whitelist {
            if !self.whitelist.iter().any(|e| e.path == entry.path) {
                self.whitelist.push(entry.clone());
            }
        }
    }
    pub fn has_enterprise_policy(&self) -> bool {
        self.enterprise_policy.is_some()
    }
    pub fn get_effective_scan_settings(&self) -> &ScanSettings {
        if let Some(ref policy) = self.enterprise_policy {
            &policy.scan_settings
        } else {
            &self.scan_settings
        }
    }
    pub fn get_effective_realtime_settings(&self) -> &RealtimeSettings {
        if let Some(ref policy) = self.enterprise_policy {
            &policy.realtime_settings
        } else {
            &self.realtime_protection
        }
    }
}
pub struct ConfigurationManager {
    config: AntivirusConfig,
    config_path: PathBuf,
}
impl ConfigurationManager {
    pub fn new(config_path: PathBuf) -> Result<Self, ConfigError> {
        let config = Self::load_config(&config_path)?;
        Ok(Self {
            config,
            config_path,
        })
    }
    fn load_config(config_path: &PathBuf) -> Result<AntivirusConfig, ConfigError> {
        let mut builder = Config::builder()
            .add_source(Config::try_from(&AntivirusConfig::default())?);
        if config_path.exists() {
            builder = builder.add_source(File::from(config_path.clone()));
        }
        builder = builder.add_source(
            Environment::with_prefix("AV")
                .separator("_")
                .try_parsing(true)
        );
        let config = builder.build()?;
        config.try_deserialize()
    }
    pub fn get_config(&self) -> &AntivirusConfig {
        &self.config
    }
    pub fn update_config(&mut self, new_config: AntivirusConfig) -> Result<(), ConfigError> {
        self.config = new_config;
        self.save_config()
    }
    pub fn save_config(&self) -> Result<(), ConfigError> {
        let config_str = toml::to_string_pretty(&self.config)
            .map_err(|e| ConfigError::Message(format!("Failed to serialize config: {}", e)))?;
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ConfigError::Message(format!("Failed to create config directory: {}", e)))?;
        }
        std::fs::write(&self.config_path, config_str)
            .map_err(|e| ConfigError::Message(format!("Failed to write config file: {}", e)))?;
        Ok(())
    }
    pub fn reload_config(&mut self) -> Result<(), ConfigError> {
        self.config = Self::load_config(&self.config_path)?;
        Ok(())
    }
    pub fn validate_config(&self) -> Result<(), crate::ConfigError> {
        if self.config.service.max_concurrent_scans == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_concurrent_scans must be greater than 0".to_string()
            ));
        }
        if self.config.service.scan_timeout_seconds == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "scan_timeout_seconds must be greater than 0".to_string()
            ));
        }
        if self.config.quarantine.max_quarantine_size_mb == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_quarantine_size_mb must be greater than 0".to_string()
            ));
        }
        if self.config.scan_settings.max_file_size_mb == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_file_size_mb must be greater than 0".to_string()
            ));
        }
        if self.config.scan_settings.heuristic_level > 5 {
            return Err(crate::ConfigError::ValidationFailed(
                "heuristic_level must be between 0 and 5".to_string()
            ));
        }
        if self.config.update.update_frequency_hours == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "update_frequency_hours must be greater than 0".to_string()
            ));
        }
        if self.config.logging.max_log_file_size_mb == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_log_file_size_mb must be greater than 0".to_string()
            ));
        }
        if self.config.logging.max_log_files == 0 {
            return Err(crate::ConfigError::ValidationFailed(
                "max_log_files must be greater than 0".to_string()
            ));
        }
        Ok(())
    }
}
#[cfg(test)
]
mod tests {
    use super::*;
    use std::path::PathBuf;
    #[test]
    fn test_default_config_validation() {
        let config = AntivirusConfig::default();
        assert!(config.validate().is_ok());
    }
    #[test]
    fn test_config_validation_failures() {
        let mut config = AntivirusConfig::default();
        config.service.max_concurrent_scans = 0;
        assert!(config.validate().is_err());
        config = AntivirusConfig::default();
        config.quarantine.max_quarantine_size_mb = 0;
        assert!(config.validate().is_err());
        config = AntivirusConfig::default();
        config.scan_settings.heuristic_level = 10;
        assert!(config.validate().is_err());
    }
    #[test]
    fn test_config_json_serialization() {
        let config = AntivirusConfig::default();
        let json = config.to_json();
        assert!(json.is_ok());
        let json_str = json.unwrap();
        let deserialized = AntivirusConfig::from_json(&json_str);
        assert!(deserialized.is_ok());
        let deserialized_config = deserialized.unwrap();
        assert!(deserialized_config.validate().is_ok());
        assert_eq!(config.service.service_name, deserialized_config.service.service_name);
    }
    #[test]
    fn test_config_merge() {
        let mut base_config = AntivirusConfig::default();
        let mut other_config = AntivirusConfig::default();
        other_config.service.max_concurrent_scans = 8;
        other_config.realtime_protection.scan_on_access = false;
        other_config.whitelist.push(crate::traits::WhitelistEntry {
            path: PathBuf::from("C:\\test.exe"),
            hash: Some("abc123".to_string()),
            expiry: None,
            reason: "Test entry".to_string(),
        });
        base_config.merge_with(&other_config);
        assert_eq!(base_config.service.max_concurrent_scans, 8);
        assert!(!base_config.realtime_protection.scan_on_access);
        assert_eq!(base_config.whitelist.len(), 1);
    }
    #[test]
    fn test_enterprise_policy_override() {
        let mut config = AntivirusConfig::default();
        assert!(!config.has_enterprise_policy());
        assert_eq!(config.get_effective_scan_settings().scan_archives, true);
        let mut enterprise_policy = crate::traits::EnterprisePolicy {
            policy_version: "1.0".to_string(),
            scan_settings: ScanSettings {
                scan_archives: false,
                scan_email: false,
                scan_network_drives: true,
                max_file_size_mb: 50,
                timeout_seconds: 60,
                heuristic_level: 1,
            },
            realtime_settings: RealtimeSettings {
                enabled: false,
                scan_on_access: false,
                scan_on_write: false,
                scan_downloads: false,
                scan_removable_media: false,
            },
            update_settings: UpdateSettings::default(),
            restrictions: crate::traits::PolicyRestrictions {
                allow_user_whitelist: false,
                allow_disable_realtime: false,
                allow_quarantine_restore: false,
                require_admin_for_settings: true,
            },
        };
        config.enterprise_policy = Some(enterprise_policy);
        assert!(config.has_enterprise_policy());
        assert!(!config.get_effective_scan_settings().scan_archives);
        assert!(!config.get_effective_realtime_settings().enabled);
    }
    #[test]
    fn test_service_config_defaults() {
        let service_config = ServiceConfig::default();
        assert_eq!(service_config.service_name, "WindowsAntivirusService");
        assert_eq!(service_config.pipe_name, "\\\\.\\pipe\\av_service");
        assert_eq!(service_config.max_concurrent_scans, 4);
        assert_eq!(service_config.scan_timeout_seconds, 3600);
        assert_eq!(service_config.memory_limit_mb, 1024);
    }
    #[test]
    fn test_quarantine_config_defaults() {
        let quarantine_config = QuarantineConfig::default();
        assert_eq!(quarantine_config.quarantine_path, PathBuf::from("C:\\ProgramData\\WindowsAntivirus\\Quarantine"));
        assert_eq!(quarantine_config.max_quarantine_size_mb, 10240);
        assert_eq!(quarantine_config.auto_delete_after_days, 30);
    }
    #[test]
    fn test_logging_config_defaults() {
        let logging_config = LoggingConfig::default();
        assert_eq!(logging_config.log_level, "info");
        assert_eq!(logging_config.max_log_file_size_mb, 100);
        assert_eq!(logging_config.max_log_files, 10);
        assert!(!logging_config.enable_console_logging);
        assert!(logging_config.enable_windows_event_log);
        assert!(logging_config.enable_json_logging);
    }
    #[test]
    fn test_configuration_manager_creation() {
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_antivirus_config.toml");
        let result = ConfigurationManager::new(config_path.clone());
        assert!(result.is_ok());
        let config_manager = result.unwrap();
        assert!(config_manager.get_config().validate().is_ok());
        if config_path.exists() {
            let _ = std::fs::remove_file(config_path);
        }
    }
}