/// Mock API client for GUI testing when service is not available
use hadron_core::{Result, ScanType, ScanJobId, ScanStatus, SystemStatus, ScanProgress, QuarantineEntry, AntivirusConfig, RemovableDevice, DeviceType};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct MockApiClient {
    connected: Arc<RwLock<bool>>,
}

impl MockApiClient {
    pub fn new(_pipe_name: String) -> Self {
        Self {
            connected: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn connect(&self) -> Result<()> {
        *self.connected.write().await = true;
        tracing::info!("Mock API client connected");
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        *self.connected.write().await = false;
        tracing::info!("Mock API client disconnected");
        Ok(())
    }

    pub async fn start_scan(&self, scan_type: ScanType, _targets: Vec<PathBuf>) -> Result<ScanJobId> {
        tracing::info!("Mock: Starting {:?} scan", scan_type);
        Ok(uuid::Uuid::new_v4())
    }

    pub async fn get_scan_status(&self, _job_id: ScanJobId) -> Result<ScanStatus> {
        Ok(ScanStatus::Running)
    }

    pub async fn get_system_status(&self) -> Result<SystemStatus> {
        Ok(SystemStatus {
            realtime_protection_enabled: true,
            engine_version: "1.0.0".to_string(),
            signature_version: "2024.01.01".to_string(),
            last_scan_time: Some(chrono::Utc::now()),
            last_update_time: Some(chrono::Utc::now()),
            threats_detected_today: 0,
            quarantine_count: 0,
        })
    }

    pub async fn get_scan_progress(&self, job_id: ScanJobId) -> Result<ScanProgress> {
        Ok(ScanProgress {
            scan_id: job_id,
            percentage_complete: 50.0,
            files_scanned: 1000,
            total_files: 2000,
            threats_found: 0,
            current_file: Some(PathBuf::from("C:\\Windows\\System32\\kernel32.dll")),
            estimated_time_remaining_ms: Some(30000),
        })
    }

    pub async fn get_scan_result(&self, job_id: ScanJobId) -> Result<hadron_core::ScanResult> {
        use hadron_core::{ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
        
        // Create some mock threats for demonstration
        let mut threats = Vec::new();
        
        // Mock virus
        if let Ok(threat1) = ThreatInfo::new(
            "Win32.TestVirus.A".to_string(),
            ThreatType::Virus,
            ThreatSeverity::High,
            PathBuf::from("C:\\Users\\Test\\Downloads\\suspicious.exe"),
            "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890".to_string(),
            DetectionMethod::Signature,
        ) {
            threats.push(threat1);
        }
        
        // Mock trojan
        if let Ok(threat2) = ThreatInfo::new(
            "Trojan.Generic.KD.12345".to_string(),
            ThreatType::Trojan,
            ThreatSeverity::Critical,
            PathBuf::from("C:\\Temp\\malware.dll"),
            "b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1".to_string(),
            DetectionMethod::Heuristic,
        ) {
            threats.push(threat2);
        }
        
        // Mock adware
        if let Ok(threat3) = ThreatInfo::new(
            "Adware.BrowserHelper".to_string(),
            ThreatType::Adware,
            ThreatSeverity::Medium,
            PathBuf::from("C:\\Program Files\\SuspiciousApp\\helper.exe"),
            "c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2".to_string(),
            DetectionMethod::MachineLearning,
        ) {
            threats.push(threat3);
        }
        
        Ok(hadron_core::ScanResult {
            scan_id: job_id,
            start_time: chrono::Utc::now() - chrono::Duration::minutes(5),
            end_time: Some(chrono::Utc::now()),
            status: ScanStatus::Completed,
            scanned_files: 15420,
            threats_found: threats,
            errors: vec![],
            statistics: hadron_core::ScanStatistics {
                total_files: 15420,
                scanned_files: 15420,
                skipped_files: 0,
                infected_files: 3,
                cleaned_files: 2,
                quarantined_files: 3,
                scan_duration_ms: 300000, // 5 minutes
                average_scan_time_ms: 19.4,
            },
        })
    }

    pub async fn get_quarantine_list(&self) -> Result<Vec<QuarantineEntry>> {
        Ok(vec![])
    }

    pub async fn restore_from_quarantine(&self, quarantine_id: String) -> Result<()> {
        tracing::info!("Mock: Restoring from quarantine: {}", quarantine_id);
        Ok(())
    }

    pub async fn delete_from_quarantine(&self, quarantine_id: String) -> Result<()> {
        tracing::info!("Mock: Deleting from quarantine: {}", quarantine_id);
        Ok(())
    }

    pub async fn check_updates(&self) -> Result<Vec<hadron_core::UpdateInfo>> {
        Ok(vec![])
    }

    pub async fn apply_updates(&self) -> Result<()> {
        tracing::info!("Mock: Applying updates");
        Ok(())
    }

    pub async fn get_configuration(&self) -> Result<AntivirusConfig> {
        Ok(AntivirusConfig::default())
    }

    pub async fn update_configuration_value(&self, key: String, value: String) -> Result<()> {
        tracing::info!("Mock: Updating configuration: {} = {}", key, value);
        Ok(())
    }

    pub async fn get_removable_devices(&self) -> Result<Vec<RemovableDevice>> {

        
        // Create some mock removable devices for testing
        let mut devices = Vec::new();
        
        // Mock USB flash drive
        let device1 = RemovableDevice {
            device_id: "usb_001".to_string(),
            mount_point: PathBuf::from("/Volumes/KINGSTON"),
            device_name: "Kingston DataTraveler".to_string(),
            device_type: DeviceType::UsbDrive,
            file_system: "FAT32".to_string(),
            total_size_bytes: 8_000_000_000, // 8GB
            free_space_bytes: 6_000_000_000, // 6GB free
            mount_time: chrono::Utc::now() - chrono::Duration::minutes(30),
            last_scan_time: None,
            is_trusted: false,
        };
        devices.push(device1);
        
        // Mock SD card
        let device2 = RemovableDevice {
            device_id: "sd_001".to_string(),
            mount_point: PathBuf::from("/Volumes/SANDISK"),
            device_name: "SanDisk Ultra".to_string(),
            device_type: DeviceType::SdCard,
            file_system: "exFAT".to_string(),
            total_size_bytes: 32_000_000_000, // 32GB
            free_space_bytes: 20_000_000_000, // 20GB free
            mount_time: chrono::Utc::now() - chrono::Duration::hours(1),
            last_scan_time: Some(chrono::Utc::now() - chrono::Duration::hours(2)),
            is_trusted: true,
        };
        devices.push(device2);
        
        // Mock external HDD
        let device3 = RemovableDevice {
            device_id: "hdd_001".to_string(),
            mount_point: PathBuf::from("/Volumes/BACKUP"),
            device_name: "Seagate Backup Plus".to_string(),
            device_type: DeviceType::ExternalHdd,
            file_system: "NTFS".to_string(),
            total_size_bytes: 1_000_000_000_000, // 1TB
            free_space_bytes: 500_000_000_000, // 500GB free
            mount_time: chrono::Utc::now() - chrono::Duration::hours(3),
            last_scan_time: Some(chrono::Utc::now() - chrono::Duration::days(1)),
            is_trusted: false,
        };
        devices.push(device3);
        
        Ok(devices)
    }

    pub async fn scan_removable_device(&self, device_id: String) -> Result<ScanJobId> {
        tracing::info!("Mock: Scanning removable device: {}", device_id);
        let scan_id = uuid::Uuid::new_v4();
        
        // Simulate finding threats on some devices
        if device_id.contains("usb") {
            tracing::info!("Mock: USB device scan will find threats");
        } else {
            tracing::info!("Mock: Device scan will be clean");
        }
        
        Ok(scan_id)
    }

    pub async fn get_removable_device_scan_result(&self, device_id: String) -> Result<hadron_core::ScanResult> {
        use hadron_core::{ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
        
        let scan_id = uuid::Uuid::new_v4();
        let mut threats = Vec::new();
        
        // USB devices have threats, others are clean
        if device_id.contains("usb") {
            // Mock USB virus
            if let Ok(threat) = ThreatInfo::new(
                "USB.Autorun.Virus".to_string(),
                ThreatType::Virus,
                ThreatSeverity::High,
                PathBuf::from("/Volumes/KINGSTON/autorun.inf"),
                "d4e5f6789012345678901234567890123456789012345678901234567890a1b2c3".to_string(),
                DetectionMethod::Signature,
            ) {
                threats.push(threat);
            }
            
            // Mock suspicious executable
            if let Ok(threat) = ThreatInfo::new(
                "Suspicious.Executable".to_string(),
                ThreatType::Suspicious,
                ThreatSeverity::Medium,
                PathBuf::from("/Volumes/KINGSTON/setup.exe"),
                "e5f6789012345678901234567890123456789012345678901234567890a1b2c3d4".to_string(),
                DetectionMethod::Heuristic,
            ) {
                threats.push(threat);
            }
        }
        
        let files_scanned = if device_id.contains("hdd") { 5000 } else { 150 };
        
        Ok(hadron_core::ScanResult {
            scan_id,
            start_time: chrono::Utc::now() - chrono::Duration::seconds(30),
            end_time: Some(chrono::Utc::now()),
            status: ScanStatus::Completed,
            scanned_files: files_scanned,
            threats_found: threats.clone(),
            errors: vec![],
            statistics: hadron_core::ScanStatistics {
                total_files: files_scanned,
                scanned_files: files_scanned,
                skipped_files: 0,
                infected_files: threats.len() as u64,
                cleaned_files: 0,
                quarantined_files: threats.len() as u64,
                scan_duration_ms: 30000,
                average_scan_time_ms: if files_scanned > 0 { 30000.0 / files_scanned as f64 } else { 0.0 },
            },
        })
    }

    pub async fn clean_removable_device(&self, device_id: String) -> Result<()> {
        tracing::info!("Mock: Cleaning removable device: {}", device_id);
        Ok(())
    }

    pub async fn set_device_trust(&self, device_id: String, trusted: bool) -> Result<()> {
        tracing::info!("Mock: Setting device {} trust to: {}", device_id, trusted);
        Ok(())
    }
}