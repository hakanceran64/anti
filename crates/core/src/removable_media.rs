use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ring::rand::{SystemRandom, SecureRandom};

use crate::{Result, AntivirusError};

/// Removable media detection and management
#[derive(Debug)]
pub struct RemovableMediaDetector {
    config: RemovableMediaConfig,
    known_devices: HashMap<String, RemovableDevice>,
    last_scan_time: Option<DateTime<Utc>>,
}

/// Configuration for removable media detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovableMediaConfig {
    pub auto_scan_enabled: bool,
    pub scan_on_mount: bool,
    pub scan_timeout_minutes: u32,
    pub excluded_device_types: Vec<String>,
    pub max_device_size_gb: u64,
    pub scan_hidden_files: bool,
}

impl Default for RemovableMediaConfig {
    fn default() -> Self {
        Self {
            auto_scan_enabled: true,
            scan_on_mount: true,
            scan_timeout_minutes: 30,
            excluded_device_types: vec![
                "cdrom".to_string(),
                "dvd".to_string(),
            ],
            max_device_size_gb: 1000, // 1TB limit
            scan_hidden_files: false,
        }
    }
}

/// Information about a removable device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovableDevice {
    pub device_id: String,
    pub mount_point: PathBuf,
    pub device_name: String,
    pub device_type: DeviceType,
    pub file_system: String,
    pub total_size_bytes: u64,
    pub free_space_bytes: u64,
    pub mount_time: DateTime<Utc>,
    pub last_scan_time: Option<DateTime<Utc>>,
    pub is_trusted: bool,
}

/// Types of removable devices
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceType {
    UsbDrive,
    ExternalHdd,
    SdCard,
    CdRom,
    Dvd,
    NetworkDrive,
    Unknown,
}

/// Device scan result
#[derive(Debug, Clone)]
pub struct DeviceScanResult {
    pub device: RemovableDevice,
    pub scan_result: crate::types::ScanResult,
    pub scan_duration_ms: u64,
}

/// Event types for removable media
#[derive(Debug, Clone)]
pub enum MediaEvent {
    DeviceConnected(RemovableDevice),
    DeviceDisconnected(String), // device_id
    ScanStarted(String),         // device_id
    ScanCompleted(DeviceScanResult),
    ScanFailed(String, String),  // device_id, error
    WipeStarted(String),         // device_id
    WipeCompleted(WipeResult),
    WipeFailed(String, String),  // device_id, error
}

/// Result of a device wipe operation
#[derive(Debug, Clone)]
pub struct WipeResult {
    pub device_id: String,
    pub device_name: String,
    pub stats: WipeStats,
    pub success: bool,
}

/// Statistics for wipe operation
#[derive(Debug, Clone, Default)]
pub struct WipeStats {
    pub total_files: usize,
    pub deleted_files: usize,
    pub failed_files: usize,
    pub duration_ms: u64,
    pub errors: Vec<String>,
}

impl RemovableMediaDetector {
    /// Create a new removable media detector
    pub fn new() -> Self {
        Self {
            config: RemovableMediaConfig::default(),
            known_devices: HashMap::new(),
            last_scan_time: None,
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: RemovableMediaConfig) -> Self {
        Self {
            config,
            known_devices: HashMap::new(),
            last_scan_time: None,
        }
    }

    /// Detect all currently connected removable devices
    pub async fn detect_devices(&mut self) -> Result<Vec<RemovableDevice>> {
        info!("Detecting removable devices...");
        
        let devices = if cfg!(target_os = "windows") {
            #[cfg(target_os = "windows")]
            {
                self.detect_windows_devices().await.unwrap_or_else(|e| {
                    warn!("Failed to detect Windows devices: {}", e);
                    Vec::new()
                })
            }
            #[cfg(not(target_os = "windows"))]
            Vec::new()
        } else if cfg!(target_os = "macos") {
            #[cfg(target_os = "macos")]
            {
                self.detect_macos_devices().await.unwrap_or_else(|e| {
                    warn!("Failed to detect macOS devices: {}", e);
                    Vec::new()
                })
            }
            #[cfg(not(target_os = "macos"))]
            Vec::new()
        } else if cfg!(target_os = "linux") {
            #[cfg(target_os = "linux")]
            {
                self.detect_linux_devices().await.unwrap_or_else(|e| {
                    warn!("Failed to detect Linux devices: {}", e);
                    Vec::new()
                })
            }
            #[cfg(not(target_os = "linux"))]
            Vec::new()
        } else {
            warn!("Unsupported operating system for removable media detection");
            Vec::new()
        };

        // Update known devices
        for device in &devices {
            self.known_devices.insert(device.device_id.clone(), device.clone());
        }

        info!("Detected {} removable devices", devices.len());
        Ok(devices)
    }

    /// Get all currently known devices
    pub fn get_known_devices(&self) -> Vec<&RemovableDevice> {
        self.known_devices.values().collect()
    }

    /// Check if a device should be scanned
    pub fn should_scan_device(&self, device: &RemovableDevice) -> bool {
        // Check if auto-scan is enabled
        if !self.config.auto_scan_enabled {
            return false;
        }

        // Check if device type is excluded
        let device_type_str = format!("{:?}", device.device_type).to_lowercase();
        if self.config.excluded_device_types.contains(&device_type_str) {
            debug!("Device type {} is excluded from scanning", device_type_str);
            return false;
        }

        // Check device size limit
        let device_size_gb = device.total_size_bytes / (1024 * 1024 * 1024);
        if device_size_gb > self.config.max_device_size_gb {
            debug!("Device {} exceeds size limit: {} GB", device.device_name, device_size_gb);
            return false;
        }

        // Check if device is trusted
        if device.is_trusted {
            debug!("Device {} is marked as trusted, skipping scan", device.device_name);
            return false;
        }

        // Check if recently scanned
        if let Some(last_scan) = device.last_scan_time {
            let now = Utc::now();
            let hours_since_scan = now.signed_duration_since(last_scan).num_hours();
            if hours_since_scan < 24 {
                debug!("Device {} was scanned {} hours ago, skipping", device.device_name, hours_since_scan);
                return false;
            }
        }

        true
    }

    /// Mark a device as trusted
    pub fn mark_device_trusted(&mut self, device_id: &str, trusted: bool) -> Result<()> {
        if let Some(device) = self.known_devices.get_mut(device_id) {
            device.is_trusted = trusted;
            info!("Device {} marked as {}", device.device_name, 
                  if trusted { "trusted" } else { "untrusted" });
            Ok(())
        } else {
            Err(AntivirusError::Internal(format!("Device not found: {}", device_id)))
        }
    }

    /// Get scan paths for a device
    pub fn get_device_scan_paths(&self, device: &RemovableDevice) -> Vec<PathBuf> {
        vec![device.mount_point.clone()]
    }

    /// Update device scan time
    pub fn update_device_scan_time(&mut self, device_id: &str) {
        if let Some(device) = self.known_devices.get_mut(device_id) {
            device.last_scan_time = Some(Utc::now());
        }
    }

    /// Windows-specific device detection
    #[cfg(target_os = "windows")]
    async fn detect_windows_devices(&self) -> Result<Vec<RemovableDevice>> {
        use std::process::Command;
        
        let mut devices = Vec::new();
        
        // Use PowerShell to get removable drives
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2} | Select-Object DeviceID, VolumeName, Size, FreeSpace, FileSystem"
            ])
            .output();

        match output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                devices.extend(self.parse_windows_drives(&output_str)?);
            }
            Err(e) => {
                warn!("Failed to detect Windows removable drives: {}", e);
            }
        }

        Ok(devices)
    }

    /// macOS-specific device detection
    #[cfg(target_os = "macos")]
    async fn detect_macos_devices(&self) -> Result<Vec<RemovableDevice>> {
        let mut devices = Vec::new();
        
        info!("Scanning /Volumes directory for removable devices...");
        
        // Check /Volumes directory for mounted devices
        if let Ok(mut entries) = fs::read_dir("/Volumes").await {
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                
                // Skip system volumes and hidden directories
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with('.') || 
                       name_str == "Macintosh HD" || 
                       name_str == "Preboot" ||
                       name_str == "Recovery" ||
                       name_str == "VM" ||
                       name_str == "Data" {
                        debug!("Skipping system volume: {}", name_str);
                        continue;
                    }
                }

                debug!("Checking potential removable device: {}", path.display());
                
                // Check if it's actually a removable device by checking if it's external
                if self.is_external_volume(&path).await {
                    match self.create_macos_device(&path).await {
                        Ok(device) => {
                            info!("Found removable device: {} at {}", device.device_name, device.mount_point.display());
                            devices.push(device);
                        }
                        Err(e) => {
                            warn!("Failed to create device info for {}: {}", path.display(), e);
                        }
                    }
                } else {
                    debug!("Volume {} is not external, skipping", path.display());
                }
            }
        } else {
            warn!("Could not read /Volumes directory");
        }

        // Also try to get diskutil info for additional validation
        if let Ok(diskutil_devices) = self.get_diskutil_info().await {
            for device in diskutil_devices {
                if !devices.iter().any(|d| d.mount_point == device.mount_point) {
                    devices.push(device);
                }
            }
        }

        info!("Found {} removable devices on macOS", devices.len());
        Ok(devices)
    }

    /// Linux-specific device detection
    #[cfg(target_os = "linux")]
    async fn detect_linux_devices(&self) -> Result<Vec<RemovableDevice>> {
        let mut devices = Vec::new();
        
        // Check /media and /mnt directories
        for mount_dir in &["/media", "/mnt"] {
            if let Ok(mut entries) = fs::read_dir(mount_dir).await {
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Ok(device) = self.create_linux_device(&path).await {
                            devices.push(device);
                        }
                    }
                }
            }
        }

        // Parse /proc/mounts for additional mounted devices
        if let Ok(mounts) = fs::read_to_string("/proc/mounts").await {
            devices.extend(self.parse_linux_mounts(&mounts)?);
        }

        Ok(devices)
    }

    /// Parse Windows drive information
    #[cfg(target_os = "windows")]
    fn parse_windows_drives(&self, output: &str) -> Result<Vec<RemovableDevice>> {
        let mut devices = Vec::new();
        
        for line in output.lines().skip(3) { // Skip header lines
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let device_id = parts[0].to_string();
                let mount_point = PathBuf::from(&device_id);
                let device_name = if parts[1] != "" { parts[1].to_string() } else { device_id.clone() };
                let total_size = parts[2].parse::<u64>().unwrap_or(0);
                let free_space = parts[3].parse::<u64>().unwrap_or(0);
                let file_system = parts[4].to_string();

                let device = RemovableDevice {
                    device_id: device_id.clone(),
                    mount_point,
                    device_name,
                    device_type: DeviceType::UsbDrive, // Default, could be refined
                    file_system,
                    total_size_bytes: total_size,
                    free_space_bytes: free_space,
                    mount_time: Utc::now(),
                    last_scan_time: None,
                    is_trusted: false,
                };

                devices.push(device);
            }
        }

        Ok(devices)
    }

    /// Create macOS device from path
    #[cfg(target_os = "macos")]
    async fn create_macos_device(&self, path: &Path) -> Result<RemovableDevice> {
        let metadata = fs::metadata(path).await
            .map_err(|e| crate::AntivirusError::Internal(format!("Failed to get metadata for {}: {}", path.display(), e)))?;
            
        let device_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown")
            .to_string();

        // Try to get filesystem info using df command
        let (total_size, free_space, file_system) = self.get_macos_fs_info(path).await
            .unwrap_or((0, 0, "unknown".to_string()));

        // Generate a shorter, more user-friendly device ID
        let clean_name = device_name.replace(" ", "_").to_lowercase();
        let device_id = if clean_name == "no_name" || clean_name.is_empty() {
            // For unnamed devices, use a hash of the path
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            let mut hasher = DefaultHasher::new();
            path.hash(&mut hasher);
            let hash = hasher.finish();
            format!("usb_{:x}", hash & 0xFFFF) // Use last 4 hex digits
        } else {
            format!("usb_{}", clean_name)
        };

        let device = RemovableDevice {
            device_id,
            mount_point: path.to_path_buf(),
            device_name: device_name.clone(),
            device_type: self.detect_macos_device_type(path).await,
            file_system,
            total_size_bytes: total_size,
            free_space_bytes: free_space,
            mount_time: metadata.created()
                .or_else(|_| metadata.modified())
                .map(|t| {
                    use std::time::UNIX_EPOCH;
                    let duration = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                    DateTime::from_timestamp(duration.as_secs() as i64, 0).unwrap_or_else(|| Utc::now())
                })
                .unwrap_or_else(|_| Utc::now()),
            last_scan_time: None,
            is_trusted: false,
        };

        debug!("Created device: {} ({})", device.device_name, device.device_id);
        Ok(device)
    }

    /// Check if a volume is external (removable) on macOS
    #[cfg(target_os = "macos")]
    async fn is_external_volume(&self, path: &Path) -> bool {
        use std::process::Command;
        
        // Use diskutil to check if the volume is external
        let output = Command::new("diskutil")
            .args(&["info", path.to_str().unwrap_or("/")])
            .output();

        match output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                
                // Check for indicators that this is an external/removable device
                let is_external = output_str.contains("External:") && output_str.contains("External: Yes") ||
                                 output_str.contains("Removable Media:") && output_str.contains("Removable Media: Yes") ||
                                 output_str.contains("Protocol:") && (
                                     output_str.contains("USB") || 
                                     output_str.contains("FireWire") ||
                                     output_str.contains("Thunderbolt")
                                 );
                
                if is_external {
                    debug!("Volume {} is external/removable", path.display());
                } else {
                    debug!("Volume {} is internal", path.display());
                }
                
                is_external
            }
            Err(e) => {
                debug!("Failed to run diskutil for {}: {}", path.display(), e);
                
                // Fallback: check if the path looks like a removable device
                let path_str = path.to_string_lossy().to_lowercase();
                let looks_removable = path_str.contains("usb") || 
                                     path_str.contains("external") ||
                                     path_str.contains("sd") ||
                                     path_str.contains("flash") ||
                                     path_str.contains("thumb");
                
                if looks_removable {
                    debug!("Volume {} looks like removable device based on name", path.display());
                }
                
                looks_removable
            }
        }
    }

    /// Get diskutil information on macOS
    #[cfg(target_os = "macos")]
    async fn get_diskutil_info(&self) -> Result<Vec<RemovableDevice>> {
        use std::process::Command;
        
        let devices = Vec::new();
        
        let output = Command::new("diskutil")
            .args(&["list", "-plist", "external"])
            .output();

        match output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // Parse plist output (simplified)
                debug!("Diskutil output: {}", output_str);
            }
            Err(e) => {
                debug!("Failed to run diskutil: {}", e);
            }
        }

        Ok(devices)
    }

    /// Get filesystem info for macOS
    #[cfg(target_os = "macos")]
    async fn get_macos_fs_info(&self, path: &Path) -> Result<(u64, u64, String)> {
        use std::process::Command;
        
        // Use df to get size info
        let df_output = Command::new("df")
            .args(&["-k", path.to_str().unwrap_or("/")])
            .output();

        let (total_size, free_space) = match df_output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = output_str.lines().nth(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let total_kb = parts[1].parse::<u64>().unwrap_or(0);
                        let available_kb = parts[3].parse::<u64>().unwrap_or(0);
                        (total_kb * 1024, available_kb * 1024)
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                }
            }
            Err(e) => {
                debug!("Failed to get df info for {}: {}", path.display(), e);
                (0, 0)
            }
        };

        // Use diskutil to get filesystem type
        let fs_output = Command::new("diskutil")
            .args(&["info", path.to_str().unwrap_or("/")])
            .output();

        let file_system = match fs_output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                
                // Look for file system type in diskutil output
                for line in output_str.lines() {
                    if line.contains("File System Personality:") || line.contains("Type (Bundle):") {
                        if let Some(fs_type) = line.split(':').nth(1) {
                            let fs_clean = fs_type.trim().to_string();
                            if !fs_clean.is_empty() && fs_clean != "Unknown" {
                                return Ok((total_size, free_space, fs_clean));
                            }
                        }
                    }
                }
                
                // Fallback patterns
                if output_str.contains("FAT32") || output_str.contains("MS-DOS FAT32") {
                    "FAT32".to_string()
                } else if output_str.contains("ExFAT") || output_str.contains("MS-DOS ExFAT") {
                    "exFAT".to_string()
                } else if output_str.contains("NTFS") {
                    "NTFS".to_string()
                } else if output_str.contains("HFS+") || output_str.contains("Mac OS Extended") {
                    "HFS+".to_string()
                } else if output_str.contains("APFS") {
                    "APFS".to_string()
                } else {
                    "unknown".to_string()
                }
            }
            Err(e) => {
                debug!("Failed to get diskutil info for {}: {}", path.display(), e);
                "unknown".to_string()
            }
        };

        Ok((total_size, free_space, file_system))
    }

    /// Detect device type on macOS
    #[cfg(target_os = "macos")]
    async fn detect_macos_device_type(&self, path: &Path) -> DeviceType {
        use std::process::Command;
        
        // Use diskutil to get detailed device info
        let output = Command::new("diskutil")
            .args(&["info", path.to_str().unwrap_or("/")])
            .output();

        match output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
                
                // Check protocol and device characteristics
                if output_str.contains("usb") || output_str.contains("usb 2.0") || output_str.contains("usb 3.0") {
                    // Further distinguish between USB drive types
                    if output_str.contains("sd") || output_str.contains("card") {
                        DeviceType::SdCard
                    } else if output_str.contains("flash") || output_str.contains("thumb") {
                        DeviceType::UsbDrive
                    } else {
                        // Could be external HDD via USB
                        DeviceType::ExternalHdd
                    }
                } else if output_str.contains("firewire") || output_str.contains("thunderbolt") {
                    DeviceType::ExternalHdd
                } else {
                    // Fallback to name-based detection
                    let path_str = path.to_string_lossy().to_lowercase();
                    
                    if path_str.contains("usb") || path_str.contains("flash") || path_str.contains("thumb") {
                        DeviceType::UsbDrive
                    } else if path_str.contains("sd") || path_str.contains("card") {
                        DeviceType::SdCard
                    } else if path_str.contains("external") || path_str.contains("backup") || path_str.contains("disk") {
                        DeviceType::ExternalHdd
                    } else {
                        DeviceType::Unknown
                    }
                }
            }
            Err(_) => {
                // Fallback to simple name-based detection
                let path_str = path.to_string_lossy().to_lowercase();
                
                if path_str.contains("usb") || path_str.contains("flash") || path_str.contains("thumb") {
                    DeviceType::UsbDrive
                } else if path_str.contains("sd") || path_str.contains("card") {
                    DeviceType::SdCard
                } else if path_str.contains("external") || path_str.contains("backup") || path_str.contains("disk") {
                    DeviceType::ExternalHdd
                } else {
                    DeviceType::Unknown
                }
            }
        }
    }

    /// Create Linux device from path
    #[cfg(target_os = "linux")]
    async fn create_linux_device(&self, path: &Path) -> Result<RemovableDevice> {
        let metadata = fs::metadata(path).await?;
        let device_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown")
            .to_string();

        let device = RemovableDevice {
            device_id: format!("linux_{}", device_name),
            mount_point: path.to_path_buf(),
            device_name,
            device_type: DeviceType::Unknown,
            file_system: "unknown".to_string(),
            total_size_bytes: 0,
            free_space_bytes: 0,
            mount_time: metadata.created()
                .or_else(|_| metadata.modified())
                .map(|t| DateTime::from(t))
                .unwrap_or_else(|_| Utc::now()),
            last_scan_time: None,
            is_trusted: false,
        };

        Ok(device)
    }

    /// Parse Linux /proc/mounts
    #[cfg(target_os = "linux")]
    fn parse_linux_mounts(&self, mounts: &str) -> Result<Vec<RemovableDevice>> {
        let mut devices = Vec::new();
        
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let device_path = parts[0];
                let mount_point = PathBuf::from(parts[1]);
                let file_system = parts[2];

                // Filter for removable devices (simplified heuristic)
                if device_path.starts_with("/dev/sd") && 
                   (mount_point.starts_with("/media") || mount_point.starts_with("/mnt")) {
                    
                    let device_name = mount_point.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Unknown")
                        .to_string();

                    let device = RemovableDevice {
                        device_id: device_path.to_string(),
                        mount_point,
                        device_name,
                        device_type: DeviceType::UsbDrive,
                        file_system: file_system.to_string(),
                        total_size_bytes: 0,
                        free_space_bytes: 0,
                        mount_time: Utc::now(),
                        last_scan_time: None,
                        is_trusted: false,
                    };

                    devices.push(device);
                }
            }
        }

        Ok(devices)
    }

    /// Start monitoring for device changes
    pub async fn start_monitoring(&mut self) -> Result<()> {
        info!("Starting removable media monitoring...");
        
        // Initial device detection
        self.detect_devices().await?;
        
        // In a real implementation, this would set up filesystem watchers
        // or use platform-specific APIs to monitor device changes
        
        Ok(())
    }

    /// Stop monitoring
    pub async fn stop_monitoring(&mut self) -> Result<()> {
        info!("Stopping removable media monitoring...");
        Ok(())
    }

    /// Wipe all contents from a removable device
    pub async fn wipe_device(&mut self, device_id: &str, secure_wipe: bool) -> Result<WipeResult> {
        info!("Starting device wipe for device: {}", device_id);
        
        let device = self.known_devices.get(device_id)
            .ok_or_else(|| AntivirusError::Internal(format!("Device not found: {}", device_id)))?
            .clone();

        // Safety check - ensure it's actually a removable device
        if !self.is_removable_device(&device) {
            return Err(AntivirusError::Internal(
                "Cannot wipe non-removable device for safety reasons".to_string()
            ));
        }

        let start_time = std::time::Instant::now();
        let mut wipe_stats = WipeStats::default();

        info!("Wiping device: {} at {}", device.device_name, device.mount_point.display());

        // First, scan and collect all files
        let files_to_delete = self.collect_all_files(&device.mount_point).await?;
        wipe_stats.total_files = files_to_delete.len();

        info!("Found {} files to delete", files_to_delete.len());

        // Delete files in batches
        for (index, file_path) in files_to_delete.iter().enumerate() {
            match self.delete_file_securely(file_path, secure_wipe).await {
                Ok(_) => {
                    wipe_stats.deleted_files += 1;
                    debug!("Deleted: {}", file_path.display());
                }
                Err(e) => {
                    wipe_stats.failed_files += 1;
                    wipe_stats.errors.push(format!("Failed to delete {}: {}", file_path.display(), e));
                    warn!("Failed to delete {}: {}", file_path.display(), e);
                }
            }

            // Update progress every 100 files
            if index % 100 == 0 {
                let progress = (index as f32 / files_to_delete.len() as f32) * 100.0;
                info!("Wipe progress: {:.1}%", progress);
            }
        }

        // Remove empty directories
        self.remove_empty_directories(&device.mount_point).await?;

        let duration = start_time.elapsed();
        wipe_stats.duration_ms = duration.as_millis() as u64;

        info!("Device wipe completed in {:?}. Deleted: {}, Failed: {}", 
              duration, wipe_stats.deleted_files, wipe_stats.failed_files);

        let success = wipe_stats.failed_files == 0;
        
        Ok(WipeResult {
            device_id: device_id.to_string(),
            device_name: device.device_name.clone(),
            stats: wipe_stats,
            success,
        })
    }

    /// Check if device is actually removable (safety check)
    fn is_removable_device(&self, device: &RemovableDevice) -> bool {
        // Check mount point to ensure it's not a system drive
        let mount_str = device.mount_point.to_string_lossy().to_lowercase();
        
        // Reject system paths
        let system_paths = [
            "/", "/usr", "/var", "/etc", "/boot", "/home", "/root",
            "c:\\", "c:\\windows", "c:\\program files", "c:\\users",
            "/system", "/applications", "/library"
        ];

        for sys_path in &system_paths {
            if mount_str.starts_with(sys_path) {
                warn!("Rejecting system path for wipe: {}", mount_str);
                return false;
            }
        }

        // Additional checks based on device type
        match device.device_type {
            DeviceType::UsbDrive | DeviceType::SdCard | DeviceType::ExternalHdd => true,
            DeviceType::CdRom | DeviceType::Dvd => false, // Read-only media
            DeviceType::NetworkDrive => false, // Network drives could be dangerous
            DeviceType::Unknown => {
                // Be conservative with unknown devices
                warn!("Unknown device type, rejecting wipe for safety");
                false
            }
        }
    }

    /// Collect all files recursively from a directory
    async fn collect_all_files(&self, root_path: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut stack = vec![root_path.to_path_buf()];

        while let Some(current_path) = stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&current_path).await {
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    
                    if path.is_dir() {
                        stack.push(path);
                    } else {
                        files.push(path);
                    }
                }
            }
        }

        // Sort files by depth (deepest first) to avoid directory access issues
        files.sort_by(|a, b| b.components().count().cmp(&a.components().count()));
        
        Ok(files)
    }

    /// Delete a file securely
    async fn delete_file_securely(&self, file_path: &Path, secure_wipe: bool) -> Result<()> {
        if secure_wipe {
            // Secure deletion: overwrite with random data before deletion
            self.secure_overwrite_file(file_path).await?;
        }

        // Remove the file
        fs::remove_file(file_path).await
            .map_err(|e| AntivirusError::Internal(format!("Failed to delete file: {}", e)))?;

        Ok(())
    }

    /// Securely overwrite file with random data
    async fn secure_overwrite_file(&self, file_path: &Path) -> Result<()> {
        use tokio::io::AsyncSeekExt;
        
        // Get file size
        let metadata = fs::metadata(file_path).await?;
        let file_size = metadata.len();

        if file_size == 0 {
            return Ok(());
        }

        // Open file for writing
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(file_path)
            .await?;

        let rng = SystemRandom::new();

        // Overwrite with random data (3 passes)
        for pass in 0..3 {
            file.seek(std::io::SeekFrom::Start(0)).await?;
            
            let mut remaining = file_size;
            let chunk_size = 64 * 1024; // 64KB chunks
            
            while remaining > 0 {
                let write_size = std::cmp::min(chunk_size, remaining) as usize;
                let mut random_data = vec![0u8; write_size];
                rng.fill(&mut random_data)
                    .map_err(|e| crate::AntivirusError::Internal(format!("Random generation failed: {:?}", e)))?;
                
                file.write_all(&random_data).await?;
                remaining -= write_size as u64;
            }
            
            file.sync_all().await?;
            debug!("Secure wipe pass {} completed for {}", pass + 1, file_path.display());
        }

        Ok(())
    }

    /// Remove empty directories recursively
    async fn remove_empty_directories(&self, root_path: &Path) -> Result<()> {
        let mut dirs_to_check = Vec::new();
        let mut stack = vec![root_path.to_path_buf()];

        // Collect all directories
        while let Some(current_path) = stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&current_path).await {
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    if path.is_dir() {
                        dirs_to_check.push(path.clone());
                        stack.push(path);
                    }
                }
            }
        }

        // Sort by depth (deepest first)
        dirs_to_check.sort_by(|a, b| b.components().count().cmp(&a.components().count()));

        // Remove empty directories
        for dir_path in dirs_to_check {
            if dir_path == root_path {
                continue; // Don't remove the root mount point
            }

            match fs::remove_dir(&dir_path).await {
                Ok(_) => debug!("Removed empty directory: {}", dir_path.display()),
                Err(e) => {
                    // Directory might not be empty or have permission issues
                    debug!("Could not remove directory {}: {}", dir_path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// Quick wipe - just delete files without secure overwrite
    pub async fn quick_wipe_device(&mut self, device_id: &str) -> Result<WipeResult> {
        self.wipe_device(device_id, false).await
    }

    /// Secure wipe - overwrite files before deletion
    pub async fn secure_wipe_device(&mut self, device_id: &str) -> Result<WipeResult> {
        self.wipe_device(device_id, true).await
    }
}

/// Trait for removable media scanning
#[async_trait]
pub trait RemovableMediaScanner {
    /// Scan a removable device
    async fn scan_device(&self, device: &RemovableDevice) -> Result<DeviceScanResult>;
    
    /// Get scan progress for a device
    async fn get_device_scan_progress(&self, device_id: &str) -> Result<Option<crate::types::ScanProgress>>;
    
    /// Cancel device scan
    async fn cancel_device_scan(&self, device_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detector_creation() {
        let detector = RemovableMediaDetector::new();
        assert!(detector.known_devices.is_empty());
    }

    #[tokio::test]
    async fn test_device_trust_management() {
        let mut detector = RemovableMediaDetector::new();
        
        // Add a mock device
        let device = RemovableDevice {
            device_id: "test_device".to_string(),
            mount_point: PathBuf::from("/test"),
            device_name: "Test Device".to_string(),
            device_type: DeviceType::UsbDrive,
            file_system: "fat32".to_string(),
            total_size_bytes: 1024 * 1024 * 1024, // 1GB
            free_space_bytes: 512 * 1024 * 1024,  // 512MB
            mount_time: Utc::now(),
            last_scan_time: None,
            is_trusted: false,
        };
        
        detector.known_devices.insert(device.device_id.clone(), device);
        
        // Test marking as trusted
        assert!(detector.mark_device_trusted("test_device", true).is_ok());
        assert!(detector.known_devices.get("test_device").unwrap().is_trusted);
        
        // Test marking as untrusted
        assert!(detector.mark_device_trusted("test_device", false).is_ok());
        assert!(!detector.known_devices.get("test_device").unwrap().is_trusted);
    }

    #[tokio::test]
    async fn test_should_scan_device() {
        let detector = RemovableMediaDetector::new();
        
        let device = RemovableDevice {
            device_id: "test_device".to_string(),
            mount_point: PathBuf::from("/test"),
            device_name: "Test Device".to_string(),
            device_type: DeviceType::UsbDrive,
            file_system: "fat32".to_string(),
            total_size_bytes: 1024 * 1024 * 1024, // 1GB
            free_space_bytes: 512 * 1024 * 1024,  // 512MB
            mount_time: Utc::now(),
            last_scan_time: None,
            is_trusted: false,
        };
        
        // Should scan untrusted device
        assert!(detector.should_scan_device(&device));
        
        // Should not scan trusted device
        let mut trusted_device = device.clone();
        trusted_device.is_trusted = true;
        assert!(!detector.should_scan_device(&trusted_device));
    }
}