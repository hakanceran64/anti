use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::fs;
use tracing::{debug, info, warn, error};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Result, AntivirusError, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};

/// USB/Removable media protection system
#[derive(Debug)]
pub struct UsbProtection {
    config: UsbProtectionConfig,
    quarantine_path: PathBuf,
    known_threats: HashMap<String, UsbThreatSignature>,
}

/// Configuration for USB protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbProtectionConfig {
    /// Enable real-time USB monitoring
    pub realtime_monitoring: bool,
    /// Auto-scan on USB insertion
    pub auto_scan_on_insert: bool,
    /// Block autorun.inf files
    pub block_autorun: bool,
    /// Block suspicious shortcuts
    pub block_suspicious_shortcuts: bool,
    /// Quarantine threats automatically
    pub auto_quarantine: bool,
    /// Show user notifications
    pub show_notifications: bool,
    /// Maximum file size to scan (MB)
    pub max_scan_size_mb: u64,
    /// Scan hidden files
    pub scan_hidden_files: bool,
}

impl Default for UsbProtectionConfig {
    fn default() -> Self {
        Self {
            realtime_monitoring: true,
            auto_scan_on_insert: true,
            block_autorun: true,
            block_suspicious_shortcuts: true,
            auto_quarantine: true,
            show_notifications: true,
            max_scan_size_mb: 100,
            scan_hidden_files: true,
        }
    }
}

/// USB-specific threat signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbThreatSignature {
    pub name: String,
    pub description: String,
    pub file_patterns: Vec<String>,
    pub content_patterns: Vec<String>,
    pub severity: ThreatSeverity,
    pub action: UsbThreatAction,
}

/// Actions to take when USB threat is detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsbThreatAction {
    Block,
    Quarantine,
    Delete,
    Warn,
}

/// USB threat detection result
#[derive(Debug, Clone)]
pub struct UsbThreatDetection {
    pub threat_type: UsbThreatType,
    pub file_path: PathBuf,
    pub threat_name: String,
    pub severity: ThreatSeverity,
    pub description: String,
    pub recommended_action: UsbThreatAction,
    pub detection_time: DateTime<Utc>,
}

/// Types of USB threats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsbThreatType {
    AutorunWorm,
    ShortcutVirus,
    HiddenExecutable,
    SuspiciousScript,
    FakeFolder,
    DataStealer,
    Ransomware,
    Unknown,
}

impl UsbProtection {
    /// Create new USB protection system
    pub fn new(quarantine_path: PathBuf) -> Self {
        let mut protection = Self {
            config: UsbProtectionConfig::default(),
            quarantine_path,
            known_threats: HashMap::new(),
        };
        
        protection.load_threat_signatures();
        protection
    }

    /// Create with custom configuration
    pub fn with_config(config: UsbProtectionConfig, quarantine_path: PathBuf) -> Self {
        let mut protection = Self {
            config,
            quarantine_path,
            known_threats: HashMap::new(),
        };
        
        protection.load_threat_signatures();
        protection
    }

    /// Load known USB threat signatures
    fn load_threat_signatures(&mut self) {
        // Conficker/Downadup worm
        self.known_threats.insert("conficker_worm".to_string(), UsbThreatSignature {
            name: "Conficker/Downadup Worm".to_string(),
            description: "Famous USB worm that spreads via autorun.inf and creates hidden copies".to_string(),
            file_patterns: vec![
                "autorun.inf".to_string(),
                "*.tmp".to_string(),
                "kavo.exe".to_string(),
                "ravmon.exe".to_string(),
            ],
            content_patterns: vec![
                "shellexecute=kavo.exe".to_string(),
                "shellexecute=ravmon.exe".to_string(),
                "open=kavo.exe".to_string(),
                "shell\\auto\\command=".to_string(),
            ],
            severity: ThreatSeverity::Critical,
            action: UsbThreatAction::Quarantine,
        });

        // Sality virus family
        self.known_threats.insert("sality_virus".to_string(), UsbThreatSignature {
            name: "Sality Virus Family".to_string(),
            description: "Polymorphic virus that infects executables and spreads via USB".to_string(),
            file_patterns: vec![
                "*.exe".to_string(),
                "*.scr".to_string(),
                "ntdelect.com".to_string(),
            ],
            content_patterns: vec![
                "sality".to_string(),
                "GetProcAddress".to_string(),
                "VirtualAlloc".to_string(),
                "CreateFileA".to_string(),
            ],
            severity: ThreatSeverity::Critical,
            action: UsbThreatAction::Quarantine,
        });

        // Shortcut virus (LNK worm)
        self.known_threats.insert("lnk_worm".to_string(), UsbThreatSignature {
            name: "LNK Shortcut Worm".to_string(),
            description: "Creates malicious shortcuts that hide real folders and execute malware".to_string(),
            file_patterns: vec![
                "*.lnk".to_string(),
            ],
            content_patterns: vec![
                "cmd /c".to_string(),
                "cmd.exe /c".to_string(),
                "powershell.exe".to_string(),
                "wscript.exe".to_string(),
                "cscript.exe".to_string(),
                "attrib +h +s".to_string(),
                "copy /y".to_string(),
            ],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Quarantine,
        });

        // Recycler virus
        self.known_threats.insert("recycler_virus".to_string(), UsbThreatSignature {
            name: "Recycler Virus".to_string(),
            description: "Hides in RECYCLER folder and spreads via autorun".to_string(),
            file_patterns: vec![
                "RECYCLER/*.exe".to_string(),
                "RECYCLER/*.com".to_string(),
                "$RECYCLE.BIN/*.exe".to_string(),
            ],
            content_patterns: vec![
                "shellexecute=RECYCLER".to_string(),
                "open=RECYCLER".to_string(),
            ],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Quarantine,
        });

        // VBS worm (like ILOVEYOU variants)
        self.known_threats.insert("vbs_worm".to_string(), UsbThreatSignature {
            name: "VBS Script Worm".to_string(),
            description: "Visual Basic Script worm that spreads via USB and email".to_string(),
            file_patterns: vec![
                "*.vbs".to_string(),
                "*.vbe".to_string(),
            ],
            content_patterns: vec![
                "WScript.Shell".to_string(),
                "CreateObject".to_string(),
                "FileSystemObject".to_string(),
                "CopyFile".to_string(),
                "RegWrite".to_string(),
                "SendKeys".to_string(),
                "HKEY_LOCAL_MACHINE".to_string(),
            ],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Quarantine,
        });

        // Batch file malware
        self.known_threats.insert("batch_malware".to_string(), UsbThreatSignature {
            name: "Malicious Batch Script".to_string(),
            description: "Batch files that perform malicious operations like file hiding or system modification".to_string(),
            file_patterns: vec![
                "*.bat".to_string(),
                "*.cmd".to_string(),
            ],
            content_patterns: vec![
                "attrib +h +s +r".to_string(),
                "copy /y".to_string(),
                "xcopy /e /h /y".to_string(),
                "reg add".to_string(),
                "net user".to_string(),
                "format c:".to_string(),
                "del /f /s /q".to_string(),
                "rd /s /q".to_string(),
                "shutdown".to_string(),
            ],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Quarantine,
        });

        // Folder.exe virus
        self.known_threats.insert("folder_exe_virus".to_string(), UsbThreatSignature {
            name: "Folder.exe Virus".to_string(),
            description: "Executable disguised as folder that hides real folders".to_string(),
            file_patterns: vec![
                "folder.exe".to_string(),
                "new folder.exe".to_string(),
                "documents.exe".to_string(),
                "photos.exe".to_string(),
                "music.exe".to_string(),
                "videos.exe".to_string(),
            ],
            content_patterns: vec![],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Quarantine,
        });

        // Autorun variants
        self.known_threats.insert("autorun_variants".to_string(), UsbThreatSignature {
            name: "Autorun Malware Variants".to_string(),
            description: "Various autorun.inf configurations used by malware".to_string(),
            file_patterns: vec![
                "autorun.inf".to_string(),
                "autorun.pif".to_string(),
                "desktop.ini".to_string(),
            ],
            content_patterns: vec![
                "shellexecute=".to_string(),
                "shell\\open\\command=".to_string(),
                "shell\\explore\\command=".to_string(),
                "shell\\auto\\command=".to_string(),
                "action=open folder to view files".to_string(),
                "useautoplay=1".to_string(),
            ],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Block,
        });

        // System file impersonators
        self.known_threats.insert("system_impersonator".to_string(), UsbThreatSignature {
            name: "System File Impersonator".to_string(),
            description: "Malware disguised as legitimate system files".to_string(),
            file_patterns: vec![
                "svchost.exe".to_string(),
                "explorer.exe".to_string(),
                "winlogon.exe".to_string(),
                "csrss.exe".to_string(),
                "lsass.exe".to_string(),
                "smss.exe".to_string(),
                "system32.exe".to_string(),
                "ntoskrnl.exe".to_string(),
            ],
            content_patterns: vec![],
            severity: ThreatSeverity::Critical,
            action: UsbThreatAction::Quarantine,
        });

        // Double extension tricks
        self.known_threats.insert("double_extension".to_string(), UsbThreatSignature {
            name: "Double Extension Malware".to_string(),
            description: "Files with double extensions to trick users (e.g., photo.jpg.exe)".to_string(),
            file_patterns: vec![
                "*.jpg.exe".to_string(),
                "*.png.exe".to_string(),
                "*.pdf.exe".to_string(),
                "*.doc.exe".to_string(),
                "*.txt.exe".to_string(),
                "*.mp3.exe".to_string(),
                "*.avi.exe".to_string(),
                "*.zip.exe".to_string(),
            ],
            content_patterns: vec![],
            severity: ThreatSeverity::High,
            action: UsbThreatAction::Quarantine,
        });

        info!("Loaded {} advanced USB threat signatures", self.known_threats.len());
    }

    /// Scan USB device for threats
    pub async fn scan_usb_device(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        info!("Starting USB threat scan for: {}", device_path.display());
        
        let mut detections = Vec::new();
        
        // Check for autorun threats first
        detections.extend(self.check_autorun_threats(device_path).await?);
        
        // Scan all files for threats
        detections.extend(self.scan_files_for_threats(device_path).await?);
        
        // Check for fake folder attacks
        detections.extend(self.check_fake_folder_attacks(device_path).await?);
        
        // Check for hidden malware
        detections.extend(self.check_hidden_malware(device_path).await?);
        
        info!("USB scan completed. Found {} threats", detections.len());
        Ok(detections)
    }

    /// Check for autorun-based threats
    async fn check_autorun_threats(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        let mut detections = Vec::new();
        
        // Check for autorun.inf
        let autorun_path = device_path.join("autorun.inf");
        if autorun_path.exists() {
            info!("Found autorun.inf file: {}", autorun_path.display());
            
            match fs::read_to_string(&autorun_path).await {
                Ok(content) => {
                    let content_lower = content.to_lowercase();
                    
                    // Check for malicious patterns
                    let malicious_patterns = [
                        "shellexecute=",
                        "shell\\open\\command=",
                        ".exe",
                        ".scr",
                        ".com",
                        ".pif",
                        ".bat",
                        ".cmd",
                    ];
                    
                    for pattern in &malicious_patterns {
                        if content_lower.contains(pattern) {
                            detections.push(UsbThreatDetection {
                                threat_type: UsbThreatType::AutorunWorm,
                                file_path: autorun_path.clone(),
                                threat_name: "Malicious Autorun File".to_string(),
                                severity: ThreatSeverity::High,
                                description: format!("Autorun.inf contains suspicious pattern: {}", pattern),
                                recommended_action: UsbThreatAction::Block,
                                detection_time: Utc::now(),
                            });
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("Could not read autorun.inf: {}", e);
                }
            }
        }
        
        Ok(detections)
    }

    /// Scan files for threat patterns
    async fn scan_files_for_threats(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        let mut detections = Vec::new();
        let mut stack = vec![device_path.to_path_buf()];
        
        while let Some(current_path) = stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&current_path).await {
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    
                    if path.is_dir() {
                        // Skip quarantine directories
                        if path.file_name().and_then(|n| n.to_str()) == Some(".quarantine") {
                            debug!("Skipping quarantine directory: {}", path.display());
                            continue;
                        }
                        stack.push(path);
                    } else {
                        // Skip files in quarantine directories
                        if path.to_string_lossy().contains("/.quarantine/") {
                            debug!("Skipping quarantined file: {}", path.display());
                            continue;
                        }
                        
                        // Check file against threat signatures
                        if let Some(detection) = self.check_file_against_signatures(&path).await? {
                            detections.push(detection);
                        }
                    }
                }
            }
        }
        
        Ok(detections)
    }

    /// Check individual file against threat signatures
    async fn check_file_against_signatures(&self, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        
        // Check file size
        let file_size = if let Ok(metadata) = fs::metadata(file_path).await {
            let size_mb = metadata.len() / (1024 * 1024);
            if size_mb > self.config.max_scan_size_mb {
                debug!("Skipping large file: {} ({} MB)", file_path.display(), size_mb);
                return Ok(None);
            }
            metadata.len()
        } else {
            0
        };

        // Perform multiple analysis layers
        
        // 1. Filename-based detection
        if let Some(detection) = self.check_filename_threats(&file_name, file_path).await? {
            return Ok(Some(detection));
        }
        
        // 2. Content-based detection
        if let Some(detection) = self.check_content_threats(file_path, file_size).await? {
            return Ok(Some(detection));
        }
        
        // 3. Behavioral pattern detection
        if let Some(detection) = self.check_behavioral_patterns(file_path).await? {
            return Ok(Some(detection));
        }
        
        // 4. Heuristic analysis
        if let Some(detection) = self.check_heuristic_threats(file_path, &file_name).await? {
            return Ok(Some(detection));
        }
        
        Ok(None)
    }

    /// Check filename-based threats
    async fn check_filename_threats(&self, file_name: &str, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        // Check for double extensions
        if self.has_double_extension(file_name) {
            return Ok(Some(UsbThreatDetection {
                threat_type: UsbThreatType::SuspiciousScript,
                file_path: file_path.to_path_buf(),
                threat_name: "Double Extension Malware".to_string(),
                severity: ThreatSeverity::High,
                description: "File with suspicious double extension (e.g., .jpg.exe) commonly used by malware".to_string(),
                recommended_action: UsbThreatAction::Quarantine,
                detection_time: Utc::now(),
            }));
        }

        // Check for system file impersonation
        if self.is_system_file_impersonator(file_name) {
            return Ok(Some(UsbThreatDetection {
                threat_type: UsbThreatType::HiddenExecutable,
                file_path: file_path.to_path_buf(),
                threat_name: "System File Impersonator".to_string(),
                severity: ThreatSeverity::Critical,
                description: "Executable disguised as legitimate system file".to_string(),
                recommended_action: UsbThreatAction::Quarantine,
                detection_time: Utc::now(),
            }));
        }

        // Check for folder impersonation
        if self.is_folder_impersonator(file_name) {
            return Ok(Some(UsbThreatDetection {
                threat_type: UsbThreatType::FakeFolder,
                file_path: file_path.to_path_buf(),
                threat_name: "Folder Impersonator Virus".to_string(),
                severity: ThreatSeverity::High,
                description: "Executable disguised as folder to hide real folders".to_string(),
                recommended_action: UsbThreatAction::Quarantine,
                detection_time: Utc::now(),
            }));
        }

        Ok(None)
    }

    /// Check content-based threats
    async fn check_content_threats(&self, file_path: &Path, file_size: u64) -> Result<Option<UsbThreatDetection>> {
        // Only analyze text files and small binaries
        if file_size > 10 * 1024 * 1024 { // 10MB limit for content analysis
            return Ok(None);
        }

        let file_extension = file_path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        match file_extension.as_str() {
            "inf" => self.analyze_autorun_content(file_path).await,
            "bat" | "cmd" => self.analyze_batch_content(file_path).await,
            "vbs" | "vbe" => self.analyze_vbs_content(file_path).await,
            "lnk" => self.analyze_shortcut_content(file_path).await,
            "exe" | "com" | "scr" | "pif" => self.analyze_executable_content(file_path).await,
            _ => Ok(None),
        }
    }

    /// Analyze autorun.inf content
    async fn analyze_autorun_content(&self, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        if let Ok(content) = fs::read_to_string(file_path).await {
            let content_lower = content.to_lowercase();
            
            let malicious_patterns = [
                ("shellexecute=", "Malicious executable launch"),
                ("shell\\open\\command=", "Shell command execution"),
                ("shell\\explore\\command=", "Explorer command hijack"),
                ("useautoplay=1", "Forced autoplay activation"),
                (".exe", "Executable file reference"),
                (".scr", "Screen saver executable"),
                (".com", "Command file reference"),
                (".bat", "Batch script reference"),
                (".vbs", "VBScript reference"),
            ];
            
            for (pattern, description) in &malicious_patterns {
                if content_lower.contains(pattern) {
                    return Ok(Some(UsbThreatDetection {
                        threat_type: UsbThreatType::AutorunWorm,
                        file_path: file_path.to_path_buf(),
                        threat_name: "Malicious Autorun Configuration".to_string(),
                        severity: ThreatSeverity::High,
                        description: format!("Autorun.inf contains malicious pattern: {}", description),
                        recommended_action: UsbThreatAction::Block,
                        detection_time: Utc::now(),
                    }));
                }
            }
        }
        
        Ok(None)
    }

    /// Analyze batch file content
    async fn analyze_batch_content(&self, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        if let Ok(content) = fs::read_to_string(file_path).await {
            let content_lower = content.to_lowercase();
            
            let malicious_patterns = [
                ("attrib +h +s", "File hiding operations"),
                ("copy /y", "Forced file copying"),
                ("xcopy /e /h /y", "Recursive hidden file copying"),
                ("reg add", "Registry modification"),
                ("net user", "User account manipulation"),
                ("format c:", "Disk formatting attempt"),
                ("del /f /s /q", "Forced file deletion"),
                ("rd /s /q", "Directory removal"),
                ("shutdown", "System shutdown"),
                ("taskkill", "Process termination"),
                ("wmic", "WMI command execution"),
            ];
            
            let mut threat_score = 0;
            let mut detected_patterns = Vec::new();
            
            for (pattern, description) in &malicious_patterns {
                if content_lower.contains(pattern) {
                    threat_score += match *pattern {
                        "format c:" | "del /f /s /q" | "rd /s /q" => 10, // Critical
                        "reg add" | "net user" | "wmic" => 5, // High
                        _ => 2, // Medium
                    };
                    detected_patterns.push(description);
                }
            }
            
            if threat_score >= 5 {
                return Ok(Some(UsbThreatDetection {
                    threat_type: UsbThreatType::SuspiciousScript,
                    file_path: file_path.to_path_buf(),
                    threat_name: "Malicious Batch Script".to_string(),
                    severity: if threat_score >= 10 { ThreatSeverity::Critical } else { ThreatSeverity::High },
                    description: format!("Batch script contains malicious operations: {}", detected_patterns.iter().cloned().collect::<Vec<_>>().join(", ")),
                    recommended_action: UsbThreatAction::Quarantine,
                    detection_time: Utc::now(),
                }));
            }
        }
        
        Ok(None)
    }

    /// Analyze VBS content
    async fn analyze_vbs_content(&self, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        if let Ok(content) = fs::read_to_string(file_path).await {
            let content_lower = content.to_lowercase();
            
            let malicious_patterns = [
                ("wscript.shell", "Shell object creation"),
                ("createobject", "COM object creation"),
                ("filesystemobject", "File system access"),
                ("copyfile", "File copying operations"),
                ("regwrite", "Registry writing"),
                ("sendkeys", "Keystroke simulation"),
                ("hkey_local_machine", "Registry access"),
                ("downloadfile", "File downloading"),
                ("execute", "Code execution"),
            ];
            
            let mut threat_score = 0;
            let mut detected_patterns = Vec::new();
            
            for (pattern, description) in &malicious_patterns {
                if content_lower.contains(pattern) {
                    threat_score += 3;
                    detected_patterns.push(description);
                }
            }
            
            if threat_score >= 6 {
                return Ok(Some(UsbThreatDetection {
                    threat_type: UsbThreatType::SuspiciousScript,
                    file_path: file_path.to_path_buf(),
                    threat_name: "Malicious VBScript".to_string(),
                    severity: ThreatSeverity::High,
                    description: format!("VBScript contains suspicious operations: {}", detected_patterns.iter().cloned().collect::<Vec<_>>().join(", ")),
                    recommended_action: UsbThreatAction::Quarantine,
                    detection_time: Utc::now(),
                }));
            }
        }
        
        Ok(None)
    }

    /// Analyze shortcut (.lnk) content
    async fn analyze_shortcut_content(&self, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        // For .lnk files, we need to parse the binary format or use system tools
        // For now, we'll do a basic binary content check
        if let Ok(content) = fs::read(file_path).await {
            let content_str = String::from_utf8_lossy(&content).to_lowercase();
            
            let malicious_patterns = [
                "cmd.exe",
                "powershell.exe",
                "wscript.exe",
                "cscript.exe",
                "attrib +h",
                "copy /y",
            ];
            
            for pattern in &malicious_patterns {
                if content_str.contains(pattern) {
                    return Ok(Some(UsbThreatDetection {
                        threat_type: UsbThreatType::ShortcutVirus,
                        file_path: file_path.to_path_buf(),
                        threat_name: "Malicious Shortcut File".to_string(),
                        severity: ThreatSeverity::High,
                        description: format!("Shortcut contains malicious command: {}", pattern),
                        recommended_action: UsbThreatAction::Quarantine,
                        detection_time: Utc::now(),
                    }));
                }
            }
        }
        
        Ok(None)
    }

    /// Analyze executable content (basic PE header check)
    async fn analyze_executable_content(&self, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        if let Ok(content) = fs::read(file_path).await {
            // Check for PE header
            if content.len() > 64 && &content[0..2] == b"MZ" {
                // Basic PE analysis
                let content_str = String::from_utf8_lossy(&content).to_lowercase();
                
                let suspicious_strings = [
                    "sality",
                    "conficker",
                    "kavo",
                    "ravmon",
                    "autorun",
                    "usb",
                    "removable",
                ];
                
                for suspicious in &suspicious_strings {
                    if content_str.contains(suspicious) {
                        return Ok(Some(UsbThreatDetection {
                            threat_type: UsbThreatType::HiddenExecutable,
                            file_path: file_path.to_path_buf(),
                            threat_name: "Suspicious Executable".to_string(),
                            severity: ThreatSeverity::Medium,
                            description: format!("Executable contains suspicious string: {}", suspicious),
                            recommended_action: UsbThreatAction::Quarantine,
                            detection_time: Utc::now(),
                        }));
                    }
                }
            }
        }
        
        Ok(None)
    }

    /// Check behavioral patterns
    async fn check_behavioral_patterns(&self, file_path: &Path) -> Result<Option<UsbThreatDetection>> {
        let parent_dir = file_path.parent().unwrap_or(file_path);
        let parent_name = parent_dir.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Check if file is in suspicious locations
        let suspicious_locations = [
            "recycler",
            "$recycle.bin",
            "system volume information",
            "temp",
            "tmp",
        ];

        if suspicious_locations.contains(&parent_name.as_str()) {
            return Ok(Some(UsbThreatDetection {
                threat_type: UsbThreatType::HiddenExecutable,
                file_path: file_path.to_path_buf(),
                threat_name: "Suspicious Location".to_string(),
                severity: ThreatSeverity::Medium,
                description: format!("File found in suspicious location: {}", parent_name),
                recommended_action: UsbThreatAction::Quarantine,
                detection_time: Utc::now(),
            }));
        }

        Ok(None)
    }

    /// Check heuristic threats
    async fn check_heuristic_threats(&self, file_path: &Path, file_name: &str) -> Result<Option<UsbThreatDetection>> {
        // Check for files with random names (common in malware)
        if self.has_random_name(file_name) {
            return Ok(Some(UsbThreatDetection {
                threat_type: UsbThreatType::Unknown,
                file_path: file_path.to_path_buf(),
                threat_name: "Random Named File".to_string(),
                severity: ThreatSeverity::Low,
                description: "File has randomly generated name, common in malware".to_string(),
                recommended_action: UsbThreatAction::Warn,
                detection_time: Utc::now(),
            }));
        }

        Ok(None)
    }

    /// Check if filename has double extension
    fn has_double_extension(&self, file_name: &str) -> bool {
        let common_fake_extensions = [
            ".jpg.exe", ".png.exe", ".pdf.exe", ".doc.exe", ".txt.exe",
            ".mp3.exe", ".avi.exe", ".zip.exe", ".rar.exe", ".docx.exe",
        ];
        
        common_fake_extensions.iter().any(|ext| file_name.ends_with(ext))
    }

    /// Check if file impersonates system files
    fn is_system_file_impersonator(&self, file_name: &str) -> bool {
        let system_files = [
            "svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe",
            "lsass.exe", "smss.exe", "system32.exe", "ntoskrnl.exe",
            "kernel32.dll", "user32.dll", "ntdll.dll",
        ];
        
        system_files.contains(&file_name)
    }

    /// Check if file impersonates folders
    fn is_folder_impersonator(&self, file_name: &str) -> bool {
        let folder_names = [
            "folder.exe", "new folder.exe", "documents.exe", "photos.exe",
            "music.exe", "videos.exe", "pictures.exe", "downloads.exe",
        ];
        
        folder_names.contains(&file_name)
    }

    /// Check if filename appears randomly generated
    fn has_random_name(&self, file_name: &str) -> bool {
        let name_without_ext = file_name.split('.').next().unwrap_or(file_name);
        
        // Check for patterns like: u123456.bat, temp_abc123.exe, etc.
        if name_without_ext.len() >= 6 {
            let has_numbers = name_without_ext.chars().any(|c| c.is_ascii_digit());
            let has_letters = name_without_ext.chars().any(|c| c.is_ascii_alphabetic());
            let ratio_numbers = name_without_ext.chars().filter(|c| c.is_ascii_digit()).count() as f32 / name_without_ext.len() as f32;
            
            // If name has both letters and numbers, and more than 40% are numbers
            if has_numbers && has_letters && ratio_numbers > 0.4 {
                return true;
            }
        }
        
        false
    }

    /// Check for fake folder attacks (shortcuts disguised as folders)
    async fn check_fake_folder_attacks(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        let mut detections = Vec::new();
        
        if let Ok(mut entries) = fs::read_dir(device_path).await {
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                
                // Look for .lnk files that might be disguised as folders
                if let Some(extension) = path.extension() {
                    if extension == "lnk" {
                        // Check if there's a real folder with similar name
                        let file_stem = path.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("");
                        
                        let potential_folder = device_path.join(file_stem);
                        if potential_folder.exists() && potential_folder.is_dir() {
                            // This might be a shortcut virus hiding the real folder
                            detections.push(UsbThreatDetection {
                                threat_type: UsbThreatType::ShortcutVirus,
                                file_path: path,
                                threat_name: "Fake Folder Shortcut".to_string(),
                                severity: ThreatSeverity::High,
                                description: "Suspicious shortcut file that may be hiding a real folder".to_string(),
                                recommended_action: UsbThreatAction::Quarantine,
                                detection_time: Utc::now(),
                            });
                        }
                    }
                }
            }
        }
        
        Ok(detections)
    }

    /// Check for hidden malware
    async fn check_hidden_malware(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        let mut detections = Vec::new();
        
        if !self.config.scan_hidden_files {
            return Ok(detections);
        }
        
        // Use system commands to find hidden files
        #[cfg(target_os = "windows")]
        {
            detections.extend(self.check_hidden_files_windows(device_path).await?);
        }
        
        #[cfg(target_os = "macos")]
        {
            detections.extend(self.check_hidden_files_macos(device_path).await?);
        }
        
        #[cfg(target_os = "linux")]
        {
            detections.extend(self.check_hidden_files_linux(device_path).await?);
        }
        
        Ok(detections)
    }

    /// Check hidden files on Windows
    #[cfg(target_os = "windows")]
    async fn check_hidden_files_windows(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        use std::process::Command;
        
        let mut detections = Vec::new();
        
        let output = Command::new("cmd")
            .args(&["/C", "dir", "/A:H", "/B", device_path.to_str().unwrap_or(".")])
            .output();
        
        if let Ok(output) = output {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                let line = line.trim();
                if !line.is_empty() && line.ends_with(".exe") {
                    let hidden_file = device_path.join(line);
                    
                    detections.push(UsbThreatDetection {
                        threat_type: UsbThreatType::HiddenExecutable,
                        file_path: hidden_file,
                        threat_name: "Hidden Executable".to_string(),
                        severity: ThreatSeverity::Medium,
                        description: "Hidden executable file found on USB device".to_string(),
                        recommended_action: UsbThreatAction::Quarantine,
                        detection_time: Utc::now(),
                    });
                }
            }
        }
        
        Ok(detections)
    }

    /// Check hidden files on macOS
    #[cfg(target_os = "macos")]
    async fn check_hidden_files_macos(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        use std::process::Command;
        
        let mut detections = Vec::new();
        
        let output = Command::new("find")
            .args(&[
                device_path.to_str().unwrap_or("."),
                "-name", ".*",
                "-type", "f",
                "-exec", "file", "{}", ";"
            ])
            .output();
        
        if let Ok(output) = output {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                if line.contains("executable") || line.contains("script") {
                    if let Some(file_path) = line.split(':').next() {
                        let hidden_file = PathBuf::from(file_path);
                        
                        detections.push(UsbThreatDetection {
                            threat_type: UsbThreatType::HiddenExecutable,
                            file_path: hidden_file,
                            threat_name: "Hidden Executable".to_string(),
                            severity: ThreatSeverity::Medium,
                            description: "Hidden executable file found on USB device".to_string(),
                            recommended_action: UsbThreatAction::Quarantine,
                            detection_time: Utc::now(),
                        });
                    }
                }
            }
        }
        
        Ok(detections)
    }

    /// Check hidden files on Linux
    #[cfg(target_os = "linux")]
    async fn check_hidden_files_linux(&self, device_path: &Path) -> Result<Vec<UsbThreatDetection>> {
        use std::process::Command;
        
        let mut detections = Vec::new();
        
        let output = Command::new("find")
            .args(&[
                device_path.to_str().unwrap_or("."),
                "-name", ".*",
                "-type", "f",
                "-executable"
            ])
            .output();
        
        if let Ok(output) = output {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    let hidden_file = PathBuf::from(line);
                    
                    detections.push(UsbThreatDetection {
                        threat_type: UsbThreatType::HiddenExecutable,
                        file_path: hidden_file,
                        threat_name: "Hidden Executable".to_string(),
                        severity: ThreatSeverity::Medium,
                        description: "Hidden executable file found on USB device".to_string(),
                        recommended_action: UsbThreatAction::Quarantine,
                        detection_time: Utc::now(),
                    });
                }
            }
        }
        
        Ok(detections)
    }

    /// Handle detected USB threat
    pub async fn handle_threat(&self, detection: &UsbThreatDetection) -> Result<()> {
        info!("Handling USB threat: {} at {}", detection.threat_name, detection.file_path.display());
        
        match detection.recommended_action {
            UsbThreatAction::Block => {
                self.block_file(&detection.file_path).await?;
            }
            UsbThreatAction::Quarantine => {
                self.quarantine_file(&detection.file_path).await?;
            }
            UsbThreatAction::Delete => {
                self.delete_file(&detection.file_path).await?;
            }
            UsbThreatAction::Warn => {
                warn!("USB threat detected but only warning: {}", detection.threat_name);
            }
        }
        
        Ok(())
    }

    /// Block access to a file
    async fn block_file(&self, file_path: &Path) -> Result<()> {
        // On Windows, we could use NTFS permissions
        // On Unix systems, we could change permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(file_path).await?.permissions();
            perms.set_mode(0o000); // Remove all permissions
            fs::set_permissions(file_path, perms).await?;
        }
        
        info!("Blocked access to file: {}", file_path.display());
        Ok(())
    }

    /// Quarantine a file
    async fn quarantine_file(&self, file_path: &Path) -> Result<()> {
        // Try to create quarantine directory in the same filesystem as the file
        let file_parent = file_path.parent().unwrap_or(file_path);
        let local_quarantine = file_parent.join(".quarantine");
        
        // Create local quarantine directory if it doesn't exist
        fs::create_dir_all(&local_quarantine).await?;
        
        // Generate unique quarantine filename
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let quarantine_file = local_quarantine.join(format!("{}_{}", timestamp, file_name));
        
        // Try to move file to local quarantine first
        match fs::rename(file_path, &quarantine_file).await {
            Ok(_) => {
                info!("Quarantined file locally: {} -> {}", file_path.display(), quarantine_file.display());
            }
            Err(_) => {
                // If rename fails, try copy and delete
                fs::copy(file_path, &quarantine_file).await?;
                fs::remove_file(file_path).await?;
                info!("Quarantined file (copy+delete): {} -> {}", file_path.display(), quarantine_file.display());
            }
        }
        
        Ok(())
    }

    /// Delete a file
    async fn delete_file(&self, file_path: &Path) -> Result<()> {
        fs::remove_file(file_path).await?;
        info!("Deleted file: {}", file_path.display());
        Ok(())
    }

    /// Check if filename matches pattern (supports wildcards)
    fn matches_pattern(&self, filename: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Simple wildcard matching
            if pattern.starts_with("*.") {
                let extension = &pattern[2..];
                filename.ends_with(extension)
            } else if pattern.ends_with("*") {
                let prefix = &pattern[..pattern.len()-1];
                filename.starts_with(prefix)
            } else {
                // More complex patterns could be implemented here
                filename.contains(&pattern.replace('*', ""))
            }
        } else {
            filename == pattern
        }
    }

    /// Get threat type from signature ID
    fn get_threat_type_from_id(&self, threat_id: &str) -> UsbThreatType {
        match threat_id {
            "autorun_worm" => UsbThreatType::AutorunWorm,
            "shortcut_virus" => UsbThreatType::ShortcutVirus,
            "hidden_executable" => UsbThreatType::HiddenExecutable,
            "suspicious_script" => UsbThreatType::SuspiciousScript,
            _ => UsbThreatType::Unknown,
        }
    }

    /// Clean USB device (remove common threats)
    pub async fn clean_usb_device(&self, device_path: &Path) -> Result<Vec<String>> {
        info!("Cleaning USB device: {}", device_path.display());
        
        let mut cleaned_files = Vec::new();
        
        // Remove autorun.inf files
        let autorun_files = ["autorun.inf", "autorun.pif", "desktop.ini"];
        for file in &autorun_files {
            let file_path = device_path.join(file);
            if file_path.exists() {
                fs::remove_file(&file_path).await?;
                cleaned_files.push(file_path.to_string_lossy().to_string());
                info!("Removed autorun file: {}", file_path.display());
            }
        }
        
        // Restore hidden folders (common shortcut virus behavior)
        self.restore_hidden_folders(device_path).await?;
        
        info!("USB cleaning completed. Removed {} files", cleaned_files.len());
        Ok(cleaned_files)
    }

    /// Immunize USB device against common viruses
    pub async fn immunize_usb_device(&self, device_path: &Path) -> Result<Vec<String>> {
        info!("Immunizing USB device: {}", device_path.display());
        
        let mut created_files = Vec::new();
        
        // Create protection files
        created_files.extend(self.create_autorun_protection(device_path).await?);
        created_files.extend(self.create_folder_protection(device_path).await?);
        created_files.extend(self.create_hadron_protection_marker(device_path).await?);
        
        info!("USB immunization completed. Created {} protection files", created_files.len());
        Ok(created_files)
    }

    /// Create autorun.inf protection (prevents virus autorun files)
    async fn create_autorun_protection(&self, device_path: &Path) -> Result<Vec<String>> {
        let mut created_files = Vec::new();
        
        // Create a read-only autorun.inf that does nothing
        let autorun_path = device_path.join("autorun.inf");
        
        // Remove existing autorun.inf if it exists
        if autorun_path.exists() {
            fs::remove_file(&autorun_path).await?;
        }
        
        // Create protective autorun.inf
        let autorun_content = r#"[autorun]
; HADRON Antivirus Protection File
; This file prevents malicious autorun.inf files from being created
; DO NOT DELETE - This protects your USB device from viruses
label=Protected USB Device
icon=autorun.ico
"#;
        
        fs::write(&autorun_path, autorun_content).await?;
        
        // Make it read-only and hidden
        self.make_file_readonly_hidden(&autorun_path).await?;
        
        created_files.push(autorun_path.to_string_lossy().to_string());
        info!("Created autorun protection: {}", autorun_path.display());
        
        Ok(created_files)
    }

    /// Create folder protection (prevents shortcut virus folder hiding)
    async fn create_folder_protection(&self, device_path: &Path) -> Result<Vec<String>> {
        let mut created_files = Vec::new();
        
        // Create a hidden folder that prevents common virus folder names
        let protection_folders = [
            "System Volume Information",
            "RECYCLER", 
            "$RECYCLE.BIN",
            "System32",
            "Windows",
        ];
        
        for folder_name in &protection_folders {
            let folder_path = device_path.join(folder_name);
            
            // Only create if it doesn't exist
            if !folder_path.exists() {
                fs::create_dir(&folder_path).await?;
                
                // Create a protection marker inside
                let marker_path = folder_path.join("HADRON_PROTECTION.txt");
                let marker_content = format!(
                    "HADRON Antivirus Protection\n\
                     This folder prevents viruses from using the name '{}'\n\
                     Created: {}\n\
                     DO NOT DELETE",
                    folder_name,
                    Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                );
                
                fs::write(&marker_path, marker_content).await?;
                self.make_file_readonly_hidden(&marker_path).await?;
                
                // Make folder hidden
                self.make_file_readonly_hidden(&folder_path).await?;
                
                created_files.push(folder_path.to_string_lossy().to_string());
                info!("Created protection folder: {}", folder_path.display());
            }
        }
        
        Ok(created_files)
    }

    /// Create HADRON protection marker
    async fn create_hadron_protection_marker(&self, device_path: &Path) -> Result<Vec<String>> {
        let mut created_files = Vec::new();
        
        // Create main protection file
        let protection_file = device_path.join("HADRON_USB_PROTECTION.txt");
        let protection_content = format!(
            "HADRON ANTIVIRUS USB PROTECTION\n\
             ================================\n\n\
             This USB device is protected by HADRON Antivirus.\n\n\
             Protection Features:\n\
             • Autorun.inf blocking\n\
             • Shortcut virus prevention\n\
             • Folder name protection\n\
             • Real-time threat monitoring\n\n\
             Protection installed: {}\n\
             Version: {}\n\n\
             WARNING: Do not delete protection files!\n\
             Deleting these files will make your USB vulnerable to viruses.\n\n\
             For more information visit: https://hadron-antivirus.com\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            env!("CARGO_PKG_VERSION")
        );
        
        fs::write(&protection_file, protection_content).await?;
        created_files.push(protection_file.to_string_lossy().to_string());
        
        // Create hidden system protection file
        let system_protection = device_path.join(".hadron_protection");
        let system_content = format!(
            "HADRON_PROTECTION_VERSION={}\n\
             PROTECTION_DATE={}\n\
             AUTORUN_PROTECTED=true\n\
             FOLDER_PROTECTED=true\n\
             SHORTCUT_PROTECTED=true\n",
            env!("CARGO_PKG_VERSION"),
            Utc::now().timestamp()
        );
        
        fs::write(&system_protection, system_content).await?;
        self.make_file_readonly_hidden(&system_protection).await?;
        created_files.push(system_protection.to_string_lossy().to_string());
        
        info!("Created HADRON protection markers");
        Ok(created_files)
    }

    /// Make file read-only and hidden
    async fn make_file_readonly_hidden(&self, file_path: &Path) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            // Use attrib command to make file read-only and hidden
            let _output = Command::new("cmd")
                .args(&["/C", "attrib", "+R", "+H", "+S", file_path.to_str().unwrap_or("")])
                .output();
        }
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            // Make file read-only (remove write permissions)
            if let Ok(metadata) = fs::metadata(file_path).await {
                let mut perms = metadata.permissions();
                perms.set_mode(0o444); // Read-only for all
                let _ = fs::set_permissions(file_path, perms).await;
            }
        }
        
        Ok(())
    }

    /// Check if USB device is already immunized
    pub async fn is_usb_immunized(&self, device_path: &Path) -> bool {
        let protection_marker = device_path.join(".hadron_protection");
        let autorun_protection = device_path.join("autorun.inf");
        
        protection_marker.exists() && autorun_protection.exists()
    }

    /// Remove USB immunization (for testing or user request)
    pub async fn remove_usb_immunization(&self, device_path: &Path) -> Result<Vec<String>> {
        info!("Removing USB immunization: {}", device_path.display());
        
        let mut removed_files = Vec::new();
        
        // Remove protection files
        let protection_files = [
            "autorun.inf",
            "HADRON_USB_PROTECTION.txt", 
            ".hadron_protection",
        ];
        
        for file_name in &protection_files {
            let file_path = device_path.join(file_name);
            if file_path.exists() {
                // Remove read-only attribute first
                self.remove_readonly_attribute(&file_path).await?;
                
                fs::remove_file(&file_path).await?;
                removed_files.push(file_path.to_string_lossy().to_string());
                info!("Removed protection file: {}", file_path.display());
            }
        }
        
        // Remove protection folders
        let protection_folders = [
            "System Volume Information",
            "RECYCLER",
            "$RECYCLE.BIN", 
            "System32",
            "Windows",
        ];
        
        for folder_name in &protection_folders {
            let folder_path = device_path.join(folder_name);
            if folder_path.exists() {
                // Check if it's our protection folder
                let marker_path = folder_path.join("HADRON_PROTECTION.txt");
                if marker_path.exists() {
                    // Remove marker first
                    self.remove_readonly_attribute(&marker_path).await?;
                    fs::remove_file(&marker_path).await?;
                    
                    // Remove folder
                    self.remove_readonly_attribute(&folder_path).await?;
                    fs::remove_dir(&folder_path).await?;
                    
                    removed_files.push(folder_path.to_string_lossy().to_string());
                    info!("Removed protection folder: {}", folder_path.display());
                }
            }
        }
        
        info!("USB immunization removal completed. Removed {} files", removed_files.len());
        Ok(removed_files)
    }

    /// Remove read-only attribute from file
    async fn remove_readonly_attribute(&self, file_path: &Path) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            let _output = Command::new("cmd")
                .args(&["/C", "attrib", "-R", "-H", "-S", file_path.to_str().unwrap_or("")])
                .output();
        }
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            if let Ok(metadata) = fs::metadata(file_path).await {
                let mut perms = metadata.permissions();
                perms.set_mode(0o644); // Read-write for owner, read for others
                let _ = fs::set_permissions(file_path, perms).await;
            }
        }
        
        Ok(())
    }

    /// Restore folders hidden by shortcut viruses
    async fn restore_hidden_folders(&self, device_path: &Path) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            // Use attrib command to unhide folders
            let _output = Command::new("cmd")
                .args(&["/C", "attrib", "-H", "-S", "/S", "/D", device_path.to_str().unwrap_or(".")])
                .output();
        }
        
        #[cfg(unix)]
        {
            // On Unix systems, hidden files start with dot, but USB viruses
            // typically use Windows-style hidden attributes
            debug!("Unix systems don't typically have hidden attribute issues");
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_usb_protection_creation() {
        let temp_dir = TempDir::new().unwrap();
        let protection = UsbProtection::new(temp_dir.path().to_path_buf());
        
        assert!(!protection.known_threats.is_empty());
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        let temp_dir = TempDir::new().unwrap();
        let protection = UsbProtection::new(temp_dir.path().to_path_buf());
        
        assert!(protection.matches_pattern("test.exe", "*.exe"));
        assert!(protection.matches_pattern("autorun.inf", "autorun.inf"));
        assert!(!protection.matches_pattern("test.txt", "*.exe"));
    }

    #[tokio::test]
    async fn test_autorun_detection() {
        let temp_dir = TempDir::new().unwrap();
        let protection = UsbProtection::new(temp_dir.path().to_path_buf());
        
        // Create malicious autorun.inf
        let autorun_path = temp_dir.path().join("autorun.inf");
        fs::write(&autorun_path, "[autorun]\nshellexecute=malware.exe\n").await.unwrap();
        
        let detections = protection.check_autorun_threats(temp_dir.path()).await.unwrap();
        assert!(!detections.is_empty());
        assert_eq!(detections[0].threat_type as u8, UsbThreatType::AutorunWorm as u8);
    }
}