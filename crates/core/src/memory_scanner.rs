use crate::{Result, ScanResult, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
use std::collections::HashMap;
use std::path::PathBuf;
use chrono::Utc;
use uuid::Uuid;
use tracing::{info, warn, debug};

/// Memory scanner for detecting threats in process memory
pub struct MemoryScanner {
    /// Signature patterns for in-memory detection
    pub signature_patterns: Vec<MemorySignature>,
    /// Rootkit detection rules
    pub rootkit_detectors: Vec<RootkitDetector>,
    /// Process handle cache
    process_handles: HashMap<u32, ProcessHandle>,
    /// Configuration settings
    config: MemoryScanConfig,
}

/// Configuration for memory scanning
#[derive(Debug, Clone)]
pub struct MemoryScanConfig {
    /// Maximum memory region size to scan (in bytes)
    pub max_region_size: usize,
    /// Timeout for scanning a single process (in seconds)
    pub scan_timeout_seconds: u32,
    /// Enable rootkit detection
    pub enable_rootkit_detection: bool,
    /// Enable heuristic analysis
    pub enable_heuristic_analysis: bool,
    /// Maximum number of concurrent scans
    pub max_concurrent_scans: usize,
}

impl Default for MemoryScanConfig {
    fn default() -> Self {
        Self {
            max_region_size: 100 * 1024 * 1024, // 100MB
            scan_timeout_seconds: 30,
            enable_rootkit_detection: true,
            enable_heuristic_analysis: true,
            max_concurrent_scans: 4,
        }
    }
}

/// Memory signature for pattern matching
#[derive(Debug, Clone)]
pub struct MemorySignature {
    /// Unique identifier for the signature
    pub id: String,
    /// Pattern to match (hex bytes)
    pub pattern: Vec<u8>,
    /// Mask for pattern matching (0xFF = must match, 0x00 = wildcard)
    pub mask: Vec<u8>,
    /// Threat information associated with this signature
    pub threat_info: ThreatInfo,
    /// Minimum offset from start of memory region
    pub min_offset: usize,
    /// Maximum offset from start of memory region
    pub max_offset: Option<usize>,
}

/// Rootkit detection algorithms
#[derive(Debug, Clone)]
pub struct RootkitDetector {
    /// Name of the detection method
    pub name: String,
    /// Detection function type
    pub detector_type: RootkitDetectorType,
    /// Severity of threats detected by this method
    pub severity: ThreatSeverity,
}

/// Types of rootkit detection methods
#[derive(Debug, Clone)]
pub enum RootkitDetectorType {
    /// Detect hidden processes
    HiddenProcess,
    /// Detect SSDT hooks
    SsdtHook,
    /// Detect inline hooks
    InlineHook,
    /// Detect DLL injection
    DllInjection,
    /// Detect process hollowing
    ProcessHollowing,
    /// Detect memory patching
    MemoryPatching,
}

/// Handle to a process for memory operations
#[derive(Debug)]
pub struct ProcessHandle {
    /// Process ID
    pub process_id: u32,
    /// Process name
    pub process_name: String,
    /// Executable path
    pub executable_path: PathBuf,
    /// Memory regions
    pub memory_regions: Vec<MemoryRegion>,
    /// Last scan time
    pub last_scan_time: Option<chrono::DateTime<Utc>>,
}

/// Memory region information
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base address of the region
    pub base_address: u64,
    /// Size of the region
    pub size: usize,
    /// Protection flags
    pub protection: MemoryProtection,
    /// Type of memory region
    pub region_type: MemoryRegionType,
    /// Associated module name (if any)
    pub module_name: Option<String>,
}

/// Memory protection flags
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryProtection {
    /// No access
    NoAccess,
    /// Read only
    ReadOnly,
    /// Read/Write
    ReadWrite,
    /// Execute only
    ExecuteOnly,
    /// Execute/Read
    ExecuteRead,
    /// Execute/Read/Write
    ExecuteReadWrite,
    /// Guard page
    Guard,
}

/// Types of memory regions
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryRegionType {
    /// Image (executable/DLL)
    Image,
    /// Mapped file
    Mapped,
    /// Private memory
    Private,
    /// Heap
    Heap,
    /// Stack
    Stack,
}

/// Result of memory scanning operation
#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    /// Process ID that was scanned
    pub process_id: u32,
    /// Process name
    pub process_name: String,
    /// Threats found in memory
    pub threats_found: Vec<MemoryThreat>,
    /// Rootkit indicators found
    pub rootkit_indicators: Vec<RootkitIndicator>,
    /// Scan statistics
    pub scan_stats: MemoryScanStats,
    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,
}

/// Threat found in memory
#[derive(Debug, Clone)]
pub struct MemoryThreat {
    /// Base threat information
    pub threat_info: ThreatInfo,
    /// Memory address where threat was found
    pub memory_address: u64,
    /// Size of the threat pattern
    pub pattern_size: usize,
    /// Memory region where threat was found
    pub memory_region: MemoryRegion,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f32,
}

/// Rootkit indicator found during scanning
#[derive(Debug, Clone)]
pub struct RootkitIndicator {
    /// Type of rootkit behavior detected
    pub indicator_type: RootkitDetectorType,
    /// Description of the indicator
    pub description: String,
    /// Memory address associated with the indicator
    pub memory_address: Option<u64>,
    /// Severity of the indicator
    pub severity: ThreatSeverity,
    /// Additional details
    pub details: HashMap<String, String>,
}

/// Statistics for memory scan operation
#[derive(Debug, Clone, Default)]
pub struct MemoryScanStats {
    /// Total memory regions scanned
    pub regions_scanned: u64,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Number of executable regions scanned
    pub executable_regions: u64,
    /// Number of suspicious regions found
    pub suspicious_regions: u64,
    /// Number of signature matches
    pub signature_matches: u64,
    /// Number of heuristic detections
    pub heuristic_detections: u64,
}

impl MemoryScanner {
    /// Create a new memory scanner with default configuration
    pub fn new() -> Self {
        Self::with_config(MemoryScanConfig::default())
    }

    /// Create a new memory scanner with custom configuration
    pub fn with_config(config: MemoryScanConfig) -> Self {
        Self {
            signature_patterns: Vec::new(),
            rootkit_detectors: Self::create_default_rootkit_detectors(),
            process_handles: HashMap::new(),
            config,
        }
    }

    /// Load signature patterns from a file or database
    pub fn load_signatures(&mut self, signatures: Vec<MemorySignature>) -> Result<()> {
        info!("Loading {} memory signatures", signatures.len());
        self.signature_patterns = signatures;
        Ok(())
    }

    /// Add a custom signature pattern
    pub fn add_signature(&mut self, signature: MemorySignature) {
        debug!("Adding memory signature: {}", signature.id);
        self.signature_patterns.push(signature);
    }

    /// Scan memory of a specific process
    pub async fn scan_process_memory(&mut self, process_id: u32) -> Result<MemoryScanResult> {
        let start_time = std::time::Instant::now();
        info!("Starting memory scan for process ID: {}", process_id);

        // Get or create process handle
        let process_handle = self.get_or_create_process_handle(process_id)?;
        let process_name = process_handle.process_name.clone();

        let mut result = MemoryScanResult {
            process_id,
            process_name,
            threats_found: Vec::new(),
            rootkit_indicators: Vec::new(),
            scan_stats: MemoryScanStats::default(),
            scan_duration_ms: 0,
        };

        // Enumerate memory regions
        let memory_regions = self.enumerate_memory_regions(process_id)?;
        result.scan_stats.regions_scanned = memory_regions.len() as u64;

        // Scan each memory region
        for region in &memory_regions {
            if let Err(e) = self.scan_memory_region(process_id, region, &mut result).await {
                warn!("Failed to scan memory region at 0x{:x}: {}", region.base_address, e);
                continue;
            }
        }

        // Perform rootkit detection if enabled
        if self.config.enable_rootkit_detection {
            self.detect_rootkit_indicators(process_id, &mut result).await?;
        }

        // Perform heuristic analysis if enabled
        if self.config.enable_heuristic_analysis {
            self.perform_heuristic_analysis(process_id, &memory_regions, &mut result).await?;
        }

        result.scan_duration_ms = start_time.elapsed().as_millis() as u64;
        info!("Memory scan completed for process {}: {} threats found", 
              process_id, result.threats_found.len());

        Ok(result)
    }

    /// Scan all running processes
    pub async fn scan_all_processes(&mut self) -> Result<Vec<MemoryScanResult>> {
        info!("Starting memory scan of all processes");
        
        let process_list = self.enumerate_processes()?;
        let mut results = Vec::new();

        for process_id in process_list {
            match self.scan_process_memory(process_id).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("Failed to scan process {}: {}", process_id, e);
                    continue;
                }
            }
        }

        info!("Completed memory scan of {} processes", results.len());
        Ok(results)
    }

    /// Get or create a process handle
    fn get_or_create_process_handle(&mut self, process_id: u32) -> Result<&ProcessHandle> {
        if !self.process_handles.contains_key(&process_id) {
            let handle = self.create_process_handle(process_id)?;
            self.process_handles.insert(process_id, handle);
        }
        
        Ok(self.process_handles.get(&process_id).unwrap())
    }

    /// Create a new process handle
    fn create_process_handle(&self, process_id: u32) -> Result<ProcessHandle> {
        // In a real implementation, this would use Windows API calls
        // For now, we'll create a mock implementation
        
        let process_name = format!("process_{}.exe", process_id);
        let executable_path = PathBuf::from(format!("C:\\Windows\\System32\\{}", process_name));
        
        Ok(ProcessHandle {
            process_id,
            process_name,
            executable_path,
            memory_regions: Vec::new(),
            last_scan_time: None,
        })
    }

    /// Enumerate memory regions for a process
    fn enumerate_memory_regions(&self, process_id: u32) -> Result<Vec<MemoryRegion>> {
        // In a real implementation, this would use VirtualQueryEx and similar APIs
        // For now, we'll create mock memory regions
        
        debug!("Enumerating memory regions for process {}", process_id);
        
        let mut regions = Vec::new();
        
        // Mock some typical memory regions
        regions.push(MemoryRegion {
            base_address: 0x00400000,
            size: 0x100000, // 1MB
            protection: MemoryProtection::ExecuteRead,
            region_type: MemoryRegionType::Image,
            module_name: Some("main.exe".to_string()),
        });
        
        regions.push(MemoryRegion {
            base_address: 0x10000000,
            size: 0x200000, // 2MB
            protection: MemoryProtection::ReadWrite,
            region_type: MemoryRegionType::Heap,
            module_name: None,
        });
        
        regions.push(MemoryRegion {
            base_address: 0x7C800000,
            size: 0x100000, // 1MB
            protection: MemoryProtection::ExecuteRead,
            region_type: MemoryRegionType::Image,
            module_name: Some("kernel32.dll".to_string()),
        });

        Ok(regions)
    }

    /// Scan a specific memory region
    async fn scan_memory_region(
        &self,
        process_id: u32,
        region: &MemoryRegion,
        result: &mut MemoryScanResult,
    ) -> Result<()> {
        debug!("Scanning memory region at 0x{:x} (size: {} bytes)", 
               region.base_address, region.size);

        // Skip regions that are too large
        if region.size > self.config.max_region_size {
            debug!("Skipping large memory region (size: {} bytes)", region.size);
            return Ok(());
        }

        // Read memory from the region
        let memory_data = self.read_process_memory(process_id, region.base_address, region.size)?;
        result.scan_stats.bytes_scanned += memory_data.len() as u64;

        // Count executable regions
        if matches!(region.protection, MemoryProtection::ExecuteRead | 
                   MemoryProtection::ExecuteReadWrite | MemoryProtection::ExecuteOnly) {
            result.scan_stats.executable_regions += 1;
        }

        // Perform signature matching
        self.match_signatures(&memory_data, region, result)?;

        Ok(())
    }

    /// Read memory from a process
    fn read_process_memory(&self, process_id: u32, address: u64, size: usize) -> Result<Vec<u8>> {
        // In a real implementation, this would use ReadProcessMemory API
        // For now, we'll create mock memory data with some patterns
        
        debug!("Reading {} bytes from process {} at address 0x{:x}", 
               size, process_id, address);

        let mut data = vec![0u8; size];
        
        // Add some mock patterns for testing
        if size > 100 {
            // Mock malware signature pattern
            let pattern = b"\x4D\x5A\x90\x00\x03\x00\x00\x00"; // PE header start
            if size >= pattern.len() {
                data[50..50 + pattern.len()].copy_from_slice(pattern);
            }
            
            // Mock suspicious API call pattern
            let api_pattern = b"CreateRemoteThread";
            if size >= 100 + api_pattern.len() {
                data[100..100 + api_pattern.len()].copy_from_slice(api_pattern);
            }
        }

        Ok(data)
    }

    /// Match signature patterns against memory data
    fn match_signatures(
        &self,
        memory_data: &[u8],
        region: &MemoryRegion,
        result: &mut MemoryScanResult,
    ) -> Result<()> {
        for signature in &self.signature_patterns {
            if let Some(offset) = self.find_pattern(memory_data, &signature.pattern, &signature.mask) {
                // Check offset constraints
                if offset < signature.min_offset {
                    continue;
                }
                if let Some(max_offset) = signature.max_offset {
                    if offset > max_offset {
                        continue;
                    }
                }

                let memory_address = region.base_address + offset as u64;
                
                info!("Memory threat detected: {} at address 0x{:x}", 
                      signature.threat_info.name, memory_address);

                let memory_threat = MemoryThreat {
                    threat_info: signature.threat_info.clone(),
                    memory_address,
                    pattern_size: signature.pattern.len(),
                    memory_region: region.clone(),
                    confidence: 0.9, // High confidence for signature matches
                };

                result.threats_found.push(memory_threat);
                result.scan_stats.signature_matches += 1;
            }
        }

        Ok(())
    }

    /// Find a pattern in memory data using mask
    pub fn find_pattern(&self, data: &[u8], pattern: &[u8], mask: &[u8]) -> Option<usize> {
        if pattern.len() != mask.len() || pattern.is_empty() || data.len() < pattern.len() {
            return None;
        }

        for i in 0..=data.len() - pattern.len() {
            let mut matches = true;
            for j in 0..pattern.len() {
                if mask[j] != 0 && data[i + j] != pattern[j] {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Some(i);
            }
        }

        None
    }

    /// Detect rootkit indicators
    async fn detect_rootkit_indicators(
        &self,
        process_id: u32,
        result: &mut MemoryScanResult,
    ) -> Result<()> {
        debug!("Performing rootkit detection for process {}", process_id);

        for detector in &self.rootkit_detectors {
            match self.run_rootkit_detector(process_id, detector).await {
                Ok(Some(indicator)) => {
                    info!("Rootkit indicator detected: {}", indicator.description);
                    result.rootkit_indicators.push(indicator);
                }
                Ok(None) => {
                    // No indicator found, continue
                }
                Err(e) => {
                    warn!("Rootkit detector '{}' failed: {}", detector.name, e);
                }
            }
        }

        Ok(())
    }

    /// Run a specific rootkit detector
    async fn run_rootkit_detector(
        &self,
        process_id: u32,
        detector: &RootkitDetector,
    ) -> Result<Option<RootkitIndicator>> {
        match detector.detector_type {
            RootkitDetectorType::HiddenProcess => {
                self.detect_hidden_process(process_id, detector).await
            }
            RootkitDetectorType::SsdtHook => {
                self.detect_ssdt_hook(process_id, detector).await
            }
            RootkitDetectorType::InlineHook => {
                self.detect_inline_hook(process_id, detector).await
            }
            RootkitDetectorType::DllInjection => {
                self.detect_dll_injection(process_id, detector).await
            }
            RootkitDetectorType::ProcessHollowing => {
                self.detect_process_hollowing(process_id, detector).await
            }
            RootkitDetectorType::MemoryPatching => {
                self.detect_memory_patching(process_id, detector).await
            }
        }
    }

    /// Detect hidden processes
    async fn detect_hidden_process(
        &self,
        _process_id: u32,
        detector: &RootkitDetector,
    ) -> Result<Option<RootkitIndicator>> {
        // Mock implementation - in reality would compare process lists from different sources
        debug!("Checking for hidden processes");
        
        // Simulate finding a hidden process occasionally
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
           .unwrap().as_secs() % 10 == 0 { // 10% chance for demo
            let mut details = HashMap::new();
            details.insert("detection_method".to_string(), "PEB_vs_EPROCESS".to_string());
            details.insert("hidden_pid".to_string(), "1234".to_string());
            
            Ok(Some(RootkitIndicator {
                indicator_type: detector.detector_type.clone(),
                description: "Hidden process detected via PEB/EPROCESS comparison".to_string(),
                memory_address: Some(0x80000000),
                severity: detector.severity.clone(),
                details,
            }))
        } else {
            Ok(None)
        }
    }

    /// Detect SSDT hooks
    async fn detect_ssdt_hook(
        &self,
        _process_id: u32,
        detector: &RootkitDetector,
    ) -> Result<Option<RootkitIndicator>> {
        // Mock implementation - in reality would check SSDT integrity
        debug!("Checking for SSDT hooks");
        
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
           .unwrap().as_secs() % 20 == 0 { // 5% chance for demo
            let mut details = HashMap::new();
            details.insert("hooked_function".to_string(), "NtCreateFile".to_string());
            details.insert("original_address".to_string(), "0x80501234".to_string());
            details.insert("hooked_address".to_string(), "0x12345678".to_string());
            
            Ok(Some(RootkitIndicator {
                indicator_type: detector.detector_type.clone(),
                description: "SSDT hook detected on NtCreateFile".to_string(),
                memory_address: Some(0x12345678),
                severity: detector.severity.clone(),
                details,
            }))
        } else {
            Ok(None)
        }
    }

    /// Detect inline hooks
    async fn detect_inline_hook(
        &self,
        _process_id: u32,
        detector: &RootkitDetector,
    ) -> Result<Option<RootkitIndicator>> {
        debug!("Checking for inline hooks");
        
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
           .unwrap().as_secs() % 12 == 0 { // 8% chance for demo
            let mut details = HashMap::new();
            details.insert("hooked_function".to_string(), "CreateFileW".to_string());
            details.insert("module".to_string(), "kernel32.dll".to_string());
            
            Ok(Some(RootkitIndicator {
                indicator_type: detector.detector_type.clone(),
                description: "Inline hook detected in CreateFileW".to_string(),
                memory_address: Some(0x7C801234),
                severity: detector.severity.clone(),
                details,
            }))
        } else {
            Ok(None)
        }
    }

    /// Detect DLL injection
    async fn detect_dll_injection(
        &self,
        _process_id: u32,
        detector: &RootkitDetector,
    ) -> Result<Option<RootkitIndicator>> {
        debug!("Checking for DLL injection");
        
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
           .unwrap().as_secs() % 8 == 0 { // 12% chance for demo
            let mut details = HashMap::new();
            details.insert("injected_dll".to_string(), "malicious.dll".to_string());
            details.insert("injection_method".to_string(), "SetWindowsHookEx".to_string());
            
            Ok(Some(RootkitIndicator {
                indicator_type: detector.detector_type.clone(),
                description: "DLL injection detected via SetWindowsHookEx".to_string(),
                memory_address: Some(0x10000000),
                severity: detector.severity.clone(),
                details,
            }))
        } else {
            Ok(None)
        }
    }

    /// Detect process hollowing
    async fn detect_process_hollowing(
        &self,
        _process_id: u32,
        detector: &RootkitDetector,
    ) -> Result<Option<RootkitIndicator>> {
        debug!("Checking for process hollowing");
        
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
           .unwrap().as_secs() % 16 == 0 { // 6% chance for demo
            let mut details = HashMap::new();
            details.insert("original_image".to_string(), "svchost.exe".to_string());
            details.insert("replaced_image".to_string(), "malware.exe".to_string());
            
            Ok(Some(RootkitIndicator {
                indicator_type: detector.detector_type.clone(),
                description: "Process hollowing detected - svchost.exe replaced".to_string(),
                memory_address: Some(0x00400000),
                severity: detector.severity.clone(),
                details,
            }))
        } else {
            Ok(None)
        }
    }

    /// Detect memory patching
    async fn detect_memory_patching(
        &self,
        _process_id: u32,
        detector: &RootkitDetector,
    ) -> Result<Option<RootkitIndicator>> {
        debug!("Checking for memory patching");
        
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
           .unwrap().as_secs() % 14 == 0 { // 7% chance for demo
            let mut details = HashMap::new();
            details.insert("patched_function".to_string(), "NtQuerySystemInformation".to_string());
            details.insert("patch_size".to_string(), "12".to_string());
            
            Ok(Some(RootkitIndicator {
                indicator_type: detector.detector_type.clone(),
                description: "Memory patching detected in NtQuerySystemInformation".to_string(),
                memory_address: Some(0x80502468),
                severity: detector.severity.clone(),
                details,
            }))
        } else {
            Ok(None)
        }
    }

    /// Perform heuristic analysis on memory regions
    async fn perform_heuristic_analysis(
        &self,
        process_id: u32,
        memory_regions: &[MemoryRegion],
        result: &mut MemoryScanResult,
    ) -> Result<()> {
        debug!("Performing heuristic analysis for process {}", process_id);

        for region in memory_regions {
            // Check for suspicious memory characteristics
            if self.is_suspicious_memory_region(region) {
                result.scan_stats.suspicious_regions += 1;
                
                // Create a heuristic threat
                let threat_info = ThreatInfo::new(
                    "Suspicious Memory Region".to_string(),
                    ThreatType::Suspicious,
                    ThreatSeverity::Medium,
                    PathBuf::from(format!("memory://process_{}/region_{:x}", 
                                         process_id, region.base_address)),
                    format!("{:x}", region.base_address), // Use address as hash
                    DetectionMethod::Heuristic,
                )?;

                let memory_threat = MemoryThreat {
                    threat_info,
                    memory_address: region.base_address,
                    pattern_size: region.size,
                    memory_region: region.clone(),
                    confidence: 0.6, // Medium confidence for heuristic detection
                };

                result.threats_found.push(memory_threat);
                result.scan_stats.heuristic_detections += 1;
            }
        }

        Ok(())
    }

    /// Check if a memory region is suspicious
    pub fn is_suspicious_memory_region(&self, region: &MemoryRegion) -> bool {
        // Heuristic rules for suspicious memory regions
        
        // Executable heap/private memory is suspicious
        if matches!(region.region_type, MemoryRegionType::Heap | MemoryRegionType::Private) &&
           matches!(region.protection, MemoryProtection::ExecuteReadWrite | 
                   MemoryProtection::ExecuteRead | MemoryProtection::ExecuteOnly) {
            return true;
        }

        // Very large executable regions without module names
        if region.size > 10 * 1024 * 1024 && // > 10MB
           region.module_name.is_none() &&
           matches!(region.protection, MemoryProtection::ExecuteReadWrite | 
                   MemoryProtection::ExecuteRead) {
            return true;
        }

        // Memory regions at unusual base addresses
        if region.base_address < 0x10000 || region.base_address > 0x7FFFFFFF {
            return true;
        }

        false
    }

    /// Enumerate running processes
    fn enumerate_processes(&self) -> Result<Vec<u32>> {
        // In a real implementation, this would use Process32First/Process32Next
        // For now, return mock process IDs
        Ok(vec![1234, 5678, 9012, 3456, 7890])
    }

    /// Create default rootkit detectors
    fn create_default_rootkit_detectors() -> Vec<RootkitDetector> {
        vec![
            RootkitDetector {
                name: "Hidden Process Detector".to_string(),
                detector_type: RootkitDetectorType::HiddenProcess,
                severity: ThreatSeverity::High,
            },
            RootkitDetector {
                name: "SSDT Hook Detector".to_string(),
                detector_type: RootkitDetectorType::SsdtHook,
                severity: ThreatSeverity::Critical,
            },
            RootkitDetector {
                name: "Inline Hook Detector".to_string(),
                detector_type: RootkitDetectorType::InlineHook,
                severity: ThreatSeverity::High,
            },
            RootkitDetector {
                name: "DLL Injection Detector".to_string(),
                detector_type: RootkitDetectorType::DllInjection,
                severity: ThreatSeverity::Medium,
            },
            RootkitDetector {
                name: "Process Hollowing Detector".to_string(),
                detector_type: RootkitDetectorType::ProcessHollowing,
                severity: ThreatSeverity::Critical,
            },
            RootkitDetector {
                name: "Memory Patching Detector".to_string(),
                detector_type: RootkitDetectorType::MemoryPatching,
                severity: ThreatSeverity::High,
            },
        ]
    }

    /// Convert memory scan result to standard scan result
    pub fn to_scan_result(&self, memory_result: MemoryScanResult) -> ScanResult {
        let mut scan_result = ScanResult::new(Uuid::new_v4());
        
        // Convert memory threats to standard threats
        for memory_threat in memory_result.threats_found {
            scan_result.add_threat(memory_threat.threat_info);
        }

        // Add rootkit indicators as threats
        for indicator in memory_result.rootkit_indicators {
            let threat_info = ThreatInfo::new(
                format!("Rootkit: {}", indicator.description),
                ThreatType::Rootkit,
                indicator.severity,
                PathBuf::from(format!("memory://process_{}", memory_result.process_id)),
                format!("{:x}", indicator.memory_address.unwrap_or(0)),
                DetectionMethod::Behavioral,
            ).unwrap_or_else(|_| {
                // Fallback if creation fails
                let mut threat = ThreatInfo::new(
                    "Rootkit Detection".to_string(),
                    ThreatType::Rootkit,
                    ThreatSeverity::High,
                    PathBuf::from("memory://unknown"),
                    "0".repeat(64),
                    DetectionMethod::Behavioral,
                ).unwrap();
                threat.add_info("description".to_string(), indicator.description);
                threat
            });
            
            scan_result.add_threat(threat_info);
        }

        scan_result.scanned_files = memory_result.scan_stats.regions_scanned;
        scan_result.complete();
        scan_result
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

// Add rand dependency for mock implementations

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_scanner_creation() {
        let scanner = MemoryScanner::new();
        assert_eq!(scanner.signature_patterns.len(), 0);
        assert_eq!(scanner.rootkit_detectors.len(), 6);
    }

    #[tokio::test]
    async fn test_signature_matching() {
        let scanner = MemoryScanner::new();
        let pattern = vec![0x4D, 0x5A, 0x90, 0x00];
        let mask = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let data = vec![0x00, 0x00, 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00];
        
        let result = scanner.find_pattern(&data, &pattern, &mask);
        assert_eq!(result, Some(2));
    }

    #[tokio::test]
    async fn test_memory_region_suspicion() {
        let scanner = MemoryScanner::new();
        
        // Suspicious: executable heap
        let suspicious_region = MemoryRegion {
            base_address: 0x10000000,
            size: 1024,
            protection: MemoryProtection::ExecuteReadWrite,
            region_type: MemoryRegionType::Heap,
            module_name: None,
        };
        
        assert!(scanner.is_suspicious_memory_region(&suspicious_region));
        
        // Normal: read-only image
        let normal_region = MemoryRegion {
            base_address: 0x00400000,
            size: 1024,
            protection: MemoryProtection::ExecuteRead,
            region_type: MemoryRegionType::Image,
            module_name: Some("test.exe".to_string()),
        };
        
        assert!(!scanner.is_suspicious_memory_region(&normal_region));
    }

    #[tokio::test]
    async fn test_process_memory_scan() {
        let mut scanner = MemoryScanner::new();
        
        // Add a test signature
        let threat_info = ThreatInfo::new(
            "Test.Malware".to_string(),
            ThreatType::Virus,
            ThreatSeverity::High,
            PathBuf::from("/tmp/test.exe"),
            "a".repeat(64),
            DetectionMethod::Signature,
        ).unwrap();
        
        let signature = MemorySignature {
            id: "test_sig_1".to_string(),
            pattern: vec![0x4D, 0x5A, 0x90, 0x00],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            threat_info,
            min_offset: 0,
            max_offset: None,
        };
        
        scanner.add_signature(signature);
        
        let result = scanner.scan_process_memory(1234).await;
        assert!(result.is_ok());
        
        let scan_result = result.unwrap();
        assert_eq!(scan_result.process_id, 1234);
        assert!(scan_result.scan_duration_ms > 0);
    }
}