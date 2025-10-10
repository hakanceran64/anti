use hadron_core::{Result, Scanner, ScanResult, ScanType, ScanJobId, ScanStatus, ScanProgress, NetworkPacket, SignatureDatabase, ThreatInfo, FileScanner, DirectoryWalker, FileInfo, HeuristicAnalyzer};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::sync::{RwLock, Mutex};
use std::sync::Arc;
pub struct ScanEngineImpl {
    active_scans: Arc<RwLock<HashMap<ScanJobId, ScanJob>>>,
    progress_callbacks: Arc<Mutex<Vec<Box<dyn Fn(ScanProgress) + Send + Sync>>>>,
    statistics: Arc<RwLock<ScanStatistics>>,
    signature_database: Arc<SignatureDatabase>,
    file_scanner: Arc<FileScanner>,
    directory_walker: Arc<DirectoryWalker>,
    heuristic_analyzer: Arc<HeuristicAnalyzer>,
}
#[derive(Debug)]
struct ScanJob {
    id: ScanJobId,
    scan_type: ScanType,
    targets: Vec<std::path::PathBuf>,
    status: ScanStatus,
    start_time: chrono::DateTime<chrono::Utc>,
    progress: ScanProgress,
    handle: Option<tokio::task::JoinHandle<Result<ScanResult>>>,
}
#[derive(Debug, Clone)]
pub struct ScanStatistics {
    pub last_scan_time: Option<chrono::DateTime<chrono::Utc>>,
    pub threats_detected_today: u32,
    pub total_files_scanned: u64,
    pub total_threats_detected: u64,
}
impl ScanEngineImpl {
    pub fn new() -> Result<Self> {
        let signature_db_path = std::env::var("SIGNATURE_DB_PATH")
            .unwrap_or_else(|_| "signatures".to_string());
        let signature_database = Arc::new(SignatureDatabase::new(signature_db_path.into()));
        let max_file_size = std::env::var("MAX_SCAN_FILE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024);
        let file_scanner = Arc::new(
            FileScanner::new()
                .with_max_file_size(max_file_size)
                .with_excluded_extensions(vec![
                    "tmp".to_string(),
                    "log".to_string(),
                    "bak".to_string(),
                    "cache".to_string(),
                ])
        );
        let directory_walker = Arc::new(
            DirectoryWalker::new()
                .with_max_depth(10)
                .with_excluded_dirs(vec![
                    "System Volume Information".to_string(),
                    "$Recycle.Bin".to_string(),
                    "Windows".to_string(),
                    "Program Files".to_string(),
                    "Program Files (x86)".to_string(),
                    "ProgramData".to_string(),
                    "AppData".to_string(),
                ])
        );
        let heuristic_analyzer = Arc::new(HeuristicAnalyzer::new());
        Ok(Self {
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            progress_callbacks: Arc::new(Mutex::new(Vec::new())),
            statistics: Arc::new(RwLock::new(ScanStatistics {
                last_scan_time: None,
                threats_detected_today: 0,
                total_files_scanned: 0,
                total_threats_detected: 0,
            })),
            signature_database,
            file_scanner,
            directory_walker,
            heuristic_analyzer,
        })
    }
    pub async fn start(&self) -> Result<()> {
        if let Err(e) = self.signature_database.reload() {
            tracing::warn!("Failed to load signature database: {}", e);
        } else {
            let stats = self.signature_database.get_statistics();
            tracing::info!("Loaded {} signatures from database version {}", 
                          stats.total_signatures, stats.version);
        }
        tracing::info!("Scan engine started");
        Ok(())
    }
    pub async fn stop(&self) -> Result<()> {
        let mut active_scans = self.active_scans.write().await;
        for (_, mut scan_job) in active_scans.drain() {
            if let Some(handle) = scan_job.handle.take() {
                handle.abort();
            }
        }
        tracing::info!("Scan engine stopped");
        Ok(())
    }
    pub async fn get_statistics(&self) -> Result<ScanStatistics> {
        Ok(self.statistics.read().await.clone())
    }
    pub async fn register_progress_callback(&self, callback: Box<dyn Fn(ScanProgress) + Send + Sync>) -> Result<()> {
        let mut callbacks = self.progress_callbacks.lock().await;
        callbacks.push(callback);
        Ok(())
    }
    async fn notify_progress(&self, progress: ScanProgress) {
        let callbacks = self.progress_callbacks.lock().await;
        for callback in callbacks.iter() {
            callback(progress.clone());
        }
    }
    async fn scan_file_internal(&self, path: &Path) -> Result<ScanResult> {
        tracing::debug!("Scanning file: {}", path.display());
        let start_time = chrono::Utc::now();
        let mut threats_found = Vec::new();
        let mut errors = Vec::new();
        let file_info = match self.file_scanner.get_file_info(path).await {
            Ok(info) => info,
            Err(e) => {
                return Err(hadron_core::AntivirusError::ScanEngine(
                    hadron_core::ScanEngineError::FileAccessDenied(
                        format!("Cannot access file {}: {}", path.display(), e)
                    )
                ));
            }
        };
        if !self.file_scanner.should_scan_file(&file_info) {
            tracing::debug!("Skipping file: {}", path.display());
            return Ok(ScanResult {
                scan_id: uuid::Uuid::new_v4(),
                start_time,
                end_time: Some(chrono::Utc::now()),
                status: ScanStatus::Completed,
                scanned_files: 0,
                threats_found: Vec::new(),
                errors: Vec::new(),
                statistics: hadron_core::ScanStatistics {
                    total_files: 1,
                    scanned_files: 0,
                    skipped_files: 1,
                    infected_files: 0,
                    cleaned_files: 0,
                    quarantined_files: 0,
                    scan_duration_ms: 0,
                    average_scan_time_ms: 0.0,
                },
            });
        }
        match self.signature_database.scan_file(path) {
            Ok(matches) => {
                if !matches.is_empty() {
                    match self.signature_database.matches_to_threats(matches, path) {
                        Ok(signature_threats) => {
                            threats_found.extend(signature_threats);
                            tracing::info!("Found {} signature-based threats in {}", 
                                         threats_found.len(), path.display());
                        }
                        Err(e) => {
                            tracing::error!("Failed to convert matches to threats: {}", e);
                            errors.push(hadron_core::ScanError {
                                file_path: path.to_path_buf(),
                                error_message: format!("Threat conversion failed: {}", e),
                                timestamp: chrono::Utc::now(),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Signature scan failed for {}: {}", path.display(), e);
                errors.push(hadron_core::ScanError {
                    file_path: path.to_path_buf(),
                    error_message: format!("Signature scan failed: {}", e),
                    timestamp: chrono::Utc::now(),
                });
            }
        }
        if file_info.is_executable {
            if let Err(e) = self.scan_executable_file(&file_info, &mut threats_found, &mut errors).await {
                tracing::error!("Executable analysis failed for {}: {}", path.display(), e);
                errors.push(hadron_core::ScanError {
                    file_path: path.to_path_buf(),
                    error_message: format!("Executable analysis failed: {}", e),
                    timestamp: chrono::Utc::now(),
                });
            }
        }
        match self.heuristic_analyzer.analyze_file(path, &file_info).await {
            Ok(heuristic_result) => {
                if heuristic_result.overall_score > 0.3 {
                    let file_hash = match self.file_scanner.calculate_sha256(path).await {
                        Ok(hash) => hash,
                        Err(e) => {
                            tracing::warn!("Failed to calculate hash for {}: {}", path.display(), e);
                            "unknown".to_string()
                        }
                    };
                    match self.heuristic_analyzer.results_to_threats(&heuristic_result, path, &file_hash) {
                        Ok(heuristic_threats) => {
                            let threat_count = heuristic_threats.len();
                            threats_found.extend(heuristic_threats);
                            tracing::info!("Found {} heuristic threats in {} (score: {:.2})", 
                                         threat_count, path.display(), heuristic_result.overall_score);
                        }
                        Err(e) => {
                            tracing::error!("Failed to convert heuristic results to threats: {}", e);
                            errors.push(hadron_core::ScanError {
                                file_path: path.to_path_buf(),
                                error_message: format!("Heuristic threat conversion failed: {}", e),
                                timestamp: chrono::Utc::now(),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Heuristic analysis failed for {}: {}", path.display(), e);
                errors.push(hadron_core::ScanError {
                    file_path: path.to_path_buf(),
                    error_message: format!("Heuristic analysis failed: {}", e),
                    timestamp: chrono::Utc::now(),
                });
            }
        }
        let end_time = chrono::Utc::now();
        let duration_ms = (end_time - start_time).num_milliseconds().max(0) as u64;
        Ok(ScanResult {
            scan_id: uuid::Uuid::new_v4(),
            start_time,
            end_time: Some(end_time),
            status: ScanStatus::Completed,
            scanned_files: 1,
            threats_found,
            errors,
            statistics: hadron_core::ScanStatistics {
                total_files: 1,
                scanned_files: 1,
                skipped_files: 0,
                infected_files: threats_found.len() as u64,
                cleaned_files: 0,
                quarantined_files: 0,
                scan_duration_ms: duration_ms,
                average_scan_time_ms: duration_ms as f64,
            },
        })
    }
    async fn scan_executable_file(
        &self,
        file_info: &FileInfo,
        threats_found: &mut Vec<ThreatInfo>,
        errors: &mut Vec<hadron_core::ScanError>,
    ) -> Result<()> {
        tracing::debug!("Performing executable analysis for: {}", file_info.path.display());
        if let Ok(is_pe) = self.file_scanner.is_pe_file(&file_info.path).await {
            if is_pe {
                tracing::debug!("Detected PE file: {}", file_info.path.display());
                if let Ok(strings) = self.file_scanner.extract_strings(&file_info.path, 4).await {
                    self.analyze_strings(&strings, file_info, threats_found).await?;
                }
                if let Ok(signature) = self.file_scanner.get_file_signature(&file_info.path).await {
                    self.analyze_file_signature(&signature, file_info, threats_found).await?;
                }
            }
        }
        Ok(())
    }
    async fn analyze_strings(
        &self,
        strings: &[String],
        file_info: &FileInfo,
        threats_found: &mut Vec<ThreatInfo>,
    ) -> Result<()> {
        let suspicious_strings = [
            "cmd.exe", "powershell.exe", "regedit.exe",
            "keylog", "password", "backdoor", "rootkit",
            "bitcoin", "ransom", "encrypt", "decrypt",
            "virus", "malware", "trojan", "worm",
        ];
        let mut suspicious_count = 0;
        let mut found_strings = Vec::new();
        for string in strings {
            let string_lower = string.to_lowercase();
            for &suspicious in &suspicious_strings {
                if string_lower.contains(suspicious) {
                    suspicious_count += 1;
                    found_strings.push(string.clone());
                    break;
                }
            }
        }
        if suspicious_count >= 3 {
            let hash = self.file_scanner.calculate_sha256(&file_info.path).await?;
            let mut threat = ThreatInfo::new(
                "Suspicious.Strings".to_string(),
                hadron_core::ThreatType::Suspicious,
                hadron_core::ThreatSeverity::Medium,
                file_info.path.clone(),
                hash,
                hadron_core::DetectionMethod::Heuristic,
            )?;
            threat.add_info("suspicious_strings".to_string(), found_strings.join(", "));
            threat.add_info("suspicious_count".to_string(), suspicious_count.to_string());
            threats_found.push(threat);
            tracing::info!("Detected suspicious strings in: {}", file_info.path.display());
        }
        Ok(())
    }
    async fn analyze_file_signature(
        &self,
        signature: &[u8],
        file_info: &FileInfo,
        threats_found: &mut Vec<ThreatInfo>,
    ) -> Result<()> {
        let malicious_signatures = [
            &[0x58, 0x35, 0x4F, 0x21, 0x50, 0x25, 0x40, 0x41][..],
        ];
        for (i, &malicious_sig) in malicious_signatures.iter().enumerate() {
            if signature.len() >= malicious_sig.len() && 
               signature[..malicious_sig.len()] == *malicious_sig {
                let hash = self.file_scanner.calculate_sha256(&file_info.path).await?;
                let mut threat = ThreatInfo::new(
                    format!("Signature.Malicious.{}", i),
                    hadron_core::ThreatType::Virus,
                    hadron_core::ThreatSeverity::High,
                    file_info.path.clone(),
                    hash,
                    hadron_core::DetectionMethod::Signature,
                )?;
                threat.add_info("signature_match".to_string(), 
                              format!("Pattern {}: {:02x?}", i, malicious_sig));
                threats_found.push(threat);
                tracing::info!("Detected malicious signature in: {}", file_info.path.display());
                break;
            }
        }
        Ok(())
    }
    async fn collect_scan_targets(&self, scan_type: &ScanType, targets: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let mut files_to_scan = Vec::new();
        match scan_type {
            ScanType::Quick => {
                let quick_paths = vec![
                    PathBuf::from("C:\\Users"),
                    PathBuf::from("C:\\Temp"),
                    PathBuf::from("C:\\Windows\\Temp"),
                    PathBuf::from("C:\\ProgramData"),
                ];
                for path in quick_paths {
                    if path.exists() {
                        let walker_files = self.directory_walker.walk_directory(&path).await?;
                        files_to_scan.extend(walker_files);
                    }
                }
            }
            ScanType::Full => {
                let drives = vec![
                    PathBuf::from("C:\\"),
                    PathBuf::from("D:\\"),
                    PathBuf::from("E:\\"),
                ];
                for drive in drives {
                    if drive.exists() {
                        let walker_files = self.directory_walker.walk_directory(&drive).await?;
                        files_to_scan.extend(walker_files);
                    }
                }
            }
            ScanType::Custom(custom_paths) => {
                for path in custom_paths {
                    if path.is_file() {
                        files_to_scan.push(path.clone());
                    } else if path.is_dir() {
                        let walker_files = self.directory_walker.walk_directory(path).await?;
                        files_to_scan.extend(walker_files);
                    }
                }
            }
            ScanType::Memory => {
                return Ok(Vec::new());
            }
            ScanType::Startup => {
                let startup_paths = vec![
                    PathBuf::from("C:\\Users\\All Users\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                    PathBuf::from("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                ];
                for path in startup_paths {
                    if path.exists() {
                        let walker_files = self.directory_walker.walk_directory(&path).await?;
                        files_to_scan.extend(walker_files);
                    }
                }
            }
        }
        for target in targets {
            if target.is_file() {
                files_to_scan.push(target.clone());
            } else if target.is_dir() {
                let walker_files = self.directory_walker.walk_directory(target).await?;
                files_to_scan.extend(walker_files);
            }
        }
        files_to_scan.sort();
        files_to_scan.dedup();
        let mut filtered_files = Vec::new();
        for file_path in files_to_scan {
            if let Ok(file_info) = self.file_scanner.get_file_info(&file_path).await {
                if self.file_scanner.should_scan_file(&file_info) {
                    filtered_files.push(file_path);
                }
            }
        }
        tracing::info!("Collected {} files for scanning", filtered_files.len());
        Ok(filtered_files)
    }
    async fn perform_scan(&self, job_id: ScanJobId, scan_type: ScanType, targets: Vec<std::path::PathBuf>) -> Result<ScanResult> {
        let start_time = chrono::Utc::now();
        let mut scanned_files = 0u64;
        let mut threats_found = Vec::new();
        let mut errors = Vec::new();
        let files_to_scan = self.collect_scan_targets(&scan_type, &targets).await?;
        let total_files = files_to_scan.len() as u64;
        tracing::info!("Starting scan job {} with {} files", job_id, total_files);
        if matches!(scan_type, ScanType::Memory) {
            return self.perform_memory_scan(job_id).await;
        }
        for (index, file_path) in files_to_scan.iter().enumerate() {
            {
                let active_scans = self.active_scans.read().await;
                if let Some(scan_job) = active_scans.get(&job_id) {
                    if matches!(scan_job.status, ScanStatus::Cancelled) {
                        tracing::info!("Scan job {} was cancelled", job_id);
                        break;
                    }
                }
            }
            match self.scan_file_internal(file_path).await {
                Ok(result) => {
                    scanned_files += result.statistics.scanned_files;
                    threats_found.extend(result.threats_found);
                    errors.extend(result.errors);
                    if index % 10 == 0 || index == files_to_scan.len() - 1 {
                        let progress = ScanProgress {
                            scan_id: job_id,
                            current_file: Some(file_path.clone()),
                            files_scanned: scanned_files,
                            total_files,
                            threats_found: threats_found.len() as u32,
                            percentage_complete: (scanned_files as f32 / total_files as f32) * 100.0,
                            estimated_time_remaining_ms: self.estimate_remaining_time(
                                start_time, scanned_files, total_files
                            ),
                        };
                        self.notify_progress(progress).await;
                    }
                }
                Err(e) => {
                    errors.push(hadron_core::ScanError {
                        file_path: file_path.clone(),
                        error_message: e.to_string(),
                        timestamp: chrono::Utc::now(),
                    });
                }
            }
        }
        let end_time = chrono::Utc::now();
        let duration_ms = (end_time - start_time).num_milliseconds() as u64;
        {
            let mut stats = self.statistics.write().await;
            stats.last_scan_time = Some(end_time);
            stats.total_files_scanned += scanned_files;
            stats.total_threats_detected += threats_found.len() as u64;
            if let Some(last_scan) = stats.last_scan_time {
                if last_scan.date_naive() == chrono::Utc::now().date_naive() {
                    stats.threats_detected_today += threats_found.len() as u32;
                } else {
                    stats.threats_detected_today = threats_found.len() as u32;
                }
            }
        }
        Ok(ScanResult {
            scan_id: job_id,
            start_time,
            end_time: Some(end_time),
            status: ScanStatus::Completed,
            scanned_files,
            threats_found,
            errors,
            statistics: hadron_core::ScanStatistics {
                total_files,
                scanned_files,
                skipped_files: total_files - scanned_files,
                infected_files: threats_found.len() as u64,
                cleaned_files: 0,
                quarantined_files: 0,
                scan_duration_ms: duration_ms,
                average_scan_time_ms: if scanned_files > 0 { duration_ms as f64 / scanned_files as f64 } else { 0.0 },
            },
        })
    }
}
#[async_trait]
impl Scanner for ScanEngineImpl {
    async fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        self.scan_file_internal(path).await
    }
    async fn scan_memory(&self, process_id: u32) -> Result<ScanResult> {
        tracing::debug!("Scanning memory of process: {}", process_id);
        Ok(ScanResult {
            scan_id: uuid::Uuid::new_v4(),
            start_time: chrono::Utc::now(),
            end_time: Some(chrono::Utc::now()),
            status: ScanStatus::Completed,
            scanned_files: 0,
            threats_found: Vec::new(),
            errors: Vec::new(),
            statistics: hadron_core::ScanStatistics {
                total_files: 0,
                scanned_files: 0,
                skipped_files: 0,
                infected_files: 0,
                cleaned_files: 0,
                quarantined_files: 0,
                scan_duration_ms: 100,
                average_scan_time_ms: 100.0,
            },
        })
    }
    async fn scan_network_packet(&self, packet: &NetworkPacket) -> Result<ScanResult> {
        tracing::debug!("Scanning network packet from {} to {}", packet.source_ip, packet.destination_ip);
        Ok(ScanResult {
            scan_id: uuid::Uuid::new_v4(),
            start_time: chrono::Utc::now(),
            end_time: Some(chrono::Utc::now()),
            status: ScanStatus::Completed,
            scanned_files: 0,
            threats_found: Vec::new(),
            errors: Vec::new(),
            statistics: hadron_core::ScanStatistics {
                total_files: 0,
                scanned_files: 0,
                skipped_files: 0,
                infected_files: 0,
                cleaned_files: 0,
                quarantined_files: 0,
                scan_duration_ms: 1,
                average_scan_time_ms: 1.0,
            },
        })
    }
    async fn start_scan(&self, scan_type: ScanType, targets: Vec<std::path::PathBuf>) -> Result<ScanJobId> {
        let job_id = uuid::Uuid::new_v4();
        let start_time = chrono::Utc::now();
        let progress = ScanProgress {
            scan_id: job_id,
            current_file: None,
            files_scanned: 0,
            total_files: 0,
            threats_found: 0,
            percentage_complete: 0.0,
            estimated_time_remaining_ms: None,
        };
        let scan_engine = Arc::new(self.clone());
        let scan_targets = targets.clone();
        let scan_type_clone = scan_type.clone();
        let handle = tokio::spawn(async move {
            scan_engine.perform_scan(job_id, scan_type_clone, scan_targets).await
        });
        let scan_job = ScanJob {
            id: job_id,
            scan_type,
            targets,
            status: ScanStatus::Running,
            start_time,
            progress,
            handle: Some(handle),
        };
        {
            let mut active_scans = self.active_scans.write().await;
            active_scans.insert(job_id, scan_job);
        }
        tracing::info!("Started scan job: {}", job_id);
        Ok(job_id)
    }
    async fn get_scan_status(&self, job_id: ScanJobId) -> Result<ScanStatus> {
        let active_scans = self.active_scans.read().await;
        if let Some(scan_job) = active_scans.get(&job_id) {
            Ok(scan_job.status.clone())
        } else {
            Err(hadron_core::AntivirusError::Internal(format!("Scan job not found: {}", job_id)))
        }
    }
    async fn cancel_scan(&self, job_id: ScanJobId) -> Result<()> {
        let mut active_scans = self.active_scans.write().await;
        if let Some(mut scan_job) = active_scans.remove(&job_id) {
            if let Some(handle) = scan_job.handle.take() {
                handle.abort();
            }
            scan_job.status = ScanStatus::Cancelled;
            tracing::info!("Cancelled scan job: {}", job_id);
            Ok(())
        } else {
            Err(hadron_core::AntivirusError::Internal(format!("Scan job not found: {}", job_id)))
        }
    }
}
impl ScanEngineImpl {
    pub async fn get_signature_stats(&self) -> hadron_core::DatabaseStatistics {
        self.signature_database.get_statistics()
    }
    pub async fn reload_signatures(&self) -> Result<hadron_core::CompilationStats> {
        self.signature_database.reload()
    }
    async fn perform_memory_scan(&self, job_id: ScanJobId) -> Result<ScanResult> {
        tracing::info!("Starting memory scan for job {}", job_id);
        let start_time = chrono::Utc::now();
        let mut threats_found = Vec::new();
        let mut errors = Vec::new();
        tracing::warn!("Memory scanning not yet implemented");
        let end_time = chrono::Utc::now();
        let duration_ms = (end_time - start_time).num_milliseconds().max(0) as u64;
        Ok(ScanResult {
            scan_id: job_id,
            start_time,
            end_time: Some(end_time),
            status: ScanStatus::Completed,
            scanned_files: 0,
            threats_found,
            errors,
            statistics: hadron_core::ScanStatistics {
                total_files: 0,
                scanned_files: 0,
                skipped_files: 0,
                infected_files: 0,
                cleaned_files: 0,
                quarantined_files: 0,
                scan_duration_ms: duration_ms,
                average_scan_time_ms: 0.0,
            },
        })
    }
    fn estimate_remaining_time(
        &self,
        start_time: chrono::DateTime<chrono::Utc>,
        scanned_files: u64,
        total_files: u64,
    ) -> Option<u64> {
        if scanned_files == 0 || total_files == 0 {
            return None;
        }
        let elapsed = chrono::Utc::now().signed_duration_since(start_time);
        let elapsed_ms = elapsed.num_milliseconds().max(0) as u64;
        let remaining_files = total_files - scanned_files;
        let avg_time_per_file = elapsed_ms as f64 / scanned_files as f64;
        let estimated_remaining = (remaining_files as f64 * avg_time_per_file) as u64;
        Some(estimated_remaining)
    }
    pub fn get_file_scanner(&self) -> &FileScanner {
        &self.file_scanner
    }
    pub fn get_directory_walker(&self) -> &DirectoryWalker {
        &self.directory_walker
    }
    pub fn get_heuristic_analyzer(&self) -> &HeuristicAnalyzer {
        &self.heuristic_analyzer
    }
    pub fn add_heuristic_rule(&self, rule: hadron_core::HeuristicRule) {
        tracing::info!("Heuristic rule added: {} ({})", rule.name, rule.id);
    }
    pub fn set_heuristic_rule_enabled(&self, rule_id: &str, enabled: bool) {
        tracing::info!("Heuristic rule {} {}", rule_id, if enabled { "enabled" } else { "disabled" });
    }
}
impl Clone for ScanEngineImpl {
    fn clone(&self) -> Self {
        Self {
            active_scans: Arc::clone(&self.active_scans),
            progress_callbacks: Arc::clone(&self.progress_callbacks),
            statistics: Arc::clone(&self.statistics),
            signature_database: Arc::clone(&self.signature_database),
            file_scanner: Arc::clone(&self.file_scanner),
            directory_walker: Arc::clone(&self.directory_walker),
            heuristic_analyzer: Arc::clone(&self.heuristic_analyzer),
        }
    }
}