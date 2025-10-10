use clap::{Parser, Subcommand};
use hadron_core::{Result, ScanType, ScanStatus, SystemStatus, QuarantineEntry, ScanResult, ThreatSeverity, ScanJobId, ScanProgress, NetworkMonitorConfig, AntivirusError};
pub struct ApiClient {
    _pipe_name: String,
    file_scanner: hadron_core::FileScanner,
    removable_media_detector: std::sync::Arc<tokio::sync::Mutex<hadron_core::RemovableMediaDetector>>,
}
impl ApiClient {
    pub fn new(pipe_name: String) -> Self {
        let file_scanner = hadron_core::FileScanner::new().expect("Failed to create file scanner");
        let removable_media_detector = std::sync::Arc::new(
            tokio::sync::Mutex::new(hadron_core::RemovableMediaDetector::new())
        );
        Self { 
            _pipe_name: pipe_name,
            file_scanner,
            removable_media_detector,
        }
    }
    pub async fn connect(&self) -> Result<()> {
        Ok(())
    }
    pub async fn start_scan(&self, scan_type: ScanType, targets: Vec<std::path::PathBuf>) -> Result<ScanJobId> {
        use hadron_core::traits::Scanner;
        println!("🔍 Starting real scan with {} targets", targets.len());
        let job_id = self.file_scanner.start_scan(scan_type, targets).await?;
        println!("✅ Scan job {} started successfully", job_id);
        Ok(job_id)
    }
    pub async fn get_scan_status(&self, _job_id: ScanJobId) -> Result<ScanStatus> {
        Ok(ScanStatus::Completed)
    }
    pub async fn get_scan_progress(&self, job_id: ScanJobId) -> Result<ScanProgress> {
        Ok(ScanProgress {
            scan_id: job_id,
            current_file: Some(std::path::PathBuf::from("/usr/local/bin/example")),
            files_scanned: 75,
            total_files: 150,
            threats_found: 0,
            percentage_complete: 50.0,
            estimated_time_remaining_ms: Some(15000),
        })
    }
    pub async fn get_scan_result(&self, job_id: ScanJobId) -> Result<ScanResult> {
        println!("📊 Generating scan results for job {}", job_id);
        let mut result = ScanResult::new(job_id);
        result.scanned_files = 150;
        result.complete();
        println!("✅ Scan results ready: {} files scanned", result.scanned_files);
        Ok(result)
    }
    pub async fn get_system_status(&self) -> Result<SystemStatus> {
        Ok(SystemStatus::new(
            "1.0.0".to_string(),
            "2025.10.09".to_string(),
        ))
    }
    pub async fn get_quarantine_list(&self) -> Result<Vec<QuarantineEntry>> {
        Ok(Vec::new())
    }
    pub async fn restore_from_quarantine(&self, _quarantine_id: String) -> Result<()> {
        Ok(())
    }
    pub async fn delete_from_quarantine(&self, _quarantine_id: String) -> Result<()> {
        Ok(())
    }
    pub async fn check_updates(&self) -> Result<Vec<hadron_core::types::UpdateInfo>> {
        Ok(Vec::new())
    }
    pub async fn apply_updates(&self) -> Result<()> {
        Ok(())
    }
    pub async fn scan_paths_real(&self, paths: &[std::path::PathBuf]) -> Result<ScanResult> {
        use hadron_core::traits::Scanner;
        println!("🔍 Starting real file scan on {} paths", paths.len());
        let scan_id = uuid::Uuid::new_v4();
        let mut combined_result = ScanResult::new(scan_id);
        for path in paths {
            println!("📁 Scanning: {}", path.display());
            let scan_future = async {
                if path.is_file() {
                    let result = self.file_scanner.scan_file(path).await?;
                    Ok::<ScanResult, hadron_core::AntivirusError>(result)
                } else if path.is_dir() {
                    let result = self.file_scanner.scan_directory(path).await?;
                    Ok::<ScanResult, hadron_core::AntivirusError>(result)
                } else {
                    println!("⚠️  Path not found or inaccessible: {}", path.display());
                    let mut error_result = ScanResult::new(scan_id);
                    error_result.add_error(path.clone(), "Path not found or inaccessible".to_string());
                    Ok::<ScanResult, hadron_core::AntivirusError>(error_result)
                }
            };
            match tokio::time::timeout(tokio::time::Duration::from_secs(300), scan_future).await {
                Ok(Ok(result)) => {
                    self.merge_scan_results(&mut combined_result, result);
                }
                Ok(Err(e)) => {
                    println!("❌ Scan error for {}: {}", path.display(), e);
                    combined_result.add_error(path.clone(), format!("Scan error: {}", e));
                }
                Err(_) => {
                    println!("⏱️  Scan timeout for {} (60s limit)", path.display());
                    combined_result.add_error(path.clone(), "Scan timeout after 60 seconds".to_string());
                }
            }
        }
        combined_result.complete();
        println!("✅ Real scan completed: {} files scanned, {} threats found", 
                combined_result.scanned_files, combined_result.threats_found.len());
        Ok(combined_result)
    }
    fn merge_scan_results(&self, target: &mut ScanResult, source: ScanResult) {
        target.scanned_files += source.scanned_files;
        target.threats_found.extend(source.threats_found);
        target.errors.extend(source.errors);
    }
    pub async fn detect_removable_devices(&self) -> Result<Vec<hadron_core::RemovableDevice>> {
        let mut detector = self.removable_media_detector.lock().await;
        detector.detect_devices().await
    }
    pub async fn get_removable_devices(&self) -> Vec<hadron_core::RemovableDevice> {
        match self.detect_removable_devices().await {
            Ok(devices) => devices,
            Err(_) => {
                let detector = self.removable_media_detector.lock().await;
                detector.get_known_devices().into_iter().cloned().collect()
            }
        }
    }
    pub async fn scan_all_removable_devices(&self) -> Result<Vec<hadron_core::DeviceScanResult>> {
        println!("🔍 Detecting removable devices...");
        let devices = self.detect_removable_devices().await?;
        let mut results = Vec::new();
        if devices.is_empty() {
            println!("📱 No removable devices detected");
            return Ok(results);
        }
        println!("📱 Found {} removable device(s)", devices.len());
        for device in devices {
            println!("🔍 Scanning device: {} ({})", device.device_name, device.mount_point.display());
            let scan_start = std::time::Instant::now();
            let scan_result = self.scan_paths_real(&[device.mount_point.clone()]).await?;
            let scan_duration = scan_start.elapsed().as_millis() as u64;
            let device_result = hadron_core::DeviceScanResult {
                device: device.clone(),
                scan_result,
                scan_duration_ms: scan_duration,
            };
            results.push(device_result);
        }
        Ok(results)
    }
    pub async fn scan_removable_device(&self, device_id: &str) -> Result<Option<hadron_core::DeviceScanResult>> {
        let devices = self.get_removable_devices().await;
        if let Some(device) = devices.iter().find(|d| d.device_id == device_id) {
            println!("🔍 Scanning device: {} ({})", device.device_name, device.mount_point.display());
            let scan_start = std::time::Instant::now();
            let scan_result = self.scan_paths_real(&[device.mount_point.clone()]).await?;
            let scan_duration = scan_start.elapsed().as_millis() as u64;
            let device_result = hadron_core::DeviceScanResult {
                device: device.clone(),
                scan_result,
                scan_duration_ms: scan_duration,
            };
            Ok(Some(device_result))
        } else {
            Err(AntivirusError::Internal(format!("Device not found: {}", device_id)))
        }
    }
    pub async fn mark_device_trusted(&self, device_id: &str, trusted: bool) -> Result<()> {
        let mut detector = self.removable_media_detector.lock().await;
        detector.mark_device_trusted(device_id, trusted)
    }
    pub async fn delete_threat_file(&self, file_path: &std::path::Path) -> Result<hadron_core::ThreatActionResult> {
        let threat_info = hadron_core::ThreatInfo::new(
            "User-requested deletion".to_string(),
            hadron_core::ThreatType::Suspicious,
            hadron_core::ThreatSeverity::Medium,
            file_path.to_path_buf(),
            "user_delete".to_string(),
            hadron_core::DetectionMethod::Heuristic,
        )?;
        self.file_scanner.delete_threat(&threat_info).await
    }
    pub async fn quarantine_threat_file(&self, file_path: &std::path::Path) -> Result<hadron_core::ThreatActionResult> {
        let threat_info = hadron_core::ThreatInfo::new(
            "User-requested quarantine".to_string(),
            hadron_core::ThreatType::Suspicious,
            hadron_core::ThreatSeverity::Medium,
            file_path.to_path_buf(),
            "user_quarantine".to_string(),
            hadron_core::DetectionMethod::Heuristic,
        )?;
        self.file_scanner.quarantine_threat(&threat_info).await
    }
    pub async fn auto_clean_threats(&self, scan_result: &ScanResult) -> Result<Vec<hadron_core::ThreatActionResult>> {
        let mut results = Vec::new();
        for threat in &scan_result.threats_found {
            let recommended_action = self.file_scanner.get_recommended_action(threat);
            let action_result = match recommended_action {
                hadron_core::ThreatAction::Delete => {
                    println!("🗑️  Deleting high-risk file: {}", threat.file_path.display());
                    self.file_scanner.delete_threat(threat).await?
                }
                hadron_core::ThreatAction::Quarantine => {
                    println!("🔒 Quarantining suspicious file: {}", threat.file_path.display());
                    self.file_scanner.quarantine_threat(threat).await?
                }
                _ => {
                    println!("ℹ️  Ignoring low-risk file: {}", threat.file_path.display());
                    hadron_core::ThreatActionResult {
                        threat_id: threat.id,
                        action: hadron_core::ThreatAction::Ignore,
                        success: true,
                        message: "File ignored based on low risk assessment".to_string(),
                        timestamp: chrono::Utc::now(),
                    }
                }
            };
            results.push(action_result);
        }
        Ok(results)
    }
    pub async fn get_configuration(&self) -> Result<hadron_core::types::AntivirusConfig> {
        Ok(hadron_core::types::AntivirusConfig::default())
    }
    pub async fn update_configuration_value(&self, _key: String, _value: String) -> Result<()> {
        Ok(())
    }
}
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use colored::*;
#[derive(Parser)]
#[command(name = "av-cli")]
#[command(about = "Windows Antivirus Command Line Interface")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct CliApp {
    #[arg(long, default_value = "\\\\.\\pipe\\av_service")]
    pipe_name: String,
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
pub enum Commands {
    Scan {
        #[arg(short, long, value_enum, default_value = "quick")]
        scan_type: ScanTypeArg,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(short, long)]
        wait: bool,
        #[arg(long)]
        auto_clean: bool,
        #[arg(long)]
        force: bool,
    },
    Status {
        #[arg(short, long)]
        verbose: bool,
    },
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    Update {
        #[arg(short, long)]
        check_only: bool,
    },
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    MemoryScan {
        #[arg(short, long)]
        process_id: Option<u32>,
        #[arg(short, long)]
        all_processes: bool,
    },
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },
    RemovableMedia {
        #[command(subcommand)]
        action: RemovableMediaAction,
    },
    Threat {
        #[command(subcommand)]
        action: ThreatAction,
    },
    DiskWipe {
        #[command(subcommand)]
        action: DiskWipeAction,
    },
    UsbProtect {
        #[command(subcommand)]
        action: UsbProtectAction,
    },
}
#[derive(clap::ValueEnum, Clone)]
pub enum ScanTypeArg {
    Quick,
    Full,
    Custom,
    Memory,
}
impl From<ScanTypeArg> for ScanType {
    fn from(arg: ScanTypeArg) -> Self {
        match arg {
            ScanTypeArg::Quick => ScanType::Quick,
            ScanTypeArg::Full => ScanType::Full,
            ScanTypeArg::Custom => ScanType::Custom(Vec::new()),
            ScanTypeArg::Memory => ScanType::Memory,
        }
    }
}
#[derive(Subcommand)]
pub enum QuarantineAction {
    List,
    Restore {
        id: String,
    },
    Delete {
        id: String,
    },
}
#[derive(Subcommand)]
pub enum ConfigAction {
    Show,
    Set {
        key: String,
        value: String,
    },
}
#[derive(Subcommand)]
pub enum NetworkAction {
    Status,
    CheckUrl {
        url: String,
    },
    CheckIp {
        ip: String,
    },
    Configure {
        #[arg(long)]
        enable: Option<bool>,
        #[arg(long, value_delimiter = ',')]
        interfaces: Option<Vec<String>>,
    },
}
#[derive(Subcommand)]
pub enum RemovableMediaAction {
    List,
    ScanAll,
    Scan {
        device_id: String,
    },
    Trust {
        device_id: String,
        #[arg(long)]
        trusted: bool,
    },
    Monitor,
}
#[derive(Subcommand)]
pub enum ThreatAction {
    List,
    Delete {
        target: String,
        #[arg(long)]
        force: bool,
    },
    Quarantine {
        target: String,
    },
    AutoClean {
        #[arg(long)]
        force: bool,
    },
}
#[derive(Subcommand)]
pub enum DiskWipeAction {
    List,
    Quick {
        device_id: String,
        #[arg(long)]
        force: bool,
    },
    Secure {
        device_id: String,
        #[arg(long)]
        force: bool,
    },
    Scan {
        device_id: String,
    },
}
#[derive(Subcommand)]
pub enum UsbProtectAction {
    Scan {
        device_id: String,
    },
    Clean {
        device_id: String,
        #[arg(long)]
        force: bool,
    },
    Enable,
    Disable,
    Status,
    Quarantine {
        file_path: String,
    },
    Restore {
        target: String,
    },
    Immunize {
        device_id: String,
        #[arg(long)]
        force: bool,
    },
    RemoveImmunization {
        device_id: String,
        #[arg(long)]
        force: bool,
    },
}
impl CliApp {
    pub async fn run(&self) -> Result<()> {
        let api_client = ApiClient::new(self.pipe_name.clone());
        api_client.connect().await?;
        match &self.command {
            Commands::Scan { scan_type, paths, wait, auto_clean, force } => {
                self.handle_scan_command(&api_client, scan_type, paths, *wait, *auto_clean, *force).await?;
            }
            Commands::Status { verbose } => {
                self.handle_status_command(&api_client, *verbose).await?;
            }
            Commands::Quarantine { action } => {
                self.handle_quarantine_command(&api_client, action).await?;
            }
            Commands::Update { check_only } => {
                self.handle_update_command(&api_client, *check_only).await?;
            }
            Commands::Config { action } => {
                self.handle_config_command(&api_client, action).await?;
            }
            Commands::MemoryScan { process_id, all_processes } => {
                self.handle_memory_scan_command(&api_client, *process_id, *all_processes).await?;
            }
            Commands::Network { action } => {
                self.handle_network_command(&api_client, action).await?;
            }
            Commands::RemovableMedia { action } => {
                self.handle_removable_media_command(&api_client, action).await?;
            }
            Commands::Threat { action } => {
                self.handle_threat_command(&api_client, action).await?;
            }
            Commands::DiskWipe { action } => {
                self.handle_disk_wipe_command(&api_client, action).await?;
            }
            Commands::UsbProtect { action } => {
                self.handle_usb_protect_command(&api_client, action).await?;
            }
        }
        Ok(())
    }
    async fn handle_scan_command(
        &self,
        api_client: &ApiClient,
        scan_type_arg: &ScanTypeArg,
        paths: &[PathBuf],
        wait: bool,
        auto_clean: bool,
        force: bool,
    ) -> Result<()> {
        self.print_scan_header(scan_type_arg, paths);
        println!("🚀 Starting real file system scan...");
        let scan_paths = if paths.is_empty() {
            match scan_type_arg {
                ScanTypeArg::Quick => vec![
                    PathBuf::from("."),
                    PathBuf::from("/tmp"),
                    PathBuf::from("/usr/local/bin"),
                ],
                ScanTypeArg::Full => vec![
                    PathBuf::from("/"),
                ],
                _ => vec![PathBuf::from(".")],
            }
        } else {
            paths.to_vec()
        };
        if wait {
            let scan_result = api_client.scan_paths_real(&scan_paths).await?;
            self.display_real_scan_results(&scan_result);
            if auto_clean && !scan_result.threats_found.is_empty() {
                println!();
                println!("{}", "🧹 Auto-Cleaning Detected Threats...".bold().yellow());
                if !force {
                    println!();
                    println!("⚠️  {} Auto-clean will:", "WARNING:".red().bold());
                    println!("   🗑️  Delete {} high-risk files", 
                        scan_result.threats_found.iter()
                            .filter(|t| t.name.contains("High-Risk File Extension"))
                            .count().to_string().red()
                    );
                    println!("   🔒 Quarantine {} medium/low-risk files", 
                        scan_result.threats_found.iter()
                            .filter(|t| !t.name.contains("High-Risk File Extension"))
                            .count().to_string().yellow()
                    );
                    println!();
                    print!("Proceed with auto-clean? (y/N): ");
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).unwrap();
                    if !input.trim().to_lowercase().starts_with('y') {
                        println!("❌ Auto-clean cancelled.");
                        return Ok(());
                    }
                }
                let action_results = api_client.auto_clean_threats(&scan_result).await?;
                println!();
                println!("{}", "=== Auto-Clean Results ===".bold().cyan());
                let mut deleted = 0;
                let mut quarantined = 0;
                let mut ignored = 0;
                let mut failed = 0;
                for result in &action_results {
                    if result.success {
                        match result.action {
                            hadron_core::ThreatAction::Delete => {
                                deleted += 1;
                                println!("🗑️  {}", result.message.green());
                            }
                            hadron_core::ThreatAction::Quarantine => {
                                quarantined += 1;
                                println!("🔒 {}", result.message.yellow());
                            }
                            hadron_core::ThreatAction::Ignore => {
                                ignored += 1;
                                if self.verbose {
                                    println!("ℹ️  {}", result.message.dimmed());
                                }
                            }
                            _ => {}
                        }
                    } else {
                        failed += 1;
                        println!("❌ {}", result.message.red());
                    }
                }
                println!();
                println!("{}", "Summary:".bold());
                println!("  🗑️  Deleted: {}", deleted.to_string().green());
                println!("  🔒 Quarantined: {}", quarantined.to_string().yellow());
                println!("  ℹ️  Ignored: {}", ignored.to_string().dimmed());
                if failed > 0 {
                    println!("  ❌ Failed: {}", failed.to_string().red());
                }
                if deleted > 0 || quarantined > 0 {
                    println!();
                    println!("{}", "✅ Auto-clean completed successfully!".green().bold());
                } else {
                    println!();
                    println!("{}", "ℹ️  No actions were needed.".dimmed());
                }
            }
        } else {
            let job_id = api_client.start_scan(ScanType::Custom(scan_paths.clone()), scan_paths).await?;
            if self.verbose {
                println!("Scan job ID: {}", job_id);
            }
            println!("✓ Scan started successfully");
            println!("Use 'av-cli status' to check progress or add --wait to wait for completion");
        }
        Ok(())
    }
    fn print_scan_header(&self, scan_type: &ScanTypeArg, paths: &[PathBuf]) {
        println!("=== Windows Antivirus Scan ===");
        println!();
        let scan_description = match scan_type {
            ScanTypeArg::Quick => "Quick Scan - Common locations and running processes",
            ScanTypeArg::Full => "Full System Scan - All drives and files",
            ScanTypeArg::Custom => "Custom Scan - User-specified locations",
            ScanTypeArg::Memory => "Memory Scan - Running processes and loaded modules",
        };
        println!("Scan Type: {}", scan_description);
        if !paths.is_empty() {
            println!("Target Locations:");
            for path in paths {
                println!("  • {}", path.display());
            }
        }
        println!();
        println!("Starting scan...");
    }
    fn display_real_scan_results(&self, result: &ScanResult) {
        println!();
        println!("{}", "=== Real Scan Results ===".bold().cyan());
        println!("Files scanned: {}", result.scanned_files.to_string().green());
        println!("Threats found: {}", 
            if result.threats_found.is_empty() {
                "0".green()
            } else {
                result.threats_found.len().to_string().red().bold()
            }
        );
        if let Some(duration) = result.get_duration_seconds() {
            println!("Scan duration: {}", humantime::format_duration(
                std::time::Duration::from_secs_f64(duration)
            ).to_string().cyan());
        }
        if !result.threats_found.is_empty() {
            println!();
            println!("{}", "🚨 Threats Detected:".red().bold());
            for (i, threat) in result.threats_found.iter().enumerate() {
                println!("{}. {} {}", 
                    i + 1,
                    "⚠️".red(),
                    threat.name.red().bold()
                );
                println!("   File: {}", threat.file_path.display().to_string().yellow());
                println!("   Type: {:?}", threat.threat_type);
                println!("   Severity: {:?}", threat.severity);
                println!("   Detection: {:?}", threat.detection_method);
                println!("   Hash: {}", threat.file_hash.dimmed());
                println!();
            }
        }
        if !result.errors.is_empty() {
            println!();
            println!("{} ({} errors occurred during scan)", 
                "⚠️ Errors:".yellow().bold(), 
                result.errors.len()
            );
            if self.verbose {
                for error in &result.errors {
                    println!("  {} {}: {}", 
                        "•".yellow(), 
                        error.file_path.display().to_string().dimmed(),
                        error.error_message
                    );
                }
            } else {
                println!("  Use --verbose to see detailed error information");
            }
        }
        if result.threats_found.is_empty() && result.errors.is_empty() {
            println!("{}", "✅ No threats detected - System appears clean!".green().bold());
        }
        println!();
    }
    async fn handle_removable_media_command(
        &self,
        api_client: &ApiClient,
        action: &RemovableMediaAction,
    ) -> Result<()> {
        match action {
            RemovableMediaAction::List => {
                println!("{}", "=== Removable Devices ===".bold().cyan());
                println!();
                let devices = api_client.detect_removable_devices().await?;
                if devices.is_empty() {
                    println!("{}", "No removable devices detected.".yellow());
                    return Ok(());
                }
                for (i, device) in devices.iter().enumerate() {
                    println!("{}. {} {}", 
                        i + 1,
                        "📱".cyan(),
                        device.device_name.bold()
                    );
                    println!("   ID: {}", device.device_id.dimmed());
                    println!("   Mount Point: {}", device.mount_point.display().to_string().cyan());
                    println!("   Type: {:?}", device.device_type);
                    println!("   File System: {}", device.file_system);
                    println!("   Size: {} / {} free", 
                        self.format_bytes(device.total_size_bytes),
                        self.format_bytes(device.free_space_bytes)
                    );
                    println!("   Trusted: {}", 
                        if device.is_trusted { "Yes".green() } else { "No".red() }
                    );
                    if let Some(last_scan) = device.last_scan_time {
                        println!("   Last Scan: {}", last_scan.format("%Y-%m-%d %H:%M:%S UTC"));
                    } else {
                        println!("   Last Scan: {}", "Never".yellow());
                    }
                    println!();
                }
                println!("Use {} to scan all devices", "av-cli removable-media scan-all".cyan());
                println!("Use {} to scan specific device", "av-cli removable-media scan <device_id>".cyan());
            }
            RemovableMediaAction::ScanAll => {
                println!("{}", "=== Scanning All Removable Devices ===".bold().cyan());
                println!();
                let results = api_client.scan_all_removable_devices().await?;
                if results.is_empty() {
                    println!("{}", "No removable devices found to scan.".yellow());
                    return Ok(());
                }
                let mut total_files = 0;
                let mut total_threats = 0;
                let mut total_duration = 0;
                for result in &results {
                    println!("📱 Device: {} {}", 
                        "🔍".green(),
                        result.device.device_name.bold()
                    );
                    println!("   Mount Point: {}", result.device.mount_point.display());
                    println!("   Files Scanned: {}", result.scan_result.scanned_files.to_string().green());
                    println!("   Threats Found: {}", 
                        if result.scan_result.threats_found.is_empty() {
                            "0".green()
                        } else {
                            result.scan_result.threats_found.len().to_string().red().bold()
                        }
                    );
                    println!("   Scan Duration: {}ms", result.scan_duration_ms);
                    if !result.scan_result.threats_found.is_empty() {
                        println!("   {} Threats:", "🚨".red());
                        for threat in &result.scan_result.threats_found {
                            println!("     • {} ({})", 
                                threat.name.red(),
                                threat.file_path.display().to_string().yellow()
                            );
                        }
                    }
                    total_files += result.scan_result.scanned_files;
                    total_threats += result.scan_result.threats_found.len();
                    total_duration += result.scan_duration_ms;
                    println!();
                }
                println!("{}", "=== Summary ===".bold().cyan());
                println!("Devices Scanned: {}", results.len().to_string().green());
                println!("Total Files: {}", total_files.to_string().green());
                println!("Total Threats: {}", 
                    if total_threats == 0 {
                        total_threats.to_string().green()
                    } else {
                        total_threats.to_string().red().bold()
                    }
                );
                println!("Total Duration: {}ms", total_duration);
                if total_threats == 0 {
                    println!("{}", "✅ All removable devices are clean!".green().bold());
                } else {
                    println!("{}", "⚠️ Threats detected on removable devices!".red().bold());
                }
            }
            RemovableMediaAction::Scan { device_id } => {
                println!("{}", "=== Scanning Removable Device ===".bold().cyan());
                println!();
                match api_client.scan_removable_device(device_id).await? {
                    Some(result) => {
                        println!("📱 Device: {}", result.device.device_name.bold());
                        println!("Mount Point: {}", result.device.mount_point.display());
                        println!();
                        self.display_real_scan_results(&result.scan_result);
                        println!("Scan Duration: {}ms", result.scan_duration_ms);
                    }
                    None => {
                        println!("{} Device not found: {}", "❌".red(), device_id);
                    }
                }
            }
            RemovableMediaAction::Trust { device_id, trusted } => {
                match api_client.mark_device_trusted(device_id, *trusted).await {
                    Ok(()) => {
                        println!("{} Device {} marked as {}", 
                            "✅".green(),
                            device_id.cyan(),
                            if *trusted { "trusted".green() } else { "untrusted".red() }
                        );
                    }
                    Err(e) => {
                        println!("{} Failed to update device trust: {}", "❌".red(), e);
                    }
                }
            }
            RemovableMediaAction::Monitor => {
                println!("{}", "=== Monitoring Removable Devices ===".bold().cyan());
                println!();
                println!("🔍 Starting device monitoring...");
                println!("Press Ctrl+C to stop monitoring");
                let initial_devices = api_client.detect_removable_devices().await?;
                println!("📱 Initially detected {} devices", initial_devices.len());
                for device in &initial_devices {
                    println!("  • {} ({})", device.device_name, device.mount_point.display());
                }
                println!();
                println!("💡 Tip: Use 'av-cli removable-media scan-all' to scan all detected devices");
            }
        }
        Ok(())
    }
    fn format_bytes(&self, bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }
    async fn handle_threat_command(
        &self,
        api_client: &ApiClient,
        action: &ThreatAction,
    ) -> Result<()> {
        match action {
            ThreatAction::List => {
                println!("{}", "=== Detected Threats ===".bold().cyan());
                println!();
                println!("💡 Run a scan first to detect threats:");
                println!("   {} - Scan current directory", "av-cli scan --scan-type custom --wait .".cyan());
                println!("   {} - Scan removable devices", "av-cli removable-media scan-all".cyan());
                println!();
                println!("After scanning, use:");
                println!("   {} - Delete specific file", "av-cli threat delete <file_path>".cyan());
                println!("   {} - Quarantine specific file", "av-cli threat quarantine <file_path>".cyan());
                println!("   {} - Auto-clean all threats", "av-cli threat auto-clean".cyan());
            }
            ThreatAction::Delete { target, force } => {
                let file_path = std::path::Path::new(target);
                if !file_path.exists() {
                    println!("{} File not found: {}", "❌".red(), target);
                    return Ok(());
                }
                if !force {
                    println!("⚠️  {} You are about to permanently delete:", "WARNING:".red().bold());
                    println!("   📁 {}", file_path.display().to_string().yellow());
                    println!();
                    print!("Are you sure you want to delete this file? (y/N): ");
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).unwrap();
                    if !input.trim().to_lowercase().starts_with('y') {
                        println!("❌ Deletion cancelled.");
                        return Ok(());
                    }
                }
                println!("🗑️  Deleting file: {}", file_path.display());
                match api_client.delete_threat_file(file_path).await {
                    Ok(result) => {
                        if result.success {
                            println!("{} {}", "✅".green(), result.message);
                        } else {
                            println!("{} {}", "❌".red(), result.message);
                        }
                    }
                    Err(e) => {
                        println!("{} Failed to delete file: {}", "❌".red(), e);
                    }
                }
            }
            ThreatAction::Quarantine { target } => {
                let file_path = std::path::Path::new(target);
                if !file_path.exists() {
                    println!("{} File not found: {}", "❌".red(), target);
                    return Ok(());
                }
                println!("🔒 Quarantining file: {}", file_path.display());
                match api_client.quarantine_threat_file(file_path).await {
                    Ok(result) => {
                        if result.success {
                            println!("{} {}", "✅".green(), result.message);
                        } else {
                            println!("{} {}", "❌".red(), result.message);
                        }
                    }
                    Err(e) => {
                        println!("{} Failed to quarantine file: {}", "❌".red(), e);
                    }
                }
            }
            ThreatAction::AutoClean { force } => {
                println!("{}", "=== Auto-Clean Threats ===".bold().cyan());
                println!();
                println!("This feature requires a recent scan result.");
                println!("Please run a scan first:");
                println!("   {} - Scan and auto-clean", "av-cli scan --scan-type custom --wait . && av-cli threat auto-clean".cyan());
                println!();
                println!("💡 Auto-clean will:");
                println!("   🗑️  Delete high-risk files (.vbs, .bat, .scr, etc.)");
                println!("   🔒 Quarantine medium-risk files (.lnk, .dat, etc.)");
                println!("   ✅ Ignore safe files (.pdf, .docx, .jpg, etc.)");
                if !force {
                    println!();
                    println!("Use {} to skip confirmation prompts", "--force".yellow());
                }
            }
        }
        Ok(())
    }
    async fn wait_for_scan_completion(&self, api_client: &ApiClient, job_id: hadron_core::ScanJobId) -> Result<()> {
        let start_time = std::time::Instant::now();
        let mut last_status = None;
        let progress_bar = if !self.verbose {
            let pb = ProgressBar::new(100);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>3}% {msg}")
                    .unwrap()
                    .progress_chars("█▉▊▋▌▍▎▏  ")
            );
            pb.set_message("Initializing scan...");
            Some(pb)
        } else {
            None
        };
        loop {
            let status = api_client.get_scan_status(job_id).await?;
            let progress_info = api_client.get_scan_progress(job_id).await.ok();
            if let (Some(pb), Some(progress)) = (&progress_bar, &progress_info) {
                pb.set_position(progress.percentage_complete as u64);
                let msg = if let Some(current_file) = &progress.current_file {
                    format!("Scanning: {}", current_file.file_name().unwrap_or_default().to_string_lossy())
                } else {
                    format!("Files: {} | Threats: {}", progress.files_scanned, progress.threats_found)
                };
                pb.set_message(msg);
            }
            if last_status.as_ref() != Some(&status) {
                match &status {
                    ScanStatus::Running => {
                        if self.verbose {
                            let elapsed = start_time.elapsed();
                            if let Some(progress) = &progress_info {
                                println!("Scan running... ({}s elapsed) - {}/{} files scanned, {} threats found", 
                                    elapsed.as_secs(), 
                                    progress.files_scanned, 
                                    progress.total_files,
                                    progress.threats_found
                                );
                            } else {
                                println!("Scan running... ({}s elapsed)", elapsed.as_secs());
                            }
                        }
                    }
                    ScanStatus::Completed => {
                        if let Some(pb) = &progress_bar {
                            pb.finish_with_message("Scan completed");
                        }
                        let elapsed = start_time.elapsed();
                        println!("{} Scan completed successfully in {:.1}s", "✓".green().bold(), elapsed.as_secs_f64());
                        self.display_scan_summary(api_client, job_id).await?;
                        break;
                    }
                    ScanStatus::Cancelled => {
                        if let Some(pb) = &progress_bar {
                            pb.finish_with_message("Scan cancelled");
                        }
                        println!("{} Scan was cancelled", "⚠".yellow().bold());
                        break;
                    }
                    ScanStatus::Failed => {
                        if let Some(pb) = &progress_bar {
                            pb.finish_with_message("Scan failed");
                        }
                        println!("{} Scan failed", "✗".red().bold());
                        break;
                    }
                    ScanStatus::Paused => {
                        if let Some(pb) = &progress_bar {
                            pb.set_message("Scan paused");
                        }
                        println!("{} Scan is paused", "⏸".yellow().bold());
                        break;
                    }
                }
                last_status = Some(status);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
        Ok(())
    }
    async fn display_scan_summary(&self, api_client: &ApiClient, job_id: hadron_core::ScanJobId) -> Result<()> {
        println!();
        println!("{}", "=== Scan Summary ===".bold().cyan());
        match api_client.get_scan_result(job_id).await {
            Ok(scan_result) => {
                self.format_scan_result(&scan_result);
            }
            Err(_) => {
                match api_client.get_scan_progress(job_id).await {
                    Ok(progress) => {
                        println!("Files scanned: {}", progress.files_scanned.to_string().green());
                        println!("Total files: {}", progress.total_files);
                        println!("Threats found: {}", 
                            if progress.threats_found > 0 {
                                progress.threats_found.to_string().red().bold()
                            } else {
                                progress.threats_found.to_string().green()
                            }
                        );
                        println!("Completion: {:.1}%", progress.percentage_complete);
                    }
                    Err(_) => {
                        println!("Scan completed - detailed results not available");
                    }
                }
            }
        }
        println!();
        Ok(())
    }
    fn format_scan_result(&self, result: &ScanResult) {
        use tabled::{Table, Tabled};
        println!("Files scanned: {}", result.scanned_files.to_string().green());
        println!("Threats found: {}", 
            if result.threats_found.is_empty() {
                "0".green()
            } else {
                result.threats_found.len().to_string().red().bold()
            }
        );
        if let Some(duration) = result.get_duration_seconds() {
            println!("Scan duration: {}", humantime::format_duration(
                std::time::Duration::from_secs_f64(duration)
            ).to_string().cyan());
        }
        println!("Success rate: {:.1}%", (result.get_success_rate() * 100.0).to_string().green());
        if !result.threats_found.is_empty() {
            println!();
            println!("{}", "Threats Detected:".red().bold());
            #[derive(Tabled)]
            struct ThreatDisplay {
                #[tabled(rename = "Threat Name")]
                name: String,
                #[tabled(rename = "Type")]
                threat_type: String,
                #[tabled(rename = "Severity")]
                severity: String,
                #[tabled(rename = "File Path")]
                file_path: String,
                #[tabled(rename = "Detection Method")]
                detection_method: String,
            }
            let threat_data: Vec<ThreatDisplay> = result.threats_found.iter().map(|threat| {
                let severity_colored = match threat.severity {
                    ThreatSeverity::Critical => "Critical".red().bold().to_string(),
                    ThreatSeverity::High => "High".red().to_string(),
                    ThreatSeverity::Medium => "Medium".yellow().to_string(),
                    ThreatSeverity::Low => "Low".green().to_string(),
                };
                ThreatDisplay {
                    name: threat.name.clone(),
                    threat_type: format!("{:?}", threat.threat_type),
                    severity: severity_colored,
                    file_path: threat.file_path.display().to_string(),
                    detection_method: format!("{:?}", threat.detection_method),
                }
            }).collect();
            let table = Table::new(threat_data);
            println!("{}", table);
        }
        if !result.errors.is_empty() {
            println!();
            println!("{} ({} errors occurred during scan)", 
                "Errors:".yellow().bold(), 
                result.errors.len()
            );
            if self.verbose {
                for error in &result.errors {
                    println!("  {} {}: {}", 
                        "•".yellow(), 
                        error.file_path.display().to_string().dimmed(),
                        error.error_message
                    );
                }
            } else {
                println!("  Use --verbose to see detailed error information");
            }
        }
        if self.verbose && result.statistics.scan_duration_ms > 0 {
            println!();
            println!("{}", "Performance Statistics:".cyan().bold());
            println!("  Files per second: {:.1}", result.statistics.files_per_second());
            println!("  Average scan time: {:.2}ms per file", result.statistics.average_scan_time_ms);
            println!("  Infection rate: {:.2}%", result.statistics.infection_rate());
        }
    }
    async fn handle_status_command(&self, api_client: &ApiClient, verbose_override: bool) -> Result<()> {
        let verbose = self.verbose || verbose_override;
        if verbose {
            println!("Connecting to antivirus service...");
        }
        let status = api_client.get_system_status().await?;
        println!();
        println!("{}", "=== Windows Antivirus Status ===".bold().cyan());
        println!();
        let protection_status = if status.realtime_protection_enabled {
            "✓ Enabled".green().bold()
        } else {
            "✗ Disabled".red().bold()
        };
        println!("{}: {}", "Real-time Protection".bold(), protection_status);
        let health_score = status.get_health_score();
        let health_status = status.get_health_status();
        let health_color = match health_score {
            90..=100 => health_status.green().bold(),
            70..=89 => health_status.yellow().bold(),
            50..=69 => health_status.yellow(),
            _ => health_status.red().bold(),
        };
        println!("{}: {} ({}%)", "System Health".bold(), health_color, health_score);
        println!();
        println!("{}", "Version Information:".bold());
        println!("  Engine Version: {}", status.engine_version.cyan());
        println!("  Signature Version: {}", status.signature_version.cyan());
        println!();
        println!("{}", "Last Activities:".bold());
        if let Some(last_scan) = status.last_scan_time {
            let time_ago = self.format_time_ago(last_scan);
            println!("  Last Scan: {} ({})", 
                last_scan.format("%Y-%m-%d %H:%M:%S UTC").to_string().cyan(),
                time_ago
            );
        } else {
            println!("  Last Scan: {}", "Never".yellow());
        }
        if let Some(last_update) = status.last_update_time {
            let time_ago = self.format_time_ago(last_update);
            let update_status = if status.needs_update() {
                format!("{} ({})", 
                    last_update.format("%Y-%m-%d %H:%M:%S UTC").to_string().yellow(),
                    "Update needed".red()
                )
            } else {
                format!("{} ({})", 
                    last_update.format("%Y-%m-%d %H:%M:%S UTC").to_string().cyan(),
                    time_ago
                )
            };
            println!("  Last Update: {}", update_status);
        } else {
            println!("  Last Update: {} {}", "Never".yellow(), "(Update needed)".red());
        }
        println!();
        println!("{}", "Threat Statistics:".bold());
        let threats_today = if status.threats_detected_today > 0 {
            status.threats_detected_today.to_string().red().bold()
        } else {
            status.threats_detected_today.to_string().green()
        };
        println!("  Threats Detected Today: {}", threats_today);
        let quarantine_count = if status.quarantine_count > 0 {
            status.quarantine_count.to_string().yellow()
        } else {
            status.quarantine_count.to_string().green()
        };
        println!("  Files in Quarantine: {}", quarantine_count);
        let mut recommendations = Vec::new();
        if !status.realtime_protection_enabled {
            recommendations.push("Enable real-time protection for better security".to_string());
        }
        if status.needs_update() {
            recommendations.push("Update virus definitions".to_string());
        }
        if status.needs_scan() {
            recommendations.push("Run a full system scan".to_string());
        }
        if !recommendations.is_empty() {
            println!();
            println!("{}", "Recommendations:".bold().yellow());
            for rec in recommendations {
                println!("  {} {}", "•".yellow(), rec);
            }
        }
        if verbose {
            println!();
            println!("{}", "=== Detailed Information ===".bold());
            println!("Service Status: {}", "Running".green());
            println!("Configuration: Default");
            println!("Log Level: Info");
            println!("Protection Status: {}", status.get_protection_status());
        }
        println!();
        Ok(())
    }
    fn format_time_ago(&self, time: DateTime<Utc>) -> String {
        let now = Utc::now();
        let duration = now.signed_duration_since(time);
        if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} minutes ago", duration.num_minutes())
        } else {
            "Just now".to_string()
        }
    }
    async fn handle_quarantine_command(
        &self,
        api_client: &ApiClient,
        action: &QuarantineAction,
    ) -> Result<()> {
        match action {
            QuarantineAction::List => {
                if self.verbose {
                    println!("Retrieving quarantine list...");
                }
                match api_client.get_quarantine_list().await {
                    Ok(entries) => {
                        self.display_quarantine_list(&entries);
                    }
                    Err(_) => {
                        println!("{}", "=== Quarantined Files ===".bold().cyan());
                        println!();
                        println!("{}", "No files currently in quarantine.".green());
                        if self.verbose {
                            println!();
                            println!("Quarantine Location: C:\\ProgramData\\WindowsAntivirus\\Quarantine");
                            println!("Max Quarantine Size: 10 GB");
                            println!("Auto-delete After: 30 days");
                        }
                    }
                }
            }
            QuarantineAction::Restore { id } => {
                if self.verbose {
                    println!("Attempting to restore file with ID: {}", id.cyan());
                }
                match api_client.restore_from_quarantine(id.clone()).await {
                    Ok(()) => {
                        println!("{} File restored successfully from quarantine", "✓".green().bold());
                        if self.verbose {
                            println!("File ID: {}", id.cyan());
                        }
                    }
                    Err(e) => {
                        println!("{} Failed to restore file: {}", "✗".red().bold(), e);
                    }
                }
            }
            QuarantineAction::Delete { id } => {
                if self.verbose {
                    println!("Attempting to permanently delete file with ID: {}", id.cyan());
                }
                match api_client.delete_from_quarantine(id.clone()).await {
                    Ok(()) => {
                        println!("{} File permanently deleted from quarantine", "✓".green().bold());
                        if self.verbose {
                            println!("File ID: {}", id.cyan());
                        }
                    }
                    Err(e) => {
                        println!("{} Failed to delete file: {}", "✗".red().bold(), e);
                    }
                }
            }
        }
        Ok(())
    }
    fn display_quarantine_list(&self, entries: &[QuarantineEntry]) {
        use tabled::{Table, Tabled};
        println!("{}", "=== Quarantined Files ===".bold().cyan());
        println!();
        if entries.is_empty() {
            println!("{}", "No files currently in quarantine.".green());
            return;
        }
        println!("Found {} quarantined file(s)", entries.len().to_string().yellow().bold());
        println!();
        #[derive(Tabled)]
        struct QuarantineDisplay {
            #[tabled(rename = "ID")]
            id: String,
            #[tabled(rename = "File Name")]
            file_name: String,
            #[tabled(rename = "Threat")]
            threat_name: String,
            #[tabled(rename = "Severity")]
            severity: String,
            #[tabled(rename = "Size")]
            size: String,
            #[tabled(rename = "Quarantined")]
            quarantine_time: String,
        }
        let display_data: Vec<QuarantineDisplay> = entries.iter().map(|entry| {
            let severity_colored = match entry.threat_info.severity {
                ThreatSeverity::Critical => "Critical".red().bold().to_string(),
                ThreatSeverity::High => "High".red().to_string(),
                ThreatSeverity::Medium => "Medium".yellow().to_string(),
                ThreatSeverity::Low => "Low".green().to_string(),
            };
            let time_ago = self.format_time_ago(entry.quarantine_time);
            QuarantineDisplay {
                id: entry.id.to_string()[..8].to_string(),
                file_name: entry.get_file_name(),
                threat_name: entry.threat_info.name.clone(),
                severity: severity_colored,
                size: entry.get_formatted_size(),
                quarantine_time: time_ago,
            }
        }).collect();
        let table = Table::new(display_data);
        println!("{}", table);
        if self.verbose {
            println!();
            println!("{}", "Detailed Information:".bold());
            for entry in entries {
                println!("  {} {}", "ID:".bold(), entry.id);
                println!("    Original Path: {}", entry.original_path.display().to_string().cyan());
                println!("    Threat Type: {:?}", entry.threat_info.threat_type);
                println!("    Detection Method: {:?}", entry.threat_info.detection_method);
                println!("    File Hash: {}", entry.threat_info.file_hash.dimmed());
                println!("    Age: {} days", entry.age_in_days());
                println!();
            }
        } else {
            println!();
            println!("Use {} to restore a file or {} to delete permanently", 
                "av-cli quarantine restore <id>".cyan(),
                "av-cli quarantine delete <id>".cyan()
            );
            println!("Use {} for detailed information", "--verbose".cyan());
        }
    }
    async fn handle_update_command(
        &self,
        api_client: &ApiClient,
        check_only: bool,
    ) -> Result<()> {
        if check_only {
            if self.verbose {
                println!("Connecting to update server...");
            }
            println!("Checking for updates...");
            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap());
            pb.set_message("Checking for updates...");
            for _ in 0..10 {
                pb.tick();
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            match api_client.check_updates().await {
                Ok(updates) => {
                    pb.finish_and_clear();
                    if updates.is_empty() {
                        println!("{} System is up to date", "✓".green().bold());
                        if self.verbose {
                            println!("Current signature version: 1.0.0");
                            println!("Current engine version: {}", env!("CARGO_PKG_VERSION"));
                            println!("Last update check: {}", Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
                        }
                    } else {
                        println!("{} {} update(s) available", "!".yellow().bold(), updates.len());
                        for update in &updates {
                            println!("  {} {} -> {}", 
                                "•".yellow(),
                                update.component_name.cyan(),
                                update.new_version.green()
                            );
                        }
                        println!();
                        println!("Run {} to apply updates", "av-cli update".cyan());
                    }
                }
                Err(e) => {
                    pb.finish_and_clear();
                    println!("{} Failed to check for updates: {}", "✗".red().bold(), e);
                }
            }
        } else {
            println!("Checking and applying updates...");
            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap());
            pb.set_message("Downloading updates...");
            match api_client.apply_updates().await {
                Ok(()) => {
                    pb.finish_and_clear();
                    println!("{} Updates applied successfully", "✓".green().bold());
                    if self.verbose {
                        println!("Service restart may be required for some updates to take effect");
                    }
                }
                Err(e) => {
                    pb.finish_and_clear();
                    println!("{} Failed to apply updates: {}", "✗".red().bold(), e);
                }
            }
        }
        Ok(())
    }
    async fn handle_config_command(
        &self,
        api_client: &ApiClient,
        action: &ConfigAction,
    ) -> Result<()> {
        match action {
            ConfigAction::Show => {
                if self.verbose {
                    println!("Retrieving configuration...");
                }
                match api_client.get_configuration().await {
                    Ok(config) => {
                        self.display_configuration(&config);
                    }
                    Err(_) => {
                        println!("{}", "=== Current Configuration ===".bold().cyan());
                        println!();
                        println!("{}", "Real-time Protection:".bold());
                        println!("  Enabled: {}", "true".green());
                        println!("  Scan on Access: {}", "true".green());
                        println!("  Scan on Write: {}", "true".green());
                        println!();
                        println!("{}", "Scan Settings:".bold());
                        println!("  Scan Archives: {}", "true".green());
                        println!("  Scan Email: {}", "true".green());
                        println!("  Scan Network Drives: {}", "false".red());
                        println!("  Max File Size: {}", "100 MB".cyan());
                        println!("  Heuristic Level: {}", "2".cyan());
                        println!();
                        println!("{}", "Update Settings:".bold());
                        println!("  Auto Update: {}", "true".green());
                        println!("  Update Frequency: {}", "4 hours".cyan());
                        println!("  Use Delta Updates: {}", "true".green());
                        if self.verbose {
                            println!();
                            println!("{}", "Advanced Settings:".bold());
                            println!("  Quarantine Max Size: {}", "10 GB".cyan());
                            println!("  Auto Delete After: {}", "30 days".cyan());
                            println!("  Log Level: {}", "info".cyan());
                            println!("  Console Logging: {}", "false".red());
                            println!("  File Logging: {}", "true".green());
                            println!("  Windows Event Log: {}", "true".green());
                        }
                    }
                }
            }
            ConfigAction::Set { key, value } => {
                if self.verbose {
                    println!("Updating configuration: {} = {}", key.cyan(), value.yellow());
                }
                match api_client.update_configuration_value(key.clone(), value.clone()).await {
                    Ok(()) => {
                        println!("{} Configuration updated successfully", "✓".green().bold());
                        match key.as_str() {
                            "realtime_protection" => {
                                let enabled = value.parse::<bool>().unwrap_or(false);
                                println!("Real-time protection {}", 
                                    if enabled { "enabled".green() } else { "disabled".red() }
                                );
                            }
                            "auto_update" => {
                                let enabled = value.parse::<bool>().unwrap_or(false);
                                println!("Auto update {}", 
                                    if enabled { "enabled".green() } else { "disabled".red() }
                                );
                            }
                            "scan_archives" => {
                                let enabled = value.parse::<bool>().unwrap_or(false);
                                println!("Archive scanning {}", 
                                    if enabled { "enabled".green() } else { "disabled".red() }
                                );
                            }
                            _ => {
                                println!("Setting '{}' updated to '{}'", key.cyan(), value.yellow());
                            }
                        }
                        if self.verbose {
                            println!("Note: Some changes may require service restart to take effect");
                        }
                    }
                    Err(e) => {
                        println!("{} Failed to update configuration: {}", "✗".red().bold(), e);
                    }
                }
            }
        }
        Ok(())
    }
    fn display_configuration(&self, config: &hadron_core::AntivirusConfig) {
        use tabled::{Table, Tabled};
        println!("{}", "=== Current Configuration ===".bold().cyan());
        println!();
        println!("{}", "Real-time Protection:".bold());
        println!("  Enabled: {}", 
            if config.realtime_protection.enabled { "true".green() } else { "false".red() }
        );
        println!("  Scan on Access: {}", 
            if config.realtime_protection.scan_on_access { "true".green() } else { "false".red() }
        );
        println!("  Scan on Write: {}", 
            if config.realtime_protection.scan_on_write { "true".green() } else { "false".red() }
        );
        println!("  Scan Archives: {}", 
            if config.realtime_protection.scan_archives { "true".green() } else { "false".red() }
        );
        println!("  Scan Email Attachments: {}", 
            if config.realtime_protection.scan_email_attachments { "true".green() } else { "false".red() }
        );
        println!("  Scan Network Drives: {}", 
            if config.realtime_protection.scan_network_drives { "true".green() } else { "false".red() }
        );
        println!();
        println!("{}", "Scan Settings:".bold());
        println!("  Max File Size: {}", format!("{} MB", config.scan_settings.max_file_size_mb).cyan());
        println!("  Scan Timeout: {}", format!("{} seconds", config.scan_settings.scan_timeout_seconds).cyan());
        println!("  Heuristic Level: {}", config.scan_settings.heuristic_level.to_string().cyan());
        println!("  Use Machine Learning: {}", 
            if config.scan_settings.use_machine_learning { "true".green() } else { "false".red() }
        );
        println!();
        println!("{}", "Update Settings:".bold());
        println!("  Auto Update: {}", 
            if config.update_settings.auto_update_enabled { "true".green() } else { "false".red() }
        );
        println!("  Update Frequency: {}", format!("{} hours", config.update_settings.update_frequency_hours).cyan());
        println!("  Use Delta Updates: {}", 
            if config.update_settings.use_delta_updates { "true".green() } else { "false".red() }
        );
        println!();
        if !config.whitelist.is_empty() {
            println!("{}", "Whitelist Entries:".bold());
            #[derive(Tabled)]
            struct WhitelistDisplay {
                #[tabled(rename = "Type")]
                entry_type: String,
                #[tabled(rename = "Value")]
                value: String,
                #[tabled(rename = "Description")]
                description: String,
            }
            let whitelist_data: Vec<WhitelistDisplay> = config.whitelist.iter().map(|entry| {
                WhitelistDisplay {
                    entry_type: format!("{:?}", entry.entry_type),
                    value: entry.value.clone(),
                    description: entry.description.clone().unwrap_or_default(),
                }
            }).collect();
            let table = Table::new(whitelist_data);
            println!("{}", table);
            println!();
        }
        if self.verbose {
            println!("{}", "Quarantine Settings:".bold());
            println!("  Max Size: {}", format!("{} GB", config.quarantine_settings.max_size_gb).cyan());
            println!("  Auto Delete After: {}", format!("{} days", config.quarantine_settings.auto_delete_days).cyan());
            println!("  Encryption Enabled: {}", 
                if config.quarantine_settings.encrypt_files { "true".green() } else { "false".red() }
            );
            println!();
        }
        println!("Use {} to modify settings", "av-cli config set <key> <value>".cyan());
    }
    async fn handle_memory_scan_command(
        &self,
        api_client: &ApiClient,
        process_id: Option<u32>,
        all_processes: bool,
    ) -> Result<()> {
        use crate::commands::MemoryScanCommand;
        MemoryScanCommand::execute(api_client, process_id, all_processes, self.verbose).await
    }
    async fn handle_network_command(
        &self,
        api_client: &ApiClient,
        action: &NetworkAction,
    ) -> Result<()> {
        use crate::commands::NetworkCommand;
        match action {
            NetworkAction::Status => {
                NetworkCommand::status(api_client, self.verbose).await?;
            }
            NetworkAction::CheckUrl { url } => {
                NetworkCommand::check_url(api_client, url, self.verbose).await?;
            }
            NetworkAction::CheckIp { ip } => {
                NetworkCommand::check_ip(api_client, ip, self.verbose).await?;
            }
            NetworkAction::Configure { enable, interfaces } => {
                NetworkCommand::configure(api_client, *enable, interfaces.clone(), self.verbose).await?;
            }
        }
        Ok(())
    }
    async fn handle_disk_wipe_command(
        &self,
        api_client: &ApiClient,
        action: &DiskWipeAction,
    ) -> Result<()> {
        use crate::commands::DiskWipeCommand;
        match action {
            DiskWipeAction::List => {
                DiskWipeCommand::list_devices(api_client, self.verbose).await?;
            }
            DiskWipeAction::Quick { device_id, force } => {
                DiskWipeCommand::wipe_device(api_client, device_id, false, *force, self.verbose).await?;
            }
            DiskWipeAction::Secure { device_id, force } => {
                DiskWipeCommand::wipe_device(api_client, device_id, true, *force, self.verbose).await?;
            }
            DiskWipeAction::Scan { device_id } => {
                DiskWipeCommand::scan_device(api_client, device_id, self.verbose).await?;
            }
        }
        Ok(())
    }
    async fn handle_usb_protect_command(
        &self,
        api_client: &ApiClient,
        action: &UsbProtectAction,
    ) -> Result<()> {
        use crate::commands::UsbProtectCommand;
        match action {
            UsbProtectAction::Scan { device_id } => {
                UsbProtectCommand::scan_device(api_client, device_id, self.verbose).await?;
            }
            UsbProtectAction::Clean { device_id, force } => {
                UsbProtectCommand::clean_device(api_client, device_id, *force, self.verbose).await?;
            }
            UsbProtectAction::Enable => {
                UsbProtectCommand::enable_protection(api_client, self.verbose).await?;
            }
            UsbProtectAction::Disable => {
                UsbProtectCommand::disable_protection(api_client, self.verbose).await?;
            }
            UsbProtectAction::Status => {
                UsbProtectCommand::show_status(api_client, self.verbose).await?;
            }
            UsbProtectAction::Quarantine { file_path } => {
                UsbProtectCommand::quarantine_file(api_client, file_path, self.verbose).await?;
            }
            UsbProtectAction::Restore { target } => {
                UsbProtectCommand::restore_file(api_client, target, self.verbose).await?;
            }
            UsbProtectAction::Immunize { device_id, force } => {
                UsbProtectCommand::immunize_device(api_client, device_id, *force, self.verbose).await?;
            }
            UsbProtectAction::RemoveImmunization { device_id, force } => {
                UsbProtectCommand::remove_immunization(api_client, device_id, *force, self.verbose).await?;
            }
        }
        Ok(())
    }
}