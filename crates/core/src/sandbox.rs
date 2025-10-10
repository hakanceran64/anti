use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::{
    Result, AntivirusError, SandboxId, 
    traits::{SandboxOperations, ExecutionReport, SandboxStatus, NetworkActivity, FileOperation, RegistryOperation, ResourceUsage}
};

/// Windows Job Object wrapper for process isolation
#[cfg(windows)]
mod job_object {
    use std::ptr;
    use winapi::um::jobapi2::{CreateJobObjectW, AssignProcessToJobObject, SetInformationJobObject};
    use winapi::um::winnt::{HANDLE, JobObjectBasicLimitInformation, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
    use winapi::um::handleapi::CloseHandle;
    use winapi::shared::minwindef::DWORD;

    #[derive(Debug)]
    pub struct JobObject {
        handle: HANDLE,
    }

    impl JobObject {
        pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
            unsafe {
                let handle = CreateJobObjectW(ptr::null_mut(), ptr::null());
                if handle.is_null() {
                    return Err("Failed to create job object".into());
                }

                // Set job limits to kill all processes when job is closed
                let mut limits = std::mem::zeroed::<winapi::um::winnt::JOBOBJECT_BASIC_LIMIT_INFORMATION>();
                limits.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

                let result = SetInformationJobObject(
                    handle,
                    JobObjectBasicLimitInformation,
                    &mut limits as *mut _ as *mut _,
                    std::mem::size_of::<winapi::um::winnt::JOBOBJECT_BASIC_LIMIT_INFORMATION>() as DWORD,
                );

                if result == 0 {
                    CloseHandle(handle);
                    return Err("Failed to set job object limits".into());
                }

                Ok(JobObject { handle })
            }
        }

        pub fn assign_process(&self, process_handle: HANDLE) -> Result<(), Box<dyn std::error::Error>> {
            unsafe {
                let result = AssignProcessToJobObject(self.handle, process_handle);
                if result == 0 {
                    return Err("Failed to assign process to job object".into());
                }
            }
            Ok(())
        }

        pub fn get_handle(&self) -> HANDLE {
            self.handle
        }
    }

    impl Drop for JobObject {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
mod job_object {
    #[derive(Debug)]
    pub struct JobObject;
    
    impl JobObject {
        pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
            Ok(JobObject)
        }
        
        pub fn assign_process(&self, _process_handle: usize) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }
}

/// Behavior monitoring data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: BehaviorEventType,
    pub process_id: u32,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehaviorEventType {
    ProcessCreated,
    ProcessTerminated,
    FileCreated,
    FileModified,
    FileDeleted,
    RegistryKeyCreated,
    RegistryKeyModified,
    RegistryKeyDeleted,
    NetworkConnection,
    DllLoaded,
    MutexCreated,
    ServiceInstalled,
    ScheduledTaskCreated,
}

/// Sandbox environment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub timeout_seconds: u32,
    pub max_memory_mb: u64,
    pub max_cpu_percent: f32,
    pub enable_network: bool,
    pub redirect_filesystem: bool,
    pub monitor_registry: bool,
    pub capture_screenshots: bool,
    pub analysis_depth: AnalysisDepth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisDepth {
    Basic,      // Process monitoring only
    Standard,   // + File system monitoring
    Deep,       // + Registry and network monitoring
    Forensic,   // + Memory dumps and detailed analysis
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 300, // 5 minutes
            max_memory_mb: 512,
            max_cpu_percent: 50.0,
            enable_network: false, // Isolated by default
            redirect_filesystem: true,
            monitor_registry: true,
            capture_screenshots: false,
            analysis_depth: AnalysisDepth::Standard,
        }
    }
}

/// Individual sandbox instance
#[derive(Debug)]
pub struct SandboxInstance {
    pub id: SandboxId,
    pub config: SandboxConfig,
    pub start_time: DateTime<Utc>,
    pub sandbox_dir: PathBuf,
    pub redirected_paths: HashMap<PathBuf, PathBuf>,
    pub behavior_events: Arc<Mutex<Vec<BehaviorEvent>>>,
    pub resource_usage: Arc<Mutex<ResourceUsage>>,
    pub is_running: bool,
    pub job_object: Option<job_object::JobObject>,
}

impl SandboxInstance {
    /// Create a new sandbox instance
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let id = Uuid::new_v4();
        let sandbox_dir = Self::create_sandbox_directory(&id)?;
        
        // Create job object for process isolation on Windows
        let job_object = if cfg!(windows) {
            match job_object::JobObject::new() {
                Ok(job) => Some(job),
                Err(e) => {
                    tracing::warn!("Failed to create job object: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            id,
            config,
            start_time: Utc::now(),
            sandbox_dir,
            redirected_paths: HashMap::new(),
            behavior_events: Arc::new(Mutex::new(Vec::new())),
            resource_usage: Arc::new(Mutex::new(ResourceUsage {
                cpu_percent: 0.0,
                memory_mb: 0,
                disk_io_mb: 0,
                network_io_mb: 0,
            })),
            is_running: false,
            job_object,
        })
    }

    /// Create sandbox directory structure
    fn create_sandbox_directory(sandbox_id: &SandboxId) -> Result<PathBuf> {
        let base_dir = std::env::temp_dir().join("windows_antivirus_sandbox");
        let sandbox_dir = base_dir.join(sandbox_id.to_string());

        std::fs::create_dir_all(&sandbox_dir)
            .map_err(|e| AntivirusError::Internal(format!("Failed to create sandbox directory: {}", e)))?;

        // Create subdirectories for file system redirection
        let subdirs = ["files", "registry", "temp", "logs"];
        for subdir in &subdirs {
            std::fs::create_dir_all(sandbox_dir.join(subdir))
                .map_err(|e| AntivirusError::Internal(format!("Failed to create sandbox subdirectory {}: {}", subdir, e)))?;
        }

        Ok(sandbox_dir)
    }

    /// Setup file system redirection
    pub fn setup_filesystem_redirection(&mut self) -> Result<()> {
        if !self.config.redirect_filesystem {
            return Ok(());
        }

        // Common Windows directories to redirect
        let redirect_paths = vec![
            (PathBuf::from(r"C:\Windows\Temp"), "temp"),
            (PathBuf::from(r"C:\Users\Public"), "files/public"),
            (PathBuf::from(r"C:\ProgramData"), "files/programdata"),
        ];

        for (original, redirect_subdir) in redirect_paths {
            let redirected = self.sandbox_dir.join(redirect_subdir);
            std::fs::create_dir_all(&redirected)
                .map_err(|e| AntivirusError::Internal(format!("Failed to create redirect directory: {}", e)))?;
            
            self.redirected_paths.insert(original, redirected);
        }

        Ok(())
    }

    /// Add behavior event
    pub fn add_behavior_event(&self, event: BehaviorEvent) {
        if let Ok(mut events) = self.behavior_events.lock() {
            events.push(event);
        }
    }

    /// Update resource usage
    pub fn update_resource_usage(&self, usage: ResourceUsage) {
        if let Ok(mut current_usage) = self.resource_usage.lock() {
            *current_usage = usage;
        }
    }

    /// Get current behavior events
    pub fn get_behavior_events(&self) -> Vec<BehaviorEvent> {
        self.behavior_events.lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    /// Get current resource usage
    pub fn get_resource_usage(&self) -> ResourceUsage {
        self.resource_usage.lock()
            .map(|usage| usage.clone())
            .unwrap_or_default()
    }

    /// Clean up sandbox resources
    pub fn cleanup(&mut self) -> Result<()> {
        self.is_running = false;

        // Remove sandbox directory
        if self.sandbox_dir.exists() {
            std::fs::remove_dir_all(&self.sandbox_dir)
                .map_err(|e| AntivirusError::Internal(format!("Failed to cleanup sandbox directory: {}", e)))?;
        }

        tracing::info!("Sandbox {} cleaned up successfully", self.id);
        Ok(())
    }
}

/// Main sandbox engine implementation
pub struct SandboxEngine {
    active_sandboxes: Arc<Mutex<HashMap<SandboxId, SandboxInstance>>>,
    default_config: SandboxConfig,
}

impl SandboxEngine {
    /// Create a new sandbox engine
    pub fn new() -> Self {
        Self {
            active_sandboxes: Arc::new(Mutex::new(HashMap::new())),
            default_config: SandboxConfig::default(),
        }
    }

    /// Create a new sandbox engine with custom configuration
    pub fn with_config(config: SandboxConfig) -> Self {
        Self {
            active_sandboxes: Arc::new(Mutex::new(HashMap::new())),
            default_config: config,
        }
    }

    /// Execute file in sandbox with behavior monitoring
    async fn execute_with_monitoring(&self, sandbox_id: SandboxId, file_path: &Path) -> Result<ExecutionReport> {
        let start_time = Instant::now();
        
        // Get sandbox instance
        let sandbox = {
            let sandboxes = self.active_sandboxes.lock()
                .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;
            
            sandboxes.get(&sandbox_id)
                .ok_or_else(|| AntivirusError::Internal("Sandbox not found".to_string()))?
                .config.clone()
        };

        // Prepare execution environment
        let execution_result = self.execute_in_isolated_environment(sandbox_id, file_path, &sandbox).await?;
        
        let execution_time = start_time.elapsed();

        // Collect behavior data
        let behavior_events = {
            let sandboxes = self.active_sandboxes.lock()
                .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;
            
            sandboxes.get(&sandbox_id)
                .map(|s| s.get_behavior_events())
                .unwrap_or_default()
        };

        // Analyze behaviors and generate report
        let report = self.analyze_execution_results(
            sandbox_id,
            execution_result,
            behavior_events,
            execution_time,
        ).await?;

        Ok(report)
    }

    /// Execute file in isolated environment
    async fn execute_in_isolated_environment(
        &self,
        sandbox_id: SandboxId,
        file_path: &Path,
        config: &SandboxConfig,
    ) -> Result<std::process::ExitStatus> {
        // Copy file to sandbox directory
        let sandbox_file_path = {
            let sandboxes = self.active_sandboxes.lock()
                .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;
            
            let sandbox = sandboxes.get(&sandbox_id)
                .ok_or_else(|| AntivirusError::Internal("Sandbox not found".to_string()))?;
            
            let target_path = sandbox.sandbox_dir.join("target_executable.exe");
            std::fs::copy(file_path, &target_path)
                .map_err(|e| AntivirusError::Internal(format!("Failed to copy file to sandbox: {}", e)))?;
            
            target_path
        };

        // Create command with restrictions
        let mut cmd = Command::new(&sandbox_file_path);
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .stdin(Stdio::null());

        // Set environment variables for isolation
        cmd.env_clear();
        cmd.env("TEMP", self.get_sandbox_temp_dir(sandbox_id)?);
        cmd.env("TMP", self.get_sandbox_temp_dir(sandbox_id)?);

        // Start process
        let mut child = cmd.spawn()
            .map_err(|e| AntivirusError::Internal(format!("Failed to start process in sandbox: {}", e)))?;

        // Assign to job object for process isolation (Windows only)
        #[cfg(windows)]
        {
            let sandboxes = self.active_sandboxes.lock()
                .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;
            
            if let Some(sandbox) = sandboxes.get(&sandbox_id) {
                if let Some(ref job_object) = sandbox.job_object {
                    // Get process handle and assign to job object
                    use winapi::um::processthreadsapi::OpenProcess;
                    use winapi::um::winnt::PROCESS_ALL_ACCESS;
                    
                    unsafe {
                        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, child.id().unwrap_or(0));
                        if !process_handle.is_null() {
                            if let Err(e) = job_object.assign_process(process_handle) {
                                tracing::warn!("Failed to assign process to job object: {}", e);
                            }
                            winapi::um::handleapi::CloseHandle(process_handle);
                        }
                    }
                }
            }
        }

        // Wait for process with timeout
        let timeout_duration = Duration::from_secs(config.timeout_seconds as u64);
        let exit_status = timeout(timeout_duration, child.wait()).await
            .map_err(|_| AntivirusError::Internal("Sandbox execution timeout".to_string()))?
            .map_err(|e| AntivirusError::Internal(format!("Failed to wait for process: {}", e)))?;

        Ok(exit_status)
    }

    /// Get sandbox temporary directory
    fn get_sandbox_temp_dir(&self, sandbox_id: SandboxId) -> Result<PathBuf> {
        let sandboxes = self.active_sandboxes.lock()
            .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;
        
        let sandbox = sandboxes.get(&sandbox_id)
            .ok_or_else(|| AntivirusError::Internal("Sandbox not found".to_string()))?;
        
        Ok(sandbox.sandbox_dir.join("temp"))
    }

    /// Analyze execution results and generate report
    async fn analyze_execution_results(
        &self,
        sandbox_id: SandboxId,
        exit_status: std::process::ExitStatus,
        behavior_events: Vec<BehaviorEvent>,
        execution_time: Duration,
    ) -> Result<ExecutionReport> {
        // Convert behavior events to report format
        let behaviors_observed: Vec<String> = behavior_events.iter()
            .map(|event| format!("{:?}: {:?}", event.event_type, event.details))
            .collect();

        // Extract network activities
        let network_activity: Vec<NetworkActivity> = behavior_events.iter()
            .filter_map(|event| {
                if matches!(event.event_type, BehaviorEventType::NetworkConnection) {
                    Some(NetworkActivity {
                        destination: event.details.get("destination").cloned().unwrap_or_default(),
                        port: event.details.get("port")
                            .and_then(|p| p.parse().ok())
                            .unwrap_or(0),
                        protocol: event.details.get("protocol").cloned().unwrap_or_default(),
                        bytes_sent: event.details.get("bytes_sent")
                            .and_then(|b| b.parse().ok())
                            .unwrap_or(0),
                        bytes_received: event.details.get("bytes_received")
                            .and_then(|b| b.parse().ok())
                            .unwrap_or(0),
                    })
                } else {
                    None
                }
            })
            .collect();

        // Extract file operations
        let file_operations: Vec<FileOperation> = behavior_events.iter()
            .filter_map(|event| {
                match event.event_type {
                    BehaviorEventType::FileCreated | 
                    BehaviorEventType::FileModified | 
                    BehaviorEventType::FileDeleted => {
                        Some(FileOperation {
                            operation: format!("{:?}", event.event_type),
                            file_path: PathBuf::from(
                                event.details.get("file_path").cloned().unwrap_or_default()
                            ),
                            success: event.details.get("success")
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(true),
                        })
                    }
                    _ => None,
                }
            })
            .collect();

        // Extract registry operations
        let registry_operations: Vec<RegistryOperation> = behavior_events.iter()
            .filter_map(|event| {
                match event.event_type {
                    BehaviorEventType::RegistryKeyCreated |
                    BehaviorEventType::RegistryKeyModified |
                    BehaviorEventType::RegistryKeyDeleted => {
                        Some(RegistryOperation {
                            operation: format!("{:?}", event.event_type),
                            key_path: event.details.get("key_path").cloned().unwrap_or_default(),
                            value_name: event.details.get("value_name").cloned(),
                            success: event.details.get("success")
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(true),
                        })
                    }
                    _ => None,
                }
            })
            .collect();

        // Determine if behavior is malicious based on heuristics
        let is_malicious = self.analyze_malicious_behavior(&behavior_events);

        Ok(ExecutionReport {
            sandbox_id,
            execution_time_ms: execution_time.as_millis() as u64,
            exit_code: exit_status.code().unwrap_or(-1),
            behaviors_observed,
            network_activity,
            file_operations,
            registry_operations,
            is_malicious,
        })
    }

    /// Analyze behavior events for malicious patterns
    pub fn analyze_malicious_behavior(&self, events: &[BehaviorEvent]) -> bool {
        let mut malicious_score = 0;

        for event in events {
            match event.event_type {
                BehaviorEventType::RegistryKeyModified => {
                    // Check for suspicious registry modifications
                    if let Some(key_path) = event.details.get("key_path") {
                        if key_path.contains("Run") || key_path.contains("RunOnce") {
                            malicious_score += 20; // Persistence mechanism
                        }
                        if key_path.contains("Windows\\CurrentVersion\\Policies") {
                            malicious_score += 15; // Policy modification
                        }
                    }
                }
                BehaviorEventType::FileCreated => {
                    // Check for suspicious file creation
                    if let Some(file_path) = event.details.get("file_path") {
                        if file_path.contains("System32") || file_path.contains("SysWOW64") {
                            malicious_score += 25; // System directory modification
                        }
                        if file_path.ends_with(".exe") && file_path.contains("Temp") {
                            malicious_score += 10; // Temporary executable
                        }
                    }
                }
                BehaviorEventType::NetworkConnection => {
                    // Suspicious network activity
                    malicious_score += 5;
                    
                    if let Some(destination) = event.details.get("destination") {
                        // Check for suspicious domains/IPs (simplified)
                        if destination.contains("tor") || destination.contains("onion") {
                            malicious_score += 30;
                        }
                    }
                }
                BehaviorEventType::ProcessCreated => {
                    // Check for process injection or suspicious spawning
                    malicious_score += 2;
                }
                BehaviorEventType::ServiceInstalled => {
                    // Service installation is suspicious
                    malicious_score += 20;
                }
                BehaviorEventType::ScheduledTaskCreated => {
                    // Scheduled task creation for persistence
                    malicious_score += 15;
                }
                _ => {}
            }
        }

        // Consider malicious if score exceeds threshold
        malicious_score >= 30
    }
}

#[async_trait]
impl SandboxOperations for SandboxEngine {
    /// Create a new sandbox environment
    async fn create_sandbox(&self) -> Result<SandboxId> {
        let mut sandbox = SandboxInstance::new(self.default_config.clone())?;
        sandbox.setup_filesystem_redirection()?;
        
        let sandbox_id = sandbox.id;
        
        // Store sandbox instance
        {
            let mut sandboxes = self.active_sandboxes.lock()
                .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;
            sandboxes.insert(sandbox_id, sandbox);
        }

        tracing::info!("Created sandbox with ID: {}", sandbox_id);
        Ok(sandbox_id)
    }

    /// Execute a file in the sandbox
    async fn execute_in_sandbox(&self, sandbox_id: SandboxId, file_path: &Path) -> Result<ExecutionReport> {
        // Validate file exists
        if !file_path.exists() {
            return Err(AntivirusError::Internal(
                format!("File not found: {}", file_path.display())
            ));
        }

        // Mark sandbox as running
        {
            let mut sandboxes = self.active_sandboxes.lock()
                .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;
            
            if let Some(sandbox) = sandboxes.get_mut(&sandbox_id) {
                sandbox.is_running = true;
            } else {
                return Err(AntivirusError::Internal("Sandbox not found".to_string()));
            }
        }

        tracing::info!("Executing file {} in sandbox {}", file_path.display(), sandbox_id);

        // Execute with monitoring
        let result = self.execute_with_monitoring(sandbox_id, file_path).await;

        // Mark sandbox as not running
        {
            let mut sandboxes = self.active_sandboxes.lock()
                .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;
            
            if let Some(sandbox) = sandboxes.get_mut(&sandbox_id) {
                sandbox.is_running = false;
            }
        }

        result
    }

    /// Destroy a sandbox environment
    async fn destroy_sandbox(&self, sandbox_id: SandboxId) -> Result<()> {
        let mut sandboxes = self.active_sandboxes.lock()
            .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;

        if let Some(mut sandbox) = sandboxes.remove(&sandbox_id) {
            sandbox.cleanup()?;
            tracing::info!("Destroyed sandbox {}", sandbox_id);
            Ok(())
        } else {
            Err(AntivirusError::Internal("Sandbox not found".to_string()))
        }
    }

    /// Get sandbox status
    async fn get_sandbox_status(&self, sandbox_id: SandboxId) -> Result<SandboxStatus> {
        let sandboxes = self.active_sandboxes.lock()
            .map_err(|_| AntivirusError::Internal("Failed to lock sandboxes".to_string()))?;

        if let Some(sandbox) = sandboxes.get(&sandbox_id) {
            Ok(SandboxStatus {
                is_running: sandbox.is_running,
                start_time: sandbox.start_time,
                resource_usage: sandbox.get_resource_usage(),
            })
        } else {
            Err(AntivirusError::Internal("Sandbox not found".to_string()))
        }
    }
}

impl Default for SandboxEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_sandbox_creation() {
        let engine = SandboxEngine::new();
        let sandbox_id = engine.create_sandbox().await.unwrap();
        
        // Verify sandbox exists
        let status = engine.get_sandbox_status(sandbox_id).await.unwrap();
        assert!(!status.is_running);
        
        // Cleanup
        engine.destroy_sandbox(sandbox_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_sandbox_execution() {
        let engine = SandboxEngine::new();
        let sandbox_id = engine.create_sandbox().await.unwrap();
        
        // Create a simple test executable (batch file on Windows)
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.bat");
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "@echo off").unwrap();
        writeln!(file, "echo Hello from sandbox").unwrap();
        
        // Execute in sandbox
        let report = engine.execute_in_sandbox(sandbox_id, &test_file).await.unwrap();
        
        assert_eq!(report.sandbox_id, sandbox_id);
        assert!(report.execution_time_ms > 0);
        
        // Cleanup
        engine.destroy_sandbox(sandbox_id).await.unwrap();
    }

    #[test]
    fn test_malicious_behavior_analysis() {
        let engine = SandboxEngine::new();
        
        // Create suspicious behavior events
        let mut events = Vec::new();
        
        // Registry modification for persistence
        let mut details = HashMap::new();
        details.insert("key_path".to_string(), "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string());
        events.push(BehaviorEvent {
            timestamp: Utc::now(),
            event_type: BehaviorEventType::RegistryKeyModified,
            process_id: 1234,
            details,
        });
        
        // System file creation
        let mut details = HashMap::new();
        details.insert("file_path".to_string(), "C:\\Windows\\System32\\malware.exe".to_string());
        events.push(BehaviorEvent {
            timestamp: Utc::now(),
            event_type: BehaviorEventType::FileCreated,
            process_id: 1234,
            details,
        });
        
        // Should be detected as malicious
        assert!(engine.analyze_malicious_behavior(&events));
        
        // Test benign behavior
        let benign_events = vec![
            BehaviorEvent {
                timestamp: Utc::now(),
                event_type: BehaviorEventType::FileCreated,
                process_id: 1234,
                details: {
                    let mut details = HashMap::new();
                    details.insert("file_path".to_string(), "C:\\Users\\Test\\Documents\\file.txt".to_string());
                    details
                },
            }
        ];
        
        // Should not be detected as malicious
        assert!(!engine.analyze_malicious_behavior(&benign_events));
    }

    #[test]
    fn test_sandbox_config() {
        let config = SandboxConfig {
            timeout_seconds: 60,
            max_memory_mb: 256,
            enable_network: true,
            analysis_depth: AnalysisDepth::Deep,
            ..Default::default()
        };
        
        let engine = SandboxEngine::with_config(config.clone());
        assert_eq!(engine.default_config.timeout_seconds, 60);
        assert_eq!(engine.default_config.max_memory_mb, 256);
        assert!(engine.default_config.enable_network);
    }
}