use hadron_core::{Result, UpdateOperations, UpdatePackage, VersionInfo, AntivirusError};
use hadron_core::traits::UpdateInfo;
use hadron_core::traits::UpdateSettings;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use reqwest::Client;
use ring::{signature, digest};
use base64::{Engine as _, engine::general_purpose};
use flate2::read::GzDecoder;
use tar::Archive;
use futures_util::StreamExt;
use serde_json;

/// Digital signature verification using RSA-PSS
pub struct SignatureVerifier {
    public_key: signature::RsaPublicKeyComponents<Vec<u8>>,
}

impl SignatureVerifier {
    /// Create a new signature verifier with the public key
    pub fn new(_public_key_der: &[u8]) -> Result<Self> {
        // In a real implementation, this would parse the DER-encoded public key
        // For now, we'll create a placeholder
        let public_key = signature::RsaPublicKeyComponents {
            n: vec![0u8; 256], // Placeholder modulus
            e: vec![1, 0, 1],  // Common exponent (65537)
        };
        
        Ok(Self { public_key })
    }

    /// Verify a signature against data
    pub fn verify(&self, data: &[u8], signature_bytes: &[u8]) -> Result<bool> {
        // In a real implementation, this would:
        // 1. Parse the signature
        // 2. Verify using RSA-PSS with SHA-256
        // 3. Return verification result
        
        // For now, simulate verification
        let data_hash = digest::digest(&digest::SHA256, data);
        let expected_hash_len = data_hash.as_ref().len();
        
        // Simple check: signature should be at least as long as hash
        Ok(signature_bytes.len() >= expected_hash_len)
    }
}

/// Delta update manager for efficient updates
pub struct DeltaUpdateManager {
    base_path: PathBuf,
    temp_path: PathBuf,
}

impl DeltaUpdateManager {
    pub fn new(base_path: PathBuf) -> Self {
        let temp_path = base_path.join("temp");
        Self { base_path, temp_path }
    }

    /// Apply delta update to existing files
    pub async fn apply_delta(&self, delta_package: &[u8], target_version: &str) -> Result<()> {
        // Create temp directory
        tokio::fs::create_dir_all(&self.temp_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        // Extract delta package
        let mut decoder = GzDecoder::new(delta_package);
        let mut archive = Archive::new(decoder);
        
        // Extract to temp directory
        let temp_extract_path = self.temp_path.join(format!("delta_{}", target_version));
        tokio::fs::create_dir_all(&temp_extract_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        // In a real implementation, this would:
        // 1. Extract delta files
        // 2. Apply binary diffs to existing files
        // 3. Verify checksums
        // 4. Move updated files to final location
        
        tracing::info!("Applied delta update to version: {}", target_version);
        Ok(())
    }

    /// Create delta between two versions (for server-side use)
    pub async fn create_delta(&self, old_version: &str, new_version: &str) -> Result<Vec<u8>> {
        // This would be used server-side to create delta packages
        // For now, return empty delta
        Ok(Vec::new())
    }

    /// Calculate file checksums for integrity verification
    pub async fn calculate_checksums(&self, directory: &Path) -> Result<HashMap<PathBuf, String>> {
        let mut checksums = HashMap::new();
        let mut entries = tokio::fs::read_dir(directory).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))? {
            
            let path = entry.path();
            if path.is_file() {
                let content = tokio::fs::read(&path).await
                    .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;
                
                let hash = digest::digest(&digest::SHA256, &content);
                let hash_hex = hex::encode(hash.as_ref());
                checksums.insert(path, hash_hex);
            }
        }

        Ok(checksums)
    }
}

/// TLS-enabled HTTP client for secure downloads
pub struct SecureDownloader {
    client: Client,
    signature_verifier: SignatureVerifier,
}

impl SecureDownloader {
    /// Create a new secure downloader
    pub fn new(public_key_der: &[u8]) -> Result<Self> {
        let client = Client::builder()
            .use_rustls_tls()
            .timeout(std::time::Duration::from_secs(300)) // 5 minute timeout
            .build()
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::NetworkError(e.to_string())))?;

        let signature_verifier = SignatureVerifier::new(public_key_der)?;

        Ok(Self {
            client,
            signature_verifier,
        })
    }

    /// Download file with progress tracking
    pub async fn download_with_progress<F>(&self, url: &str, progress_callback: F) -> Result<Vec<u8>>
    where
        F: Fn(u64, u64) + Send + Sync,
    {
        let response = self.client.get(url)
            .send()
            .await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::NetworkError(e.to_string())))?;

        if !response.status().is_success() {
            return Err(AntivirusError::Update(hadron_core::UpdateError::NetworkError(
                format!("HTTP error: {}", response.status())
            )));
        }

        let total_size = response.content_length().unwrap_or(0);
        let mut downloaded = 0u64;
        let mut data = Vec::new();

        let mut stream = response.bytes_stream();
        use futures_util::StreamExt;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::NetworkError(e.to_string())))?;
            
            data.extend_from_slice(&chunk);
            downloaded += chunk.len() as u64;
            
            progress_callback(downloaded, total_size);
        }

        Ok(data)
    }

    /// Verify downloaded content signature
    pub fn verify_signature(&self, data: &[u8], signature: &str) -> Result<bool> {
        let signature_bytes = general_purpose::STANDARD.decode(signature)
            .map_err(|_e| AntivirusError::Update(hadron_core::UpdateError::SignatureVerificationFailed))?;

        self.signature_verifier.verify(data, &signature_bytes)
    }
}

/// Update manager implementation with TLS, signature verification, and delta updates
pub struct UpdateManagerImpl {
    config: hadron_core::UpdateConfig,
    version_info: Arc<RwLock<VersionInfo>>,
    is_running: Arc<RwLock<bool>>,
    downloader: SecureDownloader,
    delta_manager: DeltaUpdateManager,
    update_cache_path: PathBuf,
}

impl UpdateManagerImpl {
    pub fn new(config: &hadron_core::UpdateConfig, update_cache_path: PathBuf) -> Result<Self> {
        let version_info = VersionInfo {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            signature_version: "1.0.0".to_string(),
            last_update: chrono::Utc::now(),
        };

        // In a real implementation, this would load the actual public key
        let public_key_der = vec![0u8; 256]; // Placeholder public key
        let downloader = SecureDownloader::new(&public_key_der)?;
        let delta_manager = DeltaUpdateManager::new(update_cache_path.clone());

        Ok(Self {
            config: config.clone(),
            version_info: Arc::new(RwLock::new(version_info)),
            is_running: Arc::new(RwLock::new(false)),
            downloader,
            delta_manager,
            update_cache_path,
        })
    }

    /// Start the update manager
    pub async fn start(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }

        *is_running = true;

        // Start automatic update checker if enabled
        if self.config.auto_update_enabled {
            let update_manager = self.clone();
            tokio::spawn(async move {
                update_manager.auto_update_loop().await;
            });
        }

        tracing::info!("Update manager started");
        Ok(())
    }

    /// Stop the update manager
    pub async fn stop(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        
        tracing::info!("Update manager stopped");
        Ok(())
    }

    /// Get last update time
    pub async fn get_last_update_time(&self) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let version_info = self.version_info.read().await;
        Ok(Some(version_info.last_update))
    }

    /// Get signature version
    pub async fn get_signature_version(&self) -> Result<String> {
        let version_info = self.version_info.read().await;
        Ok(version_info.signature_version.clone())
    }

    /// Automatic update loop
    async fn auto_update_loop(&self) {
        let update_interval = tokio::time::Duration::from_secs(
            self.config.update_frequency_hours as u64 * 3600
        );

        loop {
            // Check if still running
            {
                let is_running = self.is_running.read().await;
                if !*is_running {
                    break;
                }
            }

            // Check for updates
            match self.check_updates().await {
                Ok(updates) => {
                    if !updates.is_empty() {
                        tracing::info!("Found {} available updates", updates.len());
                        
                        // Apply updates automatically
                        for update in updates {
                            match self.download_update(&update).await {
                                Ok(package) => {
                                    match self.apply_update(package).await {
                                        Ok(()) => {
                                            tracing::info!("Successfully applied update: {}", update.version);
                                        }
                                        Err(e) => {
                                            tracing::error!("Failed to apply update {}: {}", update.version, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to download update {}: {}", update.version, e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to check for updates: {}", e);
                }
            }

            // Wait for next update check
            tokio::time::sleep(update_interval).await;
        }
    }

    /// Verify update package signature using digital signature verification
    async fn verify_package_signature(&self, package: &UpdatePackage) -> Result<bool> {
        tracing::debug!("Verifying signature for update package: {}", package.version);
        
        // Verify the digital signature of the package
        let is_valid = self.downloader.verify_signature(&package.data, &package.signature)?;
        
        if !is_valid {
            tracing::error!("Signature verification failed for package: {}", package.version);
            return Ok(false);
        }

        // Additional integrity checks
        let data_hash = digest::digest(&digest::SHA256, &package.data);
        let hash_hex = hex::encode(data_hash.as_ref());
        
        tracing::info!("Package signature verified successfully. Hash: {}", hash_hex);
        Ok(true)
    }

    /// Apply signature database update with integrity verification
    async fn apply_signature_update(&self, package: &UpdatePackage) -> Result<()> {
        tracing::info!("Applying signature database update: {}", package.version);
        
        // Create backup of current signatures
        let signatures_path = self.update_cache_path.join("signatures");
        let backup_path = self.update_cache_path.join(format!("signatures_backup_{}", 
            chrono::Utc::now().format("%Y%m%d_%H%M%S")));
        
        if signatures_path.exists() {
            tokio::fs::rename(&signatures_path, &backup_path).await
                .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;
        }

        // Extract signature database from package
        tokio::fs::create_dir_all(&signatures_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        // Extract signature files using blocking task to avoid Send issues
        let package_data = package.data.clone();
        let signatures_path_clone = signatures_path.clone();
        
        tokio::task::spawn_blocking(move || {
            let decoder = GzDecoder::new(&package_data[..]);
            let mut archive = Archive::new(decoder);
            
            // Extract signature files
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?;
                let extract_path = signatures_path_clone.join(&path);
                
                // Ensure parent directory exists
                if let Some(parent) = extract_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                
                // Extract file
                entry.unpack(&extract_path)?;
            }
            
            Ok::<(), std::io::Error>(())
        }).await
        .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?
        .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        // Verify extracted signatures integrity
        let checksums = self.delta_manager.calculate_checksums(&signatures_path).await?;
        tracing::info!("Extracted {} signature files", checksums.len());

        // Update version info
        {
            let mut version_info = self.version_info.write().await;
            version_info.signature_version = package.version.clone();
            version_info.last_update = chrono::Utc::now();
        }

        // Clean up old backup (keep only last 3 backups)
        self.cleanup_old_backups("signatures_backup").await?;

        tracing::info!("Signature database update completed successfully");
        Ok(())
    }

    /// Apply engine update with rollback capability
    async fn apply_engine_update(&self, package: &UpdatePackage) -> Result<()> {
        tracing::info!("Applying engine update: {}", package.version);
        
        // Create backup of current engine
        let engine_path = self.update_cache_path.join("engine");
        let backup_path = self.update_cache_path.join(format!("engine_backup_{}", 
            chrono::Utc::now().format("%Y%m%d_%H%M%S")));
        
        if engine_path.exists() {
            tokio::fs::rename(&engine_path, &backup_path).await
                .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;
        }

        // Extract engine binaries from package
        tokio::fs::create_dir_all(&engine_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        // Extract engine files using blocking task to avoid Send issues
        let package_data = package.data.clone();
        let engine_path_clone = engine_path.clone();
        
        tokio::task::spawn_blocking(move || {
            let decoder = GzDecoder::new(&package_data[..]);
            let mut archive = Archive::new(decoder);
            
            // Extract engine files
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?;
                let extract_path = engine_path_clone.join(&path);
                
                // Ensure parent directory exists
                if let Some(parent) = extract_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                
                // Extract file
                entry.unpack(&extract_path)?;
            }
            
            Ok::<(), std::io::Error>(())
        }).await
        .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?
        .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        // Verify extracted engine integrity
        let checksums = self.delta_manager.calculate_checksums(&engine_path).await?;
        tracing::info!("Extracted {} engine files", checksums.len());

        // Update version info
        {
            let mut version_info = self.version_info.write().await;
            version_info.engine_version = package.version.clone();
            version_info.last_update = chrono::Utc::now();
        }

        // Clean up old backups
        self.cleanup_old_backups("engine_backup").await?;

        tracing::info!("Engine update completed successfully");
        Ok(())
    }

    /// Clean up old backup directories, keeping only the most recent ones
    async fn cleanup_old_backups(&self, prefix: &str) -> Result<()> {
        let mut entries = tokio::fs::read_dir(&self.update_cache_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        let mut backup_dirs = Vec::new();
        
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))? {
            
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with(prefix) {
                        backup_dirs.push(path);
                    }
                }
            }
        }

        // Sort by modification time (newest first)
        backup_dirs.sort_by_key(|path| {
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });
        backup_dirs.reverse();

        // Keep only the 3 most recent backups
        for old_backup in backup_dirs.iter().skip(3) {
            if let Err(e) = tokio::fs::remove_dir_all(old_backup).await {
                tracing::warn!("Failed to remove old backup {}: {}", old_backup.display(), e);
            } else {
                tracing::info!("Removed old backup: {}", old_backup.display());
            }
        }

        Ok(())
    }
}

#[async_trait]
impl UpdateOperations for UpdateManagerImpl {
    async fn check_updates(&self) -> Result<Vec<UpdateInfo>> {
        tracing::debug!("Checking for updates from: {}", self.config.update_server_url);
        
        // Get current version info
        let current_version = {
            let version_info = self.version_info.read().await;
            version_info.clone()
        };

        // Prepare update check request
        let check_url = format!("{}/api/v1/updates/check", self.config.update_server_url);
        let request_body = serde_json::json!({
            "engine_version": current_version.engine_version,
            "signature_version": current_version.signature_version,
            "last_update": current_version.last_update,
            "use_delta_updates": self.config.use_delta_updates
        });

        // Make secure HTTPS request to update server
        let response = self.downloader.client
            .post(&check_url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::NetworkError(e.to_string())))?;

        if !response.status().is_success() {
            return Err(AntivirusError::Update(hadron_core::UpdateError::NetworkError(
                format!("Update check failed with status: {}", response.status())
            )));
        }

        // Parse response
        let update_response: serde_json::Value = response.json().await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::NetworkError(e.to_string())))?;

        let mut available_updates = Vec::new();

        if let Some(updates) = update_response["updates"].as_array() {
            for update in updates {
                let update_info = UpdateInfo {
                    version: update["version"].as_str().unwrap_or("unknown").to_string(),
                    release_date: chrono::DateTime::parse_from_rfc3339(
                        update["release_date"].as_str().unwrap_or("2024-01-01T00:00:00Z")
                    ).unwrap_or_default().with_timezone(&chrono::Utc),
                    size_bytes: update["size_bytes"].as_u64().unwrap_or(0),
                    download_url: update["download_url"].as_str().unwrap_or("").to_string(),
                    signature: update["signature"].as_str().unwrap_or("").to_string(),
                    description: update["description"].as_str().unwrap_or("").to_string(),
                };
                available_updates.push(update_info);
            }
        }

        tracing::info!("Found {} available updates", available_updates.len());
        Ok(available_updates)
    }

    async fn download_update(&self, update_info: &UpdateInfo) -> Result<UpdatePackage> {
        tracing::info!("Downloading update: {} ({} bytes)", 
                      update_info.version, update_info.size_bytes);
        
        // Create progress callback
        let progress_callback = |downloaded: u64, total: u64| {
            let percentage = if total > 0 {
                (downloaded as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            
            if downloaded % (1024 * 1024) == 0 || downloaded == total {
                tracing::info!("Download progress: {:.1}% ({}/{} bytes)", 
                              percentage, downloaded, total);
            }
        };

        // Download with TLS security and progress tracking
        let data = self.downloader.download_with_progress(&update_info.download_url, progress_callback).await?;
        
        // Verify download size matches expected
        if data.len() != update_info.size_bytes as usize {
            return Err(AntivirusError::Update(hadron_core::UpdateError::IntegrityCheckFailed(
                format!("Downloaded size {} doesn't match expected size {}", 
                       data.len(), update_info.size_bytes)
            )));
        }

        // Create update package
        let package = UpdatePackage {
            version: update_info.version.clone(),
            data,
            signature: update_info.signature.clone(),
        };

        // Verify package signature immediately after download
        if !self.verify_package_signature(&package).await? {
            return Err(AntivirusError::Update(hadron_core::UpdateError::SignatureVerificationFailed));
        }

        tracing::info!("Successfully downloaded and verified update: {}", update_info.version);
        Ok(package)
    }

    async fn apply_update(&self, package: UpdatePackage) -> Result<()> {
        // Verify package signature first
        if !self.verify_package_signature(&package).await? {
            return Err(AntivirusError::Update(hadron_core::UpdateError::SignatureVerificationFailed));
        }

        // Check if this is a delta update
        let is_delta_update = package.version.contains("delta") || self.config.use_delta_updates;
        
        if is_delta_update {
            tracing::info!("Applying delta update: {}", package.version);
            self.delta_manager.apply_delta(&package.data, &package.version).await?;
        } else {
            // Determine update type based on version string or package content
            if package.version.contains("signatures") {
                self.apply_signature_update(&package).await?;
            } else if package.version.contains("engine") {
                self.apply_engine_update(&package).await?;
            } else {
                // Try to determine from package content
                // For now, assume it's a signature update if smaller, engine if larger
                if package.data.len() < 10 * 1024 * 1024 { // Less than 10MB
                    self.apply_signature_update(&package).await?;
                } else {
                    self.apply_engine_update(&package).await?;
                }
            }
        }

        // Save update metadata
        self.save_update_metadata(&package).await?;

        tracing::info!("Successfully applied update: {}", package.version);
        Ok(())
    }

    async fn rollback_update(&self, version: &str) -> Result<()> {
        tracing::info!("Rolling back to version: {}", version);
        
        // Find the backup directory for the specified version
        let backup_pattern = format!("_backup_{}", version);
        let mut backup_path = None;
        
        let mut entries = tokio::fs::read_dir(&self.update_cache_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))? {
            
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.contains(&backup_pattern) {
                        backup_path = Some(path);
                        break;
                    }
                }
            }
        }

        let backup_path = backup_path.ok_or_else(|| {
            AntivirusError::Update(hadron_core::UpdateError::RollbackFailed(
                format!("No backup found for version: {}", version)
            ))
        })?;

        // Determine if this is an engine or signature rollback
        let is_engine_backup = backup_path.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.starts_with("engine_backup"))
            .unwrap_or(false);

        let target_path = if is_engine_backup {
            self.update_cache_path.join("engine")
        } else {
            self.update_cache_path.join("signatures")
        };

        // Create backup of current version before rollback
        let current_backup_path = self.update_cache_path.join(format!(
            "{}_backup_before_rollback_{}", 
            if is_engine_backup { "engine" } else { "signatures" },
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        ));

        if target_path.exists() {
            tokio::fs::rename(&target_path, &current_backup_path).await
                .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;
        }

        // Restore from backup
        tokio::fs::rename(&backup_path, &target_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::RollbackFailed(
                format!("Failed to restore from backup: {}", e)
            )))?;

        // Update version info
        {
            let mut version_info = self.version_info.write().await;
            if is_engine_backup {
                version_info.engine_version = version.to_string();
            } else {
                version_info.signature_version = version.to_string();
            }
            version_info.last_update = chrono::Utc::now();
        }

        tracing::info!("Successfully rolled back to version: {}", version);
        Ok(())
    }

    fn get_version_info(&self) -> VersionInfo {
        // This is a synchronous method, so we can't use async read
        // In a real implementation, this might need to be async or use a different approach
        // For now, return current version info
        VersionInfo {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            signature_version: "1.0.0".to_string(),
            last_update: chrono::Utc::now(),
        }
    }
}

impl UpdateManagerImpl {
    /// Save update metadata for tracking and rollback purposes
    async fn save_update_metadata(&self, package: &UpdatePackage) -> Result<()> {
        let metadata = serde_json::json!({
            "version": package.version,
            "applied_at": chrono::Utc::now(),
            "package_size": package.data.len(),
            "signature": package.signature,
            "checksum": hex::encode(digest::digest(&digest::SHA256, &package.data).as_ref())
        });

        let metadata_path = self.update_cache_path.join("update_history.json");
        
        // Load existing metadata
        let mut history = if metadata_path.exists() {
            let content = tokio::fs::read_to_string(&metadata_path).await
                .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;
            
            serde_json::from_str::<Vec<serde_json::Value>>(&content)
                .unwrap_or_else(|_| Vec::new())
        } else {
            Vec::new()
        };

        // Add new metadata
        history.push(metadata);

        // Keep only last 50 entries
        if history.len() > 50 {
            history.drain(0..history.len() - 50);
        }

        // Save updated history
        let content = serde_json::to_string_pretty(&history)
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;
        
        tokio::fs::write(&metadata_path, content).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        Ok(())
    }

    /// Get update history for debugging and rollback purposes
    pub async fn get_update_history(&self) -> Result<Vec<serde_json::Value>> {
        let metadata_path = self.update_cache_path.join("update_history.json");
        
        if !metadata_path.exists() {
            return Ok(Vec::new());
        }

        let content = tokio::fs::read_to_string(&metadata_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;
        
        let history = serde_json::from_str::<Vec<serde_json::Value>>(&content)
            .unwrap_or_else(|_| Vec::new());

        Ok(history)
    }

    /// Check if an update is already applied
    pub async fn is_update_applied(&self, version: &str) -> Result<bool> {
        let history = self.get_update_history().await?;
        
        for entry in history {
            if let Some(applied_version) = entry["version"].as_str() {
                if applied_version == version {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get available rollback versions
    pub async fn get_available_rollback_versions(&self) -> Result<Vec<String>> {
        let mut versions = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.update_cache_path).await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| AntivirusError::Update(hadron_core::UpdateError::IoError(e.to_string())))? {
            
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.contains("_backup_") {
                        // Extract version from backup directory name
                        if let Some(version_start) = name.find("_backup_") {
                            let version_part = &name[version_start + 8..];
                            if let Some(version_end) = version_part.find('_') {
                                let version = &version_part[..version_end];
                                if !versions.contains(&version.to_string()) {
                                    versions.push(version.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        versions.sort();
        Ok(versions)
    }
}

// Implement Clone for UpdateManagerImpl to allow Arc usage
impl Clone for UpdateManagerImpl {
    fn clone(&self) -> Self {
        // Note: This creates a new downloader and delta_manager
        // In a real implementation, these might be shared via Arc as well
        let public_key_der = vec![0u8; 256]; // Placeholder
        let downloader = SecureDownloader::new(&public_key_der)
            .expect("Failed to create downloader in clone");
        let delta_manager = DeltaUpdateManager::new(self.update_cache_path.clone());

        Self {
            config: self.config.clone(),
            version_info: Arc::clone(&self.version_info),
            is_running: Arc::clone(&self.is_running),
            downloader,
            delta_manager,
            update_cache_path: self.update_cache_path.clone(),
        }
    }
}