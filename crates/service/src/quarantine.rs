use hadron_core::{Result, QuarantineOperations, QuarantineId, QuarantineEntry, ThreatInfo};
use hadron_core::QuarantineConfig;
use async_trait::async_trait;
use std::path::Path;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

// Encryption and database dependencies
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, OsRng, AeadCore};
use sqlx::{SqlitePool, Row};
use sha2::{Sha256, Digest};
use rand::RngCore;

/// Quarantine statistics for monitoring and reporting
#[derive(Debug, Clone)]
pub struct QuarantineStatistics {
    pub total_entries: u32,
    pub total_size_bytes: u64,
    pub threat_type_distribution: std::collections::HashMap<hadron_core::ThreatType, u32>,
    pub severity_distribution: std::collections::HashMap<hadron_core::ThreatSeverity, u32>,
    pub oldest_entry: Option<chrono::DateTime<chrono::Utc>>,
    pub newest_entry: Option<chrono::DateTime<chrono::Utc>>,
}

/// Enhanced quarantine manager implementation with AES-256 encryption and SQLite database
pub struct QuarantineManagerImpl {
    config: QuarantineConfig,
    quarantine_path: std::path::PathBuf,
    db_pool: SqlitePool,
    encryption_key: [u8; 32],
    quarantine_entries: Arc<RwLock<HashMap<QuarantineId, QuarantineEntry>>>,
}

impl QuarantineManagerImpl {
    /// Create a new quarantine manager with database and encryption support
    pub async fn new(config: &QuarantineConfig) -> Result<Self> {
        // Create quarantine directory if it doesn't exist
        let quarantine_path = std::path::PathBuf::from("./quarantine");
        std::fs::create_dir_all(&quarantine_path)?;
        
        // Initialize SQLite database
        let db_path = quarantine_path.join("quarantine.db");
        let db_url = format!("sqlite:{}", db_path.display());
        let db_pool = SqlitePool::connect(&db_url).await
            .map_err(|e| hadron_core::AntivirusError::Database(format!("Failed to connect to database: {}", e)))?;
        
        // Create database tables
        Self::create_tables(&db_pool).await?;
        
        // Load or generate encryption key
        let key_path = quarantine_path.join("encryption.key");
        let encryption_key = Self::load_or_generate_key(&key_path)?;
        
        let manager = Self {
            config: config.clone(),
            quarantine_path,
            db_pool,
            encryption_key,
            quarantine_entries: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Load existing entries from database
        manager.load_entries_from_db().await?;
        
        Ok(manager)
    }
    
    /// Create database tables for quarantine metadata
    async fn create_tables(pool: &SqlitePool) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS quarantine_entries (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                encrypted_path TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                threat_severity TEXT NOT NULL,
                detection_method TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                quarantine_time TEXT NOT NULL,
                additional_info TEXT
            )
            "#
        )
        .execute(pool)
        .await
        .map_err(|e| hadron_core::AntivirusError::Database(format!("Failed to create tables: {}", e)))?;
        
        Ok(())
    }
    
    /// Load or generate encryption key
    fn load_or_generate_key(key_path: &Path) -> Result<[u8; 32]> {
        if key_path.exists() {
            // Load existing key
            let key_data = std::fs::read(key_path)
                .map_err(|e| hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::EncryptionFailed(format!("Failed to read key file: {}", e))
                ))?;
            
            if key_data.len() != 32 {
                return Err(hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::EncryptionFailed("Invalid key file size".to_string())
                ));
            }
            
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_data);
            Ok(key)
        } else {
            // Generate new key
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            
            // Create parent directory if needed
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| hadron_core::AntivirusError::Quarantine(
                        hadron_core::QuarantineError::EncryptionFailed(format!("Failed to create key directory: {}", e))
                    ))?;
            }
            
            // Save key to file
            std::fs::write(key_path, &key)
                .map_err(|e| hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::EncryptionFailed(format!("Failed to save key file: {}", e))
                ))?;
            
            tracing::info!("Generated new encryption key: {}", key_path.display());
            Ok(key)
        }
    }
    
    /// Load existing quarantine entries from database
    async fn load_entries_from_db(&self) -> Result<()> {
        let rows = sqlx::query("SELECT * FROM quarantine_entries")
            .fetch_all(&self.db_pool)
            .await
            .map_err(|e| hadron_core::AntivirusError::Database(format!("Failed to load entries: {}", e)))?;
        
        let mut entries = self.quarantine_entries.write().await;
        
        for row in rows {
            let id: String = row.get("id");
            let quarantine_id = uuid::Uuid::parse_str(&id)
                .map_err(|e| hadron_core::AntivirusError::Database(format!("Invalid UUID in database: {}", e)))?;
            
            let threat_info = ThreatInfo {
                id: uuid::Uuid::new_v4(),
                name: row.get("threat_name"),
                threat_type: serde_json::from_str(&row.get::<String, _>("threat_type"))
                    .unwrap_or(hadron_core::ThreatType::Unknown),
                severity: serde_json::from_str(&row.get::<String, _>("threat_severity"))
                    .unwrap_or(hadron_core::ThreatSeverity::Medium),
                file_path: std::path::PathBuf::from(row.get::<String, _>("original_path")),
                file_hash: row.get("file_hash"),
                detection_method: serde_json::from_str(&row.get::<String, _>("detection_method"))
                    .unwrap_or(hadron_core::DetectionMethod::Signature),
                timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("quarantine_time"))
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                additional_info: serde_json::from_str(&row.get::<String, _>("additional_info"))
                    .unwrap_or_default(),
            };
            
            let entry = QuarantineEntry {
                id: quarantine_id,
                original_path: std::path::PathBuf::from(row.get::<String, _>("original_path")),
                threat_info,
                quarantine_time: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("quarantine_time"))
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                file_size: row.get::<i64, _>("file_size") as u64,
                encrypted_path: std::path::PathBuf::from(row.get::<String, _>("encrypted_path")),
            };
            
            entries.insert(quarantine_id, entry);
        }
        
        tracing::info!("Loaded {} quarantine entries from database", entries.len());
        Ok(())
    }

    /// Get the count of quarantined files
    pub async fn get_quarantine_count(&self) -> Result<u32> {
        let entries = self.quarantine_entries.read().await;
        Ok(entries.len() as u32)
    }

    /// Encrypt a file for quarantine storage using AES-256-GCM
    async fn encrypt_file(&self, source_path: &Path, encrypted_path: &Path) -> Result<()> {
        // Read source file
        let plaintext = tokio::fs::read(source_path).await
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::EncryptionFailed(format!("Failed to read source file: {}", e))
            ))?;
        
        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);
        
        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt the data
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::EncryptionFailed(format!("Encryption failed: {}", e))
            ))?;
        
        // Combine nonce and ciphertext
        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&nonce);
        encrypted_data.extend_from_slice(&ciphertext);
        
        // Create parent directory if needed
        if let Some(parent) = encrypted_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::EncryptionFailed(format!("Failed to create directory: {}", e))
                ))?;
        }
        
        // Write encrypted file
        tokio::fs::write(encrypted_path, encrypted_data).await
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::EncryptionFailed(format!("Failed to write encrypted file: {}", e))
            ))?;
        
        tracing::debug!("File encrypted and moved to quarantine: {} -> {}", 
                       source_path.display(), encrypted_path.display());
        Ok(())
    }

    /// Decrypt a file from quarantine storage using AES-256-GCM
    async fn decrypt_file(&self, encrypted_path: &Path, target_path: &Path) -> Result<()> {
        // Read encrypted file
        let encrypted_data = tokio::fs::read(encrypted_path).await
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::DecryptionFailed(format!("Failed to read encrypted file: {}", e))
            ))?;
        
        if encrypted_data.len() < 12 {
            return Err(hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::DecryptionFailed("Invalid encrypted file format".to_string())
            ));
        }
        
        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);
        
        // Decrypt the data
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::DecryptionFailed(format!("Decryption failed: {}", e))
            ))?;
        
        // Create parent directory if needed
        if let Some(parent) = target_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::DecryptionFailed(format!("Failed to create directory: {}", e))
                ))?;
        }
        
        // Write decrypted file
        tokio::fs::write(target_path, plaintext).await
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::DecryptionFailed(format!("Failed to write decrypted file: {}", e))
            ))?;
        
        tracing::debug!("File decrypted and restored from quarantine: {} -> {}", 
                       encrypted_path.display(), target_path.display());
        Ok(())
    }

    /// Generate unique quarantine file path
    fn generate_quarantine_path(&self, quarantine_id: QuarantineId) -> std::path::PathBuf {
        self.quarantine_path.join(format!("{}.quar", quarantine_id))
    }
    
    /// Save quarantine entry to database
    async fn save_entry_to_db(&self, entry: &QuarantineEntry) -> Result<()> {
        let threat_type_json = serde_json::to_string(&entry.threat_info.threat_type)
            .unwrap_or_else(|_| "\"Unknown\"".to_string());
        let threat_severity_json = serde_json::to_string(&entry.threat_info.severity)
            .unwrap_or_else(|_| "\"Medium\"".to_string());
        let detection_method_json = serde_json::to_string(&entry.threat_info.detection_method)
            .unwrap_or_else(|_| "\"Signature\"".to_string());
        let additional_info_json = serde_json::to_string(&entry.threat_info.additional_info)
            .unwrap_or_else(|_| "{}".to_string());
        
        sqlx::query(
            r#"
            INSERT INTO quarantine_entries 
            (id, original_path, encrypted_path, threat_name, threat_type, threat_severity, 
             detection_method, file_hash, file_size, quarantine_time, additional_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(entry.id.to_string())
        .bind(entry.original_path.to_string_lossy().to_string())
        .bind(entry.encrypted_path.to_string_lossy().to_string())
        .bind(&entry.threat_info.name)
        .bind(threat_type_json)
        .bind(threat_severity_json)
        .bind(detection_method_json)
        .bind(&entry.threat_info.file_hash)
        .bind(entry.file_size as i64)
        .bind(entry.quarantine_time.to_rfc3339())
        .bind(additional_info_json)
        .execute(&self.db_pool)
        .await
        .map_err(|e| hadron_core::AntivirusError::Database(format!("Failed to save entry: {}", e)))?;
        
        Ok(())
    }
    
    /// Remove quarantine entry from database
    async fn remove_entry_from_db(&self, quarantine_id: QuarantineId) -> Result<()> {
        sqlx::query("DELETE FROM quarantine_entries WHERE id = ?")
            .bind(quarantine_id.to_string())
            .execute(&self.db_pool)
            .await
            .map_err(|e| hadron_core::AntivirusError::Database(format!("Failed to remove entry: {}", e)))?;
        
        Ok(())
    }
    
    /// Calculate file hash for integrity verification
    async fn calculate_file_hash(&self, file_path: &Path) -> Result<String> {
        let data = tokio::fs::read(file_path).await
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::HashCalculationFailed(format!("Failed to read file: {}", e))
            ))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        
        Ok(format!("{:x}", hash))
    }

    /// Clean up old quarantine entries
    pub async fn cleanup_old_entries(&self) -> Result<()> {
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(self.config.auto_delete_days as i64);
        let mut entries = self.quarantine_entries.write().await;
        let mut to_remove = Vec::new();

        for (id, entry) in entries.iter() {
            if entry.quarantine_time < cutoff_date {
                to_remove.push(*id);
            }
        }

        for id in to_remove {
            if let Some(entry) = entries.remove(&id) {
                // Delete the encrypted file
                if entry.encrypted_path.exists() {
                    if let Err(e) = tokio::fs::remove_file(&entry.encrypted_path).await {
                        tracing::warn!("Failed to delete encrypted file {}: {}", entry.encrypted_path.display(), e);
                    }
                }
                
                // Remove from database
                if let Err(e) = self.remove_entry_from_db(id).await {
                    tracing::warn!("Failed to remove entry from database: {}", e);
                }
                
                tracing::info!("Automatically deleted old quarantine entry: {}", id);
            }
        }

        Ok(())
    }
    
    /// Verify quarantine integrity
    pub async fn verify_integrity(&self) -> Result<Vec<QuarantineId>> {
        let entries = self.quarantine_entries.read().await;
        let mut corrupted_entries = Vec::new();
        
        for (id, entry) in entries.iter() {
            // Check if encrypted file exists
            if !entry.encrypted_path.exists() {
                tracing::warn!("Encrypted file missing for entry {}: {}", id, entry.encrypted_path.display());
                corrupted_entries.push(*id);
                continue;
            }
            
            // Verify file size matches
            if let Ok(metadata) = tokio::fs::metadata(&entry.encrypted_path).await {
                // Note: encrypted file will be larger due to nonce and authentication tag
                if metadata.len() < entry.file_size {
                    tracing::warn!("File size mismatch for entry {}: expected at least {}, found {}", 
                                 id, entry.file_size, metadata.len());
                    corrupted_entries.push(*id);
                }
            } else {
                tracing::warn!("Cannot read metadata for entry {}: {}", id, entry.encrypted_path.display());
                corrupted_entries.push(*id);
            }
        }
        
        Ok(corrupted_entries)
    }
    
    /// Get quarantine statistics
    pub async fn get_statistics(&self) -> Result<QuarantineStatistics> {
        let entries = self.quarantine_entries.read().await;
        let total_entries = entries.len() as u32;
        let total_size: u64 = entries.values().map(|e| e.file_size).sum();
        
        let mut threat_type_counts = std::collections::HashMap::new();
        let mut severity_counts = std::collections::HashMap::new();
        
        for entry in entries.values() {
            *threat_type_counts.entry(entry.threat_info.threat_type.clone()).or_insert(0) += 1;
            *severity_counts.entry(entry.threat_info.severity.clone()).or_insert(0) += 1;
        }
        
        Ok(QuarantineStatistics {
            total_entries,
            total_size_bytes: total_size,
            threat_type_distribution: threat_type_counts,
            severity_distribution: severity_counts,
            oldest_entry: entries.values().map(|e| e.quarantine_time).min(),
            newest_entry: entries.values().map(|e| e.quarantine_time).max(),
        })
    }
}

#[async_trait]
impl QuarantineOperations for QuarantineManagerImpl {
    async fn quarantine_file(&self, path: &Path, threat_info: &ThreatInfo) -> Result<QuarantineId> {
        let quarantine_id = uuid::Uuid::new_v4();
        let encrypted_path = self.generate_quarantine_path(quarantine_id);
        
        // Verify file exists and get metadata
        let metadata = tokio::fs::metadata(path).await
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::FileNotFound(format!("Source file not found: {}", e))
            ))?;
        let file_size = metadata.len();

        // Check quarantine storage limits
        let current_stats = self.get_statistics().await?;
        let max_size_bytes = self.config.max_size_gb * 1024 * 1024 * 1024;
        
        if current_stats.total_size_bytes + file_size > max_size_bytes {
            return Err(hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::StorageFull
            ));
        }

        // Calculate file hash for integrity verification
        let file_hash = self.calculate_file_hash(path).await?;

        // Encrypt and move file to quarantine
        self.encrypt_file(path, &encrypted_path).await?;

        // Create quarantine entry with calculated hash
        let mut updated_threat_info = threat_info.clone();
        updated_threat_info.file_hash = file_hash;
        
        let entry = QuarantineEntry {
            id: quarantine_id,
            original_path: path.to_path_buf(),
            threat_info: updated_threat_info,
            quarantine_time: chrono::Utc::now(),
            file_size,
            encrypted_path,
        };

        // Save to database first
        self.save_entry_to_db(&entry).await?;

        // Store entry in memory
        {
            let mut entries = self.quarantine_entries.write().await;
            entries.insert(quarantine_id, entry);
        }

        // Remove original file
        tokio::fs::remove_file(path).await
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::OriginalFileRemovalFailed(format!("Failed to remove original file: {}", e))
            ))?;

        hadron_core::log_quarantine_operation(
            hadron_core::QuarantineOperation::Quarantine,
            &quarantine_id,
            path,
            &Ok(())
        );

        tracing::info!("File quarantined: {} -> {}", path.display(), quarantine_id);
        Ok(quarantine_id)
    }

    async fn restore_file(&self, quarantine_id: QuarantineId) -> Result<()> {
        let entry = {
            let entries = self.quarantine_entries.read().await;
            entries.get(&quarantine_id).cloned()
                .ok_or_else(|| hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::EntryNotFound(quarantine_id.to_string())
                ))?
        };

        // Check if original path is available
        if entry.original_path.exists() {
            return Err(hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::RestoreFailed(
                    "File already exists at original location".to_string()
                )
            ));
        }

        // Verify encrypted file exists
        if !entry.encrypted_path.exists() {
            return Err(hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::RestoreFailed(
                    "Encrypted file not found in quarantine".to_string()
                )
            ));
        }

        // Create parent directory if needed
        if let Some(parent) = entry.original_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::RestoreFailed(format!("Failed to create parent directory: {}", e))
                ))?;
        }

        // Decrypt and restore file
        self.decrypt_file(&entry.encrypted_path, &entry.original_path).await?;

        // Verify restored file integrity
        let restored_hash = self.calculate_file_hash(&entry.original_path).await?;
        if restored_hash != entry.threat_info.file_hash {
            // Remove the potentially corrupted restored file
            let _ = tokio::fs::remove_file(&entry.original_path).await;
            return Err(hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::RestoreFailed(
                    "File integrity verification failed after restore".to_string()
                )
            ));
        }

        // Remove from quarantine storage
        tokio::fs::remove_file(&entry.encrypted_path).await
            .map_err(|e| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::RestoreFailed(format!("Failed to remove encrypted file: {}", e))
            ))?;
        
        // Remove from database
        self.remove_entry_from_db(quarantine_id).await?;
        
        // Remove from memory
        {
            let mut entries = self.quarantine_entries.write().await;
            entries.remove(&quarantine_id);
        }

        hadron_core::log_quarantine_operation(
            hadron_core::QuarantineOperation::Restore,
            &quarantine_id,
            &entry.original_path,
            &Ok(())
        );

        tracing::info!("File restored from quarantine: {} -> {}", 
                      quarantine_id, entry.original_path.display());
        Ok(())
    }

    async fn delete_quarantined(&self, quarantine_id: QuarantineId) -> Result<()> {
        let entry = {
            let mut entries = self.quarantine_entries.write().await;
            entries.remove(&quarantine_id)
                .ok_or_else(|| hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::EntryNotFound(quarantine_id.to_string())
                ))?
        };

        // Delete encrypted file if it exists
        if entry.encrypted_path.exists() {
            tokio::fs::remove_file(&entry.encrypted_path).await
                .map_err(|e| hadron_core::AntivirusError::Quarantine(
                    hadron_core::QuarantineError::DeletionFailed(format!("Failed to delete encrypted file: {}", e))
                ))?;
        }

        // Remove from database
        self.remove_entry_from_db(quarantine_id).await?;

        hadron_core::log_quarantine_operation(
            hadron_core::QuarantineOperation::Delete,
            &quarantine_id,
            &entry.original_path,
            &Ok(())
        );

        tracing::info!("Quarantined file permanently deleted: {}", quarantine_id);
        Ok(())
    }

    async fn list_quarantined(&self) -> Result<Vec<QuarantineEntry>> {
        let entries = self.quarantine_entries.read().await;
        Ok(entries.values().cloned().collect())
    }

    async fn get_quarantine_entry(&self, quarantine_id: QuarantineId) -> Result<QuarantineEntry> {
        let entries = self.quarantine_entries.read().await;
        entries.get(&quarantine_id).cloned()
            .ok_or_else(|| hadron_core::AntivirusError::Quarantine(
                hadron_core::QuarantineError::EntryNotFound(quarantine_id.to_string())
            ))
    }
}