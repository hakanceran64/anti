use crate::Result;
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use std::fs::{File, Metadata};
use std::io::{Read, BufReader};
use tokio::fs as async_fs;
use tokio::io::{AsyncReadExt, BufReader as AsyncBufReader};
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub modified: std::time::SystemTime,
    pub created: std::time::SystemTime,
    pub is_executable: bool,
    pub extension: Option<String>,
    pub mime_type: Option<String>,
}
#[derive(Debug, Clone)]
pub struct FileHashes {
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
}
pub struct FileScanner {
    max_file_size: u64,
    buffer_size: usize,
    excluded_extensions: Vec<String>,
    excluded_paths: Vec<PathBuf>,
}
impl FileScanner {
    pub fn new() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,
            buffer_size: 64 * 1024,
            excluded_extensions: vec![
                "tmp".to_string(),
                "log".to_string(),
                "bak".to_string(),
            ],
            excluded_paths: Vec::new(),
        }
    }
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
    pub fn with_excluded_extensions(mut self, extensions: Vec<String>) -> Self {
        self.excluded_extensions = extensions;
        self
    }
    pub fn with_excluded_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.excluded_paths = paths;
        self
    }
    pub async fn get_file_info(&self, path: &Path) -> Result<FileInfo> {
        let metadata = async_fs::metadata(path).await?;
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase());
        let is_executable = self.is_executable_file(path, &metadata);
        let mime_type = self.detect_mime_type(path).await;
        Ok(FileInfo {
            path: path.to_path_buf(),
            size: metadata.len(),
            modified: metadata.modified()?,
            created: metadata.created().unwrap_or_else(|_| std::time::SystemTime::now()),
            is_executable,
            extension,
            mime_type,
        })
    }
    pub fn should_scan_file(&self, file_info: &FileInfo) -> bool {
        if file_info.size > self.max_file_size {
            tracing::debug!("Skipping large file: {} ({} bytes)", 
                           file_info.path.display(), file_info.size);
            return false;
        }
        if let Some(ref ext) = file_info.extension {
            if self.excluded_extensions.contains(ext) {
                tracing::debug!("Skipping excluded extension: {}", file_info.path.display());
                return false;
            }
        }
        for excluded_path in &self.excluded_paths {
            if file_info.path.starts_with(excluded_path) {
                tracing::debug!("Skipping excluded path: {}", file_info.path.display());
                return false;
            }
        }
        true
    }
    pub async fn calculate_hashes(&self, path: &Path) -> Result<FileHashes> {
        let file = async_fs::File::open(path).await?;
        let mut reader = AsyncBufReader::with_capacity(self.buffer_size, file);
        let mut sha256_hasher = Sha256::new();
        let mut md5_hasher = md5::Md5::new();
        let mut sha1_hasher = sha1::Sha1::new();
        let mut buffer = vec![0u8; self.buffer_size];
        loop {
            let bytes_read = reader.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            let data = &buffer[..bytes_read];
            sha256_hasher.update(data);
            md5_hasher.update(data);
            sha1_hasher.update(data);
        }
        Ok(FileHashes {
            sha256: format!("{:x}", sha256_hasher.finalize()),
            md5: format!("{:x}", md5_hasher.finalize()),
            sha1: format!("{:x}", sha1_hasher.finalize()),
        })
    }
    pub async fn calculate_sha256(&self, path: &Path) -> Result<String> {
        let file = async_fs::File::open(path).await?;
        let mut reader = AsyncBufReader::with_capacity(self.buffer_size, file);
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; self.buffer_size];
        loop {
            let bytes_read = reader.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
    pub async fn read_file_content(&self, path: &Path) -> Result<Vec<u8>> {
        let metadata = async_fs::metadata(path).await?;
        if metadata.len() > self.max_file_size {
            return Err(crate::AntivirusError::ScanEngine(
                crate::ScanEngineError::FileAccessDenied(
                    format!("File too large: {} bytes", metadata.len())
                )
            ));
        }
        let content = async_fs::read(path).await?;
        Ok(content)
    }
    pub async fn read_file_chunks<F>(&self, path: &Path, mut chunk_handler: F) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<bool>,
    {
        let file = async_fs::File::open(path).await?;
        let mut reader = AsyncBufReader::with_capacity(self.buffer_size, file);
        let mut buffer = vec![0u8; self.buffer_size];
        loop {
            let bytes_read = reader.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            let should_continue = chunk_handler(&buffer[..bytes_read])?;
            if !should_continue {
                break;
            }
        }
        Ok(())
    }
    fn is_executable_file(&self, path: &Path, metadata: &Metadata) -> bool {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext = ext.to_lowercase();
            match ext.as_str() {
                "exe" | "dll" | "sys" | "com" | "scr" | "bat" | "cmd" | "ps1" | "vbs" | "js" => return true,
                _ => {}
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = metadata.permissions();
            return permissions.mode() & 0o111 != 0;
        }
        false
    }
    async fn detect_mime_type(&self, path: &Path) -> Option<String> {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext = ext.to_lowercase();
            let mime_type = match ext.as_str() {
                "exe" | "dll" | "sys" => "application/x-msdownload",
                "pdf" => "application/pdf",
                "doc" | "docx" => "application/msword",
                "xls" | "xlsx" => "application/vnd.ms-excel",
                "ppt" | "pptx" => "application/vnd.ms-powerpoint",
                "zip" => "application/zip",
                "rar" => "application/x-rar-compressed",
                "7z" => "application/x-7z-compressed",
                "txt" => "text/plain",
                "html" | "htm" => "text/html",
                "js" => "application/javascript",
                "json" => "application/json",
                "xml" => "application/xml",
                "jpg" | "jpeg" => "image/jpeg",
                "png" => "image/png",
                "gif" => "image/gif",
                "mp3" => "audio/mpeg",
                "mp4" => "video/mp4",
                "avi" => "video/x-msvideo",
                _ => return None,
            };
            Some(mime_type.to_string())
        } else {
            None
        }
    }
    pub async fn get_file_signature(&self, path: &Path) -> Result<Vec<u8>> {
        let file = async_fs::File::open(path).await?;
        let mut reader = AsyncBufReader::new(file);
        let mut signature = vec![0u8; 16];
        let bytes_read = reader.read(&mut signature).await?;
        signature.truncate(bytes_read);
        Ok(signature)
    }
    pub async fn is_pe_file(&self, path: &Path) -> Result<bool> {
        let signature = self.get_file_signature(path).await?;
        if signature.len() >= 2 && signature[0] == 0x4D && signature[1] == 0x5A {
            let content = self.read_file_content(path).await?;
            if content.len() >= 64 {
                if content.len() >= 60 {
                    let pe_offset = u32::from_le_bytes([
                        content[60], content[61], content[62], content[63]
                    ]) as usize;
                    if content.len() >= pe_offset + 4 {
                        return Ok(content[pe_offset..pe_offset + 4] == [0x50, 0x45, 0x00, 0x00]);
                    }
                }
            }
        }
        Ok(false)
    }
    pub async fn extract_strings(&self, path: &Path, min_length: usize) -> Result<Vec<String>> {
        let content = self.read_file_content(path).await?;
        let mut strings = Vec::new();
        let mut current_string = String::new();
        for &byte in &content {
            if byte.is_ascii_graphic() || byte == b' ' {
                current_string.push(byte as char);
            } else {
                if current_string.len() >= min_length {
                    strings.push(current_string.clone());
                }
                current_string.clear();
            }
        }
        if current_string.len() >= min_length {
            strings.push(current_string);
        }
        Ok(strings)
    }
}
impl Default for FileScanner {
    fn default() -> Self {
        Self::new()
    }
}
pub struct DirectoryWalker {
    max_depth: Option<usize>,
    follow_symlinks: bool,
    excluded_dirs: Vec<String>,
}
impl DirectoryWalker {
    pub fn new() -> Self {
        Self {
            max_depth: None,
            follow_symlinks: false,
            excluded_dirs: vec![
                "System Volume Information".to_string(),
                "$Recycle.Bin".to_string(),
                "Windows".to_string(),
                "Program Files".to_string(),
                "Program Files (x86)".to_string(),
            ],
        }
    }
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }
    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }
    pub fn with_excluded_dirs(mut self, dirs: Vec<String>) -> Self {
        self.excluded_dirs = dirs;
        self
    }
    pub async fn walk_directory(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        self.walk_recursive(root, 0, &mut files).await?;
        Ok(files)
    }
    pub async fn walk_with_callback<F>(&self, root: &Path, mut callback: F) -> Result<()>
    where
        F: FnMut(&Path) -> Result<bool>,
    {
        self.walk_recursive_with_callback(root, 0, &mut callback).await
    }
    async fn walk_recursive(&self, dir: &Path, depth: usize, files: &mut Vec<PathBuf>) -> Result<()> {
        if let Some(max_depth) = self.max_depth {
            if depth > max_depth {
                return Ok(());
            }
        }
        if let Some(dir_name) = dir.file_name().and_then(|n| n.to_str()) {
            if self.excluded_dirs.contains(&dir_name.to_string()) {
                tracing::debug!("Skipping excluded directory: {}", dir.display());
                return Ok(());
            }
        }
        let mut entries = async_fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                files.push(path);
            } else if metadata.is_dir() {
                if self.follow_symlinks || !metadata.file_type().is_symlink() {
                    self.walk_recursive(&path, depth + 1, files).await?;
                }
            }
        }
        Ok(())
    }
    async fn walk_recursive_with_callback<F>(&self, dir: &Path, depth: usize, callback: &mut F) -> Result<()>
    where
        F: FnMut(&Path) -> Result<bool>,
    {
        if let Some(max_depth) = self.max_depth {
            if depth > max_depth {
                return Ok(());
            }
        }
        if let Some(dir_name) = dir.file_name().and_then(|n| n.to_str()) {
            if self.excluded_dirs.contains(&dir_name.to_string()) {
                return Ok(());
            }
        }
        let mut entries = async_fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                let should_continue = callback(&path)?;
                if !should_continue {
                    return Ok(());
                }
            } else if metadata.is_dir() {
                if self.follow_symlinks || !metadata.file_type().is_symlink() {
                    self.walk_recursive_with_callback(&path, depth + 1, callback).await?;
                }
            }
        }
        Ok(())
    }
}
impl Default for DirectoryWalker {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;
    #[tokio::test]
    async fn test_file_scanner_creation() {
        let scanner = FileScanner::new();
        assert_eq!(scanner.max_file_size, 100 * 1024 * 1024);
        assert_eq!(scanner.buffer_size, 64 * 1024);
    }
    #[tokio::test]
    async fn test_file_info() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").await.unwrap();
        let scanner = FileScanner::new();
        let file_info = scanner.get_file_info(&test_file).await.unwrap();
        assert_eq!(file_info.path, test_file);
        assert_eq!(file_info.size, 12);
        assert_eq!(file_info.extension, Some("txt".to_string()));
        assert!(!file_info.is_executable);
    }
    #[tokio::test]
    async fn test_hash_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").await.unwrap();
        let scanner = FileScanner::new();
        let hashes = scanner.calculate_hashes(&test_file).await.unwrap();
        assert!(!hashes.sha256.is_empty());
        assert!(!hashes.md5.is_empty());
        assert!(!hashes.sha1.is_empty());
        assert_eq!(hashes.sha256.len(), 64);
    }
    #[tokio::test]
    async fn test_should_scan_file() {
        let scanner = FileScanner::new()
            .with_excluded_extensions(vec!["tmp".to_string(), "log".to_string()]);
        let file_info = FileInfo {
            path: PathBuf::from("test.txt"),
            size: 1024,
            modified: std::time::SystemTime::now(),
            created: std::time::SystemTime::now(),
            is_executable: false,
            extension: Some("txt".to_string()),
            mime_type: Some("text/plain".to_string()),
        };
        assert!(scanner.should_scan_file(&file_info));
        let excluded_file_info = FileInfo {
            path: PathBuf::from("test.tmp"),
            size: 1024,
            modified: std::time::SystemTime::now(),
            created: std::time::SystemTime::now(),
            is_executable: false,
            extension: Some("tmp".to_string()),
            mime_type: None,
        };
        assert!(!scanner.should_scan_file(&excluded_file_info));
    }
    #[tokio::test]
    async fn test_directory_walker() {
        let temp_dir = TempDir::new().unwrap();
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).await.unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = sub_dir.join("file2.txt");
        fs::write(&file1, "content1").await.unwrap();
        fs::write(&file2, "content2").await.unwrap();
        let walker = DirectoryWalker::new();
        let files = walker.walk_directory(temp_dir.path()).await.unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.contains(&file1));
        assert!(files.contains(&file2));
    }
    #[tokio::test]
    async fn test_pe_file_detection() {
        let temp_dir = TempDir::new().unwrap();
        let pe_file = temp_dir.path().join("test.exe");
        let mut pe_content = vec![0u8; 64];
        pe_content[0] = 0x4D;
        pe_content[1] = 0x5A;
        pe_content[60] = 60;
        pe_content[61] = 0;
        pe_content[62] = 0;
        pe_content[63] = 0;
        pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        fs::write(&pe_file, pe_content).await.unwrap();
        let scanner = FileScanner::new();
        let is_pe = scanner.is_pe_file(&pe_file).await.unwrap();
        assert!(is_pe);
    }
    #[tokio::test]
    async fn test_string_extraction() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.bin");
        let content = b"Hello\x00World\x00This is a test\x00\xFF\xFE";
        fs::write(&test_file, content).await.unwrap();
        let scanner = FileScanner::new();
        let strings = scanner.extract_strings(&test_file, 4).await.unwrap();
        assert!(strings.contains(&"Hello".to_string()));
        assert!(strings.contains(&"World".to_string()));
        assert!(strings.contains(&"This is a test".to_string()));
    }
}