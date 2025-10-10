use crate::{Result, BrowserExtensionError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};
use url::Url;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlReputationResult {
    pub is_safe: bool,
    pub threat_type: Option<String>,
    pub reputation_score: f32,
    pub block_reason: Option<String>,
    pub categories: Vec<String>,
}
#[derive(Debug, Clone)]
struct CachedResult {
    result: UrlReputationResult,
    timestamp: u64,
    ttl: u64,
}
pub struct UrlReputationChecker {
    cache: RwLock<HashMap<String, CachedResult>>,
    blacklist: RwLock<Vec<String>>,
    whitelist: RwLock<Vec<String>>,
    suspicious_patterns: Vec<regex::Regex>,
}
impl UrlReputationChecker {
    pub fn new() -> Self {
        let suspicious_patterns = vec![
            regex::Regex::new(r"(?i)(phishing|malware|virus|trojan)").unwrap(),
            regex::Regex::new(r"(?i)(download|get|free).*\.(exe|scr|bat|cmd|pif)").unwrap(),
            regex::Regex::new(r"(?i)(bit\.ly|tinyurl|t\.co)/[a-zA-Z0-9]+").unwrap(),
            regex::Regex::new(r"(?i)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}").unwrap(),
        ];
        Self {
            cache: RwLock::new(HashMap::new()),
            blacklist: RwLock::new(Self::load_default_blacklist()),
            whitelist: RwLock::new(Self::load_default_whitelist()),
            suspicious_patterns,
        }
    }
    pub async fn check_url(&self, url_str: &str) -> Result<UrlReputationResult> {
        debug!("Checking URL reputation: {}", url_str);
        let url = Url::parse(url_str)
            .map_err(|e| BrowserExtensionError::UrlReputation(format!("Invalid URL: {}", e)))?;
        if let Some(cached) = self.get_cached_result(url_str).await {
            debug!("Using cached result for URL: {}", url_str);
            return Ok(cached);
        }
        let result = self.perform_reputation_check(&url).await?;
        self.cache_result(url_str, &result).await;
        Ok(result)
    }
    async fn perform_reputation_check(&self, url: &Url) -> Result<UrlReputationResult> {
        let url_str = url.as_str();
        let domain = url.domain().unwrap_or("");
        if self.is_whitelisted(domain).await {
            return Ok(UrlReputationResult {
                is_safe: true,
                threat_type: None,
                reputation_score: 1.0,
                block_reason: None,
                categories: vec!["whitelisted".to_string()],
            });
        }
        if self.is_blacklisted(domain).await {
            return Ok(UrlReputationResult {
                is_safe: false,
                threat_type: Some("blacklisted".to_string()),
                reputation_score: 0.0,
                block_reason: Some("Domain is in blacklist".to_string()),
                categories: vec!["malicious".to_string()],
            });
        }
        let mut reputation_score = 0.5;
        let mut threat_indicators = Vec::new();
        let mut categories = Vec::new();
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(url_str) {
                reputation_score -= 0.2;
                threat_indicators.push("suspicious_pattern".to_string());
            }
        }
        if self.is_suspicious_domain(domain) {
            reputation_score -= 0.3;
            threat_indicators.push("suspicious_domain".to_string());
        }
        if url_str.len() > 200 {
            reputation_score -= 0.1;
            threat_indicators.push("long_url".to_string());
        }
        if self.is_url_shortener(domain) {
            reputation_score -= 0.1;
            categories.push("url_shortener".to_string());
        }
        if let Some(path) = url.path_segments() {
            for segment in path {
                if self.has_suspicious_extension(segment) {
                    reputation_score -= 0.4;
                    threat_indicators.push("suspicious_file".to_string());
                    categories.push("potentially_unwanted".to_string());
                }
            }
        }
        if let Ok(online_result) = self.check_online_reputation(url_str).await {
            reputation_score = (reputation_score + online_result.reputation_score) / 2.0;
            if !online_result.is_safe {
                threat_indicators.extend(online_result.categories);
            }
        }
        let is_safe = reputation_score >= 0.3;
        let threat_type = if !threat_indicators.is_empty() {
            Some(threat_indicators.join(", "))
        } else {
            None
        };
        let block_reason = if !is_safe {
            Some(format!("Low reputation score: {:.2}", reputation_score))
        } else {
            None
        };
        Ok(UrlReputationResult {
            is_safe,
            threat_type,
            reputation_score,
            block_reason,
            categories,
        })
    }
    async fn is_whitelisted(&self, domain: &str) -> bool {
        let whitelist = self.whitelist.read().await;
        whitelist.iter().any(|entry| domain.ends_with(entry))
    }
    async fn is_blacklisted(&self, domain: &str) -> bool {
        let blacklist = self.blacklist.read().await;
        blacklist.iter().any(|entry| domain.contains(entry))
    }
    fn is_suspicious_domain(&self, domain: &str) -> bool {
        let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".click", ".download"];
        if suspicious_tlds.iter().any(|tld| domain.ends_with(tld)) {
            return true;
        }
        if domain.split('.').count() > 4 {
            return true;
        }
        if domain.contains("--") || domain.contains("..") {
            return true;
        }
        if domain.chars().any(|c| c as u32 > 127) {
            return true;
        }
        false
    }
    fn is_url_shortener(&self, domain: &str) -> bool {
        let shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "short.link", "tiny.cc", "is.gd", "buff.ly"
        ];
        shorteners.iter().any(|shortener| domain == *shortener)
    }
    fn has_suspicious_extension(&self, filename: &str) -> bool {
        let suspicious_extensions = [
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
            ".js", ".jar", ".app", ".deb", ".pkg", ".dmg"
        ];
        suspicious_extensions.iter().any(|ext| filename.to_lowercase().ends_with(ext))
    }
    async fn check_online_reputation(&self, url: &str) -> Result<UrlReputationResult> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(UrlReputationResult {
            is_safe: true,
            threat_type: None,
            reputation_score: 0.7,
            block_reason: None,
            categories: vec!["unknown".to_string()],
        })
    }
    async fn get_cached_result(&self, url: &str) -> Option<UrlReputationResult> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(url) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now < cached.timestamp + cached.ttl {
                return Some(cached.result.clone());
            }
        }
        None
    }
    async fn cache_result(&self, url: &str, result: &UrlReputationResult) {
        let mut cache = self.cache.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ttl = if result.is_safe { 3600 } else { 300 };
        cache.insert(url.to_string(), CachedResult {
            result: result.clone(),
            timestamp: now,
            ttl,
        });
        cache.retain(|_, cached| now < cached.timestamp + cached.ttl);
    }
    pub async fn update_blacklist(&self, domains: Vec<String>) {
        let mut blacklist = self.blacklist.write().await;
        *blacklist = domains;
        debug!("Updated blacklist with {} domains", blacklist.len());
    }
    pub async fn update_whitelist(&self, domains: Vec<String>) {
        let mut whitelist = self.whitelist.write().await;
        *whitelist = domains;
        debug!("Updated whitelist with {} domains", whitelist.len());
    }
    fn load_default_blacklist() -> Vec<String> {
        vec![
            "malware-site.com".to_string(),
            "phishing-example.net".to_string(),
            "suspicious-domain.tk".to_string(),
            "fake-bank.ml".to_string(),
        ]
    }
    fn load_default_whitelist() -> Vec<String> {
        vec![
            "google.com".to_string(),
            "microsoft.com".to_string(),
            "github.com".to_string(),
            "stackoverflow.com".to_string(),
            "wikipedia.org".to_string(),
        ]
    }
}
impl Default for UrlReputationChecker {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_whitelist_check() {
        let checker = UrlReputationChecker::new();
        let result = checker.check_url("https:
        assert!(result.is_safe);
        assert_eq!(result.reputation_score, 1.0);
    }
    #[tokio::test]
    async fn test_suspicious_pattern_detection() {
        let checker = UrlReputationChecker::new();
        let result = checker.check_url("https:
        assert!(!result.is_safe);
        assert!(result.threat_type.is_some());
    }
    #[tokio::test]
    async fn test_url_shortener_detection() {
        let checker = UrlReputationChecker::new();
        let result = checker.check_url("https:
        assert!(result.categories.contains(&"url_shortener".to_string()));
    }
    #[tokio::test]
    async fn test_cache_functionality() {
        let checker = UrlReputationChecker::new();
        let url = "https:
        let result1 = checker.check_url(url).await.unwrap();
        let result2 = checker.check_url(url).await.unwrap();
        assert_eq!(result1.reputation_score, result2.reputation_score);
    }
}