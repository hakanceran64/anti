use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    Result, AntivirusError, ThreatType, DetectionMethod,
    traits::{MLClassification, FeatureVector, ClassificationResult, ModelInfo}
};

/// Machine Learning Engine for malware detection
#[derive(Debug)]
pub struct MLEngine {
    feature_extractor: Arc<FeatureExtractor>,
    classifier: Arc<RwLock<MLClassifier>>,
    model_manager: Arc<ModelManager>,
    config: MLConfig,
}

/// Configuration for ML Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLConfig {
    pub enabled: bool,
    pub confidence_threshold: f32,
    pub model_update_interval_hours: u32,
    pub max_feature_extraction_time_ms: u64,
    pub use_ensemble: bool,
    pub fallback_to_heuristics: bool,
}

impl Default for MLConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            confidence_threshold: 0.7,
            model_update_interval_hours: 24,
            max_feature_extraction_time_ms: 5000,
            use_ensemble: true,
            fallback_to_heuristics: true,
        }
    }
}

/// Feature extraction component
#[derive(Debug)]
pub struct FeatureExtractor {
    extractors: Vec<Box<dyn FeatureExtractorTrait + Send + Sync>>,
}

/// Trait for different feature extraction methods
#[async_trait]
pub trait FeatureExtractorTrait {
    async fn extract(&self, file_data: &[u8]) -> Result<Vec<f32>>;
    fn get_feature_names(&self) -> Vec<String>;
    fn get_feature_count(&self) -> usize;
}

/// Static analysis feature extractor
#[derive(Debug)]
pub struct StaticFeatureExtractor;

/// Dynamic analysis feature extractor
#[derive(Debug)]
pub struct DynamicFeatureExtractor;

/// N-gram feature extractor
#[derive(Debug)]
pub struct NGramFeatureExtractor {
    n: usize,
    max_features: usize,
}

/// PE header feature extractor
#[derive(Debug)]
pub struct PEHeaderFeatureExtractor;

/// Entropy-based feature extractor
#[derive(Debug)]
pub struct EntropyFeatureExtractor {
    block_size: usize,
}

/// ML Classifier component
#[derive(Debug)]
pub struct MLClassifier {
    models: HashMap<String, Box<dyn MLModel + Send + Sync>>,
    ensemble_weights: HashMap<String, f32>,
    current_model: String,
}

/// Trait for ML models
#[async_trait]
pub trait MLModel {
    async fn predict(&self, features: &[f32]) -> Result<ModelPrediction>;
    async fn load_model(&mut self, model_data: &[u8]) -> Result<()>;
    fn get_model_info(&self) -> ModelInfo;
    fn is_loaded(&self) -> bool;
}

/// Model prediction result
#[derive(Debug, Clone)]
pub struct ModelPrediction {
    pub is_malicious: bool,
    pub confidence: f32,
    pub threat_type: Option<ThreatType>,
    pub feature_importance: Vec<f32>,
}

/// ONNX Runtime model implementation
#[derive(Debug)]
pub struct ONNXModel {
    model_path: Option<std::path::PathBuf>,
    model_info: ModelInfo,
    is_loaded: bool,
    // Note: In a real implementation, this would contain ONNX runtime session
    // For now, we'll use a mock implementation
}

/// TensorFlow Lite model implementation
#[derive(Debug)]
pub struct TensorFlowLiteModel {
    model_path: Option<std::path::PathBuf>,
    model_info: ModelInfo,
    is_loaded: bool,
    // Note: In a real implementation, this would contain TensorFlow Lite interpreter
    // For now, we'll use a mock implementation
}

/// Model management component
#[derive(Debug)]
pub struct ModelManager {
    model_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    model_metadata: Arc<RwLock<HashMap<String, ModelMetadata>>>,
    config: ModelManagerConfig,
}

/// Model metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub model_id: String,
    pub version: String,
    pub model_type: String,
    pub size_bytes: u64,
    pub checksum: String,
    pub created_at: DateTime<Utc>,
    pub accuracy: f32,
    pub false_positive_rate: f32,
    pub supported_file_types: Vec<String>,
}

/// Model manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelManagerConfig {
    pub cache_size_mb: u64,
    pub auto_cleanup: bool,
    pub verify_checksums: bool,
    pub model_server_url: String,
}

impl Default for ModelManagerConfig {
    fn default() -> Self {
        Self {
            cache_size_mb: 512,
            auto_cleanup: true,
            verify_checksums: true,
            model_server_url: "https://models.windowsantivirus.com".to_string(),
        }
    }
}

impl MLEngine {
    /// Create a new ML Engine
    pub fn new(config: MLConfig) -> Result<Self> {
        let feature_extractor = Arc::new(FeatureExtractor::new()?);
        let classifier = Arc::new(RwLock::new(MLClassifier::new()?));
        let model_manager = Arc::new(ModelManager::new(ModelManagerConfig::default())?);

        Ok(Self {
            feature_extractor,
            classifier,
            model_manager,
            config,
        })
    }

    /// Initialize the ML engine with default models
    pub async fn initialize(&self) -> Result<()> {
        tracing::info!("Initializing ML Engine");

        // Load default models
        self.load_default_models().await?;

        // Verify models are working
        self.verify_models().await?;

        tracing::info!("ML Engine initialized successfully");
        Ok(())
    }

    /// Load default models
    async fn load_default_models(&self) -> Result<()> {
        let mut classifier = self.classifier.write().await;

        // Load ONNX model for general malware detection
        let onnx_model = ONNXModel::new("general_malware_v1.0".to_string())?;
        classifier.add_model("onnx_general".to_string(), Box::new(onnx_model), 0.6)?;

        // Load TensorFlow Lite model for PE analysis
        let tflite_model = TensorFlowLiteModel::new("pe_analysis_v1.0".to_string())?;
        classifier.add_model("tflite_pe".to_string(), Box::new(tflite_model), 0.4)?;

        Ok(())
    }

    /// Verify that models are working correctly
    async fn verify_models(&self) -> Result<()> {
        // Create test feature vector
        let test_features = vec![0.5; 100]; // Mock feature vector
        let feature_vector = FeatureVector {
            features: test_features,
            feature_names: (0..100).map(|i| format!("feature_{}", i)).collect(),
        };

        // Test classification
        let result = self.classify(&feature_vector).await?;
        tracing::debug!("Model verification result: confidence={}", result.confidence);

        Ok(())
    }

    /// Check if ML engine is enabled and ready
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Update ML configuration
    pub fn update_config(&mut self, config: MLConfig) {
        self.config = config;
        tracing::info!("ML Engine configuration updated");
    }

    /// Get current configuration
    pub fn get_config(&self) -> &MLConfig {
        &self.config
    }

    /// Get engine statistics
    pub async fn get_statistics(&self) -> Result<MLEngineStats> {
        let classifier = self.classifier.read().await;
        let model_manager = self.model_manager.model_metadata.read().await;

        Ok(MLEngineStats {
            models_loaded: classifier.models.len(),
            total_predictions: 0, // Would be tracked in real implementation
            accuracy: 0.85, // Would be calculated from real data
            last_model_update: Utc::now(),
            cache_size_mb: model_manager.len() as u64,
        })
    }
}

/// ML Engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLEngineStats {
    pub models_loaded: usize,
    pub total_predictions: u64,
    pub accuracy: f32,
    pub last_model_update: DateTime<Utc>,
    pub cache_size_mb: u64,
}

#[async_trait]
impl MLClassification for MLEngine {
    async fn extract_features(&self, file_data: &[u8]) -> Result<FeatureVector> {
        if !self.config.enabled {
            return Err(AntivirusError::Internal(
                "ML Engine is disabled".to_string()
            ));
        }

        tracing::debug!("Extracting features from {} bytes of data", file_data.len());

        // Set timeout for feature extraction
        let timeout = tokio::time::Duration::from_millis(self.config.max_feature_extraction_time_ms);
        
        let extraction_future = self.feature_extractor.extract_all_features(file_data);
        
        match tokio::time::timeout(timeout, extraction_future).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!("Feature extraction timed out");
                Err(AntivirusError::Internal(
                    "Feature extraction timeout".to_string()
                ))
            }
        }
    }

    async fn classify(&self, features: &FeatureVector) -> Result<ClassificationResult> {
        if !self.config.enabled {
            return Err(AntivirusError::Internal(
                "ML Engine is disabled".to_string()
            ));
        }

        tracing::debug!("Classifying with {} features", features.features.len());

        let classifier = self.classifier.read().await;
        let prediction = classifier.predict(&features.features).await?;

        // Apply confidence threshold
        let is_malicious = prediction.is_malicious && 
                          prediction.confidence >= self.config.confidence_threshold;

        Ok(ClassificationResult {
            is_malicious,
            confidence: prediction.confidence,
            threat_type: prediction.threat_type,
            explanation: format!(
                "ML classification with {:.2}% confidence using {} models",
                prediction.confidence * 100.0,
                classifier.models.len()
            ),
        })
    }

    async fn update_model(&self, model_data: &[u8]) -> Result<()> {
        tracing::info!("Updating ML model with {} bytes of data", model_data.len());

        // Store model in cache
        self.model_manager.store_model("updated_model".to_string(), model_data.to_vec()).await?;

        // Reload classifier with new model
        let mut classifier = self.classifier.write().await;
        classifier.reload_models().await?;

        tracing::info!("ML model updated successfully");
        Ok(())
    }

    fn get_model_info(&self) -> ModelInfo {
        ModelInfo {
            model_version: "1.0.0".to_string(),
            model_type: "Ensemble (ONNX + TensorFlow Lite)".to_string(),
            last_updated: Utc::now(),
            accuracy: 0.85,
        }
    }
}

impl FeatureExtractor {
    /// Create a new feature extractor with all available extractors
    pub fn new() -> Result<Self> {
        let mut extractors: Vec<Box<dyn FeatureExtractorTrait + Send + Sync>> = Vec::new();

        // Add different feature extractors
        extractors.push(Box::new(StaticFeatureExtractor));
        extractors.push(Box::new(NGramFeatureExtractor::new(2, 1000)?));
        extractors.push(Box::new(PEHeaderFeatureExtractor));
        extractors.push(Box::new(EntropyFeatureExtractor::new(256)?));

        Ok(Self { extractors })
    }

    /// Extract features using all available extractors
    pub async fn extract_all_features(&self, file_data: &[u8]) -> Result<FeatureVector> {
        let mut all_features = Vec::new();
        let mut all_feature_names = Vec::new();

        for extractor in &self.extractors {
            let features = extractor.extract(file_data).await?;
            let names = extractor.get_feature_names();

            all_features.extend(features);
            all_feature_names.extend(names);
        }

        Ok(FeatureVector {
            features: all_features,
            feature_names: all_feature_names,
        })
    }

    /// Get total number of features
    pub fn get_total_feature_count(&self) -> usize {
        self.extractors.iter().map(|e| e.get_feature_count()).sum()
    }
}

// Feature extractor implementations

#[async_trait]
impl FeatureExtractorTrait for StaticFeatureExtractor {
    async fn extract(&self, file_data: &[u8]) -> Result<Vec<f32>> {
        // Extract basic static features
        let mut features = Vec::new();

        // File size (normalized)
        features.push((file_data.len() as f32).ln() / 20.0);

        // Byte frequency analysis
        let mut byte_counts = [0u32; 256];
        for &byte in file_data {
            byte_counts[byte as usize] += 1;
        }

        // Convert to frequencies
        let total_bytes = file_data.len() as f32;
        for count in byte_counts.iter() {
            features.push(*count as f32 / total_bytes);
        }

        // Basic entropy
        let entropy = self.calculate_entropy(file_data);
        features.push(entropy);

        Ok(features)
    }

    fn get_feature_names(&self) -> Vec<String> {
        let mut names = vec!["file_size_log".to_string()];
        
        // Byte frequency features
        for i in 0..256 {
            names.push(format!("byte_freq_{:02x}", i));
        }
        
        names.push("entropy".to_string());
        names
    }

    fn get_feature_count(&self) -> usize {
        258 // 1 (size) + 256 (byte frequencies) + 1 (entropy)
    }
}

impl StaticFeatureExtractor {
    fn calculate_entropy(&self, data: &[u8]) -> f32 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy = 0.0;

        for count in counts.iter() {
            if *count > 0 {
                let p = *count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy / 8.0 // Normalize to 0-1 range
    }
}

#[async_trait]
impl FeatureExtractorTrait for DynamicFeatureExtractor {
    async fn extract(&self, _file_data: &[u8]) -> Result<Vec<f32>> {
        // Dynamic analysis would require execution
        // For now, return placeholder features
        Ok(vec![0.0; 50])
    }

    fn get_feature_names(&self) -> Vec<String> {
        (0..50).map(|i| format!("dynamic_feature_{}", i)).collect()
    }

    fn get_feature_count(&self) -> usize {
        50
    }
}

impl NGramFeatureExtractor {
    pub fn new(n: usize, max_features: usize) -> Result<Self> {
        if n == 0 || n > 8 {
            return Err(AntivirusError::Internal(
                "N-gram size must be between 1 and 8".to_string()
            ));
        }

        Ok(Self { n, max_features })
    }
}

#[async_trait]
impl FeatureExtractorTrait for NGramFeatureExtractor {
    async fn extract(&self, file_data: &[u8]) -> Result<Vec<f32>> {
        let mut ngram_counts = HashMap::new();
        
        // Extract n-grams
        if file_data.len() >= self.n {
            for window in file_data.windows(self.n) {
                let ngram = window.to_vec();
                *ngram_counts.entry(ngram).or_insert(0u32) += 1;
            }
        }

        // Convert to feature vector (top max_features n-grams)
        let mut sorted_ngrams: Vec<_> = ngram_counts.into_iter().collect();
        sorted_ngrams.sort_by(|a, b| b.1.cmp(&a.1));
        sorted_ngrams.truncate(self.max_features);

        let total_ngrams = file_data.len().saturating_sub(self.n - 1) as f32;
        let mut features = vec![0.0; self.max_features];

        for (i, (_, count)) in sorted_ngrams.into_iter().enumerate() {
            features[i] = count as f32 / total_ngrams;
        }

        Ok(features)
    }

    fn get_feature_names(&self) -> Vec<String> {
        (0..self.max_features)
            .map(|i| format!("ngram_{}_{}", self.n, i))
            .collect()
    }

    fn get_feature_count(&self) -> usize {
        self.max_features
    }
}

#[async_trait]
impl FeatureExtractorTrait for PEHeaderFeatureExtractor {
    async fn extract(&self, file_data: &[u8]) -> Result<Vec<f32>> {
        // Basic PE header analysis
        let mut features = vec![0.0; 20];

        if file_data.len() < 64 {
            return Ok(features);
        }

        // Check for PE signature
        if file_data.len() > 60 {
            let pe_offset = u32::from_le_bytes([
                file_data[60], file_data[61], file_data[62], file_data[63]
            ]) as usize;

            if pe_offset + 4 < file_data.len() {
                let pe_sig = &file_data[pe_offset..pe_offset + 4];
                if pe_sig == b"PE\0\0" {
                    features[0] = 1.0; // Is PE file
                    
                    // Extract more PE features if available
                    if pe_offset + 24 < file_data.len() {
                        // Machine type
                        let machine = u16::from_le_bytes([
                            file_data[pe_offset + 4], file_data[pe_offset + 5]
                        ]);
                        features[1] = (machine as f32) / 65535.0;

                        // Number of sections
                        let sections = u16::from_le_bytes([
                            file_data[pe_offset + 6], file_data[pe_offset + 7]
                        ]);
                        features[2] = (sections as f32) / 100.0;
                    }
                }
            }
        }

        Ok(features)
    }

    fn get_feature_names(&self) -> Vec<String> {
        vec![
            "is_pe".to_string(),
            "machine_type".to_string(),
            "section_count".to_string(),
        ].into_iter()
        .chain((3..20).map(|i| format!("pe_feature_{}", i)))
        .collect()
    }

    fn get_feature_count(&self) -> usize {
        20
    }
}

impl EntropyFeatureExtractor {
    pub fn new(block_size: usize) -> Result<Self> {
        if block_size == 0 {
            return Err(AntivirusError::Internal(
                "Block size must be greater than 0".to_string()
            ));
        }

        Ok(Self { block_size })
    }
}

#[async_trait]
impl FeatureExtractorTrait for EntropyFeatureExtractor {
    async fn extract(&self, file_data: &[u8]) -> Result<Vec<f32>> {
        let mut features = Vec::new();

        // Calculate entropy for blocks
        for chunk in file_data.chunks(self.block_size) {
            let entropy = self.calculate_block_entropy(chunk);
            features.push(entropy);
        }

        // Pad or truncate to fixed size (10 blocks)
        features.resize(10, 0.0);

        // Add overall statistics
        let mean_entropy = features.iter().sum::<f32>() / features.len() as f32;
        let variance = features.iter()
            .map(|x| (x - mean_entropy).powi(2))
            .sum::<f32>() / features.len() as f32;

        features.push(mean_entropy);
        features.push(variance.sqrt());

        Ok(features)
    }

    fn get_feature_names(&self) -> Vec<String> {
        let mut names: Vec<String> = (0..10)
            .map(|i| format!("block_entropy_{}", i))
            .collect();
        names.push("mean_entropy".to_string());
        names.push("entropy_stddev".to_string());
        names
    }

    fn get_feature_count(&self) -> usize {
        12 // 10 block entropies + mean + stddev
    }
}

impl EntropyFeatureExtractor {
    fn calculate_block_entropy(&self, data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy = 0.0;

        for count in counts.iter() {
            if *count > 0 {
                let p = *count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy / 8.0 // Normalize to 0-1 range
    }
}

impl MLClassifier {
    /// Create a new ML classifier
    pub fn new() -> Result<Self> {
        Ok(Self {
            models: HashMap::new(),
            ensemble_weights: HashMap::new(),
            current_model: String::new(),
        })
    }

    /// Add a model to the classifier
    pub fn add_model(
        &mut self,
        name: String,
        model: Box<dyn MLModel + Send + Sync>,
        weight: f32,
    ) -> Result<()> {
        self.ensemble_weights.insert(name.clone(), weight);
        self.models.insert(name.clone(), model);
        
        if self.current_model.is_empty() {
            self.current_model = name;
        }

        Ok(())
    }

    /// Predict using ensemble of models
    pub async fn predict(&self, features: &[f32]) -> Result<ModelPrediction> {
        if self.models.is_empty() {
            return Err(AntivirusError::Internal(
                "No models loaded".to_string()
            ));
        }

        let mut predictions = Vec::new();
        let mut total_weight = 0.0;

        // Get predictions from all models
        for (name, model) in &self.models {
            if let Some(&weight) = self.ensemble_weights.get(name) {
                match model.predict(features).await {
                    Ok(prediction) => {
                        predictions.push((prediction, weight));
                        total_weight += weight;
                    }
                    Err(e) => {
                        tracing::warn!("Model {} prediction failed: {}", name, e);
                    }
                }
            }
        }

        if predictions.is_empty() {
            return Err(AntivirusError::Internal(
                "All model predictions failed".to_string()
            ));
        }

        // Combine predictions using weighted average
        let mut weighted_confidence = 0.0;
        let mut malicious_votes = 0.0;
        let mut threat_type_votes: HashMap<ThreatType, f32> = HashMap::new();

        for (prediction, weight) in predictions {
            weighted_confidence += prediction.confidence * weight;
            
            if prediction.is_malicious {
                malicious_votes += weight;
            }

            if let Some(threat_type) = prediction.threat_type {
                *threat_type_votes.entry(threat_type).or_insert(0.0) += weight;
            }
        }

        let final_confidence = weighted_confidence / total_weight;
        let is_malicious = malicious_votes > (total_weight / 2.0);

        // Determine most likely threat type
        let threat_type = threat_type_votes
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(threat_type, _)| threat_type);

        Ok(ModelPrediction {
            is_malicious,
            confidence: final_confidence,
            threat_type,
            feature_importance: vec![0.0; features.len()], // Would be calculated in real implementation
        })
    }

    /// Reload all models
    pub async fn reload_models(&mut self) -> Result<()> {
        for model in self.models.values_mut() {
            // In a real implementation, this would reload the model from disk
            tracing::debug!("Reloading model: {}", model.get_model_info().model_version);
        }
        Ok(())
    }
}

impl ONNXModel {
    pub fn new(model_id: String) -> Result<Self> {
        Ok(Self {
            model_path: None,
            model_info: ModelInfo {
                model_version: "1.0.0".to_string(),
                model_type: "ONNX".to_string(),
                last_updated: Utc::now(),
                accuracy: 0.87,
            },
            is_loaded: false,
        })
    }
}

#[async_trait]
impl MLModel for ONNXModel {
    async fn predict(&self, features: &[f32]) -> Result<ModelPrediction> {
        if !self.is_loaded {
            return Err(AntivirusError::Internal(
                "ONNX model not loaded".to_string()
            ));
        }

        // Mock prediction - in real implementation, this would use ONNX Runtime
        let confidence = (features.iter().sum::<f32>() / features.len() as f32).clamp(0.0, 1.0);
        let is_malicious = confidence > 0.5;

        Ok(ModelPrediction {
            is_malicious,
            confidence,
            threat_type: if is_malicious { Some(ThreatType::Suspicious) } else { None },
            feature_importance: vec![1.0 / features.len() as f32; features.len()],
        })
    }

    async fn load_model(&mut self, model_data: &[u8]) -> Result<()> {
        tracing::info!("Loading ONNX model ({} bytes)", model_data.len());
        
        // In real implementation, this would load the ONNX model
        // For now, just mark as loaded
        self.is_loaded = true;
        
        Ok(())
    }

    fn get_model_info(&self) -> ModelInfo {
        self.model_info.clone()
    }

    fn is_loaded(&self) -> bool {
        self.is_loaded
    }
}

impl TensorFlowLiteModel {
    pub fn new(model_id: String) -> Result<Self> {
        Ok(Self {
            model_path: None,
            model_info: ModelInfo {
                model_version: "1.0.0".to_string(),
                model_type: "TensorFlow Lite".to_string(),
                last_updated: Utc::now(),
                accuracy: 0.83,
            },
            is_loaded: false,
        })
    }
}

#[async_trait]
impl MLModel for TensorFlowLiteModel {
    async fn predict(&self, features: &[f32]) -> Result<ModelPrediction> {
        if !self.is_loaded {
            return Err(AntivirusError::Internal(
                "TensorFlow Lite model not loaded".to_string()
            ));
        }

        // Mock prediction - in real implementation, this would use TensorFlow Lite
        let confidence = (features.iter().map(|x| x.abs()).sum::<f32>() / features.len() as f32).clamp(0.0, 1.0);
        let is_malicious = confidence > 0.6;

        Ok(ModelPrediction {
            is_malicious,
            confidence,
            threat_type: if is_malicious { Some(ThreatType::Trojan) } else { None },
            feature_importance: vec![1.0 / features.len() as f32; features.len()],
        })
    }

    async fn load_model(&mut self, model_data: &[u8]) -> Result<()> {
        tracing::info!("Loading TensorFlow Lite model ({} bytes)", model_data.len());
        
        // In real implementation, this would load the TensorFlow Lite model
        // For now, just mark as loaded
        self.is_loaded = true;
        
        Ok(())
    }

    fn get_model_info(&self) -> ModelInfo {
        self.model_info.clone()
    }

    fn is_loaded(&self) -> bool {
        self.is_loaded
    }
}

impl ModelManager {
    /// Create a new model manager
    pub fn new(config: ModelManagerConfig) -> Result<Self> {
        Ok(Self {
            model_cache: Arc::new(RwLock::new(HashMap::new())),
            model_metadata: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    /// Store a model in cache
    pub async fn store_model(&self, model_id: String, model_data: Vec<u8>) -> Result<()> {
        let checksum = self.calculate_checksum(&model_data);
        
        let metadata = ModelMetadata {
            model_id: model_id.clone(),
            version: "1.0.0".to_string(),
            model_type: "Unknown".to_string(),
            size_bytes: model_data.len() as u64,
            checksum: checksum.clone(),
            created_at: Utc::now(),
            accuracy: 0.0,
            false_positive_rate: 0.0,
            supported_file_types: vec!["*".to_string()],
        };

        // Store model data
        {
            let mut cache = self.model_cache.write().await;
            cache.insert(model_id.clone(), model_data);
        }

        // Store metadata
        {
            let mut metadata_map = self.model_metadata.write().await;
            metadata_map.insert(model_id, metadata);
        }

        // Cleanup if cache is too large
        if self.config.auto_cleanup {
            self.cleanup_cache().await?;
        }

        Ok(())
    }

    /// Get a model from cache
    pub async fn get_model(&self, model_id: &str) -> Result<Option<Vec<u8>>> {
        let cache = self.model_cache.read().await;
        Ok(cache.get(model_id).cloned())
    }

    /// Calculate checksum for model data
    fn calculate_checksum(&self, data: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Cleanup old models from cache
    async fn cleanup_cache(&self) -> Result<()> {
        let cache_size_limit = self.config.cache_size_mb * 1024 * 1024;
        
        let cache = self.model_cache.read().await;
        let current_size: u64 = cache.values().map(|data| data.len() as u64).sum();
        
        if current_size > cache_size_limit {
            tracing::info!("Cache size ({} MB) exceeds limit, cleaning up", current_size / 1024 / 1024);
            // In real implementation, would remove oldest models
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ml_engine_creation() {
        let config = MLConfig::default();
        let engine = MLEngine::new(config);
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_feature_extraction() {
        let engine = MLEngine::new(MLConfig::default()).unwrap();
        let test_data = b"This is test data for feature extraction";
        
        let features = engine.extract_features(test_data).await;
        assert!(features.is_ok());
        
        let feature_vector = features.unwrap();
        assert!(!feature_vector.features.is_empty());
        assert_eq!(feature_vector.features.len(), feature_vector.feature_names.len());
    }

    #[tokio::test]
    async fn test_classification() {
        let engine = MLEngine::new(MLConfig::default()).unwrap();