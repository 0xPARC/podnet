use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[derive(Default)]
pub struct ServerConfig {
    /// Whether to use mock proofs instead of real ZK proofs for faster development
    pub mock_proofs: bool,
}


impl ServerConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(path.as_ref().to_str().unwrap()))
            .add_source(config::Environment::with_prefix("PODNET"))
            .build()?;

        settings.try_deserialize()
    }

    /// Load configuration with fallback to defaults
    pub fn load() -> Self {
        // Try to load from config.toml, fall back to defaults if it doesn't exist
        if Path::new("config.toml").exists() {
            match Self::from_file("config.toml") {
                Ok(config) => {
                    tracing::info!("Loaded configuration from config.toml");
                    config
                }
                Err(e) => {
                    tracing::warn!("Failed to load config.toml: {}, using defaults", e);
                    Self::default()
                }
            }
        } else {
            tracing::info!("No config.toml found, using default configuration");
            Self::default()
        }
    }
}