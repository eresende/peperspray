use crate::cli::AssistantCliOptions;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_PROVIDER: &str = "ollama";
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";
pub const DEFAULT_MODEL: &str = "gemma4:12b";
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
pub const DEFAULT_MAX_EVENTS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum RedactionMode {
    Strict,
    Balanced,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssistantConfig {
    pub provider: String,
    pub endpoint: String,
    pub model: String,
    pub timeout_seconds: u64,
    pub max_events: usize,
    pub redaction: RedactionMode,
}

impl Default for AssistantConfig {
    fn default() -> Self {
        Self {
            provider: DEFAULT_PROVIDER.to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
            model: DEFAULT_MODEL.to_string(),
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            max_events: DEFAULT_MAX_EVENTS,
            redaction: RedactionMode::Balanced,
        }
    }
}

impl AssistantConfig {
    pub fn load_user_config() -> anyhow::Result<Option<Self>> {
        let Some(path) = user_config_path() else {
            return Ok(None);
        };

        if !path.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(&path)?;
        Ok(Some(toml::from_str(&contents)?))
    }

    pub fn apply_cli_options(&mut self, options: &AssistantCliOptions) -> anyhow::Result<()> {
        if let Some(provider) = &options.provider {
            self.provider = provider.clone();
        }
        if let Some(endpoint) = &options.endpoint {
            self.endpoint = endpoint.trim_end_matches('/').to_string();
        }
        if let Some(model) = &options.model {
            self.model = model.clone();
        }
        if let Some(timeout_seconds) = options.timeout_seconds {
            if timeout_seconds == 0 {
                anyhow::bail!("--assistant-timeout must be greater than zero");
            }
            self.timeout_seconds = timeout_seconds;
        }
        if let Some(redaction) = options.redaction {
            self.redaction = redaction;
        }

        if self.provider != DEFAULT_PROVIDER {
            anyhow::bail!(
                "unsupported assistant provider '{}'; supported provider: ollama",
                self.provider
            );
        }

        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
}

pub fn user_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/peperspray/assistant.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_model_is_gemma4_12b() {
        assert_eq!(AssistantConfig::default().model, "gemma4:12b");
    }

    #[test]
    fn cli_options_override_defaults() {
        let mut config = AssistantConfig::default();
        let options = AssistantCliOptions {
            provider: Some("ollama".to_string()),
            endpoint: Some("http://localhost:9999/".to_string()),
            model: Some("qwen3:14b".to_string()),
            timeout_seconds: Some(7),
            redaction: Some(RedactionMode::Strict),
            assistant_json: false,
        };

        config
            .apply_cli_options(&options)
            .expect("options should apply");

        assert_eq!(config.endpoint, "http://localhost:9999");
        assert_eq!(config.model, "qwen3:14b");
        assert_eq!(config.timeout_seconds, 7);
        assert_eq!(config.redaction, RedactionMode::Strict);
    }
}
