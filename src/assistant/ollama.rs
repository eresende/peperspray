use crate::assistant::config::AssistantConfig;
use crate::assistant::provider::AssistantProvider;
use crate::assistant::schema::{self, AssistantFailure, AssistantReview, AssistantTask};
use anyhow::Context;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct OllamaProvider {
    config: AssistantConfig,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct TagsResponse {
    #[serde(default)]
    models: Vec<ModelInfo>,
}

#[derive(Debug, Deserialize)]
struct ModelInfo {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    message: ChatMessage,
    #[serde(default)]
    done_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    content: String,
    #[serde(default)]
    thinking: Option<String>,
}

impl OllamaProvider {
    pub fn new(config: AssistantConfig) -> anyhow::Result<Self> {
        let client = Client::builder().timeout(config.timeout()).build()?;
        Ok(Self { config, client })
    }

    fn ensure_model_exists(&self) -> anyhow::Result<()> {
        let response = self
            .client
            .get(format!("{}/api/tags", self.config.endpoint))
            .send()
            .with_context(|| {
                format!(
                    "Assistant unavailable: could not connect to {}. Run `peperspray assistant doctor` for details.",
                    self.config.endpoint
                )
            })?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Assistant provider returned HTTP status {} while listing models",
                response.status()
            );
        }

        let tags: TagsResponse = response.json()?;
        let exists = tags
            .models
            .iter()
            .any(|model| model.name == self.config.model);

        if !exists {
            anyhow::bail!(
                "Assistant model not found: {}. Install it with: ollama pull {}",
                self.config.model,
                self.config.model
            );
        }

        Ok(())
    }
}

impl AssistantProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn health_check(&self) -> anyhow::Result<()> {
        self.ensure_model_exists()?;

        let body = json!({
            "model": self.config.model,
            "stream": false,
            "messages": [
                {
                    "role": "user",
                    "content": "Reply with OK."
                }
            ],
        });

        let response = self
            .client
            .post(format!("{}/api/chat", self.config.endpoint))
            .json(&body)
            .send()
            .with_context(|| {
                format!(
                    "Assistant unavailable: could not connect to {}. Run `peperspray assistant doctor` for details.",
                    self.config.endpoint
                )
            })?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Assistant test prompt failed with HTTP status {}",
                response.status()
            );
        }

        let _: ChatResponse = response.json()?;
        Ok(())
    }

    fn complete(
        &self,
        task: AssistantTask,
        input: serde_json::Value,
    ) -> anyhow::Result<Result<AssistantReview, AssistantFailure>> {
        self.ensure_model_exists()?;

        if matches!(
            self.config.redaction,
            crate::assistant::config::RedactionMode::None
        ) {
            eprintln!(
                "Warning: assistant redaction is disabled; raw event metadata will be sent to {}.",
                self.config.endpoint
            );
        }

        let body = json!({
            "model": self.config.model,
            "stream": false,
            "think": false,
            "format": "json",
            "options": {
                "temperature": 0,
                "num_predict": 2048
            },
            "messages": schema::request_messages(task, &input),
        });

        let response = self
            .client
            .post(format!("{}/api/chat", self.config.endpoint))
            .json(&body)
            .send()
            .with_context(|| {
                format!(
                    "Assistant unavailable: could not connect to {}. Run `peperspray assistant doctor` for details.",
                    self.config.endpoint
                )
            })?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Assistant request failed with HTTP status {}. Run `peperspray assistant doctor` for details.",
                response.status()
            );
        }

        let response: ChatResponse = response.json()?;
        if response.message.content.trim().is_empty() {
            let reason = response.done_reason.as_deref().unwrap_or("unknown");
            let thinking_note = if response
                .message
                .thinking
                .as_deref()
                .is_some_and(|thinking| !thinking.trim().is_empty())
            {
                " The model returned reasoning text but no final assistant content."
            } else {
                ""
            };

            return Ok(Err(AssistantFailure {
                message: format!(
                    "assistant returned an empty response (done_reason: {reason}).{thinking_note}"
                ),
            }));
        }

        Ok(schema::parse_review(&response.message.content))
    }
}
