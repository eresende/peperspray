pub mod config;
pub mod ollama;
pub mod prompts;
pub mod provider;
pub mod redaction;
pub mod render;
pub mod risk;
pub mod schema;

use crate::cli::AssistantCliOptions;
use crate::logging::OwnedDecisionLog;
use crate::review::ReviewCandidate;
use anyhow::Context;
use config::AssistantConfig;
use ollama::OllamaProvider;
use provider::AssistantProvider;
use schema::{AssistantFailure, AssistantReview, AssistantTask};

pub fn effective_config(options: &AssistantCliOptions) -> anyhow::Result<AssistantConfig> {
    let mut config = AssistantConfig::load_user_config()?.unwrap_or_default();
    config.apply_cli_options(options)?;
    Ok(config)
}

pub fn run_doctor(options: &AssistantCliOptions) -> anyhow::Result<bool> {
    let config = effective_config(options)?;
    let provider = OllamaProvider::new(config.clone())?;

    println!("Assistant provider: {}", provider.name());
    println!("Endpoint: {}", config.endpoint);
    println!("Model: {}", config.model);
    print_processing_message("checking", &config);

    match provider.health_check() {
        Ok(()) => {
            println!("Status: OK");
            println!();
            println!("Privacy: assistant input is sent to the configured local endpoint only.");
            println!("No cloud provider is used by peperspray.");
            Ok(true)
        }
        Err(err) => {
            println!("Status: unavailable");
            println!("Error: {err}");
            Ok(false)
        }
    }
}

pub fn explain_event(
    log: &OwnedDecisionLog,
    options: &AssistantCliOptions,
) -> anyhow::Result<Result<AssistantReview, AssistantFailure>> {
    let config = effective_config(options)?;
    let provider = OllamaProvider::new(config.clone())?;
    let input = schema::event_input(log, &config)
        .with_context(|| "failed to build assistant event input")?;
    print_processing_message("reviewing event", &config);
    provider.complete(AssistantTask::ExplainEvent, input)
}

pub fn review_candidates(
    candidates: &[ReviewCandidate],
    options: &AssistantCliOptions,
) -> anyhow::Result<Result<AssistantReview, AssistantFailure>> {
    let config = effective_config(options)?;
    let provider = OllamaProvider::new(config.clone())?;
    let input = schema::policy_review_input(candidates, &config)
        .with_context(|| "failed to build assistant policy-review input")?;
    print_processing_message("reviewing policy candidates", &config);
    provider.complete(AssistantTask::ReviewPolicyCandidates, input)
}

fn print_processing_message(action: &str, config: &AssistantConfig) {
    eprintln!(
        "Assistant: {action} with local model '{}' at {} (timeout: {}s)...",
        config.model, config.endpoint, config.timeout_seconds
    );
}
