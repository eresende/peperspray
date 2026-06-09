use crate::assistant::config::{AssistantConfig, RedactionMode};
use crate::assistant::{prompts, redaction, risk};
use crate::logging::OwnedDecisionLog;
use crate::review::{self, ReviewCandidate};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Copy)]
pub enum AssistantTask {
    ExplainEvent,
    ReviewPolicyCandidates,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    LikelySafe,
    NeedsReview,
    Risky,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantReview {
    pub summary: String,
    #[serde(deserialize_with = "deserialize_risk_level")]
    pub risk_level: RiskLevel,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub why: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub recommendations: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    pub safe_rule_guidance: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssistantFailure {
    pub message: String,
}

pub fn event_input(
    log: &OwnedDecisionLog,
    config: &AssistantConfig,
) -> anyhow::Result<serde_json::Value> {
    let path_group = log.matched_path_group.as_deref();
    let risk_hints = path_group
        .map(|group| risk::hints_for_access(&log.exe, group, None))
        .unwrap_or_default();

    Ok(json!({
        "task": "explain_event",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "redaction": format!("{:?}", config.redaction).to_lowercase(),
        "deterministic_risk_hints": risk_hints,
        "event": {
            "event_id": log.event_id,
            "decision": log.decision,
            "would_deny": log.would_deny,
            "operation": log.operation,
            "matched_path_group": log.matched_path_group,
            "target_path": redaction::redact_path(&log.target_path, config.redaction, path_group),
            "exe": redaction::redact_exe(&log.exe, config.redaction),
            "cwd": log.cwd.as_ref().map(|cwd| redaction::redact_path(cwd, config.redaction, None)),
            "cmdline": redaction::redact_cmdline(&log.cmdline, config.redaction),
            "parent_chain": log.parent_chain.iter().map(|parent| {
                json!({
                    "exe": parent.exe.as_ref().map(|exe| redaction::redact_exe(exe, config.redaction)),
                    "cmdline": redaction::redact_cmdline(&parent.cmdline, config.redaction),
                })
            }).collect::<Vec<_>>(),
        }
    }))
}

pub fn policy_review_input(
    candidates: &[ReviewCandidate],
    config: &AssistantConfig,
) -> anyhow::Result<serde_json::Value> {
    let candidate_groups = candidates
        .iter()
        .take(config.max_events)
        .map(|candidate| {
            let path_group = candidate.path_group();
            json!({
                "exe": redaction::redact_exe(candidate.exe(), config.redaction),
                "path_group": path_group,
                "operation": "open_read",
                "event_count": candidate.event_count(),
                "parent_exe": candidate.parent_exe().map(|exe| redaction::redact_exe(exe, config.redaction)),
                "deterministic_risk_hints": risk::hints_for_access(candidate.exe(), path_group, Some(candidate.event_count())),
                "suggested_rule": suggested_rule_for_prompt(candidate, config.redaction),
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "task": "review_policy_candidates",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "redaction": format!("{:?}", config.redaction).to_lowercase(),
        "candidate_groups": candidate_groups,
    }))
}

fn suggested_rule_for_prompt(candidate: &ReviewCandidate, mode: RedactionMode) -> String {
    match mode {
        RedactionMode::Strict => "<omitted by strict redaction>".to_string(),
        RedactionMode::Balanced | RedactionMode::None => review::candidate_to_toml(candidate),
    }
}

pub fn parse_review(content: &str) -> Result<AssistantReview, AssistantFailure> {
    let Some(json_text) = extract_json_object(content) else {
        let detail = if content.trim().is_empty() {
            "assistant returned an empty response".to_string()
        } else {
            format!(
                "assistant returned non-JSON text; structured parsing failed:\n{}",
                content.trim()
            )
        };

        return Err(AssistantFailure { message: detail });
    };

    parse_review_json(json_text).or_else(|first_err| {
        let repaired = repair_json_like_text(json_text);
        if repaired == json_text {
            return Err(first_err);
        }

        parse_review_json(&repaired).map_err(|_| first_err)
    })
}

fn parse_review_json(json_text: &str) -> Result<AssistantReview, AssistantFailure> {
    match serde_json::from_str::<AssistantReview>(json_text) {
        Ok(review) => Ok(review),
        Err(err) => {
            let value = serde_json::from_str::<serde_json::Value>(json_text).map_err(|_| {
                AssistantFailure {
                    message: format!(
                        "assistant returned JSON-like text, but structured parsing failed: {err}\n{}",
                        json_text.trim()
                    ),
                }
            })?;

            review_from_value(value).ok_or_else(|| AssistantFailure {
                message: format!(
                    "assistant returned JSON, but it did not contain review fields:\n{}",
                    json_text.trim()
                ),
            })
        }
    }
}

fn review_from_value(value: serde_json::Value) -> Option<AssistantReview> {
    let object = value.as_object()?;
    let summary = object
        .get("summary")
        .or_else(|| object.get("reason"))
        .or_else(|| object.get("status"))
        .map(value_to_string)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            "Assistant returned a structured response without a summary.".to_string()
        });

    let risk_level = object
        .get("risk_level")
        .or_else(|| object.get("risk"))
        .and_then(serde_json::Value::as_str)
        .map(parse_risk_level)
        .unwrap_or(RiskLevel::Unknown);

    let why = object
        .get("why")
        .or_else(|| object.get("reason"))
        .map(value_to_string_list)
        .unwrap_or_default();

    let recommendations = object
        .get("recommendations")
        .or_else(|| object.get("recommendation"))
        .map(value_to_string_list)
        .unwrap_or_default();

    let safe_rule_guidance = object
        .get("safe_rule_guidance")
        .or_else(|| object.get("guidance"))
        .map(value_to_string)
        .filter(|value| !value.trim().is_empty());

    Some(AssistantReview {
        summary,
        risk_level,
        why,
        recommendations,
        safe_rule_guidance,
    })
}

fn value_to_string(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(ToString::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn value_to_string_list(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(items) => items.iter().map(value_to_string).collect(),
        serde_json::Value::Null => Vec::new(),
        value => vec![value_to_string(value)],
    }
}

fn repair_json_like_text(value: &str) -> String {
    let key_regex = Regex::new(r#"([,{]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:"#)
        .expect("json repair key regex should compile");
    let repaired = key_regex.replace_all(value, "$1\"$2\":");

    let risk_regex = Regex::new(r#""risk_level"\s*:\s*([A-Za-z_][A-Za-z0-9_]*)"#)
        .expect("json repair risk regex should compile");
    risk_regex
        .replace_all(&repaired, "\"risk_level\":\"$1\"")
        .to_string()
}

fn extract_json_object(content: &str) -> Option<&str> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return Some(trimmed);
    }

    let mut start = None;
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, character) in trimmed.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match character {
            '\\' if in_string => {
                escaped = true;
            }
            '"' => {
                in_string = !in_string;
            }
            '{' if !in_string => {
                if depth == 0 {
                    start = Some(index);
                }
                depth += 1;
            }
            '}' if !in_string && depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    let start = start.expect("json start should be set");
                    return Some(&trimmed[start..=index]);
                }
            }
            _ => {}
        }
    }

    None
}

fn deserialize_risk_level<'de, D>(deserializer: D) -> Result<RiskLevel, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(parse_risk_level(&value))
}

fn parse_risk_level(value: &str) -> RiskLevel {
    match value.to_lowercase().as_str() {
        "likely_safe" | "low" => RiskLevel::LikelySafe,
        "needs_review" | "medium" => RiskLevel::NeedsReview,
        "risky" | "high" => RiskLevel::Risky,
        "unknown" => RiskLevel::Unknown,
        _ => RiskLevel::Unknown,
    }
}

fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Array(items) => Ok(items
            .into_iter()
            .filter_map(|item| item.as_str().map(ToString::to_string))
            .collect()),
        serde_json::Value::String(item) => Ok(vec![item]),
        serde_json::Value::Null => Ok(Vec::new()),
        _ => Ok(vec![value.to_string()]),
    }
}

fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::String(value)) => Some(value),
        Some(serde_json::Value::Null) | None => None,
        Some(value) => Some(value.to_string()),
    })
}

pub fn request_messages(task: AssistantTask, input: &serde_json::Value) -> serde_json::Value {
    json!([
        {
            "role": "system",
            "content": prompts::SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": prompts::user_prompt(task, input)
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_review_accepts_common_model_variants() {
        let review = parse_review(
            r#"{
                "summary": "Shell read AWS credentials.",
                "risk_level": "high",
                "why": "Shells are broad interpreters.",
                "recommendations": "Avoid allowing shells globally.",
                "safe_rule_guidance": "Prefer a specific tool."
            }"#,
        )
        .expect("variant response should parse");

        assert!(matches!(review.risk_level, RiskLevel::Risky));
        assert_eq!(review.why, ["Shells are broad interpreters."]);
        assert_eq!(review.recommendations, ["Avoid allowing shells globally."]);
    }

    #[test]
    fn parse_review_extracts_json_from_markdown_fence() {
        let review = parse_review(
            r#"Here is the review:

```json
{
  "summary": "Cat read AWS credentials.",
  "risk_level": "risky",
  "why": ["cat is too broad"],
  "recommendations": ["do not allow cat globally"]
}
```
"#,
        )
        .expect("fenced json should parse");

        assert_eq!(review.summary, "Cat read AWS credentials.");
        assert!(matches!(review.risk_level, RiskLevel::Risky));
    }

    #[test]
    fn parse_review_reports_empty_response() {
        let failure = parse_review("   ").expect_err("empty response should fail");

        assert_eq!(failure.message, "assistant returned an empty response");
    }

    #[test]
    fn parse_review_accepts_object_safe_rule_guidance() {
        let review = parse_review(
            r#"{
              "summary": "No candidates.",
              "risk_level": "Low",
              "why": "Nothing to review.",
              "recommendations": ["Keep watching."],
              "safe_rule_guidance": {
                "default_policy": "deny_all"
              }
            }"#,
        )
        .expect("object guidance should parse");

        assert!(matches!(review.risk_level, RiskLevel::LikelySafe));
        assert!(
            review
                .safe_rule_guidance
                .as_deref()
                .is_some_and(|guidance| guidance.contains("deny_all"))
        );
    }

    #[test]
    fn parse_review_repairs_unquoted_model_json() {
        let review = parse_review(
            r#"{summary: "Cat reads AWS credentials.", risk_level: needs_review, why: ["cat is broad"], recommendations: ["review manually"], safe_rule_guidance: "do not auto-approve"}"#,
        )
        .expect("json-like model output should parse");

        assert_eq!(review.summary, "Cat reads AWS credentials.");
        assert!(matches!(review.risk_level, RiskLevel::NeedsReview));
    }

    #[test]
    fn parse_review_normalizes_generic_json_response() {
        let review = parse_review(
            r#"{"status":"denied","reason":"executable violates security policy by reading AWS credentials"}"#,
        )
        .expect("generic json should normalize");

        assert_eq!(
            review.summary,
            "executable violates security policy by reading AWS credentials"
        );
        assert!(matches!(review.risk_level, RiskLevel::Unknown));
    }
}
