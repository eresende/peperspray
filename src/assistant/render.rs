use crate::assistant::schema::{AssistantFailure, AssistantReview, RiskLevel};

pub fn print_review(result: &Result<AssistantReview, AssistantFailure>) {
    println!();
    println!("Assistant review");
    println!("----------------");

    match result {
        Ok(review) => {
            println!("Risk: {}", risk_level_text(&review.risk_level));
            println!();
            println!("{}", review.summary);

            if !review.why.is_empty() {
                println!();
                println!("Why:");
                for item in &review.why {
                    println!("- {item}");
                }
            }

            if !review.recommendations.is_empty() {
                println!();
                println!("Recommended next steps:");
                for (index, item) in review.recommendations.iter().enumerate() {
                    println!("{}. {item}", index + 1);
                }
            }

            if let Some(guidance) = &review.safe_rule_guidance {
                println!();
                println!("{guidance}");
            }
        }
        Err(failure) => {
            println!("{}", failure.message);
        }
    }
}

pub fn print_json(result: &Result<AssistantReview, AssistantFailure>) -> anyhow::Result<()> {
    match result {
        Ok(review) => println!("{}", serde_json::to_string_pretty(review)?),
        Err(failure) => {
            let value = serde_json::json!({
                "assistant_error": failure.message,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
    }

    Ok(())
}

fn risk_level_text(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::LikelySafe => "likely_safe",
        RiskLevel::NeedsReview => "needs_review",
        RiskLevel::Risky => "risky",
        RiskLevel::Unknown => "unknown",
    }
}
