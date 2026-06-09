use crate::assistant::schema::{AssistantFailure, AssistantReview, AssistantTask};

pub trait AssistantProvider {
    fn name(&self) -> &'static str;

    fn health_check(&self) -> anyhow::Result<()>;

    fn complete(
        &self,
        task: AssistantTask,
        input: serde_json::Value,
    ) -> anyhow::Result<Result<AssistantReview, AssistantFailure>>;
}
