use crate::event::{AccessEvent, Operation};
use crate::policy::Decision;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct DecisionLog<'a> {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,

    #[serde(flatten)]
    pub event: &'a AccessEvent,

    #[serde(flatten)]
    pub decision: &'a Decision,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OwnedDecisionLog {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,

    #[serde(default)]
    pub pid: Option<u32>,

    pub uid: u32,
    pub exe: PathBuf,

    #[serde(default)]
    pub cwd: Option<PathBuf>,

    #[serde(default)]
    pub cmdline: Vec<String>,

    #[serde(default)]
    pub parent_chain: Vec<crate::process::ProcessChainEntry>,

    pub target_path: PathBuf,
    pub operation: Operation,
    pub decision: String,
    pub reason: String,

    #[serde(default)]
    pub matched_path_group: Option<String>,

    #[serde(default)]
    pub would_deny: bool,
}

#[derive(Debug, Serialize)]
pub struct DaemonLog {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub component: String,
    pub level: String,
    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_users: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_groups: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_rules: Option<usize>,
}

impl<'a> DecisionLog<'a> {
    pub fn new(event: &'a AccessEvent, decision: &'a Decision) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event,
            decision,
        }
    }
}

impl DaemonLog {
    pub fn new(level: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            component: "pepersprayd".to_string(),
            level: level.into(),
            message: message.into(),
            config_path: None,
            protected_users: None,
            protected_groups: None,
            allow_rules: None,
        }
    }

    pub fn with_config_summary(
        mut self,
        config_path: PathBuf,
        protected_users: usize,
        protected_groups: usize,
        allow_rules: usize,
    ) -> Self {
        self.config_path = Some(config_path);
        self.protected_users = Some(protected_users);
        self.protected_groups = Some(protected_groups);
        self.allow_rules = Some(allow_rules);
        self
    }
}

pub fn print_json_log(log: &DecisionLog) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(&log)?;

    println!("{json}");

    Ok(())
}

pub fn append_jsonl_log(path: &Path, log: &DecisionLog) -> anyhow::Result<()> {
    let json = serde_json::to_string(&log)?;

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "{json}")?;

    Ok(())
}

pub fn append_daemon_jsonl_log(path: &Path, log: &DaemonLog) -> anyhow::Result<()> {
    let json = serde_json::to_string(log)?;

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "{json}")?;

    Ok(())
}

pub fn read_jsonl_logs(path: &Path) -> anyhow::Result<Vec<OwnedDecisionLog>> {
    let contents = std::fs::read_to_string(path)?;

    let mut logs = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let log: OwnedDecisionLog = serde_json::from_str(line).map_err(|err| {
            anyhow::anyhow!("failed to parse log line {}: {}", line_number + 1, err)
        })?;

        logs.push(log);
    }

    Ok(logs)
}
