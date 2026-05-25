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
    pub uid: u32,
    pub exe: PathBuf,
    pub target_path: PathBuf,
    pub operation: Operation,
    pub decision: String,
    pub reason: String,

    #[serde(default)]
    pub matched_path_group: Option<String>,

    #[serde(default)]
    pub would_deny: bool,
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

pub fn print_json_log(log: &DecisionLog) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(&log)?;

    println!("{json}");

    Ok(())
}

pub fn append_jsonl_log(
    path: &Path,
    log: &DecisionLog,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(&log)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

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

        let log: OwnedDecisionLog = serde_json::from_str(line)
            .map_err(|err| {
                anyhow::anyhow!(
                    "failed to parse log line {}: {}",
                    line_number + 1,
                    err
                )
            })?;

        logs.push(log);
    }

    Ok(logs)
}
