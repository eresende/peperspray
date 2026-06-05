use crate::event::{AccessEvent, Operation};
use crate::policy::Decision;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Mode applied when the daemon (or CLI) first creates a decision/lifecycle log.
///
/// Decision records contain sensitive process context (cmdline, cwd, exe,
/// parent chain, and target credential paths), so the audit log must not be
/// world-readable. `0o640` keeps it readable only by the owner and group.
/// This only affects newly created files; existing files keep their mode.
const LOG_FILE_MODE: u32 = 0o640;

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

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(LOG_FILE_MODE)
        .open(path)?;

    writeln!(file, "{json}")?;

    Ok(())
}

pub fn append_daemon_jsonl_log(path: &Path, log: &DaemonLog) -> anyhow::Result<()> {
    let json = serde_json::to_string(log)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(LOG_FILE_MODE)
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

        let Some(log) = parse_decision_jsonl_line(line).map_err(|err| {
            anyhow::anyhow!("failed to parse log line {}: {}", line_number + 1, err)
        })?
        else {
            continue;
        };

        logs.push(log);
    }

    Ok(logs)
}

pub fn parse_decision_jsonl_line(line: &str) -> anyhow::Result<Option<OwnedDecisionLog>> {
    let value: serde_json::Value = serde_json::from_str(line)?;

    if is_daemon_lifecycle_log(&value) {
        return Ok(None);
    }

    Ok(Some(serde_json::from_value(value)?))
}

fn is_daemon_lifecycle_log(value: &serde_json::Value) -> bool {
    value.get("component").and_then(serde_json::Value::as_str) == Some("pepersprayd")
        && value.get("level").is_some()
        && value.get("message").is_some()
        && value.get("uid").is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECISION_LOG: &str = r#"{"event_id":"00000000-0000-0000-0000-000000000001","timestamp":"2026-01-01T00:00:00Z","uid":1000,"exe":"/usr/bin/python3","target_path":"/home/alice/.aws/credentials","operation":"open_read","decision":"allow","reason":"learn","matched_path_group":"aws","would_deny":true}"#;
    const DAEMON_LOG: &str = r#"{"event_id":"00000000-0000-0000-0000-000000000002","timestamp":"2026-01-01T00:00:01Z","component":"pepersprayd","level":"info","message":"daemon config loaded","config_path":"/etc/peperspray/config.toml","protected_users":1,"protected_groups":1,"allow_rules":0}"#;

    #[test]
    fn append_daemon_jsonl_log_creates_non_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("events.jsonl");

        append_daemon_jsonl_log(&path, &DaemonLog::new("info", "started"))
            .expect("daemon log should append");

        let mode = std::fs::metadata(&path)
            .expect("log metadata should be readable")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, LOG_FILE_MODE);
        assert_eq!(mode & 0o007, 0, "log must not be world-accessible");
    }

    #[test]
    fn read_jsonl_logs_skips_daemon_lifecycle_records() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, format!("{DAEMON_LOG}\n{DECISION_LOG}\n"))
            .expect("log should be written");

        let logs = read_jsonl_logs(&path).expect("logs should be readable");

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].uid, 1000);
        assert_eq!(logs[0].exe, PathBuf::from("/usr/bin/python3"));
    }

    #[test]
    fn read_jsonl_logs_rejects_malformed_json() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, "{").expect("log should be written");

        let err = read_jsonl_logs(&path).expect_err("malformed json should fail");

        assert!(err.to_string().contains("failed to parse log line 1"));
    }

    #[test]
    fn read_jsonl_logs_rejects_malformed_decision_records() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("events.jsonl");
        std::fs::write(
            &path,
            r#"{"event_id":"00000000-0000-0000-0000-000000000001","timestamp":"2026-01-01T00:00:00Z","exe":"/usr/bin/python3","target_path":"/tmp/file","operation":"open_read","decision":"allow","reason":"learn"}"#,
        )
        .expect("log should be written");

        let err = read_jsonl_logs(&path).expect_err("malformed decision should fail");

        assert!(err.to_string().contains("failed to parse log line 1"));
        assert!(err.to_string().contains("missing field `uid`"));
    }
}
