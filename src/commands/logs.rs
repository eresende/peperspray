use crate::cli::DecisionFilter;
use crate::logging;
use chrono::{DateTime, Utc};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek};
use std::path::Path;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

pub fn print_log_entry(log: &logging::OwnedDecisionLog) {
    let pid_text = log
        .pid
        .map(|pid| format!("pid={pid}"))
        .unwrap_or_else(|| "pid=?".to_string());

    println!(
        "{}  {}  {}  uid={}  {}  ->  {}",
        log.timestamp,
        log.decision.to_uppercase(),
        pid_text,
        log.uid,
        log.exe.display(),
        log.target_path.display()
    );

    println!("  event_id: {}", log.event_id);
    println!("  operation: {}", log.operation);
    println!("  reason: {}", log.reason);
    println!();
}

pub fn logs_to_json(logs: &[&logging::OwnedDecisionLog]) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(logs)?)
}

pub fn print_logs_json(logs: &[&logging::OwnedDecisionLog]) -> anyhow::Result<()> {
    println!("{}", logs_to_json(logs)?);
    Ok(())
}

pub fn select_last_logs<'a>(
    logs: &'a [&'a logging::OwnedDecisionLog],
    last: Option<usize>,
) -> &'a [&'a logging::OwnedDecisionLog] {
    match last {
        Some(0) => &[],
        Some(n) if n < logs.len() => &logs[logs.len() - n..],
        Some(_) | None => logs,
    }
}

pub fn filter_logs_by_decision(
    logs: &[logging::OwnedDecisionLog],
    decision: Option<DecisionFilter>,
) -> Vec<&logging::OwnedDecisionLog> {
    logs.iter()
        .filter(|log| match decision {
            Some(DecisionFilter::Allow) => log.decision == "allow",
            Some(DecisionFilter::Deny) => log.decision == "deny",
            None => true,
        })
        .collect()
}

pub fn filter_log_refs_since<'a>(
    logs: &[&'a logging::OwnedDecisionLog],
    since: Option<DateTime<Utc>>,
) -> Vec<&'a logging::OwnedDecisionLog> {
    logs.iter()
        .copied()
        .filter(|log| match since {
            Some(since) => log.timestamp >= since,
            None => true,
        })
        .collect()
}

pub fn parse_since_timestamp(value: &str) -> anyhow::Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

pub fn follow_jsonl_log(
    path: &Path,
    decision: Option<DecisionFilter>,
    since: Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    let mut file = File::open(path)?;
    file.seek(std::io::SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);

    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;

        if bytes == 0 {
            thread::sleep(Duration::from_millis(500));
            continue;
        }

        if line.trim().is_empty() {
            continue;
        }

        let log: logging::OwnedDecisionLog = serde_json::from_str(line.trim())?;

        if !matches_decision(&log, decision) {
            continue;
        }

        if since.is_some_and(|since| log.timestamp < since) {
            continue;
        }

        print_log_entry(&log);
    }
}

pub fn find_log_by_event_id(
    logs: &[logging::OwnedDecisionLog],
    event_id: Uuid,
) -> Option<&logging::OwnedDecisionLog> {
    logs.iter().find(|log| log.event_id == event_id)
}

fn matches_decision(log: &logging::OwnedDecisionLog, decision: Option<DecisionFilter>) -> bool {
    match decision {
        Some(DecisionFilter::Allow) => log.decision == "allow",
        Some(DecisionFilter::Deny) => log.decision == "deny",
        None => true,
    }
}

pub fn print_log_detail(log: &logging::OwnedDecisionLog) {
    println!("Event {}", log.event_id);
    println!();
    println!("Timestamp:   {}", log.timestamp);
    println!("Decision:    {}", log.decision.to_uppercase());
    println!(
        "PID:         {}",
        log.pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "<unknown>".to_string())
    );
    println!("UID:         {}", log.uid);
    println!("Executable:  {}", log.exe.display());
    println!(
        "CWD:         {}",
        log.cwd
            .as_ref()
            .map(|cwd| cwd.display().to_string())
            .unwrap_or_else(|| "<unknown>".to_string())
    );

    if log.cmdline.is_empty() {
        println!("Cmdline:    <unknown>");
    } else {
        println!("Cmdline:    {}", log.cmdline.join(" "));
    }

    if log.parent_chain.is_empty() {
        println!("Parent chain: <empty>");
    } else {
        println!("Parent chain:");

        for parent in &log.parent_chain {
            let exe = parent
                .exe
                .as_ref()
                .map(|exe| exe.display().to_string())
                .unwrap_or_else(|| "<unknown>".to_string());

            let cmdline = if parent.cmdline.is_empty() {
                "<empty>".to_string()
            } else {
                parent.cmdline.join(" ")
            };

            println!(
                "  pid={} ppid={} uid={} exe={} cmdline={}",
                parent.pid,
                parent
                    .ppid
                    .map(|ppid| ppid.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
                parent.uid,
                exe,
                cmdline
            );
        }
    }

    println!("Target:      {}", log.target_path.display());
    println!("Operation:   {}", log.operation);
    println!();
    println!("Reason:");
    println!("  {}", log.reason);
}

pub fn log_to_json(log: &logging::OwnedDecisionLog) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(log)?)
}

pub fn print_log_json(log: &logging::OwnedDecisionLog) -> anyhow::Result<()> {
    println!("{}", log_to_json(log)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn fake_log(index: usize) -> logging::OwnedDecisionLog {
        logging::OwnedDecisionLog {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            pid: None,
            uid: 1000,
            exe: PathBuf::from(format!("/usr/bin/tool-{index}")),
            cwd: None,
            cmdline: Vec::new(),
            parent_chain: Vec::new(),
            target_path: PathBuf::from(format!("/tmp/file-{index}")),
            operation: crate::event::Operation::OpenRead,
            decision: "allow".to_string(),
            reason: "test".to_string(),
            matched_path_group: None,
            would_deny: false,
        }
    }

    #[test]
    fn select_last_none_returns_all_logs() {
        let logs = [fake_log(1), fake_log(2), fake_log(3)];
        let refs: Vec<&logging::OwnedDecisionLog> = logs.iter().collect();

        let selected = select_last_logs(&refs, None);

        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn select_last_returns_last_n_logs() {
        let logs = [fake_log(1), fake_log(2), fake_log(3)];
        let refs: Vec<&logging::OwnedDecisionLog> = logs.iter().collect();

        let selected = select_last_logs(&refs, Some(2));

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].exe, PathBuf::from("/usr/bin/tool-2"));
        assert_eq!(selected[1].exe, PathBuf::from("/usr/bin/tool-3"));
    }

    #[test]
    fn select_last_larger_than_log_count_returns_all_logs() {
        let logs = [fake_log(1), fake_log(2)];
        let refs: Vec<&logging::OwnedDecisionLog> = logs.iter().collect();

        let selected = select_last_logs(&refs, None);

        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_last_zero_returns_no_logs() {
        let logs = [fake_log(1), fake_log(2)];
        let refs: Vec<&logging::OwnedDecisionLog> = logs.iter().collect();

        let selected = select_last_logs(&refs, Some(0));

        assert!(selected.is_empty());
    }

    #[test]
    fn filter_logs_by_decision_returns_all_when_no_filter() {
        let mut logs = [fake_log(1), fake_log(2)];
        logs[1].decision = "deny".to_string();

        let selected = filter_logs_by_decision(&logs, None);

        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn filter_log_refs_since_returns_logs_at_or_after_timestamp() {
        let mut logs = [fake_log(1), fake_log(2), fake_log(3)];
        logs[0].timestamp = parse_since_timestamp("2026-01-01T00:00:00Z").unwrap();
        logs[1].timestamp = parse_since_timestamp("2026-01-02T00:00:00Z").unwrap();
        logs[2].timestamp = parse_since_timestamp("2026-01-03T00:00:00Z").unwrap();
        let refs: Vec<&logging::OwnedDecisionLog> = logs.iter().collect();

        let selected = filter_log_refs_since(
            &refs,
            Some(parse_since_timestamp("2026-01-02T00:00:00Z").unwrap()),
        );

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].exe, PathBuf::from("/usr/bin/tool-2"));
        assert_eq!(selected[1].exe, PathBuf::from("/usr/bin/tool-3"));
    }

    #[test]
    fn parse_since_timestamp_accepts_rfc3339() {
        let timestamp = parse_since_timestamp("2026-01-02T03:04:05Z").unwrap();

        assert_eq!(timestamp.to_rfc3339(), "2026-01-02T03:04:05+00:00");
    }

    #[test]
    fn filter_logs_by_decision_returns_only_allow() {
        let mut logs = [fake_log(1), fake_log(2), fake_log(3)];
        logs[1].decision = "deny".to_string();

        let selected = filter_logs_by_decision(&logs, Some(DecisionFilter::Allow));

        assert_eq!(selected.len(), 2);
        assert!(selected.iter().all(|log| log.decision == "allow"));
    }

    #[test]
    fn filter_logs_by_decision_returns_only_deny() {
        let mut logs = [fake_log(1), fake_log(2), fake_log(3)];
        logs[0].decision = "deny".to_string();
        logs[2].decision = "deny".to_string();

        let selected = filter_logs_by_decision(&logs, Some(DecisionFilter::Deny));

        assert_eq!(selected.len(), 2);
        assert!(selected.iter().all(|log| log.decision == "deny"));
    }

    #[test]
    fn logs_to_json_outputs_array() {
        let logs = [fake_log(1), fake_log(2)];
        let refs: Vec<&logging::OwnedDecisionLog> = logs.iter().collect();

        let json = logs_to_json(&refs).expect("logs should serialize");

        assert!(json.starts_with("["));
        assert!(json.contains("\"uid\": 1000"));
        assert!(json.contains("/usr/bin/tool-1"));
        assert!(json.contains("/usr/bin/tool-2"));
    }

    #[test]
    fn find_log_by_event_id_returns_matching_log() {
        let logs = [fake_log(1), fake_log(2), fake_log(3)];
        let wanted_id = logs[1].event_id;

        let found = find_log_by_event_id(&logs, wanted_id);

        assert!(found.is_some());
        assert_eq!(found.unwrap().event_id, wanted_id);
        assert_eq!(found.unwrap().exe, PathBuf::from("/usr/bin/tool-2"));
    }

    #[test]
    fn find_log_by_event_id_returns_none_for_missing_log() {
        let logs = [fake_log(1), fake_log(2), fake_log(3)];

        let found = find_log_by_event_id(
            &logs,
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").expect("valid uuid"),
        );

        assert!(found.is_none());
    }

    #[test]
    fn log_to_json_outputs_single_object() {
        let log = fake_log(1);

        let json = log_to_json(&log).expect("log should serialize");

        assert!(json.starts_with("{"));
        assert!(json.contains("\"uid\": 1000"));
        assert!(json.contains("/usr/bin/tool-1"));
    }
}
