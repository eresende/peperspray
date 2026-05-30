mod config;
mod event;
mod logging;
mod policy;
mod process;

use anyhow::Context;
use clap::{Parser, Subcommand};
use event::{AccessEvent, Operation};
use policy::Decision;
use serde::Serialize;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "peperspray")]
#[command(about = "Credential access guard for developer workstations.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DecisionFilter {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReviewCandidateKey {
    uid: u32,
    exe: PathBuf,
    path_group: String,
}

#[derive(Debug)]
struct ReviewCandidate {
    key: ReviewCandidateKey,
    event_count: usize,
}

#[derive(Debug, Serialize)]
struct ReviewCandidateOutput {
    uid: u32,
    exe: PathBuf,
    path_group: String,
    event_count: usize,
    suggested_name: String,
}

#[derive(Debug, Subcommand)]
enum Command {
    PolicyValidate {
        #[arg(long, default_value = "examples/config.toml")]
        config: PathBuf,
    },

    TestAccess {
        target_path: PathBuf,

        #[arg(long, required_unless_present = "pid")]
        exe: Option<PathBuf>,

        #[arg(long, required_unless_present = "pid")]
        uid: Option<u32>,

        #[arg(long, conflicts_with_all = ["exe", "uid"])]
        pid: Option<u32>,

        #[arg(long, default_value = "examples/config.toml")]
        config: PathBuf,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        log_file: Option<PathBuf>,

    },

    Logs {
        #[arg(long, default_value = "./events.jsonl")]
        log_file: PathBuf,

        #[arg(long)]
        last: Option<usize>,

        #[arg(long)]
        decision: Option<DecisionFilter>,

        #[arg(long)]
        json: bool,
    },

    Why {
        event_id: Uuid,

        #[arg(long, default_value = "./events.jsonl")]
        log_file: PathBuf,

        #[arg(long)]
        json: bool,
    },

    PolicyReview {
        #[arg(long, default_value = "./events.jsonl")]
        log_file: PathBuf,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        toml: bool,

        #[arg(long)]
        write_suggestions: Option<PathBuf>,

        #[arg(long)]
        force: bool,
    },

    InspectProcess {
        pid: u32,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::PolicyValidate { config } => {
            let parsed_config = config::load_config(&config)
                .with_context(|| format!("failed to load config from {}", config.display()))?;

            let validation_errors = config::validate_config(&parsed_config);

            if validation_errors.is_empty() {
                println!("Config is valid.");
                println!("Mode: {:?}", parsed_config.mode);
                println!("Protected users: {}", parsed_config.users.len());
                println!("Protected groups: {}", parsed_config.protected_groups.len());
                println!("Allow rules: {}", parsed_config.allow_rules.len());
            } else {
                println!("Config validation failed:");

                for error in validation_errors {
                    println!("- {error}");
                }

                std::process::exit(1);
            }
        }

        Command::TestAccess {
            target_path,
            exe,
            uid,
            pid,
            config,
            json,
            log_file,
        } => {
            let parsed_config = config::load_config(&config)
                .with_context(|| format!("failed to load config from {}", config.display()))?;

            let event = build_access_event(target_path, exe, uid, pid)?;

            let decision = policy::decide(&parsed_config, &event);
            let decision_log = logging::DecisionLog::new(&event, &decision);

            if let Some(log_file) = log_file {
                logging::append_jsonl_log(&log_file, &decision_log)
                    .with_context(|| format!("failed to append log to {}", log_file.display()))?;
            }

            if json {
                logging::print_json_log(&decision_log)?;
            } else {
                print_decision(&decision);
            }
        }

        Command::Logs {
            log_file,
            last,
            decision,
            json,
        } => {
            let logs = logging::read_jsonl_logs(&log_file)
                .with_context(|| format!("failed to read logs from {}", log_file.display()))?;

            let logs = filter_logs_by_decision(&logs, decision);
            let logs = select_last_logs(&logs, last);

            if json {
                print_logs_json(logs)?;
            } else if logs.is_empty() {
                println!("No log events found.");
            } else {
                for log in logs {
                    print_log_entry(log);
                }
            }
        }

        Command::Why {
            event_id,
            log_file,
            json,
        } => {
            let logs = logging::read_jsonl_logs(&log_file)
                .with_context(|| format!("failed to read log file {}", log_file.display()))?;

            let Some(log) = find_log_by_event_id(&logs, event_id) else {
                anyhow::bail!(
                    "event id {} was not found in {}",
                    event_id,
                    log_file.display()
                );
            };

            if json {
                print_log_json(log)?;
            } else {
                print_log_detail(log);
            }
        }

        Command::PolicyReview {
            log_file,
            json,
            toml,
            write_suggestions,
            force,
        } => {
            if json && toml {
                anyhow::bail!("--json and --toml cannot be used together");
            }

            if write_suggestions.is_some() && (json || toml) {
                anyhow::bail!("--write-suggestions cannot be used together with --json or --toml");
            }

            if force && write_suggestions.is_none() {
                anyhow::bail!("--force can only be used with --write-suggestions");
            }

            let logs = logging::read_jsonl_logs(&log_file)
                .with_context(|| format!("failed to read logs from {}", log_file.display()))?;

            let candidates = build_review_candidates(&logs);

            if let Some(path) = write_suggestions {
                write_review_suggestions(&path, &candidates, force).with_context(|| {
                    format!("failed to write suggestions to {}", path.display())
                })?;

                println!(
                    "Wrote {} to {}",
                    allow_rule_count_text(candidates.len()),
                    path.display()
                );
            } else if json {
                print_review_candidates_json(&candidates)?;
            } else if toml {
                print_review_candidates_toml(&candidates);
            } else {
                print_review_candidates(&candidates);
            }
        }

        Command::InspectProcess { pid } => {
            let info = process::inspect_process(pid)
                .with_context(|| format!("failed to inspect proces {pid}"))?;

            print_process_info(&info);
        }

    }

    Ok(())
}

fn build_access_event(
    target_path: PathBuf,
    exe: Option<PathBuf>,
    uid: Option<u32>,
    pid: Option<u32>,
) -> anyhow::Result<AccessEvent> {
    if let Some(pid) = pid {
        let process_info = process::inspect_process(pid)
            .with_context(|| format!("failed to inspect process {pid}"))?;

        return Ok(AccessEvent {
            uid: process_info.uid,
            exe: process_info.exe,
            target_path,
            operation: Operation::OpenRead,
        });
    }

    let exe = exe.context("--exe is required when --pid is not provided")?;
    let uid = uid.context("--uid is required when --pid is not provided")?;

    Ok(AccessEvent {
        uid,
        exe,
        target_path,
        operation: Operation::OpenRead,
    })
}

fn print_decision(decision: &Decision) {
    match decision {
        Decision::Allow { reason, .. } => {
            println!("ALLOW: {reason}");
        }
        Decision::Deny { reason, .. } => {
            println!("DENY: {reason}");
        }
    }
}

fn print_log_entry(log: &logging::OwnedDecisionLog) {
    println!(
        "{} {} uid={} {} -> {}",
        log.timestamp,
        log.decision.to_uppercase(),
        log.uid,
        log.exe.display(),
        log.target_path.display()
    );

    println!("  event_id: {}", log.event_id);
    println!("  operation: {:?}", log.operation);
    println!("  reason: {}", log.reason);
    println!();
}

fn logs_to_json(logs: &[&logging::OwnedDecisionLog]) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(logs)?)
}
fn print_logs_json(logs: &[&logging::OwnedDecisionLog]) -> anyhow::Result<()> {
    println!("{}", logs_to_json(logs)?);
    Ok(())
}

fn select_last_logs<'a>(
    logs: &'a [&'a logging::OwnedDecisionLog],
    last: Option<usize>,
) -> &'a [&'a logging::OwnedDecisionLog] {
    match last {
        Some(0) => &[],
        Some(n) if n < logs.len() => &logs[logs.len() - n..],
        Some(_) | None => logs,
    }
}

fn filter_logs_by_decision(
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

fn find_log_by_event_id(
    logs: &[logging::OwnedDecisionLog],
    event_id: Uuid,
) -> Option<&logging::OwnedDecisionLog> {
    logs.iter().find(|log| log.event_id == event_id)
}

fn print_log_detail(log: &logging::OwnedDecisionLog) {
    println!("Event {}", log.event_id);
    println!();
    println!("Timestamp:   {}", log.timestamp);
    println!("Decision:    {}", log.decision.to_uppercase());
    println!("UID:         {}", log.uid);
    println!("Executable:  {}", log.exe.display());
    println!("Target:      {}", log.target_path.display());
    println!("Operation:   {:?}", log.operation);
    println!();
    println!("Reason:");
    println!("  {}", log.reason);
}

fn log_to_json(log: &logging::OwnedDecisionLog) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(log)?)
}

fn print_log_json(log: &logging::OwnedDecisionLog) -> anyhow::Result<()> {
    println!("{}", log_to_json(log)?);
    Ok(())
}

fn build_review_candidates(logs: &[logging::OwnedDecisionLog]) -> Vec<ReviewCandidate> {
    let mut counts: std::collections::HashMap<ReviewCandidateKey, usize> =
        std::collections::HashMap::new();

    for log in logs {
        if !log.would_deny {
            continue;
        }

        let Some(path_group) = &log.matched_path_group else {
            continue;
        };

        let key = ReviewCandidateKey {
            uid: log.uid,
            exe: log.exe.clone(),
            path_group: path_group.clone(),
        };

        *counts.entry(key).or_insert(0) += 1;
    }

    let mut candidates: Vec<ReviewCandidate> = counts
        .into_iter()
        .map(|(key, event_count)| ReviewCandidate { key, event_count })
        .collect();

    candidates.sort_by(|a, b| {
        b.event_count
            .cmp(&a.event_count)
            .then_with(|| a.key.exe.cmp(&b.key.exe))
            .then_with(|| a.key.path_group.cmp(&b.key.path_group))
    });

    candidates
}

fn print_review_candidates(candidates: &[ReviewCandidate]) {
    if candidates.is_empty() {
        println!("No learn-mode would-deny events found.");
        return;
    }

    println!("Candidate allow rules from learned accesses:");
    println!();

    for (index, candidate) in candidates.iter().enumerate() {
        println!(
            "{}. Allow {} to access {}",
            index + 1,
            candidate.key.exe.display(),
            candidate.key.path_group
        );
        println!("   uid:        {}", candidate.key.uid);
        println!("   exe:        {}", candidate.key.exe.display());
        println!("   path_group: {}", candidate.key.path_group);
        println!("   events:     {}", candidate.event_count);
        println!();

        print_candidate_toml(candidate);
        println!();
    }
}

fn executable_name(exe: &std::path::Path) -> String {
    exe.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn suggested_allow_rule_name(candidate: &ReviewCandidate) -> String {
    format!(
        "Allow {} to access {}",
        executable_name(&candidate.key.exe),
        candidate.key.path_group
    )
}

fn print_candidate_toml(candidate: &ReviewCandidate) {
    println!("   Suggested TOML:");

    for line in candidate_to_toml(candidate).lines() {
        println!("   {line}");
    }
}

fn review_candidate_to_output(candidate: &ReviewCandidate) -> ReviewCandidateOutput {
    ReviewCandidateOutput {
        uid: candidate.key.uid,
        exe: candidate.key.exe.clone(),
        path_group: candidate.key.path_group.clone(),
        event_count: candidate.event_count,
        suggested_name: suggested_allow_rule_name(candidate),
    }
}

fn review_candidates_to_output(candidates: &[ReviewCandidate]) -> Vec<ReviewCandidateOutput> {
    candidates.iter().map(review_candidate_to_output).collect()
}

fn review_candidates_to_json(candidates: &[ReviewCandidate]) -> anyhow::Result<String> {
    let output = review_candidates_to_output(candidates);
    Ok(serde_json::to_string_pretty(&output)?)
}

fn print_review_candidates_json(candidates: &[ReviewCandidate]) -> anyhow::Result<()> {
    println!("{}", review_candidates_to_json(candidates)?);
    Ok(())
}

fn candidate_to_toml(candidate: &ReviewCandidate) -> String {
    format!(
        "[[allow_rules]]\nname = \"{}\"\nuid = {}\nexe = \"{}\"\npath_group = \"{}\"",
        suggested_allow_rule_name(candidate),
        candidate.key.uid,
        candidate.key.exe.display(),
        candidate.key.path_group
    )
}

fn review_candidates_to_toml(candidates: &[ReviewCandidate]) -> String {
    candidates
        .iter()
        .map(candidate_to_toml)
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn print_review_candidates_toml(candidates: &[ReviewCandidate]) {
    let toml = review_candidates_to_toml(candidates);

    if !toml.is_empty() {
        println!("{toml}");
    }
}

fn write_review_suggestions(
    path: &Path,
    candidates: &[ReviewCandidate],
    force: bool,
) -> anyhow::Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; use --force to overwrite it",
            path.display()
        );
    }

    let toml = review_candidates_to_toml(candidates);

    std::fs::write(path, toml)?;

    Ok(())
}

fn allow_rule_count_text(count: usize) -> String {
    match count {
        1 => "1 suggested allow rule".to_string(),
        n => format!("{n} suggested allow rules"),
    }
}

fn print_process_info(info: &process::ProcessInfo) {
    println!("PID:       {}", info.pid);
    println!("UID:       {}", info.uid);
    println!("EXE:       {}", info.exe.display());
    println!("CWD:       {}", info.cwd.display());

    if info.cmdline.is_empty() {
        println!("CMDLINE:   <empty>");
    } else {
        println!("CMDLINE:   {}", info.cmdline.join(" "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn fake_log(index: usize) -> logging::OwnedDecisionLog {
        logging::OwnedDecisionLog {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            uid: 1000,
            exe: PathBuf::from(format!("/usr/bin/tool-{index}")),
            target_path: PathBuf::from(format!("/tmp/file-{index}")),
            operation: event::Operation::OpenRead,
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

    #[test]
    fn build_review_candidates_groups_matching_events() {
        let mut logs = [fake_log(1), fake_log(2), fake_log(3)];

        logs[0].exe = PathBuf::from("/usr/bin/python3");
        logs[0].would_deny = true;
        logs[0].matched_path_group = Some("aws".to_string());

        logs[1].exe = PathBuf::from("/usr/bin/python3");
        logs[1].would_deny = true;
        logs[1].matched_path_group = Some("aws".to_string());

        logs[2].exe = PathBuf::from("/usr/bin/git");
        logs[2].would_deny = true;
        logs[2].matched_path_group = Some("ssh".to_string());

        let candidates = build_review_candidates(&logs);

        assert_eq!(candidates.len(), 2);

        assert_eq!(candidates[0].key.exe, PathBuf::from("/usr/bin/python3"));
        assert_eq!(candidates[0].key.path_group, "aws");
        assert_eq!(candidates[0].event_count, 2);

        assert_eq!(candidates[1].key.exe, PathBuf::from("/usr/bin/git"));
        assert_eq!(candidates[1].key.path_group, "ssh");
        assert_eq!(candidates[1].event_count, 1);
    }

    #[test]
    fn review_candidate_to_output_adds_suggested_name() {
        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
            },
            event_count: 2,
        };

        let output = review_candidate_to_output(&candidate);

        assert_eq!(output.uid, 1000);
        assert_eq!(output.exe, PathBuf::from("/usr/bin/python3"));
        assert_eq!(output.path_group, "aws");
        assert_eq!(output.event_count, 2);
        assert_eq!(output.suggested_name, "Allow python3 to access aws");
    }

    #[test]
    fn review_candidates_to_json_array() {
        let candidates = [ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
            },
            event_count: 1,
        }];

        let json =
            review_candidates_to_json(&candidates).expect("review candidates should serialize");

        assert!(json.starts_with("["));
        assert!(json.contains("\"uid\": 1000"));
        assert!(json.contains("\"path_group\": \"aws\""));
        assert!(json.contains("\"suggested_name\": \"Allow python3 to access aws\""));
    }

    #[test]
    fn candidate_to_toml_outputs_allow_rule_snippet() {
        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
            },
            event_count: 1,
        };

        let toml = candidate_to_toml(&candidate);

        assert!(toml.contains("[[allow_rules]]"));
        assert!(toml.contains("name = \"Allow python3 to access aws\""));
        assert!(toml.contains("uid = 1000"));
        assert!(toml.contains("exe = \"/usr/bin/python3\""));
        assert!(toml.contains("path_group = \"aws\""));
    }

    #[test]
    fn review_candidates_to_toml_separates_multiple_rules() {
        let candidates = [
            ReviewCandidate {
                key: ReviewCandidateKey {
                    uid: 1000,
                    exe: PathBuf::from("/usr/bin/python3"),
                    path_group: "aws".to_string(),
                },
                event_count: 1,
            },
            ReviewCandidate {
                key: ReviewCandidateKey {
                    uid: 1000,
                    exe: PathBuf::from("/usr/bin/git"),
                    path_group: "ssh".to_string(),
                },
                event_count: 1,
            },
        ];

        let toml = review_candidates_to_toml(&candidates);

        assert!(toml.contains("name = \"Allow python3 to access aws\""));
        assert!(toml.contains("name = \"Allow git to access ssh\""));
        assert!(toml.contains("\n\n[[allow_rules]]"));
    }

    #[test]
    fn allow_rule_count_text_handles_singular() {
        assert_eq!(allow_rule_count_text(1), "1 suggested allow rule");
    }

    #[test]
    fn allow_rule_count_text_handles_plural() {
        assert_eq!(allow_rule_count_text(0), "0 suggested allow rules");
        assert_eq!(allow_rule_count_text(2), "2 suggested allow rules");
    }

    #[test]
    fn write_review_suggestions_writes_toml_file() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("suggested-rules.toml");

        let candidates = [ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
            },
            event_count: 1,
        }];

        write_review_suggestions(&path, &candidates, false).expect("suggestions should be written");

        let contents = std::fs::read_to_string(&path).expect("suggestions should be readable");

        assert!(contents.contains("[[allow_rules]]"));
        assert!(contents.contains("name = \"Allow python3 to access aws\""));
    }

    #[test]
    fn write_review_suggestions_refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("suggested-rules.toml");

        let candidates = [ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
            },
            event_count: 1,
        }];

        write_review_suggestions(&path, &candidates, false).expect("first write should succeed");

        let result = write_review_suggestions(&path, &candidates, false);

        assert!(result.is_err());
    }

    #[test]
    fn write_review_suggestions_overwrites_with_force() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("suggested-rules.toml");

        let candidates = [ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
            },
            event_count: 1,
        }];

        std::fs::write(&path, "old content").expect("initial file should be written");

        write_review_suggestions(&path, &candidates, true).expect("force write should succeed");

        let contents = std::fs::read_to_string(&path).expect("suggestions should be readable");

        assert!(contents.contains("[[allow_rules]]"));
        assert!(!contents.contains("old contents"));
    }

    #[test]
    fn build_access_event_from_manual_exe_and_uid() {
        let event = build_access_event(
            PathBuf::from("/home/alice/.aws/credentials"),
            Some(PathBuf::from("/usr/bin/python3")),
            Some(1000),
            None,
        ).expect("event should be built");

        assert_eq!(event.uid, 1000);
        assert_eq!(event.exe, PathBuf::from("/usr/bin/python3"));
        assert_eq!(
            event.target_path,
            PathBuf::from("/home/alice/.aws/credentials")
        );
    }

    #[test]
    fn build_access_event_requires_exe_without_pid() {
        let result = build_access_event(
            PathBuf::from("/home/alice/.aws/credentials"),
            None,
            Some(1000),
            None,
        );

        assert!(result.is_err());
    }
}
