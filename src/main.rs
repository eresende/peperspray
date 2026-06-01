mod config;
mod event;
mod logging;
mod paths;
mod policy;
mod process;

use anyhow::Context;
use clap::{Parser, Subcommand};
use event::{AccessEvent, Operation};
use policy::Decision;
use serde::Serialize;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const DEFAULT_CONFIG_PATH: &str = "examples/config.toml";
const DEFAULT_LOG_FILE: &str = "./events.jsonl";

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
    parent_exe: Option<PathBuf>,
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

    #[serde(skip_serializing_if = "Option::is_none")]
    parent_exe: Option<PathBuf>,

    event_count: usize,
    suggested_name: String,
}

#[derive(Debug, Serialize)]
struct StatusOutput<'a> {
    mode: String,
    protected_users: usize,
    protected_groups: usize,
    allow_rules: usize,
    groups: &'a [config::ProtectedPathGroup],
    rules: &'a [config::AllowRule],
}

#[derive(Debug, Serialize)]
struct SetupOutput {
    output: PathBuf,
    uid: u32,
    written: bool,
    detected_tools: Vec<SetupDetectedToolOutput>,
    skipped_tools: Vec<SetupSkippedToolOutput>,
}

#[derive(Debug, Serialize)]
struct SetupDetectedToolOutput {
    command: String,
    rule_name: String,
    path_group: String,
    exe: PathBuf,
}

#[derive(Debug, Serialize)]
struct SetupSkippedToolOutput {
    command: String,
    rule_name: String,
    path_group: String,
    reason: String,
}

#[derive(Debug, Subcommand)]
enum Command {
    PolicyValidate {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
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

        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        log_file: Option<PathBuf>,
    },

    Logs {
        #[arg(long, default_value = DEFAULT_LOG_FILE)]
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

        #[arg(long, default_value = DEFAULT_LOG_FILE)]
        log_file: PathBuf,

        #[arg(long)]
        json: bool,
    },

    PolicyReview {
        #[arg(long, default_value = DEFAULT_LOG_FILE)]
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

    Status {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        #[arg(long)]
        json: bool,
    },

    Setup {
        #[arg(long, default_value = "generated-config.toml")]
        output: PathBuf,

        #[arg(long)]
        force: bool,

        #[arg(long)]
        json: bool,
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

        Command::Status { config, json } => {
            let parsed_config = config::load_config(&config)
                .with_context(|| format!("failed to load config from {}", config.display()))?;

            let validation_errors = config::validate_config(&parsed_config);

            if !validation_errors.is_empty() {
                println!("Config validation failed:");

                for error in validation_errors {
                    println!("- {error}");
                }

                std::process::exit(1);
            }

            if json {
                print_status_json(&parsed_config)?;
            } else {
                print_status(&parsed_config);
            }
        }

        Command::Setup {
            output,
            force,
            json,
        } => {
            let uid = current_uid();

            let statuses = detect_setup_tool_statuses();
            let tools = detected_tools_from_statuses(&statuses);

            write_starter_config_with_tools(&output, uid, &tools, force).with_context(|| {
                format!("failed to write starter config to {}", output.display())
            })?;

            if json {
                let setup_output = setup_output_from_statuses(output.clone(), uid, true, &statuses);

                print_setup_output_json(&setup_output)?;
            } else {
                print_setup_tool_detection(&statuses);
                println!("Wrote starter config to {}", output.display());
            }
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
            pid: Some(process_info.pid),
            uid: process_info.uid,
            exe: paths::normalize_path(&process_info.exe),
            cwd: Some(paths::normalize_path(&process_info.cwd)),
            cmdline: process_info.cmdline,
            parent_chain: process_info.parent_chain,
            target_path: paths::normalize_path(&target_path),
            operation: Operation::OpenRead,
        });
    }

    let exe = exe.context("--exe is required when --pid is not provided")?;
    let uid = uid.context("--uid is required when --pid is not provided")?;

    let exe = paths::normalize_path(&exe);
    let target_path = paths::normalize_path(&target_path);

    Ok(AccessEvent {
        pid: None,
        uid,
        exe,
        cwd: None,
        cmdline: Vec::new(),
        parent_chain: Vec::new(),
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
            parent_exe: immediate_parent_exe(log),
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
        println!(
            "   parent_exe: {}",
            candidate
                .key
                .parent_exe
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string())
        );
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
    match &candidate.key.parent_exe {
        Some(parent_exe) => format!(
            "Allow {} to access {} from {}",
            executable_name(&candidate.key.exe),
            candidate.key.path_group,
            executable_name(parent_exe)
        ),
        None => format!(
            "Allow {} to access {}",
            executable_name(&candidate.key.exe),
            candidate.key.path_group
        ),
    }
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
        parent_exe: candidate.key.parent_exe.clone(),
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
    let mut toml = format!(
        "[[allow_rules]]\nname = \"{}\"\nuid = {}\nexe = \"{}\"\npath_group = \"{}\"\noperation = \"{}\"",
        suggested_allow_rule_name(candidate),
        candidate.key.uid,
        candidate.key.exe.display(),
        candidate.key.path_group,
        Operation::OpenRead
    );

    if let Some(parent_exe) = &candidate.key.parent_exe {
        toml.push_str(&format!("\nparent_exe = \"{}\"", parent_exe.display()));
    }

    toml
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
    println!(
        "PPID:      {}",
        info.ppid
            .map(|ppid| ppid.to_string())
            .unwrap_or_else(|| "<unknown>".to_string())
    );
    println!("UID:       {}", info.uid);
    println!("EXE:       {}", info.exe.display());
    println!("CWD:       {}", info.cwd.display());

    if info.cmdline.is_empty() {
        println!("CMDLINE:   <empty>");
    } else {
        println!("CMDLINE:   {}", info.cmdline.join(" "));
    }

    if info.parent_chain.is_empty() {
        println!();
        println!("Parent chain: <empty>");
    } else {
        println!();
        println!("Parent chain:");

        for parent in &info.parent_chain {
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
}

fn immediate_parent_exe(log: &logging::OwnedDecisionLog) -> Option<PathBuf> {
    log.parent_chain
        .first()
        .and_then(|parent| parent.exe.clone())
}

fn print_status(config: &config::Config) {
    println!("Mode: {}", config.mode);
    println!("Protected users: {}", config.users.len());
    println!("Protected groups: {}", config.protected_groups.len());
    println!("Allow rules: {}", config.allow_rules.len());
    println!();

    println!("Protected groups:");
    for group in &config.protected_groups {
        println!("  {}", group.name);

        for path in &group.paths {
            println!("    {}", path.display());
        }
    }

    println!();
    println!("Allow rules:");

    if config.allow_rules.is_empty() {
        println!("  <none>");
        return;
    }

    for rule in &config.allow_rules {
        println!("  {}", rule.name);
        println!("    uid:        {}", rule.uid);
        println!("    exe:        {}", rule.exe.display());
        println!("    path_group: {}", rule.path_group);
        println!(
            "    operation:  {}",
            rule.operation
                .map(|operation| operation.to_string())
                .unwrap_or_else(|| "<any>".to_string())
        );
        println!(
            "    parent_exe: {}",
            rule.parent_exe
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string())
        );
    }
}

fn status_to_json(config: &config::Config) -> anyhow::Result<String> {
    let output = StatusOutput {
        mode: config.mode.to_string(),
        protected_users: config.users.len(),
        protected_groups: config.protected_groups.len(),
        allow_rules: config.allow_rules.len(),
        groups: &config.protected_groups,
        rules: &config.allow_rules,
    };

    Ok(serde_json::to_string_pretty(&output)?)
}

fn print_status_json(config: &config::Config) -> anyhow::Result<()> {
    println!("{}", status_to_json(config)?);
    Ok(())
}

fn current_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn starter_config_toml_with_tools(uid: u32, tools: &[DetectedTool]) -> String {
    let protected_groups = starter_protected_groups_toml();
    let allow_rules = starter_allow_rules_toml(uid, tools);

    let mut toml = format!(
        r#"mode = "learn"

[[users]]
uid = {uid}
groups = ["aws", "ssh", "github", "gcloud", "docker"]

{protected_groups}
"#
    );

    if !allow_rules.is_empty() {
        toml.push('\n');
        toml.push_str(&allow_rules);
        toml.push('\n');
    }

    toml
}

fn starter_protected_groups_toml() -> String {
    [
        r#"[[protected_groups]]
name = "aws"
paths = ["~/.aws"]"#,
        r#"[[protected_groups]]
name = "ssh"
paths = ["~/.ssh"]"#,
        r#"[[protected_groups]]
name = "github"
paths = ["~/.config/gh", "~/.git-credentials", "~/.netrc"]"#,
        r#"[[protected_groups]]
name = "gcloud"
paths = ["~/.config/gcloud"]"#,
        r#"[[protected_groups]]
name = "docker"
paths = ["~/.docker"]"#,
    ]
    .join("\n\n")
}

fn starter_allow_rules_toml(uid: u32, tools: &[DetectedTool]) -> String {
    tools
        .iter()
        .map(|tool| {
            format!(
                r#"[[allow_rules]]
name = "{}"
uid = {}
exe = "{}"
path_group = "{}"
operation = "open_read""#,
                tool.rule_name,
                uid,
                tool.exe.display(),
                tool.path_group
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn write_starter_config_with_tools(
    path: &std::path::Path,
    uid: u32,
    tools: &[DetectedTool],
    force: bool,
) -> anyhow::Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; use --force to overwrite it",
            path.display()
        );
    }

    std::fs::write(path, starter_config_toml_with_tools(uid, tools))?;

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct SetupTool {
    command: &'static str,
    rule_name: &'static str,
    path_group: &'static str,
}

const SETUP_TOOLS: &[SetupTool] = &[
    SetupTool {
        command: "aws",
        rule_name: "Allow AWS CLI",
        path_group: "aws",
    },
    SetupTool {
        command: "ssh",
        rule_name: "Allow SSH client",
        path_group: "ssh",
    },
    SetupTool {
        command: "gh",
        rule_name: "Allow GitHub CLI",
        path_group: "github",
    },
    SetupTool {
        command: "gcloud",
        rule_name: "Allow Google Cloud CLI",
        path_group: "gcloud",
    },
    SetupTool {
        command: "docker",
        rule_name: "Allow Docker CLI",
        path_group: "docker",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectedTool {
    rule_name: String,
    exe: PathBuf,
    path_group: String,
}

fn detected_tools_from_statuses(statuses: &[SetupToolDetection]) -> Vec<DetectedTool> {
    statuses
        .iter()
        .filter_map(|status| {
            let exe = status.exe.clone()?;

            Some(DetectedTool {
                rule_name: status.tool.rule_name.to_string(),
                exe,
                path_group: status.tool.path_group.to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
struct SetupToolDetection {
    tool: SetupTool,
    exe: Option<PathBuf>,
}

fn detect_setup_tool_statuses() -> Vec<SetupToolDetection> {
    SETUP_TOOLS
        .iter()
        .map(|tool| {
            let exe = which::which(tool.command)
                .ok()
                .map(|path| paths::normalize_path(&path));

            SetupToolDetection { tool: *tool, exe }
        })
        .collect()
}

fn print_setup_tool_detection(statuses: &[SetupToolDetection]) {
    let detected: Vec<&SetupToolDetection> = statuses
        .iter()
        .filter(|status| status.exe.is_some())
        .collect();

    let skipped: Vec<&SetupToolDetection> = statuses
        .iter()
        .filter(|status| status.exe.is_none())
        .collect();

    println!("Detected tools:");

    if detected.is_empty() {
        println!("  <none>");
    } else {
        for status in detected {
            let exe = status.exe.as_ref().expect("detected tool should have exe");
            println!("  {:<7} {}", status.tool.command, exe.display());
        }
    }

    println!();
    println!("Skipped tools:");

    if skipped.is_empty() {
        println!("  <none>");
    } else {
        for status in skipped {
            println!("  {:<7} not found in PATH", status.tool.command);
        }
    }

    println!();
}

fn setup_output_from_statuses(
    output: PathBuf,
    uid: u32,
    written: bool,
    statuses: &[SetupToolDetection],
) -> SetupOutput {
    let detected_tools = statuses
        .iter()
        .filter_map(|status| {
            let exe = status.exe.clone()?;

            Some(SetupDetectedToolOutput {
                command: status.tool.command.to_string(),
                rule_name: status.tool.rule_name.to_string(),
                path_group: status.tool.path_group.to_string(),
                exe,
            })
        })
        .collect();

    let skipped_tools = statuses
        .iter()
        .filter(|status| status.exe.is_none())
        .map(|status| SetupSkippedToolOutput {
            command: status.tool.command.to_string(),
            rule_name: status.tool.rule_name.to_string(),
            path_group: status.tool.path_group.to_string(),
            reason: "not found in PATH".to_string(),
        })
        .collect();

    SetupOutput {
        output,
        uid,
        written,
        detected_tools,
        skipped_tools,
    }
}

fn setup_output_to_json(output: &SetupOutput) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(output)?)
}

fn print_setup_output_json(output: &SetupOutput) -> anyhow::Result<()> {
    println!("{}", setup_output_to_json(output)?);
    Ok(())
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
            pid: None,
            uid: 1000,
            exe: PathBuf::from(format!("/usr/bin/tool-{index}")),
            cwd: None,
            cmdline: Vec::new(),
            parent_chain: Vec::new(),
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
                parent_exe: None,
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
                parent_exe: None,
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
                parent_exe: None,
            },
            event_count: 1,
        };

        let toml = candidate_to_toml(&candidate);

        assert!(toml.contains("[[allow_rules]]"));
        assert!(toml.contains("name = \"Allow python3 to access aws\""));
        assert!(toml.contains("uid = 1000"));
        assert!(toml.contains("exe = \"/usr/bin/python3\""));
        assert!(toml.contains("path_group = \"aws\""));
        assert!(toml.contains("operation = \"open_read\""));
    }

    #[test]
    fn review_candidates_to_toml_separates_multiple_rules() {
        let candidates = [
            ReviewCandidate {
                key: ReviewCandidateKey {
                    uid: 1000,
                    exe: PathBuf::from("/usr/bin/python3"),
                    path_group: "aws".to_string(),
                    parent_exe: None,
                },
                event_count: 1,
            },
            ReviewCandidate {
                key: ReviewCandidateKey {
                    uid: 1000,
                    exe: PathBuf::from("/usr/bin/git"),
                    path_group: "ssh".to_string(),
                    parent_exe: None,
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
                parent_exe: None,
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
                parent_exe: None,
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
                parent_exe: None,
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
            Some(PathBuf::from("/missing/bin/python3")),
            Some(1000),
            None,
        )
        .expect("event should be built");

        assert_eq!(event.uid, 1000);
        assert_eq!(event.exe, PathBuf::from("/missing/bin/python3"));
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

    #[test]
    fn suggested_allow_rule_name_includes_parent_when_present() {
        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: Some(PathBuf::from("/usr/bin/zsh")),
            },
            event_count: 1,
        };

        let name = suggested_allow_rule_name(&candidate);

        assert_eq!(name, "Allow python3 to access aws from zsh");
    }

    #[test]
    fn candidate_to_toml_includes_parent_exe_when_present() {
        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: Some(PathBuf::from("/usr/bin/zsh")),
            },
            event_count: 1,
        };

        let toml = candidate_to_toml(&candidate);

        assert!(toml.contains("parent_exe = \"/usr/bin/zsh\""));
        assert!(toml.contains("name = \"Allow python3 to access aws from zsh\""));
        assert!(toml.contains("operation = \"open_read\""));
    }

    #[test]
    fn immediate_parent_exe_returns_first_parent_exe() {
        let mut log = fake_log(1);

        log.parent_chain = vec![
            process::ProcessChainEntry {
                pid: 2000,
                ppid: Some(1000),
                uid: 1000,
                exe: Some(PathBuf::from("/usr/bin/zsh")),
                cmdline: Vec::new(),
            },
            process::ProcessChainEntry {
                pid: 1000,
                ppid: Some(1),
                uid: 1000,
                exe: Some(PathBuf::from("/usr/lib/systemd/systemd")),
                cmdline: Vec::new(),
            },
        ];

        assert_eq!(
            immediate_parent_exe(&log),
            Some(PathBuf::from("/usr/bin/zsh"))
        );
    }

    #[test]
    fn status_to_json_outputs_summary() {
        let config = config::Config {
            mode: config::Mode::Learn,
            users: vec![config::ProtectedUser {
                uid: 1000,
                groups: vec!["aws".to_string()],
            }],
            protected_groups: vec![config::ProtectedPathGroup {
                name: "aws".to_string(),
                paths: vec![PathBuf::from("/home/alice/.aws")],
            }],
            allow_rules: vec![config::AllowRule {
                name: "Allow AWS CLI".to_string(),
                uid: 1000,
                exe: PathBuf::from("/usr/bin/aws"),
                path_group: "aws".to_string(),
                parent_exe: None,
                operation: None,
            }],
        };

        let json = status_to_json(&config).expect("status should serialize");

        assert!(json.contains("\"mode\": \"learn\""));
        assert!(json.contains("\"protected_users\": 1"));
        assert!(json.contains("\"protected_groups\": 1"));
        assert!(json.contains("\"allow_rules\": 1"));
        assert!(json.contains("\"name\": \"aws\""));
        assert!(json.contains("\"name\": \"Allow AWS CLI\""));
    }

    #[test]
    fn starter_config_contains_uid_and_default_groups() {
        let tools = [
            DetectedTool {
                rule_name: "Allow AWS CLI".to_string(),
                exe: PathBuf::from("/usr/bin/aws"),
                path_group: "aws".to_string(),
            },
            DetectedTool {
                rule_name: "Allow SSH client".to_string(),
                exe: PathBuf::from("/usr/bin/ssh"),
                path_group: "ssh".to_string(),
            },
        ];

        let toml = starter_config_toml_with_tools(1000, &tools);

        assert!(toml.contains("uid = 1000"));
        assert!(toml.contains("groups = [\"aws\", \"ssh\", \"github\", \"gcloud\", \"docker\"]"));
        assert!(toml.contains("paths = [\"~/.aws\"]"));
        assert!(toml.contains("paths = [\"~/.ssh\"]"));
        assert!(toml.contains("name = \"Allow AWS CLI\""));
        assert!(toml.contains("name = \"Allow SSH client\""));
        assert!(toml.contains("operation = \"open_read\""));
    }

    #[test]
    fn starter_config_parses_as_config() {
        let tools = [DetectedTool {
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        let toml = starter_config_toml_with_tools(1000, &tools);

        let config: config::Config = toml::from_str(&toml).expect("starter config should parse");

        assert_eq!(config.mode, config::Mode::Learn);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.protected_groups.len(), 5);
        assert_eq!(config.allow_rules.len(), 1);
    }

    #[test]
    fn write_starter_config_writes_file() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");

        let tools = [DetectedTool {
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        write_starter_config_with_tools(&path, 1000, &tools, false)
            .expect("starter config should be written");

        let contents = std::fs::read_to_string(&path).expect("config should be readable");

        assert!(contents.contains("uid = 1000"));
        assert!(contents.contains("mode = \"learn\""));
        assert!(contents.contains("Allow SSH client"));
    }

    #[test]
    fn write_starter_config_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");

        let tools = [DetectedTool {
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        write_starter_config_with_tools(&path, 1000, &tools, false)
            .expect("first write should succeed");

        let result = write_starter_config_with_tools(&path, 1000, &tools, false);

        assert!(result.is_err());
    }

    #[test]
    fn write_starter_config_overwrites_with_force() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "old contents").expect("old config should be written");

        let tools = [DetectedTool {
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        write_starter_config_with_tools(&path, 1000, &tools, true)
            .expect("force write should succeed");

        let contents = std::fs::read_to_string(&path).expect("config should be readable");

        assert!(contents.contains("mode = \"learn\""));
        assert!(!contents.contains("old contents"));
    }

    #[test]
    fn starter_config_allows_no_detected_tools() {
        let tools = [];

        let toml = starter_config_toml_with_tools(1000, &tools);

        let config: config::Config = toml::from_str(&toml).expect("starter config should parse");

        assert_eq!(config.allow_rules.len(), 0);
        assert!(toml.contains("groups = [\"aws\", \"ssh\", \"github\", \"gcloud\", \"docker\"]"));
    }

    #[test]
    fn detected_tools_from_statuses_returns_only_found_tools() {
        let statuses = [
            SetupToolDetection {
                tool: SetupTool {
                    command: "aws",
                    rule_name: "Allow AWS CLI",
                    path_group: "aws",
                },
                exe: Some(PathBuf::from("/usr/bin/aws")),
            },
            SetupToolDetection {
                tool: SetupTool {
                    command: "gcloud",
                    rule_name: "Allow Google Cloud CLI",
                    path_group: "gcloud",
                },
                exe: None,
            },
        ];

        let tools = detected_tools_from_statuses(&statuses);

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].rule_name, "Allow AWS CLI");
        assert_eq!(tools[0].exe, PathBuf::from("/usr/bin/aws"));
        assert_eq!(tools[0].path_group, "aws");
    }

    #[test]
    fn setup_output_from_statuses_splits_detected_and_skipped_tools() {
        let statuses = [
            SetupToolDetection {
                tool: SetupTool {
                    command: "ssh",
                    rule_name: "Allow SSH client",
                    path_group: "ssh",
                },
                exe: Some(PathBuf::from("/usr/bin/ssh")),
            },
            SetupToolDetection {
                tool: SetupTool {
                    command: "gcloud",
                    rule_name: "Allow Google Cloud CLI",
                    path_group: "gcloud",
                },
                exe: None,
            },
        ];

        let output = setup_output_from_statuses(
            PathBuf::from("./generated-config.toml"),
            1000,
            true,
            &statuses,
        );

        assert_eq!(output.uid, 1000);
        assert!(output.written);
        assert_eq!(output.detected_tools.len(), 1);
        assert_eq!(output.skipped_tools.len(), 1);
        assert_eq!(output.detected_tools[0].command, "ssh");
        assert_eq!(output.detected_tools[0].exe, PathBuf::from("/usr/bin/ssh"));
        assert_eq!(output.skipped_tools[0].command, "gcloud");
        assert_eq!(output.skipped_tools[0].reason, "not found in PATH");
    }

    #[test]
    fn setup_output_to_json_outputs_expected_shape() {
        let statuses = [SetupToolDetection {
            tool: SetupTool {
                command: "ssh",
                rule_name: "Allow SSH client",
                path_group: "ssh",
            },
            exe: Some(PathBuf::from("/usr/bin/ssh")),
        }];

        let output = setup_output_from_statuses(
            PathBuf::from("./generated-config.toml"),
            1000,
            true,
            &statuses,
        );

        let json = setup_output_to_json(&output).expect("setup output should serialize");

        assert!(json.contains("\"output\": \"./generated-config.toml\""));
        assert!(json.contains("\"uid\": 1000"));
        assert!(json.contains("\"written\": true"));
        assert!(json.contains("\"detected_tools\""));
        assert!(json.contains("\"command\": \"ssh\""));
    }
}
