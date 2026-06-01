mod cli;
mod commands;
mod config;
mod event;
mod logging;
mod paths;
mod policy;
mod process;
mod review;
mod setup;
mod status;

use anyhow::Context;
use clap::Parser;
use cli::{Cli, Command};
use event::{AccessEvent, Operation};
use policy::Decision;
use std::path::PathBuf;

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

            let logs = commands::logs::filter_logs_by_decision(&logs, decision);
            let logs = commands::logs::select_last_logs(&logs, last);

            if json {
                commands::logs::print_logs_json(logs)?;
            } else if logs.is_empty() {
                println!("No log events found.");
            } else {
                for log in logs {
                    commands::logs::print_log_entry(log);
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

            let Some(log) = commands::logs::find_log_by_event_id(&logs, event_id) else {
                anyhow::bail!(
                    "event id {} was not found in {}",
                    event_id,
                    log_file.display()
                );
            };

            if json {
                commands::logs::print_log_json(log)?;
            } else {
                commands::logs::print_log_detail(log);
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

            let candidates = review::build_review_candidates(&logs);

            if let Some(path) = write_suggestions {
                review::write_review_suggestions(&path, &candidates, force).with_context(|| {
                    format!("failed to write suggestions to {}", path.display())
                })?;

                println!(
                    "Wrote {} to {}",
                    review::allow_rule_count_text(candidates.len()),
                    path.display()
                );
            } else if json {
                review::print_review_candidates_json(&candidates)?;
            } else if toml {
                review::print_review_candidates_toml(&candidates);
            } else {
                review::print_review_candidates(&candidates);
            }
        }

        Command::InspectProcess { pid } => {
            let info = process::inspect_process(pid)
                .with_context(|| format!("failed to inspect process {pid}"))?;

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
                status::print_status_json(&parsed_config)?;
            } else {
                status::print_status(&parsed_config);
            }
        }

        Command::Setup {
            output,
            force,
            json,
        } => {
            let uid = setup::current_uid();

            let statuses = setup::detect_setup_tool_statuses();
            let tools = setup::detected_tools_from_statuses(&statuses);

            setup::write_starter_config_with_tools(&output, uid, &tools, force).with_context(
                || format!("failed to write starter config to {}", output.display()),
            )?;

            if json {
                let setup_output =
                    setup::setup_output_from_statuses(output.clone(), uid, true, &statuses);

                setup::print_setup_output_json(&setup_output)?;
            } else {
                setup::print_setup_tool_detection(&statuses);
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

    Ok(AccessEvent {
        pid: None,
        uid,
        exe: paths::normalize_path(&exe),
        cwd: None,
        cmdline: Vec::new(),
        parent_chain: Vec::new(),
        target_path: paths::normalize_path(&target_path),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
