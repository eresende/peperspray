use crate::config;
use crate::fanotify;
use crate::fanotify::FanotifyPermissionEvent;
use crate::logging::{self, DaemonLog};
use crate::policy;
use anyhow::Context;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub const DEFAULT_DAEMON_CONFIG_PATH: &str = "/etc/peperspray/config.toml";
pub const DEFAULT_DAEMON_LOG_FILE: &str = "/var/log/peperspray/events.jsonl";

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub config_path: PathBuf,
    pub log_file: PathBuf,
    pub check_only: bool,
    pub fanotify_probe: Option<PathBuf>,
}

#[derive(Debug)]
pub struct LoadedDaemonConfig {
    pub config: config::Config,
}

pub fn load_and_validate_config(path: &Path) -> anyhow::Result<LoadedDaemonConfig> {
    let config = config::load_config(path)
        .with_context(|| format!("failed to load daemon config from {}", path.display()))?;

    let validation_errors = config::validate_config(&config);

    if !validation_errors.is_empty() {
        anyhow::bail!(
            "daemon config validation failed:\n{}",
            validation_errors
                .iter()
                .map(|error| format!("- {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    Ok(LoadedDaemonConfig { config })
}

pub fn run(options: DaemonOptions) -> anyhow::Result<()> {
    let loaded = load_and_validate_config(&options.config_path)?;

    append_lifecycle_log(
        &options.log_file,
        DaemonLog::new("info", "daemon config loaded").with_config_summary(
            options.config_path.clone(),
            loaded.config.users.len(),
            loaded.config.protected_groups.len(),
            loaded.config.allow_rules.len(),
        ),
    )?;

    if let Some(path) = &options.fanotify_probe {
        let probe = fanotify::probe_path(path)
            .with_context(|| format!("failed to probe fanotify for {}", path.display()))?;

        append_lifecycle_log(
            &options.log_file,
            DaemonLog::new(
                "info",
                format!(
                    "fanotify probe initialized fd {} for {}",
                    probe.raw_fd(),
                    path.display()
                ),
            ),
        )?;

        println!(
            "fanotify probe initialized fd {} for {}",
            probe.raw_fd(),
            path.display()
        );
    }

    if options.check_only {
        println!(
            "Daemon config is valid. users={} groups={} allow_rules={}",
            loaded.config.users.len(),
            loaded.config.protected_groups.len(),
            loaded.config.allow_rules.len()
        );
        return Ok(());
    }

    println!("pepersprayd skeleton running without enforcement.");
    println!("Config: {}", options.config_path.display());
    println!("Log file: {}", options.log_file.display());

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

pub fn handle_permission_event(
    fanotify_fd: std::os::fd::RawFd,
    config: &config::Config,
    log_file: &Path,
    event: &FanotifyPermissionEvent,
) -> anyhow::Result<()> {
    let access_event = fanotify::access_event_from_permission_event(event)?;
    let decision = policy::decide(config, &access_event);
    let decision_log = logging::DecisionLog::new(&access_event, &decision);

    logging::append_jsonl_log(log_file, &decision_log)
        .with_context(|| format!("failed to append decision log to {}", log_file.display()))?;

    fanotify::respond_to_permission_event(fanotify_fd, event, &decision)
}

fn append_lifecycle_log(path: &Path, log: DaemonLog) -> anyhow::Result<()> {
    logging::append_daemon_jsonl_log(path, &log)
        .with_context(|| format!("failed to append daemon log to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> String {
        r#"mode = "learn"

[[users]]
uid = 1000
groups = ["aws"]

[[protected_groups]]
name = "aws"
paths = ["~/.aws"]
"#
        .to_string()
    }

    #[test]
    fn load_and_validate_config_accepts_valid_config() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, sample_config()).expect("config should be written");

        let loaded = load_and_validate_config(&path).expect("config should load");

        assert_eq!(loaded.config.users.len(), 1);
    }

    #[test]
    fn load_and_validate_config_rejects_invalid_config() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"mode = "learn"

[[users]]
uid = 1000
groups = ["missing"]
"#,
        )
        .expect("config should be written");

        let result = load_and_validate_config(&path);

        assert!(result.is_err());
    }

    #[test]
    fn handle_permission_event_components_can_build_decision_log() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let target = dir.path().join("credentials");
        std::fs::write(&target, "secret").expect("target should be written");
        let file = std::fs::File::open(&target).expect("target should open");

        let config = config::Config {
            mode: config::Mode::Enforce,
            users: vec![config::ProtectedUser {
                uid: nix::unistd::geteuid().as_raw(),
                groups: vec!["test".to_string()],
            }],
            protected_groups: vec![config::ProtectedPathGroup {
                name: "test".to_string(),
                paths: vec![dir.path().to_path_buf()],
            }],
            allow_rules: Vec::new(),
        };

        let event = FanotifyPermissionEvent {
            pid: std::process::id(),
            target_fd: std::os::fd::AsRawFd::as_raw_fd(&file),
            mask: nix::libc::FAN_OPEN_PERM,
        };
        let access_event =
            fanotify::access_event_from_permission_event(&event).expect("event should convert");
        let decision = policy::decide(&config, &access_event);

        assert_eq!(access_event.target_path, target);
        assert!(matches!(decision, policy::Decision::Deny { .. }));
    }
}
