use crate::config;
use crate::doctor;
use crate::fanotify;
use crate::fanotify::FanotifyPermissionEvent;
use crate::logging::{self, DaemonLog};
use crate::notifications::{DenyNotifier, NotificationStatus};
use crate::policy;
use anyhow::Context;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_DAEMON_CONFIG_PATH: &str = "/etc/peperspray/config.toml";
pub const DEFAULT_DAEMON_LOG_FILE: &str = "/var/log/peperspray/events.jsonl";
const FANOTIFY_RESCAN_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub config_path: PathBuf,
    pub log_file: PathBuf,
    pub check_only: bool,
    pub fanotify_probe: Option<PathBuf>,
    pub fanotify_path: Option<PathBuf>,
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
    refuse_unsafe_installed_paths(&options)?;

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

    if let Some(path) = &options.fanotify_path {
        run_fanotify_loop(
            std::slice::from_ref(path),
            &loaded.config,
            &options.log_file,
        )?;
        return Ok(());
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

    let fanotify_paths = configured_fanotify_paths(&loaded.config);

    if !fanotify_paths.is_empty() {
        run_fanotify_loop(&fanotify_paths, &loaded.config, &options.log_file)?;
        return Ok(());
    }

    append_lifecycle_log(
        &options.log_file,
        DaemonLog::new(
            "warn",
            "no absolute protected paths available for fanotify marks",
        ),
    )?;

    println!("pepersprayd running without fanotify marks.");
    println!("Config: {}", options.config_path.display());
    println!("Log file: {}", options.log_file.display());

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn refuse_unsafe_installed_paths(options: &DaemonOptions) -> anyhow::Result<()> {
    if !uses_installed_layout(options) {
        return Ok(());
    }

    let tamper_errors =
        doctor::installed_path_tamper_errors(&options.config_path, &options.log_file);

    if tamper_errors.is_empty() {
        return Ok(());
    }

    anyhow::bail!(
        "daemon startup refused because installed path permissions are unsafe:\n{}",
        tamper_errors
            .iter()
            .map(|error| format!("- {error}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn uses_installed_layout(options: &DaemonOptions) -> bool {
    options.config_path == Path::new(DEFAULT_DAEMON_CONFIG_PATH)
        || options.log_file == Path::new(DEFAULT_DAEMON_LOG_FILE)
}

fn run_fanotify_loop(
    paths: &[PathBuf],
    config: &config::Config,
    log_file: &Path,
) -> anyhow::Result<()> {
    let fanotify = fanotify::FanotifyProbe::new()
        .context("failed to initialize fanotify permission listener")?;
    let mut marked_paths = BTreeSet::new();
    mark_new_fanotify_paths(&fanotify, paths, &mut marked_paths)
        .context("failed to mark initial protected paths for fanotify")?;

    append_lifecycle_log(
        log_file,
        DaemonLog::new(
            "info",
            format!(
                "fanotify loop started fd {} for {} protected paths",
                fanotify.raw_fd(),
                marked_paths.len()
            ),
        ),
    )?;

    println!(
        "fanotify loop started for {} protected paths",
        marked_paths.len()
    );

    let mut deny_notifier = DenyNotifier::default();
    let mut next_rescan = Instant::now() + FANOTIFY_RESCAN_INTERVAL;

    loop {
        let events = fanotify.read_permission_events()?;

        if events.is_empty() {
            if Instant::now() >= next_rescan {
                if let Err(error) =
                    rescan_fanotify_marks(&fanotify, paths, &mut marked_paths, log_file)
                {
                    let _ = append_lifecycle_log(
                        log_file,
                        DaemonLog::new(
                            "warn",
                            format!(
                                "failed to rescan protected paths for fanotify marks: {error:#}"
                            ),
                        ),
                    );
                }

                next_rescan = Instant::now() + FANOTIFY_RESCAN_INTERVAL;
            }

            thread::sleep(Duration::from_millis(50));
            continue;
        }

        for event in events {
            if let Err(error) = handle_permission_event_with_notifier(
                fanotify.raw_fd(),
                config,
                log_file,
                &event,
                Some(&mut deny_notifier),
            ) {
                let fallback = match config.mode {
                    config::Mode::Learn => {
                        let _ = fanotify::allow_permission_event(fanotify.raw_fd(), &event);
                        "allowed"
                    }
                    config::Mode::Enforce => {
                        let _ = fanotify::deny_permission_event(fanotify.raw_fd(), &event);
                        "denied"
                    }
                };
                let _ = append_lifecycle_log(
                    log_file,
                    DaemonLog::new(
                        "error",
                        format!(
                            "failed to handle fanotify permission event pid={} fd={}; {fallback} by mode fallback: {error:#}",
                            event.pid, event.target_fd
                        ),
                    ),
                );
            }

            let _ = fanotify::close_permission_event_fd(&event);
        }
    }
}

fn rescan_fanotify_marks(
    fanotify: &fanotify::FanotifyProbe,
    paths: &[PathBuf],
    marked_paths: &mut BTreeSet<PathBuf>,
    log_file: &Path,
) -> anyhow::Result<()> {
    let added = mark_new_fanotify_paths(fanotify, paths, marked_paths)?;

    if added > 0 {
        append_lifecycle_log(
            log_file,
            DaemonLog::new(
                "info",
                format!("fanotify rescan added {added} protected path marks"),
            ),
        )?;
    }

    Ok(())
}

fn mark_new_fanotify_paths(
    fanotify: &fanotify::FanotifyProbe,
    paths: &[PathBuf],
    marked_paths: &mut BTreeSet<PathBuf>,
) -> anyhow::Result<usize> {
    let new_paths = new_fanotify_mark_paths(paths, marked_paths);
    let mut added = 0;

    for path in new_paths {
        fanotify
            .mark_path(&path)
            .with_context(|| format!("failed to mark {} for fanotify", path.display()))?;
        marked_paths.insert(path);
        added += 1;
    }

    Ok(added)
}

fn new_fanotify_mark_paths(paths: &[PathBuf], marked_paths: &BTreeSet<PathBuf>) -> Vec<PathBuf> {
    fanotify_mark_paths(paths)
        .into_iter()
        .filter(|path| !marked_paths.contains(path))
        .collect()
}

fn configured_fanotify_paths(config: &config::Config) -> Vec<PathBuf> {
    config
        .protected_groups
        .iter()
        .flat_map(|group| group.paths.iter())
        .filter(|path| path.is_absolute())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fanotify_mark_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .flat_map(|path| existing_path_and_descendants(path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn existing_path_and_descendants(path: &Path) -> Vec<PathBuf> {
    let Ok(metadata) = std::fs::metadata(path) else {
        return Vec::new();
    };

    let mut paths = vec![path.to_path_buf()];

    if metadata.is_dir() {
        collect_existing_descendants(path, &mut paths);
    }

    paths
}

fn collect_existing_descendants(directory: &Path, paths: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };

        paths.push(path.clone());

        if metadata.is_dir() {
            collect_existing_descendants(&path, paths);
        }
    }
}

pub fn handle_permission_event(
    fanotify_fd: std::os::fd::RawFd,
    config: &config::Config,
    log_file: &Path,
    event: &FanotifyPermissionEvent,
) -> anyhow::Result<()> {
    handle_permission_event_with_notifier(fanotify_fd, config, log_file, event, None)
}

fn handle_permission_event_with_notifier(
    fanotify_fd: std::os::fd::RawFd,
    config: &config::Config,
    log_file: &Path,
    event: &FanotifyPermissionEvent,
    deny_notifier: Option<&mut DenyNotifier>,
) -> anyhow::Result<()> {
    let access_event = fanotify::access_event_from_permission_event(event)?;
    let decision = policy::decide(config, &access_event);
    let decision_log = logging::DecisionLog::new(&access_event, &decision);

    logging::append_jsonl_log(log_file, &decision_log)
        .with_context(|| format!("failed to append decision log to {}", log_file.display()))?;

    fanotify::respond_to_permission_event(fanotify_fd, event, &decision)?;

    if let Some(deny_notifier) = deny_notifier {
        notify_denied_access(log_file, deny_notifier, &access_event, &decision);
    }

    Ok(())
}

fn notify_denied_access(
    log_file: &Path,
    deny_notifier: &mut DenyNotifier,
    access_event: &crate::event::AccessEvent,
    decision: &policy::Decision,
) {
    match deny_notifier.notify_if_denied(access_event, decision) {
        Ok(
            NotificationStatus::Sent
            | NotificationStatus::Suppressed
            | NotificationStatus::NotDenied,
        ) => {}
        Ok(NotificationStatus::Unavailable(reason)) => {
            let _ = append_lifecycle_log(
                log_file,
                DaemonLog::new(
                    "warn",
                    format!("desktop notification unavailable: {reason}"),
                ),
            );
        }
        Err(error) => {
            let _ = append_lifecycle_log(
                log_file,
                DaemonLog::new(
                    "warn",
                    format!("failed to send desktop notification: {error}"),
                ),
            );
        }
    }
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
    fn unsafe_installed_paths_refuse_startup() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, sample_config()).expect("config should be written");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&config_path)
                .expect("metadata should be readable")
                .permissions();
            permissions.set_mode(0o666);
            std::fs::set_permissions(&config_path, permissions)
                .expect("permissions should be updated");
        }

        let options = DaemonOptions {
            config_path,
            log_file: PathBuf::from(DEFAULT_DAEMON_LOG_FILE),
            check_only: true,
            fanotify_probe: None,
            fanotify_path: None,
        };

        let result = refuse_unsafe_installed_paths(&options);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("installed path permissions are unsafe")
        );
    }

    #[test]
    fn custom_development_paths_skip_installed_path_refusal() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let options = DaemonOptions {
            config_path: dir.path().join("config.toml"),
            log_file: dir.path().join("events.jsonl"),
            check_only: true,
            fanotify_probe: None,
            fanotify_path: None,
        };

        let result = refuse_unsafe_installed_paths(&options);

        assert!(result.is_ok());
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
                patterns: Vec::new(),
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

    #[test]
    fn configured_fanotify_paths_returns_absolute_paths() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let protected = dir.path().join(".aws");
        let missing = dir.path().join("missing");
        std::fs::create_dir(&protected).expect("protected dir should be created");

        let config = config::Config {
            mode: config::Mode::Learn,
            users: Vec::new(),
            protected_groups: vec![config::ProtectedPathGroup {
                name: "aws".to_string(),
                paths: vec![
                    protected.clone(),
                    protected.clone(),
                    missing.clone(),
                    PathBuf::from(".env"),
                ],
                patterns: Vec::new(),
            }],
            allow_rules: Vec::new(),
        };

        let paths = configured_fanotify_paths(&config);

        assert_eq!(paths, vec![protected, missing]);
    }

    #[test]
    fn fanotify_mark_paths_include_existing_descendants() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let protected = dir.path().join("protected");
        let nested = protected.join("nested");
        let secret = nested.join("secret.txt");

        std::fs::create_dir(&protected).expect("protected dir should be created");
        std::fs::create_dir(&nested).expect("nested dir should be created");
        std::fs::write(&secret, "secret").expect("secret should be written");

        let paths = fanotify_mark_paths(std::slice::from_ref(&protected));

        assert!(paths.contains(&protected));
        assert!(paths.contains(&nested));
        assert!(paths.contains(&secret));
    }

    #[test]
    fn new_fanotify_mark_paths_returns_only_unmarked_existing_paths() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let protected = dir.path().join("protected");
        let nested = protected.join("nested");
        let missing = dir.path().join("missing");

        std::fs::create_dir(&protected).expect("protected dir should be created");
        std::fs::create_dir(&nested).expect("nested dir should be created");

        let mut marked_paths = BTreeSet::new();
        marked_paths.insert(protected.clone());

        let paths = new_fanotify_mark_paths(&[protected.clone(), missing], &marked_paths);

        assert_eq!(paths, vec![nested]);
    }

    #[test]
    fn new_fanotify_mark_paths_discovers_root_created_after_startup() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let protected = dir.path().join("protected");
        let marked_paths = BTreeSet::new();

        assert!(
            new_fanotify_mark_paths(std::slice::from_ref(&protected), &marked_paths).is_empty()
        );

        std::fs::create_dir(&protected).expect("protected dir should be created");

        assert_eq!(
            new_fanotify_mark_paths(std::slice::from_ref(&protected), &marked_paths),
            vec![protected]
        );
    }
}
