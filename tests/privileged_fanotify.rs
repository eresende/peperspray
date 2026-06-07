#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn daemon_bin() -> String {
    std::env::var("PEPERSPRAYD_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_pepersprayd").to_owned())
}

fn current_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn skip_unless_root() -> bool {
    if current_uid() != 0 {
        eprintln!("skipping privileged fanotify test; run as root");
        return true;
    }

    false
}

fn config_for(mode: &str, uid: u32, protected_path: &Path) -> String {
    format!(
        r#"mode = "{mode}"

[[users]]
uid = {uid}
groups = ["test"]

[[protected_groups]]
name = "test"
paths = ["{}"]
"#,
        protected_path.display()
    )
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_daemon(config: &Path, log_file: &Path, fanotify_path: &Path) -> ChildGuard {
    let child = Command::new(daemon_bin())
        .arg("--config")
        .arg(config)
        .arg("--log-file")
        .arg(log_file)
        .arg("--fanotify-path")
        .arg(fanotify_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon should start");

    ChildGuard::new(child)
}

fn start_daemon_from_config(config: &Path, log_file: &Path) -> ChildGuard {
    let child = Command::new(daemon_bin())
        .arg("--config")
        .arg(config)
        .arg("--log-file")
        .arg(log_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon should start");

    ChildGuard::new(child)
}

fn wait_for_log_contains(log_file: &Path, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);

    while Instant::now() < deadline {
        if std::fs::read_to_string(log_file)
            .unwrap_or_default()
            .contains(needle)
        {
            return;
        }

        thread::sleep(Duration::from_millis(50));
    }

    panic!("timed out waiting for log entry containing {needle:?}");
}

fn run_cat_with_timeout(path: &Path) -> ExitStatus {
    let mut child = Command::new("cat")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("cat should start");

    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        if let Some(status) = child.try_wait().expect("cat status should be readable") {
            return status;
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cat timed out reading protected file");
        }

        thread::sleep(Duration::from_millis(20));
    }
}

fn setup_case(mode: &str) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let protected_dir = dir.path().join("protected");
    let target = protected_dir.join("secret.txt");
    let config = dir.path().join("config.toml");
    let log_file = dir.path().join("events.jsonl");

    std::fs::create_dir(&protected_dir).expect("protected dir should be created");
    std::fs::write(&target, "secret").expect("target should be written");
    std::fs::write(&config, config_for(mode, current_uid(), &protected_dir))
        .expect("config should be written");

    (dir, protected_dir, target, log_file)
}

#[test]
#[ignore = "requires root and Linux fanotify permission events"]
fn fanotify_loop_allows_reads_in_learn_mode_and_logs_would_deny() {
    if skip_unless_root() {
        return;
    }

    let (_dir, protected_dir, target, log_file) = setup_case("learn");
    let config = protected_dir.parent().unwrap().join("config.toml");
    let _daemon = start_daemon(&config, &log_file, &protected_dir);

    wait_for_log_contains(&log_file, "fanotify loop started");

    let status = run_cat_with_timeout(&target);

    assert!(status.success());
    wait_for_log_contains(&log_file, "\"would_deny\":true");
}

#[test]
#[ignore = "requires root and Linux fanotify permission events"]
fn fanotify_loop_denies_reads_in_enforce_mode() {
    if skip_unless_root() {
        return;
    }

    let (_dir, protected_dir, target, log_file) = setup_case("enforce");
    let config = protected_dir.parent().unwrap().join("config.toml");
    let _daemon = start_daemon(&config, &log_file, &protected_dir);

    wait_for_log_contains(&log_file, "fanotify loop started");

    let status = run_cat_with_timeout(&target);

    assert!(!status.success());
    wait_for_log_contains(&log_file, "\"decision\":\"deny\"");
}

#[test]
#[ignore = "requires root and Linux fanotify permission events"]
fn fanotify_rescan_marks_protected_path_created_after_startup() {
    if skip_unless_root() {
        return;
    }

    let dir = tempfile::tempdir().expect("temp dir should be created");
    let protected_dir = dir.path().join("protected");
    let target = protected_dir.join("secret.txt");
    let config = dir.path().join("config.toml");
    let log_file = dir.path().join("events.jsonl");

    std::fs::write(
        &config,
        config_for("enforce", current_uid(), &protected_dir),
    )
    .expect("config should be written");

    let _daemon = start_daemon_from_config(&config, &log_file);
    wait_for_log_contains(&log_file, "fanotify loop started");

    std::fs::create_dir(&protected_dir).expect("protected dir should be created");
    std::fs::write(&target, "secret").expect("target should be written");
    wait_for_log_contains(&log_file, "fanotify rescan added");

    let status = run_cat_with_timeout(&target);

    assert!(!status.success());
    wait_for_log_contains(&log_file, "\"decision\":\"deny\"");
}
