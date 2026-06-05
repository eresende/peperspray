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
        eprintln!("skipping privileged path-identity test; run as root");
        return true;
    }

    false
}

fn config_for(uid: u32, protected_path: &Path) -> String {
    format!(
        r#"mode = "enforce"

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

struct BindMountGuard {
    mountpoint: PathBuf,
}

impl BindMountGuard {
    fn mount(source: &Path, mountpoint: &Path) -> Option<Self> {
        let status = Command::new("mount")
            .arg("--bind")
            .arg(source)
            .arg(mountpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match status {
            Ok(status) if status.success() => Some(Self {
                mountpoint: mountpoint.to_path_buf(),
            }),
            Ok(status) => {
                eprintln!("skipping bind-mount test; mount --bind failed with {status}");
                None
            }
            Err(error) => {
                eprintln!("skipping bind-mount test; failed to run mount: {error}");
                None
            }
        }
    }
}

impl Drop for BindMountGuard {
    fn drop(&mut self) {
        let _ = Command::new("umount")
            .arg(&self.mountpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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

    wait_for_child(&mut child, "cat")
}

fn run_command_with_timeout(command: &mut Command, name: &str) -> Option<ExitStatus> {
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("skipping namespace test; failed to run {name}: {error}");
            return None;
        }
    };

    Some(wait_for_child(&mut child, name))
}

fn wait_for_child(child: &mut Child, name: &str) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        if let Some(status) = child.try_wait().expect("child status should be readable") {
            return status;
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{name} timed out");
        }

        thread::sleep(Duration::from_millis(20));
    }
}

fn setup_case() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let protected_dir = dir.path().join("protected");
    let target = protected_dir.join("secret.txt");
    let config = dir.path().join("config.toml");
    let log_file = dir.path().join("events.jsonl");

    std::fs::create_dir(&protected_dir).expect("protected dir should be created");
    std::fs::write(&target, "secret").expect("target should be written");
    std::fs::write(&config, config_for(current_uid(), &protected_dir))
        .expect("config should be written");

    (dir, protected_dir, target, config, log_file)
}

#[test]
#[ignore = "requires root and Linux fanotify permission events"]
fn hard_link_alias_outside_marked_dir_is_blocked() {
    if skip_unless_root() {
        return;
    }

    let (dir, protected_dir, target, config, log_file) = setup_case();
    let alias = dir.path().join("outside-secret.txt");
    std::fs::hard_link(&target, &alias).expect("hard link should be created");

    let _daemon = start_daemon(&config, &log_file, &protected_dir);
    wait_for_log_contains(&log_file, "fanotify loop started");

    let status = run_cat_with_timeout(&alias);

    assert!(
        !status.success(),
        "hard-link alias should be blocked by inode/device identity hardening"
    );
}

#[test]
#[ignore = "requires root, Linux fanotify permission events, and mount permissions"]
fn bind_mount_alias_outside_marked_dir_is_blocked() {
    if skip_unless_root() {
        return;
    }

    let (dir, protected_dir, _target, config, log_file) = setup_case();
    let alias_dir = dir.path().join("alias");
    std::fs::create_dir(&alias_dir).expect("alias dir should be created");
    let Some(_bind_mount) = BindMountGuard::mount(&protected_dir, &alias_dir) else {
        return;
    };

    let _daemon = start_daemon(&config, &log_file, &protected_dir);
    wait_for_log_contains(&log_file, "fanotify loop started");

    let status = run_cat_with_timeout(&alias_dir.join("secret.txt"));

    assert!(
        !status.success(),
        "bind-mount alias should be blocked by inode/device identity hardening"
    );
}

#[test]
#[ignore = "requires root, Linux fanotify permission events, unshare, and mount permissions"]
fn mount_namespace_bind_mount_alias_is_blocked() {
    if skip_unless_root() {
        return;
    }

    let mut preflight = Command::new("unshare");
    preflight.arg("--mount").arg("true");
    let Some(preflight_status) = run_command_with_timeout(&mut preflight, "unshare") else {
        return;
    };
    if !preflight_status.success() {
        eprintln!("skipping namespace test; unshare --mount failed with {preflight_status}");
        return;
    }

    let (dir, protected_dir, _target, config, log_file) = setup_case();
    let alias_dir = dir.path().join("namespace-alias");
    std::fs::create_dir(&alias_dir).expect("alias dir should be created");

    let _daemon = start_daemon(&config, &log_file, &protected_dir);
    wait_for_log_contains(&log_file, "fanotify loop started");

    let mut command = Command::new("unshare");
    command
        .arg("--mount")
        .arg("--propagation")
        .arg("private")
        .arg("sh")
        .arg("-c")
        .arg("mount --bind \"$1\" \"$2\" || exit 125; cat \"$2/secret.txt\" >/dev/null")
        .arg("sh")
        .arg(&protected_dir)
        .arg(&alias_dir);

    let Some(status) = run_command_with_timeout(&mut command, "unshare") else {
        return;
    };

    if status.code() == Some(125) {
        eprintln!("skipping namespace test; mount --bind failed inside namespace");
        return;
    }

    assert!(
        !status.success(),
        "mount-namespace bind alias should be blocked by inode/device identity hardening"
    );
}
