use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_peperspray")
}

fn daemon_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pepersprayd")
}

fn sample_config(mode: &str) -> String {
    format!(
        r#"mode = "{mode}"

[[users]]
uid = 1000
groups = ["aws"]

[[protected_groups]]
name = "aws"
paths = ["/home/alice/.aws"]
"#
    )
}

#[test]
fn status_json_reports_config_summary() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, sample_config("learn")).expect("config should be written");

    let output = Command::new(bin())
        .args(["status", "--config"])
        .arg(&config)
        .arg("--json")
        .output()
        .expect("command should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    assert!(stdout.contains("\"mode\": \"learn\""));
    assert!(stdout.contains("\"protected_users\": 1"));
}

#[test]
fn enforce_updates_config_and_writes_backup() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, sample_config("learn")).expect("config should be written");

    let output = Command::new(bin())
        .args(["enforce", "--config"])
        .arg(&config)
        .output()
        .expect("command should run");

    assert!(output.status.success());

    let updated = std::fs::read_to_string(&config).expect("config should be readable");
    let backup =
        std::fs::read_to_string(dir.path().join("config.toml.bak")).expect("backup should exist");

    assert!(updated.contains("mode = \"enforce\""));
    assert!(backup.contains("mode = \"learn\""));
}

#[test]
fn logs_since_filters_old_events() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let log_file = dir.path().join("events.jsonl");
    std::fs::write(
        &log_file,
        r#"{"event_id":"00000000-0000-0000-0000-000000000001","timestamp":"2026-01-01T00:00:00Z","uid":1000,"exe":"/usr/bin/old","target_path":"/tmp/old","operation":"open_read","decision":"allow","reason":"old","would_deny":false}
{"event_id":"00000000-0000-0000-0000-000000000002","timestamp":"2026-01-03T00:00:00Z","uid":1000,"exe":"/usr/bin/new","target_path":"/tmp/new","operation":"open_read","decision":"allow","reason":"new","would_deny":false}
"#,
    )
    .expect("log should be written");

    let output = Command::new(bin())
        .args(["logs", "--log-file"])
        .arg(&log_file)
        .args(["--since", "2026-01-02T00:00:00Z"])
        .output()
        .expect("command should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    assert!(!stdout.contains("/usr/bin/old"));
    assert!(stdout.contains("/usr/bin/new"));
}

#[test]
fn policy_review_min_events_filters_suggestions() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let log_file = dir.path().join("events.jsonl");
    std::fs::write(
        &log_file,
        r#"{"event_id":"00000000-0000-0000-0000-000000000001","timestamp":"2026-01-01T00:00:00Z","uid":1000,"exe":"/usr/bin/python3","target_path":"/home/alice/.aws/credentials","operation":"open_read","decision":"allow","reason":"learn","matched_path_group":"aws","would_deny":true}
{"event_id":"00000000-0000-0000-0000-000000000002","timestamp":"2026-01-01T00:00:01Z","uid":1000,"exe":"/usr/bin/python3","target_path":"/home/alice/.aws/config","operation":"open_read","decision":"allow","reason":"learn","matched_path_group":"aws","would_deny":true}
{"event_id":"00000000-0000-0000-0000-000000000003","timestamp":"2026-01-01T00:00:02Z","uid":1000,"exe":"/usr/bin/git","target_path":"/home/alice/.ssh/id_ed25519","operation":"open_read","decision":"allow","reason":"learn","matched_path_group":"ssh","would_deny":true}
"#,
    )
    .expect("log should be written");

    let output = Command::new(bin())
        .args(["policy-review", "--log-file"])
        .arg(&log_file)
        .args(["--min-events", "2", "--toml"])
        .output()
        .expect("command should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    assert!(stdout.contains("Allow python3 to access aws"));
    assert!(!stdout.contains("Allow git to access ssh"));
}

#[test]
fn daemon_check_validates_config_and_writes_lifecycle_log() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let config = dir.path().join("config.toml");
    let log_file = dir.path().join("daemon.jsonl");
    std::fs::write(&config, sample_config("learn")).expect("config should be written");

    let output = Command::new(daemon_bin())
        .args(["--config"])
        .arg(&config)
        .args(["--log-file"])
        .arg(&log_file)
        .arg("--check")
        .output()
        .expect("command should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let log = std::fs::read_to_string(log_file).expect("daemon log should be written");

    assert!(stdout.contains("Daemon config is valid."));
    assert!(log.contains("\"component\":\"pepersprayd\""));
    assert!(log.contains("\"message\":\"daemon config loaded\""));
}
