use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::thread;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_peperspray")
}

fn daemon_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pepersprayd")
}

fn start_mock_ollama(
    model: &str,
    chat_content: &str,
    requests: usize,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock server should bind");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let model = model.to_string();
    let chat_content = chat_content.to_string();

    let handle = thread::spawn(move || {
        let mut request_lines = Vec::new();

        for _ in 0..requests {
            let (mut stream, _) = listener.accept().expect("mock request should connect");
            let mut buffer = [0_u8; 8192];
            let bytes = stream.read(&mut buffer).expect("request should read");
            let request = String::from_utf8_lossy(&buffer[..bytes]).to_string();
            let first_line = request.lines().next().unwrap_or("").to_string();
            request_lines.push(first_line.clone());

            let body = if first_line.starts_with("GET /api/tags ") {
                serde_json::json!({
                    "models": [
                        {
                            "name": model
                        }
                    ]
                })
            } else {
                serde_json::json!({
                    "message": {
                        "content": chat_content
                    }
                })
            };

            let body = body.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        }

        request_lines
    });

    (endpoint, handle)
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
        r#"{"event_id":"00000000-0000-0000-0000-000000000099","timestamp":"2026-01-01T00:00:00Z","component":"pepersprayd","level":"info","message":"daemon config loaded","config_path":"/etc/peperspray/config.toml","protected_users":1,"protected_groups":1,"allow_rules":0}
{"event_id":"00000000-0000-0000-0000-000000000001","timestamp":"2026-01-01T00:00:00Z","uid":1000,"exe":"/usr/bin/python3","target_path":"/home/alice/.aws/credentials","operation":"open_read","decision":"allow","reason":"learn","matched_path_group":"aws","would_deny":true}
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
fn why_last_with_decision_filter_explains_latest_matching_event() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let log_file = dir.path().join("events.jsonl");
    std::fs::write(
        &log_file,
        r#"{"event_id":"00000000-0000-0000-0000-000000000001","timestamp":"2026-01-01T00:00:00Z","uid":1000,"exe":"/usr/bin/old-deny","target_path":"/tmp/old-deny","operation":"open_read","decision":"deny","reason":"old deny","would_deny":false}
{"event_id":"00000000-0000-0000-0000-000000000002","timestamp":"2026-01-01T00:00:01Z","uid":1000,"exe":"/usr/bin/allow","target_path":"/tmp/allow","operation":"open_read","decision":"allow","reason":"allow","would_deny":false}
{"event_id":"00000000-0000-0000-0000-000000000003","timestamp":"2026-01-01T00:00:02Z","uid":1000,"exe":"/usr/bin/new-deny","target_path":"/tmp/new-deny","operation":"open_read","decision":"deny","reason":"new deny","would_deny":false}
"#,
    )
    .expect("log should be written");

    let output = Command::new(bin())
        .args(["why", "last", "--log-file"])
        .arg(&log_file)
        .args(["--decision", "deny"])
        .output()
        .expect("command should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    assert!(stdout.contains("Event 00000000-0000-0000-0000-000000000003"));
    assert!(stdout.contains("Executable:  /usr/bin/new-deny"));
    assert!(stdout.contains("new deny"));
    assert!(!stdout.contains("/usr/bin/old-deny"));
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

#[test]
fn service_restart_invokes_systemctl_wrapper() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let systemctl = dir.path().join("systemctl-mock");
    let args_file = dir.path().join("args.txt");

    std::fs::write(
        &systemctl,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
            args_file.display()
        ),
    )
    .expect("mock systemctl should be written");

    let mut permissions = std::fs::metadata(&systemctl)
        .expect("mock metadata should be readable")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&systemctl, permissions).expect("mock should be executable");

    let output = Command::new(bin())
        .env("PEPERSPRAY_SYSTEMCTL", &systemctl)
        .args(["service", "restart"])
        .output()
        .expect("command should run");

    assert!(output.status.success());

    let args = std::fs::read_to_string(args_file).expect("args should be written");

    assert_eq!(args, "restart\npepersprayd\n");
}

#[test]
fn assistant_doctor_succeeds_against_mock_ollama() {
    let (endpoint, handle) = start_mock_ollama("gemma4:12b", "OK", 2);

    let output = Command::new(bin())
        .args([
            "assistant",
            "doctor",
            "--assistant-endpoint",
            &endpoint,
            "--assistant-model",
            "gemma4:12b",
        ])
        .output()
        .expect("command should run");

    let requests = handle.join().expect("mock server should finish");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    assert!(output.status.success());
    assert!(stdout.contains("Model: gemma4:12b"));
    assert!(stdout.contains("Status: OK"));
    assert_eq!(requests[0], "GET /api/tags HTTP/1.1");
    assert_eq!(requests[1], "POST /api/chat HTTP/1.1");
}

#[test]
fn assistant_doctor_reports_missing_default_model() {
    let (endpoint, handle) = start_mock_ollama("qwen3:14b", "OK", 1);

    let output = Command::new(bin())
        .args(["assistant", "doctor", "--assistant-endpoint", &endpoint])
        .output()
        .expect("command should run");

    handle.join().expect("mock server should finish");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    assert!(!output.status.success());
    assert!(stdout.contains("Assistant model not found: gemma4:12b"));
    assert!(stdout.contains("ollama pull gemma4:12b"));
}

#[test]
fn why_assist_includes_assistant_review_when_provider_succeeds() {
    let review = serde_json::json!({
        "summary": "Python read AWS credentials.",
        "risk_level": "needs_review",
        "why": ["Python is a broad interpreter."],
        "recommendations": ["Verify the script."],
        "safe_rule_guidance": "Avoid allowing python3 globally."
    })
    .to_string();
    let (endpoint, handle) = start_mock_ollama("gemma4:12b", &review, 2);

    let dir = tempfile::tempdir().expect("temp dir should be created");
    let log_file = dir.path().join("events.jsonl");
    std::fs::write(
        &log_file,
        r#"{"event_id":"00000000-0000-0000-0000-000000000004","timestamp":"2026-01-01T00:00:00Z","uid":1000,"exe":"/usr/bin/python3","target_path":"/home/alice/.aws/credentials","operation":"open_read","decision":"deny","reason":"blocked","matched_path_group":"aws","would_deny":true}
"#,
    )
    .expect("log should be written");

    let output = Command::new(bin())
        .args(["why", "last", "--log-file"])
        .arg(&log_file)
        .args([
            "--assist",
            "--assistant-endpoint",
            &endpoint,
            "--assistant-model",
            "gemma4:12b",
        ])
        .output()
        .expect("command should run");

    handle.join().expect("mock server should finish");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    assert!(output.status.success());
    assert!(stdout.contains("Decision:    DENY"));
    assert!(stdout.contains("Assistant review"));
    assert!(stdout.contains("Risk: needs_review"));
    assert!(stdout.contains("Python read AWS credentials."));
}
