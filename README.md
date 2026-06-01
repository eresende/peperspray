# peperspray

`peperspray` is a Linux-first credential access guard for developer
workstations.

The planned MVP is a root-owned daemon that uses Linux `fanotify` permission
events to detect protected credential-file reads and block them before they
complete unless an explicit policy rule allows the access.

This repository is currently a **policy and CLI prototype**. It does not yet
perform host-level enforcement, but it already implements most of the portable
core that the future daemon will use:

- TOML configuration parsing and logical validation
- protected users and protected credential path groups
- allow-rule based policy decisions
- learn/enforce decision behavior
- path normalization and `~` expansion for protected paths
- optional operation and parent-process constraints on allow rules
- Linux `/proc` process inspection
- JSONL decision logs with timestamps and event IDs
- log inspection, filtering, JSON output, and event lookup
- learned-access review and suggested allow-rule generation
- starter config generation through `setup`
- human and JSON status output

The daemon, Linux `fanotify` backend, `systemd` service, `.deb` packaging, and
real read blocking are not implemented yet.

## Design Target

The target product is described in [docs/SPEC.md](docs/SPEC.md). In short:

- `pepersprayd` will run as a root-owned `systemd` service on Ubuntu 24.04.
- `peperspray` will manage setup, status, modes, logs, testing, and policy
  review.
- Default posture is zero-trust in enforce mode: protected credential reads are
  denied unless an allow rule matches.
- Learn mode records accesses that would have been denied without blocking them.
- Platform-neutral policy, event, process, and logging types are kept separate
  from Linux-specific event collection where practical.

## Current Status

Implemented commands:

- `setup`
- `status`
- `policy-validate`
- `test-access`
- `inspect-process`
- `logs`
- `why`
- `policy-review`

Implemented policy and CLI capabilities:

- Config loading from TOML
- Config validation beyond syntax, including:
  - unknown protected groups
  - duplicate protected group names
  - duplicate allow-rule names
  - duplicate allow-rule behavior
- Learn/enforce policy decisions
- Protected path matching using component-aware `Path::starts_with`
- Path normalization for config and access events
- `~` expansion for protected group paths
- Optional `operation` field on allow rules
- Optional `parent_exe` field on allow rules
- Process inspection from `/proc/<pid>`
- Parent-process chain collection
- JSONL decision logs
- Log filtering by decision and count
- Single-event lookup by event ID
- Policy-review suggestions as human text, JSON, TOML, or suggestion file
- Starter config generation with detected local tools

Not implemented yet:

- root daemon
- Linux `fanotify` permission-event integration
- real file-read blocking
- `learn` and `enforce` commands that modify the active config
- installation layout under `/etc/peperspray/` and `/var/log/peperspray/`
- `.deb` packaging
- `systemd` service management
- interactive setup
- advanced tamper resistance

## Requirements

- Rust toolchain with Cargo
- Linux is the intended platform
- The current CLI prototype reads Linux `/proc` for process inspection, but it
  does not require root privileges for normal simulated policy tests

## Build, Test, and Lint

```sh
cargo build
cargo test
cargo fmt
cargo clippy --all-targets -- -D warnings
```

The current test suite covers config validation, policy decisions, path handling,
process metadata parsing, log filtering, event lookup, setup generation, status
JSON, and policy-review candidate grouping/output.

## Configuration

During development, the default config path is:

```text
examples/config.toml
```

A typical config looks like this:

```toml
mode = "learn"

[[users]]
uid = 1000
groups = ["aws", "ssh", "github", "gcloud", "docker"]

[[protected_groups]]
name = "aws"
paths = ["~/.aws"]

[[protected_groups]]
name = "ssh"
paths = ["~/.ssh"]

[[protected_groups]]
name = "github"
paths = ["~/.config/gh", "~/.git-credentials", "~/.netrc"]

[[protected_groups]]
name = "gcloud"
paths = ["~/.config/gcloud"]

[[protected_groups]]
name = "docker"
paths = ["~/.docker"]

[[allow_rules]]
name = "Allow AWS CLI"
uid = 1000
exe = "/usr/bin/aws"
path_group = "aws"
operation = "open_read"

[[allow_rules]]
name = "Allow SSH client"
uid = 1000
exe = "/usr/bin/ssh"
path_group = "ssh"
operation = "open_read"
```

Policy fields:

- `mode`: `learn` or `enforce`
- `users`: protected user IDs and the credential groups that apply to them
- `protected_groups`: named sets of protected paths
- `allow_rules`: explicit access rules

Allow-rule fields:

- `name`: human-readable rule name
- `uid`: protected user ID
- `exe`: executable path that is allowed
- `path_group`: protected group the executable may access
- `operation`: optional operation constraint; currently `open_read`
- `parent_exe`: optional parent executable constraint

If `operation` is omitted, the rule currently applies to any known operation.
Since the prototype only models `open_read`, generated rules include
`operation = "open_read"` for clarity.

If `parent_exe` is set, at least one parent process in the logged parent chain
must match that executable.

In `learn` mode, a protected access without a matching allow rule is allowed and
logged with:

```json
"would_deny": true
```

In `enforce` mode, the same access is denied.

## CLI Usage

Run commands through Cargo during development.

### Generate a starter config

```sh
cargo run -- setup --output ./generated-config.toml
```

Overwrite an existing generated config:

```sh
cargo run -- setup --output ./generated-config.toml --force
```

Emit a JSON setup report:

```sh
cargo run -- setup --output ./generated-config.toml --force --json
```

`setup` detects common tools in `PATH`, such as `aws`, `ssh`, `gh`, `gcloud`,
and `docker`, and only generates allow rules for tools that are present.

### Show policy status

```sh
cargo run -- status
cargo run -- status --json
cargo run -- status --config ./generated-config.toml
```

### Validate a config

```sh
cargo run -- policy-validate
cargo run -- policy-validate --config examples/config.toml
```

### Test a simulated access

Manual executable/UID input:

```sh
cargo run -- test-access ~/.aws/credentials \
  --exe /usr/bin/python3 \
  --uid 1000
```

PID-derived process metadata:

```sh
cargo run -- test-access ~/.aws/credentials --pid $$
```

Emit JSON for a decision:

```sh
cargo run -- test-access ~/.aws/credentials \
  --exe /usr/bin/python3 \
  --uid 1000 \
  --json
```

Append a decision to a JSONL log:

```sh
cargo run -- test-access ~/.aws/credentials \
  --exe /usr/bin/python3 \
  --uid 1000 \
  --log-file ./events.jsonl
```

### Inspect process metadata

```sh
cargo run -- inspect-process $$
```

This reads process metadata from `/proc`, including UID, executable, CWD,
command line, parent PID, and parent chain.

### Inspect logs

```sh
cargo run -- logs --log-file ./events.jsonl
cargo run -- logs --log-file ./events.jsonl --last 5
cargo run -- logs --log-file ./events.jsonl --decision allow
cargo run -- logs --log-file ./events.jsonl --decision deny
cargo run -- logs --log-file ./events.jsonl --json
```

### Explain one event

```sh
cargo run -- why <event-id> --log-file ./events.jsonl
cargo run -- why <event-id> --log-file ./events.jsonl --json
```

### Review learned accesses

Human-readable review:

```sh
cargo run -- policy-review --log-file ./events.jsonl
```

JSON review output:

```sh
cargo run -- policy-review --log-file ./events.jsonl --json
```

TOML snippets only:

```sh
cargo run -- policy-review --log-file ./events.jsonl --toml
```

Write TOML suggestions to a separate file:

```sh
cargo run -- policy-review \
  --log-file ./events.jsonl \
  --write-suggestions ./suggested-rules.toml
```

Overwrite an existing suggestion file:

```sh
cargo run -- policy-review \
  --log-file ./events.jsonl \
  --write-suggestions ./suggested-rules.toml \
  --force
```

`policy-review` never modifies the active config. It only suggests allow rules
based on learn-mode `would_deny` events.

## Log Format

Logs are newline-delimited JSON. Each event can include:

- `event_id`
- `timestamp`
- `pid`
- `uid`
- `exe`
- `cwd`
- `cmdline`
- `parent_chain`
- `target_path`
- `operation`
- `decision`
- `reason`
- `matched_path_group`
- `would_deny`

Example shape:

```json
{
  "event_id": "7bcb0f0c-2d1f-4726-bf88-60d14db0e847c",
  "timestamp": "2026-05-24T20:30:12.123456789Z",
  "pid": 12345,
  "uid": 1000,
  "exe": "/usr/bin/python3",
  "cwd": "/home/alice/project",
  "cmdline": ["python3", "script.py"],
  "parent_chain": [
    {
      "pid": 12300,
      "ppid": 12000,
      "uid": 1000,
      "exe": "/usr/bin/zsh",
      "cmdline": ["zsh"]
    }
  ],
  "target_path": "/home/alice/.aws/credentials",
  "operation": "open_read",
  "decision": "allow",
  "reason": "learn mode: would deny access to protected group 'aws'",
  "matched_path_group": "aws",
  "would_deny": true
}
```

## Development Notes

The current code is organized around the planned backend split:

- `src/config.rs`: config types, loading, normalization, and validation
- `src/event.rs`: access-event model and operation type
- `src/policy.rs`: policy decision engine
- `src/logging.rs`: decision log serialization and JSONL helpers
- `src/paths.rs`: path normalization and `~` expansion helpers
- `src/process.rs`: Linux `/proc` process inspection
- `src/main.rs`: CLI commands, output formatting, setup, and review helpers

`src/main.rs` is now intentionally feature-rich but getting large. A near-term
cleanup task is to move setup, status, logs, and policy-review helpers into
separate modules before starting the daemon work.

## Pending Milestones / Tasks

Suggested next milestones:

1. Refactor `src/main.rs` into smaller modules:
  - `cli.rs`
  - `setup.rs`
  - `status.rs`
  - `review.rs`
  - `commands/logs.rs` or similar
2. Add integration tests for CLI behavior using `assert_cmd` or a similar crate.
3. Add `learn` and `enforce` commands that update the configured mode safely.
4. Add safe config-writing helpers for mode changes.
5. Add config backup behavior before writing changes.
6. Add `logs --follow`.
7. Add `logs --since` or timestamp filtering.
8. Add `policy-review --min-events <N>`.
9. Add support for more protected presets:
  - npm
  - Ansible Vault
  - Git credentials
  - dotenv files
10. Add project-root based dotenv protection.
11. Improve setup from generated starter config to interactive setup.
12. Add explicit threat-model and MVP-limitation sections to `docs/SPEC.md`.
13. Split binaries into:
- `peperspray`
- `pepersprayd`
14. Add a minimal daemon skeleton without enforcement.
15. Add daemon config loading and validation.
16. Add daemon JSONL logging.
17. Add a minimal Linux `fanotify` proof of concept.
18. Convert `fanotify` permission events into `AccessEvent`.
19. Add allow/deny responses for `FAN_OPEN_PERM`.
20. Add integration tests for protected temporary files on Linux.
21. Add systemd unit file.
22. Add `/etc/peperspray/config.toml` and `/var/log/peperspray/events.jsonl`
    defaults for installed mode.
23. Add `.deb` packaging.
24. Add uninstall/purge behavior.
25. Document failure behavior:
  - daemon crash
  - config parse failure
  - log write failure
  - process metadata lookup failure
26. Evaluate symlink, hard-link, bind-mount, and file-replacement behavior.
27. Add optional binary identity hardening, such as inode or hash matching.
28. Add desktop notification or `why last` UX.
29. Add CI for `cargo fmt`, `cargo test`, and `cargo clippy`.
30. Add release documentation.

## Current MVP Boundary

The current prototype is useful for developing and testing the policy model, but
it does not protect the host yet.

It can answer:

```text
Would this access be allowed or denied by the policy?
```

It cannot yet enforce:

```text
Block this real process before it reads the file.
```

That enforcement boundary starts when the daemon and `fanotify` backend are
implemented.

## License

`peperspray` is available under either the MIT License or the Apache License
2.0, at your option. This permissive dual-license model is intended to be
friendly to both personal and professional use, including enterprise adoption.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).