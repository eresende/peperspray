# peperspray

`peperspray` is a Linux-first credential access guard for developer
workstations. The planned MVP is a root-owned daemon that uses Linux
`fanotify` permission events to detect credential-file reads and block them
before they complete unless an explicit policy rule allows the access.

This repository is currently at the policy/CLI prototype stage. It implements
the portable core pieces used by that future daemon:

- TOML configuration parsing and validation
- protected path groups and protected users
- allow-rule based access decisions
- learn/enforce policy behavior
- JSONL decision logs
- log inspection, event lookup, and learned-access review

The daemon, `fanotify` backend, `systemd` packaging, interactive setup flow, and
host-level enforcement are not implemented yet.

## Design Target

The target product is described in [docs/SPEC.md](docs/SPEC.md). In short:

- `pepersprayd` will run as a root-owned `systemd` service on Ubuntu 24.04.
- `peperspray` will manage setup, status, modes, logs, testing, and policy
  review.
- Default posture is zero-trust in enforce mode: protected credential reads are
  denied unless an allow rule matches.
- Learn mode records accesses that would have been denied without blocking them.
- Platform-neutral policy, event, process, and logging types are kept separate
  from Linux-specific event collection.

## Current Status

Implemented commands:

- `policy-validate`
- `test-access`
- `logs`
- `why`
- `policy-review`

Planned but not yet implemented from the spec:

- `setup`
- `status`
- `learn`
- `enforce`
- root daemon
- Linux `fanotify` integration
- process metadata capture beyond UID, executable, target path, and operation
- `/etc/peperspray/config.toml` and `/var/log/peperspray/` installation layout
- `.deb` packaging and `systemd` service management

## Requirements

- Rust toolchain with Cargo
- Linux is the intended platform, although the current prototype does not depend
  on Linux-only enforcement APIs yet

## Build and Test

```sh
cargo build
cargo test
```

The current test suite covers config validation, policy decisions, log
filtering, event lookup, and policy-review candidate grouping.

## Configuration

The default example config is [examples/config.toml](examples/config.toml):

```toml
mode = "learn"

[[users]]
uid = 1000
groups = ["aws", "ssh"]

[[protected_groups]]
name = "aws"
paths = [
    "/home/alice/.aws"
]

[[protected_groups]]
name = "ssh"
paths = [
    "/home/alice/.ssh"
]

[[allow_rules]]
name = "Allow AWS CLI"
uid = 1000
exe = "/usr/bin/aws"
path_group = "aws"

[[allow_rules]]
name = "Allow SSH client"
uid = 1000
exe = "/usr/bin/ssh"
path_group = "ssh"
```

Policy fields:

- `mode`: `learn` or `enforce`
- `users`: protected user IDs and the credential groups that apply to them
- `protected_groups`: named sets of protected paths
- `allow_rules`: exact executable/UID/path-group combinations that are allowed

In `learn` mode, a protected access without a matching allow rule is allowed and
logged with `would_deny = true`. In `enforce` mode, the same access is denied.

## CLI Usage

Run commands through Cargo during development:

```sh
cargo run -- policy-validate
```

Validate a config:

```sh
cargo run -- policy-validate --config examples/config.toml
```

Test a simulated read against the policy:

```sh
cargo run -- test-access /home/alice/.aws/credentials \
  --exe /usr/bin/aws \
  --uid 1000 \
  --config examples/config.toml
```

Emit JSON for a decision:

```sh
cargo run -- test-access /home/alice/.aws/credentials \
  --exe /usr/bin/python3 \
  --uid 1000 \
  --json
```

Append a decision to a JSONL log:

```sh
cargo run -- test-access /home/alice/.aws/credentials \
  --exe /usr/bin/python3 \
  --uid 1000 \
  --log-file ./events.jsonl
```

Inspect logs:

```sh
cargo run -- logs --log-file ./events.jsonl
cargo run -- logs --log-file ./events.jsonl --last 5
cargo run -- logs --log-file ./events.jsonl --decision deny
cargo run -- logs --log-file ./events.jsonl --json
```

Show details for one event:

```sh
cargo run -- why <event-id> --log-file ./events.jsonl
```

Review learned accesses that could become allow rules:

```sh
cargo run -- policy-review --log-file ./events.jsonl
```

## Log Format

Logs are newline-delimited JSON. Each event includes:

- `event_id`
- `timestamp`
- `uid`
- `exe`
- `target_path`
- `operation`
- `decision`
- `reason`
- `matched_path_group`
- `would_deny`

## Development Notes

The code is organized around the planned backend split:

- `src/config.rs`: config types, loading, and validation
- `src/event.rs`: portable access-event model
- `src/policy.rs`: policy decision engine
- `src/logging.rs`: decision log serialization and JSONL helpers
- `src/main.rs`: CLI commands and log review helpers

The next major implementation step is adding the Linux event collection layer
and daemon process that can translate real file-access events into the existing
`AccessEvent` model.

## License

`peperspray` is available under either the MIT License or the Apache License
2.0, at your option. This permissive dual-license model is intended to be
friendly to both personal and professional use, including enterprise adoption.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
