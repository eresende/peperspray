# peperspray Credential Access Guard Spec

## Summary

Define `peperspray` as a Linux-first credential access guard for developer workstations. The MVP is a Rust root daemon using `fanotify` permission events to detect and block protected credential-file reads before they complete, with a portable core architecture for future macOS/Windows backends.

Default posture is zero-trust: protected credential reads are denied in enforce mode unless explicitly allowed. Initial setup is interactive and proposes allow rules, but does not silently trust tools.

## Key Design

- `pepersprayd` runs as a root-owned `systemd` service on Ubuntu 24.04.
- `peperspray` CLI manages setup, status, mode changes, logs, test access, and policy review.
- Core logic is platform-neutral: policy parsing, access decisions, process metadata, logs, and CLI models.
- Linux backend translates `fanotify` events into generic access events: PID, UID, executable, cmdline, cwd, parent chain, target path, and operation.
- Config lives at `/etc/peperspray/config.toml`; logs live under `/var/log/peperspray/` with root-owned permissions.

## Policy Behavior

- Protected presets include dotenv files, SSH, AWS, Docker, npm, Ansible Vault, GitHub/Git credentials, and Google Cloud credentials.
- Setup asks which local users and credential groups to protect, then proposes explicit allow rules for expected tools such as `ssh`, `aws`, `docker`, `gh`, and `gcloud`.
- Modes:
  - `learn`: log would-allow/would-deny decisions without blocking.
  - `enforce`: block protected reads unless an allow rule matches.
- Allow rules match executable/cmdline/process ancestry/path group, with no blanket trusted tools by default.
- Denied events include a full running-process snapshot; normal allowed/learn events log only the access event context.

## CLI Surface

- `peperspray setup`: interactive first-run configuration and allowlist bootstrap.
- `peperspray status`: daemon state, mode, protected users, active policy summary.
- `peperspray learn`: switch to learn mode.
- `peperspray enforce`: switch to enforce mode.
- `peperspray logs`: inspect or follow structured logs.
- `peperspray test-access <path>`: verify whether a read would be allowed or denied.
- `peperspray policy-review`: review learned accesses and promote selected entries to allow rules.
- `peperspray policy-validate`: validate config syntax and rule consistency.
- `pepersprayd --check`: validate daemon config and emit a lifecycle log without starting enforcement.

## Implementation Staging

The current daemon implementation is experimental. It can load and validate
daemon configuration, write lifecycle JSONL logs, initialize a fanotify
permission-event probe, run a fanotify loop for one marked path, convert
`FAN_OPEN_PERM` metadata into the portable `AccessEvent` model, and map policy
decisions to `FAN_ALLOW` or `FAN_DENY` responses.

The remaining enforcement proof is a privileged Linux integration test that
starts the daemon against temporary protected files and proves allowed/denied
reads end to end.

Failure behavior is tracked separately in
[FAILURE_BEHAVIOR.md](FAILURE_BEHAVIOR.md).

## Test Plan

- Unit-test policy matching for allowlist-first behavior, protected path expansion, process ancestry, and mode-specific decisions.
- Integration-test Linux backend with temporary protected files to prove reads are allowed in learn mode and denied in enforce mode.
- Verify logs contain executable, cmdline, cwd, parent chain, target path, decision, reason, datetime, and denied-event process snapshots.
- Package-test `.deb` install, `systemd` startup, config permissions, log permissions, and clean uninstall behavior on Ubuntu 24.04.

## Assumptions

- MVP targets Ubuntu 24.04 developer workstations only.
- macOS and Windows are future ports; the initial implementation keeps backend boundaries clean but only ships the Linux backend.
- The product prioritizes blocking credential reads over fleet management, SIEM integrations, or advanced tamper resistance in v1.

## Threat Model

`peperspray` is designed to reduce accidental or opportunistic credential
exfiltration from developer workstations. The primary threats are local user
processes, scripts, package hooks, compromised development tools, or copied
commands that attempt to read credential files such as cloud tokens, SSH keys,
package-manager credentials, Git credentials, and project dotenv files.

The daemon is expected to run as root and enforce policy before protected read
operations complete. A normal user process should not be able to bypass an
enforce-mode denial by racing the CLI, editing root-owned policy files, or
modifying root-owned logs.

The MVP does not claim to defend against a fully compromised root account,
kernel compromise, malicious firmware, or an attacker with physical access and
disk-level control. It also does not replace secret rotation, least-privilege
cloud IAM, sandboxing, endpoint detection, or package supply-chain controls.

## MVP Limitations

The first enforcement milestone is intentionally narrow:

- Linux `fanotify` read enforcement is the only planned blocking backend.
- Policy identity is based on executable path, UID, protected group, operation,
  and optional parent executable. Stronger binary identity checks such as inode,
  signature, or content hash matching are future hardening.
- Path behavior around symlinks, hard links, bind mounts, file replacement, and
  namespace boundaries must be evaluated before relying on the tool for
  high-assurance environments.
- Learn mode is observational. It records accesses that would be denied but does
  not prevent credential reads.
- If the daemon is not running, the current prototype cannot protect the host.
  Installed failure behavior must be documented and tested before release.
- The initial CLI writes local TOML configuration and JSONL logs. It does not
  provide fleet policy distribution, remote attestation, central audit export,
  or multi-user approval workflows.
