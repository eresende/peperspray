# peperspray Credential Access Guard Spec

## Summary

Define `peperspray` as a Linux-first credential access guard for developer workstations. The MVP is a Rust root daemon using `fanotify` permission events to detect and block protected credential-file reads before they complete, with a portable core architecture for future macOS/Windows backends.

Default posture is zero-trust: protected credential reads are denied in enforce mode unless explicitly allowed. Initial setup is interactive and proposes allow rules, but does not silently trust tools.

## Key Design

- `pepersprayd` runs as a root-owned `systemd` service on Linux systems with
  fanotify permission-event support.
- `peperspray` CLI manages setup, preset discovery, status, doctor checks, mode
  changes, logs, test access, policy review, and reviewed policy application.
- Core logic is platform-neutral: policy parsing, access decisions, process metadata, logs, and CLI models.
- Linux backend translates `fanotify` events into generic access events: PID, UID, executable, cmdline, cwd, parent chain, target path, and operation.
- Config lives at `/etc/peperspray/config.toml`; logs live under
  `/var/log/peperspray/` with root-owned permissions.
- Installed `.deb` and RPM packages include log rotation for runtime logs and
  best-effort desktop notifications for denied reads.

## Policy Behavior

- The default protected preset profile is `dev-browser-wallet`, covering
  developer credentials, cloud/package-manager files, browser credential stores,
  wallets, and password managers.
- Protected groups may contain concrete paths and glob-style `patterns` for
  browser/profile locations.
- Setup asks which local users and credential groups to protect, then proposes
  explicit allow rules for detected expected tools such as `ssh`, `aws`,
  `docker`, `gh`, `gcloud`, browsers, and known helper binaries.
- Modes:
  - `learn`: log would-allow/would-deny decisions without blocking.
  - `enforce`: block protected reads unless an allow rule matches.
- Allow rules match executable path, optional executable SHA-256 digest,
  cmdline/process ancestry, path group, and operation, with no blanket trusted
  tools by default.
- Denied events include a full running-process snapshot; normal allowed/learn events log only the access event context.

## CLI Surface

- `peperspray setup`: interactive first-run configuration and allowlist bootstrap.
- `peperspray presets`: list protected preset groups and platform paths.
- `peperspray status`: daemon state, mode, protected users, active policy summary.
- `peperspray doctor`: validate backend health, config/log/binary permissions,
  config validity, and missing configured protected paths.
- `peperspray learn`: switch to learn mode.
- `peperspray enforce`: switch to enforce mode.
- `peperspray logs`: inspect or follow structured logs.
- `peperspray test-access <path>`: verify whether a read would be allowed or denied.
- `peperspray policy-review`: review learned accesses and promote selected entries to allow rules.
- `peperspray policy-apply`: merge a reviewed allow-rule suggestion file into a
  config with validation and backup.
- `peperspray policy-validate`: validate config syntax and rule consistency.
- `pepersprayd --check`: validate daemon config and emit a lifecycle log without starting enforcement.

## Implementation Staging

The current daemon implementation can load and validate daemon configuration,
write lifecycle JSONL logs, initialize a fanotify permission-event probe, mark
existing protected paths from the config, convert `FAN_OPEN_PERM` metadata into
the portable `AccessEvent` model, and map policy decisions to `FAN_ALLOW` or
`FAN_DENY` responses.

If fanotify event handling fails before policy evaluation, learn mode allows by
fallback and records a daemon error; enforce mode denies by fallback.

In enforce mode, denied reads trigger best-effort desktop notifications through
the user's session bus when `notify-send` is available. Notifications are
throttled per user, executable, protected group, and operation for five minutes.

Privileged Linux integration tests on Ubuntu 24.04 start the daemon against
temporary protected files, prove allowed/denied reads end to end, and verify
that hard-link, bind-mount, and mount-namespace aliases are blocked by
device/inode path-identity matching.

Failure behavior is tracked separately in
[FAILURE_BEHAVIOR.md](FAILURE_BEHAVIOR.md).

Path behavior and remaining identity caveats are tracked in
[PATH_SEMANTICS.md](PATH_SEMANTICS.md).

## Test Plan

- Unit-test policy matching for allowlist-first behavior, protected path expansion, process ancestry, and mode-specific decisions.
- Integration-test Linux backend with temporary protected files to prove reads
  are allowed in learn mode and denied in enforce mode.
- Run ignored privileged path-identity regressions to prove hard-link,
  bind-mount, and mount-namespace aliases are blocked on dogfood hosts.
- Verify logs contain executable, cmdline, cwd, parent chain, target path, decision, reason, datetime, and denied-event process snapshots.
- Package-test `.deb` install, `systemd` startup, config permissions, log
  permissions, logrotate policy, service metadata, and clean uninstall behavior
  on Ubuntu 24.04.
- Package-test RPM install, `systemd` startup, config permissions, log
  permissions, logrotate policy, service metadata, reinstall permission repair,
  and clean uninstall behavior on Fedora/RHEL-family systems.
- Release builds publish Linux x86_64 and ARM64 binaries plus Debian
  `amd64`/`arm64` and RPM `x86_64`/`aarch64` packages.

## Assumptions

- MVP targets Linux developer workstations with fanotify permission-event
  support. Ubuntu 24.04 currently has the deepest privileged test coverage;
  Fedora/RHEL-family systems have RPM packaging and a QEMU lifecycle runner.
- ARM64 Linux package builds are supported; ARM64 QEMU package lifecycle tests
  are deferred.
- macOS and Windows are future ports; the initial implementation keeps backend boundaries clean but only ships the Linux backend.
- The product prioritizes blocking credential reads over fleet management, SIEM integrations, or full daemon self-protection in v1.

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
- Policy identity is based on executable path, optional executable SHA-256
  digest, UID, protected group, operation, optional parent executable, and, for
  Linux fanotify events, target device/inode identity used to detect protected
  file aliases.
- Path-identity hardening marks existing protected descendants at daemon loop
  startup. The supported shape is small credential trees and individual secret
  files. Newly created nested directories and rename-heavy workflows need
  additional lifecycle coverage before relying on the tool for high-assurance
  environments.
- Learn mode is observational. It records accesses that would be denied but does
  not prevent credential reads.
- If the daemon is not running, the current MVP cannot protect the host.
- The initial CLI writes local TOML configuration and JSONL logs. It does not
  provide fleet policy distribution, remote attestation, central audit export,
  or multi-user approval workflows.
- `doctor` reports unsafe installed path ownership and permissions, and the
  daemon refuses installed-mode startup on those checks.
