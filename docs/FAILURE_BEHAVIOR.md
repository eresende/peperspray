# Failure Behavior

This document records intended failure behavior for the MVP. The current daemon
has a Linux fanotify enforcement loop with privileged integration coverage on
Ubuntu 24.04, plus RPM packaging support for Fedora/RHEL-family systems. It
still has personal-production hardening gaps documented in
`PATH_SEMANTICS.md`.

## Daemon Crash

Installed mode runs `pepersprayd` under systemd with `Restart=always` and a
short restart backoff. If the daemon exits or crashes, protected reads are no
longer blocked until systemd restarts it and the fanotify marks are
re-established. The daemon writes startup lifecycle logs after config validation
and after the fanotify loop starts so operators can distinguish "never started"
from "started then crashed".

Current daemon failure is effectively fail-open while the process is down. A
future hardening milestone should decide whether fail-closed behavior is
possible and acceptable for each protected mount/user scope.

## Config Parse Or Validation Failure

The daemon refuses to start with an invalid config. CLI mode changes also refuse
to write changes if the existing config cannot be loaded and validated.

Expected behavior:

- return a non-zero exit status
- print validation errors to stderr/stdout through the current command path
- avoid replacing the active config
- preserve the previous `.bak` file if no write was attempted

## Log Write Failure

Decision logs and daemon lifecycle logs are part of the audit trail. If the
daemon cannot append a log entry during startup, it returns an error. During
event handling, log write failure is treated as a handling failure. In learn
mode, the daemon allows the permission event by fallback; in enforce mode, it
attempts to deny the permission event. Notification failures are not treated as
policy failures; they are written as daemon lifecycle warnings when possible.

## Process Metadata Lookup Failure

The policy engine expects UID, executable path, cwd, cmdline, and parent chain
metadata when converting a real fanotify event into an `AccessEvent`. If process
metadata cannot be read from `/proc`, event handling fails. Learn mode allows
the permission event by fallback and records a daemon error so observation does
not accidentally block short-lived tools. Enforce mode denies by fallback,
preserving the zero-trust posture when the daemon cannot determine the process
identity.

## Fanotify Setup Failure

Fanotify initialization can fail because the daemon lacks privileges, the kernel
does not support the requested flags, or the mark target is invalid. The daemon
must treat setup failure as startup failure for enforce mode, because no host
protection exists without the fanotify mark.
