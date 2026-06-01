# Failure Behavior

This document records intended failure behavior for the MVP. The current daemon
is still a non-enforcing skeleton, so enforcement-specific behavior must be
proved by the future privileged fanotify integration tests.

## Daemon Crash

Installed mode should run `pepersprayd` under systemd with `Restart=on-failure`.
If the daemon crashes before enforcement is complete, protected reads are not
blocked by the prototype. The daemon should write a startup lifecycle log after
config validation so operators can distinguish "never started" from "started
then crashed".

Future enforcement mode must explicitly decide whether daemon failure is
fail-open or fail-closed for each protected mount/user scope. That decision is
not implemented yet.

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
daemon cannot append a log entry during startup, it currently returns an error.
For future enforcement, the project must choose and test whether log-write
failure blocks access decisions or allows policy evaluation to continue with a
visible degraded state.

## Process Metadata Lookup Failure

The policy engine expects UID, executable path, cwd, cmdline, and parent chain
metadata when converting a real fanotify event into an `AccessEvent`. If process
metadata cannot be read from `/proc`, the future enforcement loop should record
that failure and deny protected reads in enforce mode unless a deliberate
fail-open policy is added.

## Fanotify Setup Failure

Fanotify initialization can fail because the daemon lacks privileges, the kernel
does not support the requested flags, or the mark target is invalid. The daemon
must treat setup failure as startup failure for enforce mode, because no host
protection exists without the fanotify mark.
