# Path Semantics

This document records the current path behavior for protected credential reads.
The policy model is path-based today; future hardening may add inode, device, or
content identity checks.

## Current Behavior

Protected group paths are expanded and normalized when the config is loaded:

- `~` is expanded to the current user's home directory.
- Existing paths are canonicalized with `std::fs::canonicalize`.
- Missing paths are kept as written.

Access-event target paths are normalized before policy evaluation in the CLI and
fanotify conversion paths. A protected absolute path matches when the normalized
target path starts with the normalized protected path using component-aware
`Path::starts_with`.

Relative protected paths are only used for project dotenv presets. They match by
filename, so a relative preset such as `.env` protects files named `.env`
regardless of project directory.

## Symlinks

When the accessed path exists and can be canonicalized, symlinks resolve to their
target path before policy evaluation. A symlink outside a protected directory
that points into a protected directory should therefore be treated as protected.

This depends on resolving the path from the fanotify file descriptor and then
normalizing it successfully.

## File Replacement

Files created or replaced under a protected directory remain protected because
the parent directory path still matches the protected prefix.

## Directory Rename

Config paths are normalized at load time. If a protected directory is renamed
after config load, the path-prefix policy may no longer match the renamed path.
The fanotify mark may still refer to the marked filesystem object, but the
policy layer currently reasons over paths, not persistent object identity.

This must be tested before relying on rename behavior for enforcement.

## Hard Links

Hard links are a known limitation. A file inside a protected directory can have a
hard link outside that directory. Because the current policy model only checks
path prefixes, an access through the outside hard-link path is not detected as
protected.

The ignored privileged regression test
`hard_link_alias_outside_marked_dir_is_currently_not_blocked` documents this
current behavior end to end.

Future hardening should consider matching device/inode identity for protected
files or marking broader filesystem scopes and resolving object identity before
policy evaluation.

## Bind Mounts And Namespaces

Bind mounts and mount namespaces can present the same filesystem object under
different paths, so path-prefix policy alone is insufficient. Current
regression coverage documents that an alias outside the configured protected
path can still be read when it is reached through a bind mount or through a bind
mount created inside a separate mount namespace.

The ignored privileged tests are:

- bind mount from protected directory to unprotected path
- process mount namespace bind mount from protected directory to unprotected
  path

Remaining hardening work should add inode/device identity tracking for protected
files and then update these tests to assert the hardened behavior.
