# Path Semantics

This document records the current path behavior for protected credential reads.
The policy model uses normalized paths and, for Linux `fanotify` events,
device/inode identity captured from the target file descriptor.

## Current Behavior

Protected group paths are expanded and normalized when the config is loaded:

- `~` is expanded to the current user's home directory.
- Existing paths are canonicalized with `std::fs::canonicalize`.
- Missing paths are kept as written.

Access-event target paths are normalized before policy evaluation in the CLI and
fanotify conversion paths. A protected absolute path matches when either:

- the normalized target path starts with the normalized protected path using
  component-aware `Path::starts_with`; or
- the event's target `(dev, ino)` identity matches the protected file, or a file
  below a protected directory.

Relative protected paths are only used for project dotenv presets. They match by
filename, so a relative preset such as `.env` protects files named `.env`
regardless of project directory. Relative protected paths do not participate in
device/inode identity matching.

When the daemon starts its fanotify loop, it marks each existing protected path
and each existing descendant below protected directories. That gives the kernel a
mark on existing protected files, so an access through a hard-link or bind-mount
alias can still produce a permission event even when the alias path is outside
the configured protected directory. This is intended for credential-sized
protected paths such as key directories, token files, and dotenv files, not for
arbitrary large application trees.

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
after config load, path-prefix matching follows the loaded path, not the new
directory name. For existing protected files with fanotify marks, device/inode
identity matching can still identify the underlying file object. The daemon
periodically rescans configured protected roots and marks newly created paths,
but rename-heavy workflows still need more coverage before relying on rename
behavior for high-assurance enforcement.

## Hard Links

Hard-link aliases for existing protected files are blocked by device/inode
identity matching. The privileged regression test
`hard_link_alias_outside_marked_dir_is_blocked` covers this behavior end to end.

The current implementation relies on marks placed at daemon loop startup and by
periodic rescans for existing protected descendants. New hard-link patterns
created after startup should be covered by path-prefix behavior when the access
path remains under a protected directory, but alias visibility outside the
protected tree should be retested when broadening the creation/rename threat
model.

## Bind Mounts And Namespaces

Bind mounts and mount namespaces can present the same filesystem object under
different paths, so path-prefix policy alone is insufficient. The daemon records
the target file's device/inode identity from the fanotify event and policy
matching compares that identity to protected files.

The ignored privileged tests are:

- bind mount from protected directory to unprotected path
- process mount namespace bind mount from protected directory to unprotected
  path

Both tests assert that the alias read is denied.

## Remaining Caveats

- If the daemon is not running, the current MVP cannot protect the host.
- Existing-descendant fanotify marks are collected when the daemon loop starts.
  The supported shape is small credential trees and individual secret files.
  Newly created nested directories and rename-heavy workflows need additional
  lifecycle coverage before relying on them for high-assurance enforcement.
- Device/inode identity hardens protected file aliasing. It is not a signature
  check and does not defend against root compromise, kernel compromise, or a
  privileged attacker that can stop or tamper with the daemon.
