# Installed Layout

The intended Linux package layout is:

```text
/usr/bin/peperspray
/usr/bin/pepersprayd
/etc/peperspray/config.toml
/var/log/peperspray/events.jsonl
/lib/systemd/system/pepersprayd.service
```

Ownership and permissions:

- `/etc/peperspray/`: `root:root`, `0755`
- `/etc/peperspray/config.toml`: `root:root`, `0644` initially
- `/var/log/peperspray/`: `root:root`, `0755`
- `/var/log/peperspray/events.jsonl`: created by `pepersprayd`
- `/usr/bin/peperspray`: `root:root`, executable
- `/usr/bin/pepersprayd`: `root:root`, executable

The service runs as root by default because fanotify permission events and
policy enforcement require elevated privileges.
