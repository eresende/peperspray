use crate::event::{AccessEvent, Operation};
use crate::policy::Decision;
use nix::unistd::{Uid, User};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub const DEFAULT_DENY_NOTIFICATION_THROTTLE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationStatus {
    Sent,
    Suppressed,
    NotDenied,
    Unavailable(String),
}

#[derive(Debug)]
pub struct DenyNotifier {
    throttle: Duration,
    last_sent: HashMap<NotificationKey, Instant>,
    runuser_path: PathBuf,
    notify_send_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NotificationKey {
    uid: u32,
    exe: PathBuf,
    matched_path_group: Option<String>,
    operation: Operation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NotificationMessage {
    summary: String,
    body: String,
}

impl Default for DenyNotifier {
    fn default() -> Self {
        Self {
            throttle: DEFAULT_DENY_NOTIFICATION_THROTTLE,
            last_sent: HashMap::new(),
            runuser_path: PathBuf::from("/usr/sbin/runuser"),
            notify_send_path: PathBuf::from("/usr/bin/notify-send"),
        }
    }
}

impl DenyNotifier {
    pub fn notify_if_denied(
        &mut self,
        event: &AccessEvent,
        decision: &Decision,
    ) -> anyhow::Result<NotificationStatus> {
        self.notify_if_denied_at(event, decision, Instant::now())
    }

    fn notify_if_denied_at(
        &mut self,
        event: &AccessEvent,
        decision: &Decision,
        now: Instant,
    ) -> anyhow::Result<NotificationStatus> {
        let Decision::Deny {
            matched_path_group, ..
        } = decision
        else {
            return Ok(NotificationStatus::NotDenied);
        };

        let key = NotificationKey {
            uid: event.uid,
            exe: event.exe.clone(),
            matched_path_group: matched_path_group.clone(),
            operation: event.operation,
        };

        if self.is_throttled(&key, now) {
            return Ok(NotificationStatus::Suppressed);
        }

        self.last_sent.insert(key, now);

        if !self.runuser_path.exists() {
            return Ok(NotificationStatus::Unavailable(format!(
                "{} not found",
                self.runuser_path.display()
            )));
        }

        if !self.notify_send_path.exists() {
            return Ok(NotificationStatus::Unavailable(format!(
                "{} not found",
                self.notify_send_path.display()
            )));
        }

        let Some(user) = User::from_uid(Uid::from_raw(event.uid))? else {
            return Ok(NotificationStatus::Unavailable(format!(
                "no passwd entry for uid {}",
                event.uid
            )));
        };

        let message = notification_message(event, matched_path_group.as_deref());
        let status = Command::new(&self.runuser_path)
            .args(runuser_notify_args(
                &user.name,
                event.uid,
                &self.notify_send_path,
                &message,
            ))
            .status()?;

        if !status.success() {
            anyhow::bail!("notify-send exited with {status}");
        }

        Ok(NotificationStatus::Sent)
    }

    fn is_throttled(&self, key: &NotificationKey, now: Instant) -> bool {
        self.last_sent
            .get(key)
            .is_some_and(|last_sent| now.duration_since(*last_sent) < self.throttle)
    }
}

fn notification_message(
    event: &AccessEvent,
    matched_path_group: Option<&str>,
) -> NotificationMessage {
    let executable = event
        .exe
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| event.exe.display().to_string());
    let group = matched_path_group.unwrap_or("protected files");

    NotificationMessage {
        summary: "Credential access blocked".to_string(),
        body: format!(
            "{executable} tried to read {group} credentials\n{}",
            event.target_path.display()
        ),
    }
}

fn runuser_notify_args(
    username: &str,
    uid: u32,
    notify_send_path: &Path,
    message: &NotificationMessage,
) -> Vec<String> {
    vec![
        "-u".to_string(),
        username.to_string(),
        "--".to_string(),
        "/usr/bin/env".to_string(),
        format!("XDG_RUNTIME_DIR=/run/user/{uid}"),
        format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"),
        notify_send_path.display().to_string(),
        "--app-name=peperspray".to_string(),
        "--urgency=normal".to_string(),
        "--icon=security-high".to_string(),
        "--hint=string:x-canonical-private-synchronous:peperspray-deny".to_string(),
        message.summary.clone(),
        message.body.clone(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access_event(exe: &str, target_path: &str) -> AccessEvent {
        AccessEvent {
            pid: Some(1234),
            uid: 1000,
            exe: PathBuf::from(exe),
            cwd: None,
            cmdline: Vec::new(),
            parent_chain: Vec::new(),
            target_path: PathBuf::from(target_path),
            operation: Operation::OpenRead,
        }
    }

    fn deny(group: &str) -> Decision {
        Decision::Deny {
            reason: "blocked".to_string(),
            matched_path_group: Some(group.to_string()),
            would_deny: false,
        }
    }

    #[test]
    fn non_denies_do_not_notify() {
        let mut notifier = DenyNotifier::default();
        let event = access_event("/usr/bin/cat", "/home/alice/.aws/credentials");
        let decision = Decision::Allow {
            reason: "allowed".to_string(),
            matched_path_group: Some("aws".to_string()),
            would_deny: false,
        };

        let status = notifier
            .notify_if_denied_at(&event, &decision, Instant::now())
            .expect("notification should not fail");

        assert_eq!(status, NotificationStatus::NotDenied);
    }

    #[test]
    fn repeated_denies_for_same_tool_and_group_are_throttled() {
        let mut notifier = DenyNotifier {
            runuser_path: PathBuf::from("/missing/runuser"),
            notify_send_path: PathBuf::from("/missing/notify-send"),
            ..Default::default()
        };
        let event = access_event("/usr/bin/cat", "/home/alice/.aws/credentials");
        let now = Instant::now();

        let first = notifier
            .notify_if_denied_at(&event, &deny("aws"), now)
            .expect("notification should not fail");
        let second = notifier
            .notify_if_denied_at(&event, &deny("aws"), now + Duration::from_secs(10))
            .expect("notification should not fail");

        assert!(matches!(first, NotificationStatus::Unavailable(_)));
        assert_eq!(second, NotificationStatus::Suppressed);
    }

    #[test]
    fn throttle_key_includes_path_group() {
        let mut notifier = DenyNotifier {
            runuser_path: PathBuf::from("/missing/runuser"),
            notify_send_path: PathBuf::from("/missing/notify-send"),
            ..Default::default()
        };
        let event = access_event("/usr/bin/cat", "/home/alice/.aws/credentials");
        let now = Instant::now();

        let first = notifier
            .notify_if_denied_at(&event, &deny("aws"), now)
            .expect("notification should not fail");
        let second = notifier
            .notify_if_denied_at(&event, &deny("npm"), now + Duration::from_secs(10))
            .expect("notification should not fail");

        assert!(matches!(first, NotificationStatus::Unavailable(_)));
        assert!(matches!(second, NotificationStatus::Unavailable(_)));
    }

    #[test]
    fn runuser_args_target_user_desktop_bus() {
        let message = NotificationMessage {
            summary: "summary".to_string(),
            body: "body".to_string(),
        };

        let args = runuser_notify_args("alice", 1000, Path::new("/usr/bin/notify-send"), &message);

        assert_eq!(args[0], "-u");
        assert_eq!(args[1], "alice");
        assert!(args.contains(&"/usr/bin/env".to_string()));
        assert!(args.contains(&"XDG_RUNTIME_DIR=/run/user/1000".to_string()));
        assert!(
            args.contains(&"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus".to_string())
        );
        assert!(args.contains(&"/usr/bin/notify-send".to_string()));
        assert!(args.contains(&"--urgency=normal".to_string()));
        assert!(args.contains(&"--icon=security-high".to_string()));
        assert!(args.contains(
            &"--hint=string:x-canonical-private-synchronous:peperspray-deny".to_string()
        ));
    }

    #[test]
    fn notification_message_is_concise() {
        let event = access_event("/usr/bin/cat", "/home/alice/.aws/credentials");

        let message = notification_message(&event, Some("aws"));

        assert_eq!(message.summary, "Credential access blocked");
        assert_eq!(
            message.body,
            "cat tried to read aws credentials\n/home/alice/.aws/credentials"
        );
        assert!(!message.body.contains("throttled"));
    }
}
