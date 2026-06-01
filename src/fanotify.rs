use crate::event::{AccessEvent, Operation};
use crate::paths;
use crate::policy::Decision;
use crate::process;
use anyhow::Context;
use nix::libc;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Debug)]
pub struct FanotifyProbe {
    fd: OwnedFd,
}

impl FanotifyProbe {
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanotifyPermissionEvent {
    pub pid: u32,
    pub target_fd: RawFd,
    pub mask: u64,
}

pub fn probe_path(path: &Path) -> anyhow::Result<FanotifyProbe> {
    let fanotify_fd = fanotify_init()?;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;

    let result = unsafe {
        libc::fanotify_mark(
            fanotify_fd.as_raw_fd(),
            libc::FAN_MARK_ADD,
            libc::FAN_OPEN_PERM,
            libc::AT_FDCWD,
            path.as_ptr(),
        )
    };

    if result < 0 {
        return Err(Into::into(std::io::Error::last_os_error()));
    }

    Ok(FanotifyProbe { fd: fanotify_fd })
}

pub fn permission_event_from_metadata(
    metadata: &libc::fanotify_event_metadata,
) -> Option<FanotifyPermissionEvent> {
    if metadata.vers != libc::FANOTIFY_METADATA_VERSION {
        return None;
    }

    if metadata.fd < 0 {
        return None;
    }

    if metadata.mask & libc::FAN_OPEN_PERM == 0 {
        return None;
    }

    Some(FanotifyPermissionEvent {
        pid: metadata.pid.try_into().ok()?,
        target_fd: metadata.fd,
        mask: metadata.mask,
    })
}

pub fn access_event_from_permission_event(
    event: &FanotifyPermissionEvent,
) -> anyhow::Result<AccessEvent> {
    let process_info = process::inspect_process(event.pid)
        .with_context(|| format!("failed to inspect process {}", event.pid))?;
    let target_path = std::fs::read_link(format!("/proc/self/fd/{}", event.target_fd))
        .with_context(|| format!("failed to resolve fanotify fd {}", event.target_fd))?;

    Ok(AccessEvent {
        pid: Some(process_info.pid),
        uid: process_info.uid,
        exe: paths::normalize_path(&process_info.exe),
        cwd: Some(paths::normalize_path(&process_info.cwd)),
        cmdline: process_info.cmdline,
        parent_chain: process_info.parent_chain,
        target_path: paths::normalize_path(&target_path),
        operation: Operation::OpenRead,
    })
}

pub fn respond_to_permission_event(
    fanotify_fd: RawFd,
    event: &FanotifyPermissionEvent,
    decision: &Decision,
) -> anyhow::Result<()> {
    let response = libc::fanotify_response {
        fd: event.target_fd,
        response: response_code_for_decision(decision),
    };

    let bytes_written = unsafe {
        libc::write(
            fanotify_fd,
            std::ptr::addr_of!(response).cast(),
            std::mem::size_of::<libc::fanotify_response>(),
        )
    };

    if bytes_written < 0 {
        return Err(Into::into(std::io::Error::last_os_error()));
    }

    Ok(())
}

fn response_code_for_decision(decision: &Decision) -> u32 {
    match decision {
        Decision::Allow { .. } => libc::FAN_ALLOW,
        Decision::Deny { .. } => libc::FAN_DENY,
    }
}

fn fanotify_init() -> anyhow::Result<OwnedFd> {
    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };

    if fd < 0 {
        return Err(Into::into(std::io::Error::last_os_error()));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_event_from_metadata_accepts_open_perm_event() {
        let metadata = libc::fanotify_event_metadata {
            event_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u32,
            vers: libc::FANOTIFY_METADATA_VERSION,
            reserved: 0,
            metadata_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u16,
            mask: libc::FAN_OPEN_PERM,
            fd: 10,
            pid: 1234,
        };

        let event = permission_event_from_metadata(&metadata).expect("event should convert");

        assert_eq!(event.pid, 1234);
        assert_eq!(event.target_fd, 10);
        assert_eq!(event.mask, libc::FAN_OPEN_PERM);
    }

    #[test]
    fn permission_event_from_metadata_ignores_non_permission_event() {
        let metadata = libc::fanotify_event_metadata {
            event_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u32,
            vers: libc::FANOTIFY_METADATA_VERSION,
            reserved: 0,
            metadata_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u16,
            mask: 0,
            fd: 10,
            pid: 1234,
        };

        assert!(permission_event_from_metadata(&metadata).is_none());
    }

    #[test]
    fn response_code_matches_policy_decision() {
        assert_eq!(
            response_code_for_decision(&Decision::Allow {
                reason: "test".to_string(),
                matched_path_group: None,
                would_deny: false,
            }),
            libc::FAN_ALLOW
        );

        assert_eq!(
            response_code_for_decision(&Decision::Deny {
                reason: "test".to_string(),
                matched_path_group: None,
                would_deny: false,
            }),
            libc::FAN_DENY
        );
    }
}
