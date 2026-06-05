use crate::event::{AccessEvent, FileIdentity, Operation};
use crate::paths;
use crate::policy::Decision;
use crate::process;
use anyhow::Context;
use nix::libc;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub const FANOTIFY_PERMISSION_MASK: u64 = libc::FAN_OPEN_PERM | libc::FAN_EVENT_ON_CHILD;

#[derive(Debug)]
pub struct FanotifyProbe {
    fd: OwnedFd,
}

impl FanotifyProbe {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            fd: fanotify_init()?,
        })
    }

    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn mark_path(&self, path: &Path) -> anyhow::Result<()> {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;

        let result = unsafe {
            libc::fanotify_mark(
                self.raw_fd(),
                libc::FAN_MARK_ADD,
                FANOTIFY_PERMISSION_MASK,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };

        if result < 0 {
            return Err(Into::into(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    pub fn read_permission_events(&self) -> anyhow::Result<Vec<FanotifyPermissionEvent>> {
        let mut buffer = [0_u8; 8192];
        let bytes_read =
            unsafe { libc::read(self.raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };

        if bytes_read < 0 {
            let error = std::io::Error::last_os_error();

            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(Vec::new());
            }

            return Err(Into::into(error));
        }

        Ok(permission_events_from_buffer(
            &buffer[..bytes_read.try_into()?],
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanotifyPermissionEvent {
    pub pid: u32,
    pub target_fd: RawFd,
    pub mask: u64,
}

pub fn probe_path(path: &Path) -> anyhow::Result<FanotifyProbe> {
    let probe = FanotifyProbe::new()?;
    probe.mark_path(path)?;

    Ok(probe)
}

pub fn permission_events_from_buffer(buffer: &[u8]) -> Vec<FanotifyPermissionEvent> {
    let metadata_size = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + metadata_size <= buffer.len() {
        let metadata = unsafe {
            std::ptr::read_unaligned(
                buffer[offset..]
                    .as_ptr()
                    .cast::<libc::fanotify_event_metadata>(),
            )
        };

        let event_len = metadata.event_len as usize;

        if event_len < metadata_size || offset + event_len > buffer.len() {
            break;
        }

        if let Some(event) = permission_event_from_metadata(&metadata) {
            events.push(event);
        }

        offset += event_len;
    }

    events
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
    let target_file_identity = file_identity_for_fd(event.target_fd)
        .with_context(|| format!("failed to stat fanotify fd {}", event.target_fd))?;

    Ok(AccessEvent {
        pid: Some(process_info.pid),
        uid: process_info.uid,
        exe: paths::normalize_path(&process_info.exe),
        cwd: Some(paths::normalize_path(&process_info.cwd)),
        cmdline: process_info.cmdline,
        parent_chain: process_info.parent_chain,
        target_path: paths::normalize_path(&target_path),
        target_file_identity: Some(target_file_identity),
        operation: Operation::OpenRead,
    })
}

fn file_identity_for_fd(fd: RawFd) -> anyhow::Result<FileIdentity> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };

    if result < 0 {
        return Err(Into::into(std::io::Error::last_os_error()));
    }

    let stat = unsafe { stat.assume_init() };

    Ok(FileIdentity {
        dev: stat.st_dev,
        ino: stat.st_ino,
    })
}

pub fn respond_to_permission_event(
    fanotify_fd: RawFd,
    event: &FanotifyPermissionEvent,
    decision: &Decision,
) -> anyhow::Result<()> {
    write_permission_response(
        fanotify_fd,
        event.target_fd,
        response_code_for_decision(decision),
    )
}

pub fn deny_permission_event(
    fanotify_fd: RawFd,
    event: &FanotifyPermissionEvent,
) -> anyhow::Result<()> {
    write_permission_response(fanotify_fd, event.target_fd, libc::FAN_DENY)
}

fn response_code_for_decision(decision: &Decision) -> u32 {
    match decision {
        Decision::Allow { .. } => libc::FAN_ALLOW,
        Decision::Deny { .. } => libc::FAN_DENY,
    }
}

fn write_permission_response(
    fanotify_fd: RawFd,
    target_fd: RawFd,
    response_code: u32,
) -> anyhow::Result<()> {
    let response = libc::fanotify_response {
        fd: target_fd,
        response: response_code,
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

pub fn close_permission_event_fd(event: &FanotifyPermissionEvent) -> anyhow::Result<()> {
    let result = unsafe { libc::close(event.target_fd) };

    if result < 0 {
        return Err(Into::into(std::io::Error::last_os_error()));
    }

    Ok(())
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
    fn permission_events_from_buffer_parses_multiple_metadata_entries() {
        let first = libc::fanotify_event_metadata {
            event_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u32,
            vers: libc::FANOTIFY_METADATA_VERSION,
            reserved: 0,
            metadata_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u16,
            mask: libc::FAN_OPEN_PERM,
            fd: 10,
            pid: 1234,
        };
        let second = libc::fanotify_event_metadata {
            event_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u32,
            vers: libc::FANOTIFY_METADATA_VERSION,
            reserved: 0,
            metadata_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u16,
            mask: libc::FAN_OPEN_PERM,
            fd: 11,
            pid: 1235,
        };

        let mut buffer = Vec::new();
        buffer.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!(first).cast::<u8>(),
                std::mem::size_of::<libc::fanotify_event_metadata>(),
            )
        });
        buffer.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!(second).cast::<u8>(),
                std::mem::size_of::<libc::fanotify_event_metadata>(),
            )
        });

        let events = permission_events_from_buffer(&buffer);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].target_fd, 10);
        assert_eq!(events[1].target_fd, 11);
    }

    #[test]
    fn permission_events_from_buffer_ignores_truncated_metadata() {
        let buffer = vec![0_u8; std::mem::size_of::<libc::fanotify_event_metadata>() - 1];

        assert!(permission_events_from_buffer(&buffer).is_empty());
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
