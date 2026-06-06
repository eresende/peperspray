pub mod cli;
pub mod commands;
pub mod config;
pub mod daemon;
pub mod doctor;
pub mod event;
pub mod fanotify;
pub mod identity;
pub mod logging;
pub mod notifications;
pub mod paths;
pub mod policy;
pub mod process;
pub mod review;
pub mod service;
pub mod setup;
pub mod status;

pub fn backend_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "fanotify"
    } else if cfg!(target_os = "macos") {
        "endpoint-security-required"
    } else if cfg!(target_os = "windows") {
        "minifilter-required"
    } else {
        "unsupported"
    }
}
