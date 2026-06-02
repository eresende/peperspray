use clap::Parser;
use peperspray::daemon::{
    self, DEFAULT_DAEMON_CONFIG_PATH, DEFAULT_DAEMON_LOG_FILE, DaemonOptions,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "pepersprayd")]
#[command(about = "Credential access guard daemon.")]
struct Cli {
    #[arg(long, default_value = DEFAULT_DAEMON_CONFIG_PATH)]
    config: PathBuf,

    #[arg(long, default_value = DEFAULT_DAEMON_LOG_FILE)]
    log_file: PathBuf,

    #[arg(long)]
    check: bool,

    #[arg(long, conflicts_with = "fanotify_path")]
    fanotify_probe: Option<PathBuf>,

    #[arg(long, conflicts_with = "check")]
    fanotify_path: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    daemon::run(DaemonOptions {
        config_path: cli.config,
        log_file: cli.log_file,
        check_only: cli.check,
        fanotify_probe: cli.fanotify_probe,
        fanotify_path: cli.fanotify_path,
    })
}
