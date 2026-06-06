use std::path::PathBuf;
use std::str::FromStr;
use uuid::Uuid;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/peperspray/config.toml";
pub const DEFAULT_LOG_FILE: &str = "/var/log/peperspray/events.jsonl";

#[derive(Debug, clap::Parser)]
#[command(name = "peperspray")]
#[command(about = "Credential access guard for developer workstations.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DecisionFilter {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhyTarget {
    EventId(Uuid),
    Last,
}

impl FromStr for WhyTarget {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "last" {
            return Ok(Self::Last);
        }

        Uuid::parse_str(value)
            .map(Self::EventId)
            .map_err(|err| format!("expected an event id or 'last': {err}"))
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    Learn {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },

    Enforce {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },

    PolicyValidate {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },

    Presets {
        #[arg(long)]
        json: bool,
    },

    Doctor {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        #[arg(long, default_value = DEFAULT_LOG_FILE)]
        log_file: PathBuf,

        #[arg(long)]
        json: bool,
    },

    PolicyApply {
        #[arg(long)]
        suggestions: PathBuf,

        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        #[arg(long, conflicts_with = "force")]
        dry_run: bool,

        #[arg(long, conflicts_with = "dry_run")]
        force: bool,
    },

    TestAccess {
        target_path: PathBuf,

        #[arg(long, required_unless_present = "pid")]
        exe: Option<PathBuf>,

        #[arg(long, required_unless_present = "pid")]
        uid: Option<u32>,

        #[arg(long, conflicts_with_all = ["exe", "uid"])]
        pid: Option<u32>,

        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        log_file: Option<PathBuf>,
    },

    Logs {
        #[arg(long, default_value = DEFAULT_LOG_FILE)]
        log_file: PathBuf,

        #[arg(long)]
        last: Option<usize>,

        #[arg(long)]
        since: Option<String>,

        #[arg(long)]
        decision: Option<DecisionFilter>,

        #[arg(long)]
        follow: bool,

        #[arg(long)]
        json: bool,
    },

    Why {
        target: WhyTarget,

        #[arg(long, default_value = DEFAULT_LOG_FILE)]
        log_file: PathBuf,

        #[arg(long)]
        decision: Option<DecisionFilter>,

        #[arg(long)]
        json: bool,
    },

    PolicyReview {
        #[arg(long, default_value = DEFAULT_LOG_FILE)]
        log_file: PathBuf,

        #[arg(long, default_value_t = 1)]
        min_events: usize,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        toml: bool,

        #[arg(long)]
        write_suggestions: Option<PathBuf>,

        #[arg(long)]
        force: bool,
    },

    InspectProcess {
        pid: u32,
    },

    Status {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        #[arg(long)]
        json: bool,
    },

    Setup {
        #[arg(long, default_value = "generated-config.toml")]
        output: PathBuf,

        #[arg(long)]
        force: bool,

        #[arg(long)]
        interactive: bool,

        #[arg(long)]
        json: bool,
    },

    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum ServiceCommand {
    Status,
    Start,
    Stop,
    Restart,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_use_installed_paths() {
        assert_eq!(DEFAULT_CONFIG_PATH, "/etc/peperspray/config.toml");
        assert_eq!(DEFAULT_LOG_FILE, "/var/log/peperspray/events.jsonl");
    }
}
