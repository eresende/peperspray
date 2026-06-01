use std::path::PathBuf;
use uuid::Uuid;

pub const DEFAULT_CONFIG_PATH: &str = "examples/config.toml";
pub const DEFAULT_LOG_FILE: &str = "./events.jsonl";

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
        event_id: Uuid,

        #[arg(long, default_value = DEFAULT_LOG_FILE)]
        log_file: PathBuf,

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
}
