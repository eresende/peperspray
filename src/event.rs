use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    OpenRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    pub uid: u32,
    pub exe: PathBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cmdline: Vec<String>,

    pub target_path: PathBuf,
    pub operation: Operation,
}
