use crate::process::ProcessChainEntry;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    OpenRead,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::OpenRead => write!(f, "open_read"),
        }
    }
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

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parent_chain: Vec<ProcessChainEntry>,

    pub target_path: PathBuf,
    pub operation: Operation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_display_uses_snake_case() {
        assert_eq!(Operation::OpenRead.to_string(), "open_read");
    }
}
