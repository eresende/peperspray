use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    OpenRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessEvent {
    pub uid: u32,
    pub exe: PathBuf,
    pub target_path: PathBuf,
    pub operation: Operation,
}
