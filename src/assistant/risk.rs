use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RiskHint {
    pub level: &'static str,
    pub reason: String,
}

pub fn hints_for_access(exe: &Path, path_group: &str, event_count: Option<usize>) -> Vec<RiskHint> {
    let mut hints = Vec::new();
    let name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");

    if is_expected_tool(name, path_group) {
        hints.push(RiskHint {
            level: "low",
            reason: format!("{name} is an expected tool for protected group {path_group}"),
        });
    }

    if is_stable_system_path(exe) {
        hints.push(RiskHint {
            level: "low",
            reason: "executable is under a stable system binary directory".to_string(),
        });
    }

    if event_count.is_some_and(|count| count > 1) {
        hints.push(RiskHint {
            level: "low",
            reason: "access repeated across learned events".to_string(),
        });
    }

    if is_interpreter_or_shell(name) {
        hints.push(RiskHint {
            level: "medium",
            reason: format!("{name} is a broad interpreter or shell"),
        });
    }

    if is_editor_or_build_tool(name) {
        hints.push(RiskHint {
            level: "medium",
            reason: format!("{name} can execute project-controlled code or inspect broad files"),
        });
    }

    if is_writable_or_temp_path(exe) {
        hints.push(RiskHint {
            level: "high",
            reason: "executable is under a writable, temporary, or project dependency path"
                .to_string(),
        });
    }

    if is_sensitive_group(path_group) && !is_expected_tool(name, path_group) {
        hints.push(RiskHint {
            level: "high",
            reason: format!("{name} is not an expected tool for sensitive group {path_group}"),
        });
    }

    hints
}

fn is_expected_tool(name: &str, path_group: &str) -> bool {
    matches!(
        (name, path_group),
        ("aws", "aws")
            | ("ssh", "ssh")
            | ("scp", "ssh")
            | ("sftp", "ssh")
            | ("docker", "docker")
            | ("gh", "github")
            | ("gcloud", "gcloud")
    )
}

fn is_stable_system_path(path: &Path) -> bool {
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn is_interpreter_or_shell(name: &str) -> bool {
    matches!(
        name,
        "python" | "python3" | "node" | "ruby" | "perl" | "bash" | "sh" | "zsh"
    )
}

fn is_editor_or_build_tool(name: &str) -> bool {
    matches!(
        name,
        "code"
            | "vim"
            | "nvim"
            | "emacs"
            | "cargo"
            | "make"
            | "cmake"
            | "npm"
            | "pnpm"
            | "pip"
            | "go"
            | "mvn"
            | "gradle"
    )
}

fn is_writable_or_temp_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.starts_with("/tmp/")
        || text.starts_with("/var/tmp/")
        || text.contains("/target/")
        || text.contains("/node_modules/.bin/")
        || text.starts_with("/home/")
}

fn is_sensitive_group(path_group: &str) -> bool {
    matches!(
        path_group,
        "aws" | "ssh" | "wallet" | "wallets" | "browser" | "browsers" | "password_manager"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn expected_tool_gets_low_hint() {
        let hints = hints_for_access(&PathBuf::from("/usr/bin/aws"), "aws", Some(3));

        assert!(hints.iter().any(|hint| hint.level == "low"));
    }

    #[test]
    fn interpreter_gets_medium_hint() {
        let hints = hints_for_access(&PathBuf::from("/usr/bin/python3"), "aws", None);

        assert!(hints.iter().any(|hint| hint.level == "medium"));
    }

    #[test]
    fn temp_executable_gets_high_hint() {
        let hints = hints_for_access(&PathBuf::from("/tmp/tool"), "ssh", None);

        assert!(hints.iter().any(|hint| hint.level == "high"));
    }
}
