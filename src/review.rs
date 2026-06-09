use crate::event::Operation;
use crate::identity;
use crate::logging;
use crate::{config, paths};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReviewCandidateKey {
    uid: u32,
    exe: PathBuf,
    path_group: String,
    parent_exe: Option<PathBuf>,
}

#[derive(Debug)]
pub struct ReviewCandidate {
    key: ReviewCandidateKey,
    event_count: usize,
}

impl ReviewCandidate {
    pub fn uid(&self) -> u32 {
        self.key.uid
    }

    pub fn exe(&self) -> &Path {
        &self.key.exe
    }

    pub fn path_group(&self) -> &str {
        &self.key.path_group
    }

    pub fn parent_exe(&self) -> Option<&Path> {
        self.key.parent_exe.as_deref()
    }

    pub fn event_count(&self) -> usize {
        self.event_count
    }
}

#[derive(Debug, Serialize)]
struct ReviewCandidateOutput {
    uid: u32,
    exe: PathBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    exe_sha256: Option<String>,

    path_group: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    parent_exe: Option<PathBuf>,

    event_count: usize,
    suggested_name: String,
}

pub fn build_review_candidates(logs: &[logging::OwnedDecisionLog]) -> Vec<ReviewCandidate> {
    let mut counts: std::collections::HashMap<ReviewCandidateKey, usize> =
        std::collections::HashMap::new();

    for log in logs {
        if !log.would_deny {
            continue;
        }

        let Some(path_group) = &log.matched_path_group else {
            continue;
        };

        let key = ReviewCandidateKey {
            uid: log.uid,
            exe: log.exe.clone(),
            path_group: path_group.clone(),
            parent_exe: immediate_parent_exe(log),
        };

        *counts.entry(key).or_insert(0) += 1;
    }

    let mut candidates: Vec<ReviewCandidate> = counts
        .into_iter()
        .map(|(key, event_count)| ReviewCandidate { key, event_count })
        .collect();

    candidates.sort_by(|a, b| {
        b.event_count
            .cmp(&a.event_count)
            .then_with(|| a.key.exe.cmp(&b.key.exe))
            .then_with(|| a.key.path_group.cmp(&b.key.path_group))
    });

    candidates
}

pub fn print_review_candidates(candidates: &[ReviewCandidate]) {
    if candidates.is_empty() {
        println!("No learn-mode would-deny events found.");
        return;
    }

    println!("Candidate allow rules from learned accesses:");
    println!();

    for (index, candidate) in candidates.iter().enumerate() {
        println!(
            "{}. Allow {} to access {}",
            index + 1,
            candidate.key.exe.display(),
            candidate.key.path_group
        );
        println!("   uid:        {}", candidate.key.uid);
        println!("   exe:        {}", candidate.key.exe.display());
        println!("   path_group: {}", candidate.key.path_group);
        println!(
            "   parent_exe: {}",
            candidate
                .key
                .parent_exe
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string())
        );
        println!("   events:     {}", candidate.event_count);
        println!();

        print_candidate_toml(candidate);
        println!();
    }
}

pub fn filter_candidates_by_min_events(
    candidates: Vec<ReviewCandidate>,
    min_events: usize,
) -> Vec<ReviewCandidate> {
    candidates
        .into_iter()
        .filter(|candidate| candidate.event_count >= min_events)
        .collect()
}

fn executable_name(exe: &Path) -> String {
    exe.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

pub fn suggested_allow_rule_name(candidate: &ReviewCandidate) -> String {
    match &candidate.key.parent_exe {
        Some(parent_exe) => format!(
            "Allow {} to access {} from {}",
            executable_name(&candidate.key.exe),
            candidate.key.path_group,
            executable_name(parent_exe)
        ),
        None => format!(
            "Allow {} to access {}",
            executable_name(&candidate.key.exe),
            candidate.key.path_group
        ),
    }
}

fn print_candidate_toml(candidate: &ReviewCandidate) {
    println!("   Suggested TOML:");

    for line in candidate_to_toml(candidate).lines() {
        println!("   {line}");
    }
}

fn review_candidate_to_output(candidate: &ReviewCandidate) -> ReviewCandidateOutput {
    ReviewCandidateOutput {
        uid: candidate.key.uid,
        exe: candidate.key.exe.clone(),
        exe_sha256: candidate_exe_sha256(candidate),
        path_group: candidate.key.path_group.clone(),
        parent_exe: candidate.key.parent_exe.clone(),
        event_count: candidate.event_count,
        suggested_name: suggested_allow_rule_name(candidate),
    }
}

fn review_candidates_to_output(candidates: &[ReviewCandidate]) -> Vec<ReviewCandidateOutput> {
    candidates.iter().map(review_candidate_to_output).collect()
}

pub fn review_candidates_to_json(candidates: &[ReviewCandidate]) -> anyhow::Result<String> {
    let output = review_candidates_to_output(candidates);
    Ok(serde_json::to_string_pretty(&output)?)
}

pub fn print_review_candidates_json(candidates: &[ReviewCandidate]) -> anyhow::Result<()> {
    println!("{}", review_candidates_to_json(candidates)?);
    Ok(())
}

pub fn candidate_to_toml(candidate: &ReviewCandidate) -> String {
    let mut toml = format!(
        "[[allow_rules]]\nname = \"{}\"\nuid = {}\nexe = \"{}\"",
        suggested_allow_rule_name(candidate),
        candidate.key.uid,
        candidate.key.exe.display()
    );

    if let Some(exe_sha256) = candidate_exe_sha256(candidate) {
        toml.push_str(&format!("\nexe_sha256 = \"{exe_sha256}\""));
    }

    toml.push_str(&format!(
        "\npath_group = \"{}\"\noperation = \"{}\"",
        candidate.key.path_group,
        Operation::OpenRead
    ));

    if let Some(parent_exe) = &candidate.key.parent_exe {
        toml.push_str(&format!("\nparent_exe = \"{}\"", parent_exe.display()));
    }

    toml
}

fn candidate_exe_sha256(candidate: &ReviewCandidate) -> Option<String> {
    identity::file_sha256(&candidate.key.exe).ok()
}

pub fn review_candidates_to_toml(candidates: &[ReviewCandidate]) -> String {
    candidates
        .iter()
        .map(candidate_to_toml)
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub fn print_review_candidates_toml(candidates: &[ReviewCandidate]) {
    let toml = review_candidates_to_toml(candidates);

    if !toml.is_empty() {
        println!("{toml}");
    }
}

pub fn write_review_suggestions(
    path: &Path,
    candidates: &[ReviewCandidate],
    force: bool,
) -> anyhow::Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; use --force to overwrite it",
            path.display()
        );
    }

    let toml = review_candidates_to_toml(candidates);

    std::fs::write(path, toml)?;

    Ok(())
}

pub fn apply_review_suggestions(
    config_path: &Path,
    suggestions_path: &Path,
    dry_run: bool,
    force: bool,
) -> anyhow::Result<usize> {
    if dry_run == force {
        anyhow::bail!("choose exactly one of --dry-run or --force");
    }

    let mut document: toml::Value = toml::from_str(&std::fs::read_to_string(config_path)?)?;
    let suggestions: toml::Value = toml::from_str(&std::fs::read_to_string(suggestions_path)?)?;
    let suggested_rules = suggestions
        .get("allow_rules")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if suggested_rules.is_empty() {
        return Ok(0);
    }

    let existing_rules = document
        .get("allow_rules")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut merged_rules = existing_rules.clone();
    for rule in &suggested_rules {
        if !merged_rules
            .iter()
            .any(|existing| same_allow_rule(existing, rule))
        {
            merged_rules.push(rule.clone());
        }
    }

    let added = merged_rules.len().saturating_sub(existing_rules.len());
    document["allow_rules"] = toml::Value::Array(merged_rules);

    let parsed_config: config::Config = document.clone().try_into()?;
    let errors = config::validate_config(&parsed_config);
    if !errors.is_empty() {
        anyhow::bail!("merged config is invalid: {}", errors.join("; "));
    }

    if force && added > 0 {
        let backup_path = config::backup_path_for_config(config_path);
        std::fs::copy(config_path, &backup_path)?;
        let temp_path = config_path.with_file_name(format!(
            "{}.tmp",
            config_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("config.toml")
        ));
        std::fs::write(&temp_path, toml::to_string_pretty(&document)?)?;
        std::fs::rename(&temp_path, config_path)?;
    }

    Ok(added)
}

fn same_allow_rule(left: &toml::Value, right: &toml::Value) -> bool {
    let Some(left) = left.as_table() else {
        return false;
    };
    let Some(right) = right.as_table() else {
        return false;
    };

    let keys = [
        "uid",
        "exe",
        "exe_sha256",
        "path_group",
        "parent_exe",
        "operation",
    ];

    keys.iter()
        .all(|key| normalized_rule_value(left.get(*key)) == normalized_rule_value(right.get(*key)))
}

fn normalized_rule_value(value: Option<&toml::Value>) -> Option<String> {
    match value {
        Some(toml::Value::String(path)) if path.starts_with('/') || path.starts_with('~') => Some(
            paths::expand_and_normalize_path(Path::new(path))
                .to_string_lossy()
                .to_string(),
        ),
        Some(value) => Some(value.to_string()),
        None => None,
    }
}

pub fn allow_rule_count_text(count: usize) -> String {
    match count {
        1 => "1 suggested allow rule".to_string(),
        n => format!("{n} suggested allow rules"),
    }
}

fn immediate_parent_exe(log: &logging::OwnedDecisionLog) -> Option<PathBuf> {
    log.parent_chain
        .first()
        .and_then(|parent| parent.exe.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn fake_log(index: usize) -> logging::OwnedDecisionLog {
        logging::OwnedDecisionLog {
            schema_version: 2,
            platform: Some("linux".to_string()),
            backend: Some("fanotify".to_string()),
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            pid: None,
            uid: 1000,
            exe: PathBuf::from(format!("/usr/bin/tool-{index}")),
            cwd: None,
            cmdline: Vec::new(),
            parent_chain: Vec::new(),
            target_path: PathBuf::from(format!("/tmp/file-{index}")),
            operation: Operation::OpenRead,
            decision: "allow".to_string(),
            reason: "test".to_string(),
            matched_path_group: None,
            would_deny: false,
        }
    }

    #[test]
    fn build_review_candidates_groups_matching_events() {
        let mut logs = [fake_log(1), fake_log(2), fake_log(3)];

        logs[0].exe = PathBuf::from("/usr/bin/python3");
        logs[0].would_deny = true;
        logs[0].matched_path_group = Some("aws".to_string());

        logs[1].exe = PathBuf::from("/usr/bin/python3");
        logs[1].would_deny = true;
        logs[1].matched_path_group = Some("aws".to_string());

        logs[2].exe = PathBuf::from("/usr/bin/git");
        logs[2].would_deny = true;
        logs[2].matched_path_group = Some("ssh".to_string());

        let candidates = build_review_candidates(&logs);

        assert_eq!(candidates.len(), 2);

        assert_eq!(candidates[0].key.exe, PathBuf::from("/usr/bin/python3"));
        assert_eq!(candidates[0].key.path_group, "aws");
        assert_eq!(candidates[0].event_count, 2);

        assert_eq!(candidates[1].key.exe, PathBuf::from("/usr/bin/git"));
        assert_eq!(candidates[1].key.path_group, "ssh");
        assert_eq!(candidates[1].event_count, 1);
    }

    #[test]
    fn review_candidate_to_output_adds_suggested_name() {
        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: None,
            },
            event_count: 2,
        };

        let output = review_candidate_to_output(&candidate);

        assert_eq!(output.uid, 1000);
        assert_eq!(output.exe, PathBuf::from("/usr/bin/python3"));
        assert_eq!(output.path_group, "aws");
        assert_eq!(output.event_count, 2);
        assert_eq!(output.suggested_name, "Allow python3 to access aws");
    }

    #[test]
    fn review_candidates_to_json_array() {
        let candidates = [ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: None,
            },
            event_count: 1,
        }];

        let json =
            review_candidates_to_json(&candidates).expect("review candidates should serialize");

        assert!(json.starts_with("["));
        assert!(json.contains("\"uid\": 1000"));
        assert!(json.contains("\"path_group\": \"aws\""));
        assert!(json.contains("\"suggested_name\": \"Allow python3 to access aws\""));
    }

    #[test]
    fn filter_candidates_by_min_events_removes_low_frequency_candidates() {
        let candidates = vec![
            ReviewCandidate {
                key: ReviewCandidateKey {
                    uid: 1000,
                    exe: PathBuf::from("/usr/bin/python3"),
                    path_group: "aws".to_string(),
                    parent_exe: None,
                },
                event_count: 1,
            },
            ReviewCandidate {
                key: ReviewCandidateKey {
                    uid: 1000,
                    exe: PathBuf::from("/usr/bin/git"),
                    path_group: "ssh".to_string(),
                    parent_exe: None,
                },
                event_count: 3,
            },
        ];

        let candidates = filter_candidates_by_min_events(candidates, 2);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].key.exe, PathBuf::from("/usr/bin/git"));
    }

    #[test]
    fn candidate_to_toml_outputs_allow_rule_snippet() {
        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: None,
            },
            event_count: 1,
        };

        let toml = candidate_to_toml(&candidate);

        assert!(toml.contains("[[allow_rules]]"));
        assert!(toml.contains("name = \"Allow python3 to access aws\""));
        assert!(toml.contains("uid = 1000"));
        assert!(toml.contains("exe = \"/usr/bin/python3\""));
        assert!(toml.contains("path_group = \"aws\""));
        assert!(toml.contains("operation = \"open_read\""));
    }

    #[test]
    fn candidate_to_toml_includes_exe_sha256_when_executable_is_readable() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let exe = dir.path().join("tool");
        std::fs::write(&exe, "trusted tool").expect("exe should be written");

        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: exe.clone(),
                path_group: "aws".to_string(),
                parent_exe: None,
            },
            event_count: 1,
        };

        let hash = identity::file_sha256(&exe).expect("exe should hash");
        let toml = candidate_to_toml(&candidate);

        assert!(toml.contains(&format!("exe = \"{}\"", exe.display())));
        assert!(toml.contains(&format!("exe_sha256 = \"{hash}\"")));
    }

    #[test]
    fn review_candidates_to_toml_separates_multiple_rules() {
        let candidates = [
            ReviewCandidate {
                key: ReviewCandidateKey {
                    uid: 1000,
                    exe: PathBuf::from("/usr/bin/python3"),
                    path_group: "aws".to_string(),
                    parent_exe: None,
                },
                event_count: 1,
            },
            ReviewCandidate {
                key: ReviewCandidateKey {
                    uid: 1000,
                    exe: PathBuf::from("/usr/bin/git"),
                    path_group: "ssh".to_string(),
                    parent_exe: None,
                },
                event_count: 1,
            },
        ];

        let toml = review_candidates_to_toml(&candidates);

        assert!(toml.contains("name = \"Allow python3 to access aws\""));
        assert!(toml.contains("name = \"Allow git to access ssh\""));
        assert!(toml.contains("\n\n[[allow_rules]]"));
    }

    #[test]
    fn allow_rule_count_text_handles_singular() {
        assert_eq!(allow_rule_count_text(1), "1 suggested allow rule");
    }

    #[test]
    fn allow_rule_count_text_handles_plural() {
        assert_eq!(allow_rule_count_text(0), "0 suggested allow rules");
        assert_eq!(allow_rule_count_text(2), "2 suggested allow rules");
    }

    #[test]
    fn write_review_suggestions_writes_toml_file() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("suggested-rules.toml");

        let candidates = [ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: None,
            },
            event_count: 1,
        }];

        write_review_suggestions(&path, &candidates, false).expect("suggestions should be written");

        let contents = std::fs::read_to_string(&path).expect("suggestions should be readable");

        assert!(contents.contains("[[allow_rules]]"));
        assert!(contents.contains("name = \"Allow python3 to access aws\""));
    }

    #[test]
    fn write_review_suggestions_refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("suggested-rules.toml");

        let candidates = [ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: None,
            },
            event_count: 1,
        }];

        write_review_suggestions(&path, &candidates, false).expect("first write should succeed");

        let result = write_review_suggestions(&path, &candidates, false);

        assert!(result.is_err());
    }

    #[test]
    fn write_review_suggestions_overwrites_with_force() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("suggested-rules.toml");

        let candidates = [ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: None,
            },
            event_count: 1,
        }];

        std::fs::write(&path, "old content").expect("initial file should be written");

        write_review_suggestions(&path, &candidates, true).expect("force write should succeed");

        let contents = std::fs::read_to_string(&path).expect("suggestions should be readable");

        assert!(contents.contains("[[allow_rules]]"));
        assert!(!contents.contains("old contents"));
    }

    #[test]
    fn suggested_allow_rule_name_includes_parent_when_present() {
        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: Some(PathBuf::from("/usr/bin/zsh")),
            },
            event_count: 1,
        };

        let name = suggested_allow_rule_name(&candidate);

        assert_eq!(name, "Allow python3 to access aws from zsh");
    }

    #[test]
    fn candidate_to_toml_includes_parent_exe_when_present() {
        let candidate = ReviewCandidate {
            key: ReviewCandidateKey {
                uid: 1000,
                exe: PathBuf::from("/usr/bin/python3"),
                path_group: "aws".to_string(),
                parent_exe: Some(PathBuf::from("/usr/bin/zsh")),
            },
            event_count: 1,
        };

        let toml = candidate_to_toml(&candidate);

        assert!(toml.contains("parent_exe = \"/usr/bin/zsh\""));
        assert!(toml.contains("name = \"Allow python3 to access aws from zsh\""));
        assert!(toml.contains("operation = \"open_read\""));
    }

    #[test]
    fn immediate_parent_exe_returns_first_parent_exe() {
        let mut log = fake_log(1);

        log.parent_chain = vec![
            crate::process::ProcessChainEntry {
                pid: 2000,
                ppid: Some(1000),
                uid: 1000,
                exe: Some(PathBuf::from("/usr/bin/zsh")),
                cmdline: Vec::new(),
            },
            crate::process::ProcessChainEntry {
                pid: 1000,
                ppid: Some(1),
                uid: 1000,
                exe: Some(PathBuf::from("/usr/lib/systemd/systemd")),
                cmdline: Vec::new(),
            },
        ];

        assert_eq!(
            immediate_parent_exe(&log),
            Some(PathBuf::from("/usr/bin/zsh"))
        );
    }
}
