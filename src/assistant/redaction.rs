use crate::assistant::config::RedactionMode;
use regex::Regex;
use std::path::{Path, PathBuf};

pub fn redact_string(value: &str, mode: RedactionMode) -> String {
    match mode {
        RedactionMode::None => value.to_string(),
        RedactionMode::Strict | RedactionMode::Balanced => redact_secrets(&redact_home(value)),
    }
}

pub fn redact_path(path: &Path, mode: RedactionMode, protected_group: Option<&str>) -> String {
    match mode {
        RedactionMode::None => path.display().to_string(),
        RedactionMode::Strict => protected_group
            .map(|group| format!("<protected:{group}>"))
            .unwrap_or_else(|| path_basename(path)),
        RedactionMode::Balanced => redact_home(&path.display().to_string()),
    }
}

pub fn redact_exe(path: &Path, mode: RedactionMode) -> String {
    match mode {
        RedactionMode::Strict => path_basename(path),
        RedactionMode::Balanced => redact_home(&path.display().to_string()),
        RedactionMode::None => path.display().to_string(),
    }
}

pub fn redact_cmdline(values: &[String], mode: RedactionMode) -> Vec<String> {
    match mode {
        RedactionMode::Strict => values
            .first()
            .map(|value| vec![path_basename(Path::new(value))])
            .unwrap_or_default(),
        RedactionMode::Balanced => values
            .iter()
            .map(|value| redact_string(value, mode))
            .collect(),
        RedactionMode::None => values.to_vec(),
    }
}

fn path_basename(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

fn redact_home(value: &str) -> String {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return value.to_string();
    };

    let home = home.to_string_lossy();
    if home.is_empty() {
        return value.to_string();
    }

    value.replace(home.as_ref(), "~")
}

fn redact_secrets(value: &str) -> String {
    let replacements = [
        (
            r"(?i)\bAWS_ACCESS_KEY_ID\s*=\s*([^\s]+)",
            "AWS_ACCESS_KEY_ID=<redacted:aws_access_key_id>",
        ),
        (
            r"(?i)\bAWS_SECRET_ACCESS_KEY\s*=\s*([^\s]+)",
            "AWS_SECRET_ACCESS_KEY=<redacted:aws_secret_access_key>",
        ),
        (
            r"(?i)\bAWS_SESSION_TOKEN\s*=\s*([^\s]+)",
            "AWS_SESSION_TOKEN=<redacted:aws_session_token>",
        ),
        (
            r"(?i)\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN)\s*=\s*([^\s]+)",
            "$1=<redacted:token>",
        ),
        (
            r"(?i)\b([A-Z0-9_]*(TOKEN|SECRET|PASSWORD))\s*=\s*([^\s]+)",
            "$1=<redacted:token>",
        ),
        (
            r"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._~+/=-]+)",
            "Authorization: Bearer <redacted:token>",
        ),
        (
            r"https://([^/\s:@]+):([^/\s@]+)@",
            "https://<redacted:userinfo>@",
        ),
    ];

    let mut output = value.to_string();
    for (pattern, replacement) in replacements {
        let regex = Regex::new(pattern).expect("redaction regex should compile");
        output = regex.replace_all(&output, replacement).to_string();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secret_assignments() {
        let value = "AWS_SECRET_ACCESS_KEY=abc GITHUB_TOKEN=def DB_PASSWORD=hunter2";
        let redacted = redact_string(value, RedactionMode::Balanced);

        assert!(redacted.contains("<redacted:aws_secret_access_key>"));
        assert!(redacted.contains("GITHUB_TOKEN=<redacted:token>"));
        assert!(redacted.contains("DB_PASSWORD=<redacted:token>"));
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn redacts_bearer_tokens_and_url_userinfo() {
        let value = "Authorization: Bearer abc.def https://user:pass@example.com/path";
        let redacted = redact_string(value, RedactionMode::Balanced);

        assert!(redacted.contains("Authorization: Bearer <redacted:token>"));
        assert!(redacted.contains("https://<redacted:userinfo>@example.com/path"));
    }

    #[test]
    fn strict_path_uses_protected_group() {
        let redacted = redact_path(
            Path::new("/home/alice/.aws/credentials"),
            RedactionMode::Strict,
            Some("aws"),
        );

        assert_eq!(redacted, "<protected:aws>");
    }

    #[test]
    fn none_keeps_raw_value() {
        let raw = "AWS_SECRET_ACCESS_KEY=abc";

        assert_eq!(redact_string(raw, RedactionMode::None), raw);
    }
}
