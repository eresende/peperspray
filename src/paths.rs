use std::path::{Path, PathBuf};

pub fn normalize_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();

    if path_str == "~"
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home);
    }

    if let Some(rest) = path_str.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }

    path.to_path_buf()
}

pub fn expand_and_normalize_path(path: &Path) -> PathBuf {
    let expanded = expand_tilde(path);
    normalize_path(&expanded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_existing_path_uses_canonical_path() {
        let path = PathBuf::from(".");

        let normalized = normalize_path(&path);

        assert!(normalized.is_absolute());
    }

    #[test]
    fn normalize_missing_path_keeps_original_path() {
        let path = PathBuf::from("/definitely/missing/peperspray/path");

        let normalized = normalize_path(&path);

        assert_eq!(normalized, path);
    }

    #[test]
    fn expands_bare_tilde_to_home() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };

        let expanded = expand_tilde(Path::new("~"));

        assert_eq!(expanded, PathBuf::from(home));
    }

    #[test]
    fn expands_tilde_prefix_to_home_child() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };

        let expanded = expand_tilde(Path::new("~/.aws"));

        assert_eq!(expanded, PathBuf::from(home).join(".aws"));
    }

    #[test]
    fn leaves_non_tilde_path_unchanged() {
        let path = PathBuf::from("/home/alice/.aws");

        let expanded = expand_tilde(&path);

        assert_eq!(expanded, path);
    }
}
