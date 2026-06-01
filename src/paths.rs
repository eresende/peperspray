use std::path::{Path, PathBuf};

pub fn normalize_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return path.to_path_buf();
    };

    expand_tilde_with_home(path, &home)
}

pub fn expand_tilde_with_home(path: &Path, home: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();

    if path_str == "~" {
        return home.to_path_buf();
    }

    if let Some(rest) = path_str.strip_prefix("~/") {
        return home.join(rest);
    }

    path.to_path_buf()
}

pub fn is_tilde_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    path_str == "~" || path_str.starts_with("~/")
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

    #[test]
    fn normalize_symlink_uses_target_path() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let target = dir.path().join("target");
        let link = dir.path().join("link");

        std::fs::write(&target, "secret").expect("target should be written");
        std::os::unix::fs::symlink(&target, &link).expect("symlink should be created");

        let normalized = normalize_path(&link);

        assert_eq!(normalized, target);
    }
}
