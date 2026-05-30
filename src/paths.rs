use std::path::{Path, PathBuf};

pub fn normalize_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
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
}
