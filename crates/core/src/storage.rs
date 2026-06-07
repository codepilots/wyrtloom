/// Shared storage utilities used by SQLite plugins.
use std::path::Path;

/// Reject any path that contains a `..` (ParentDir) component,
/// preventing directory-traversal attacks on database file paths.
/// Both SQLite plugins import this rather than duplicating the check.
pub fn validate_db_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    for component in p.components() {
        use std::path::Component;
        if matches!(component, Component::ParentDir) {
            return Err(format!("path traversal not allowed: {}", path));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_path_is_accepted() {
        assert!(validate_db_path("/tmp/test.db").is_ok());
        assert!(validate_db_path("data/app.db").is_ok());
    }

    #[test]
    fn parent_component_is_rejected() {
        assert!(validate_db_path("../etc/passwd").is_err());
        assert!(validate_db_path("/tmp/../etc/shadow").is_err());
    }

    // A filename that merely contains ".." (e.g. "..hidden") is NOT a ParentDir
    // component, so it is correctly allowed — only real `..` traversal is rejected.
    #[test]
    fn dotdot_within_filename_is_allowed() {
        assert!(validate_db_path("/tmp/..hidden").is_ok());
    }
}
