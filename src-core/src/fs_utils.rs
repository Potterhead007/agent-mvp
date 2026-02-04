use std::fs;
use std::path::Path;

pub fn atomic_write(path: &Path, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content).map_err(|e| format!("Failed to write tmp: {}", e))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("Failed to rename tmp to target: {}", e)
    })
}

/// Atomic write with 0o600 permissions on Unix. Use for files containing
/// secrets (vault locks, .env, config with tokens).
///
/// Permissions are set on the temp file *before* the rename so the
/// target path is never visible with default (world-readable) bits.
pub fn atomic_write_secure(path: &Path, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content).map_err(|e| format!("Failed to write tmp: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("Failed to set permissions on {}: {}", tmp.display(), e)
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("Failed to rename tmp to target: {}", e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.json");
        atomic_write(&path, r#"{"test": true}"#).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("test"));
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn atomic_write_replaces_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.json");
        fs::write(&path, "old").unwrap();
        atomic_write(&path, "new").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn atomic_write_secure_sets_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secret.json");
        super::atomic_write_secure(&path, r#"{"key": "secret"}"#).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("secret"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
