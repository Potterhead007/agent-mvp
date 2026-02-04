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
}
