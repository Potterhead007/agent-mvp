use chrono::Utc;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const MAX_LOG_SIZE: u64 = 5 * 1024 * 1024;
const MAX_ROTATED_COPIES: u32 = 3;

fn maybe_rotate(path: &str) {
    let p = Path::new(path);
    if let Ok(meta) = fs::metadata(p) {
        if meta.len() >= MAX_LOG_SIZE {
            // Shift existing rotated files: .2 → .3, .1 → .2
            for i in (1..MAX_ROTATED_COPIES).rev() {
                let from = format!("{}.{}", path, i);
                let to = format!("{}.{}", path, i + 1);
                let _ = fs::rename(&from, &to);
            }
            let rotated = format!("{}.1", path);
            let _ = fs::rename(p, &rotated);
        }
    }
}

pub fn log_action(audit_path: &str, action: &str, details: &str) {
    maybe_rotate(audit_path);

    let timestamp = Utc::now().to_rfc3339();
    let entry = format!("[{}] {} | {}\n", timestamp, action, details);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)
    {
        let _ = file.write_all(entry.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_action_creates_file_and_appends() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("test_audit.log");
        let log_str = log_path.to_str().unwrap();

        log_action(log_str, "TEST_ACTION", "did something");
        log_action(log_str, "ANOTHER", "more stuff");

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("TEST_ACTION"));
        assert!(lines[0].contains("did something"));
        assert!(lines[1].contains("ANOTHER"));
    }

    #[test]
    fn log_action_format_is_parseable() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("test_audit.log");
        let log_str = log_path.to_str().unwrap();

        log_action(log_str, "VAULT_STORE", "Stored credential: MY_KEY");

        let content = std::fs::read_to_string(&log_path).unwrap();
        let line = content.lines().next().unwrap();

        // Verify format: [timestamp] ACTION | details
        assert!(line.starts_with('['));
        assert!(line.contains("] VAULT_STORE | Stored credential: MY_KEY"));
    }
}
