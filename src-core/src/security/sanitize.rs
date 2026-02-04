pub fn sanitize_path(base: &str, requested: &str) -> Option<String> {
    let base_path = std::path::Path::new(base).canonicalize().ok()?;
    let full_path = base_path.join(requested);

    if let Ok(canonical) = full_path.canonicalize() {
        if canonical.starts_with(&base_path) {
            return Some(canonical.to_string_lossy().to_string());
        }
        return None;
    }

    let mut ancestor = full_path.as_path();
    loop {
        match ancestor.parent() {
            Some(parent) if parent != ancestor => {
                if let Ok(canonical_parent) = parent.canonicalize() {
                    if canonical_parent.starts_with(&base_path) {
                        let remainder = full_path.strip_prefix(parent).ok()?;
                        let safe = canonical_parent.join(remainder);
                        return Some(safe.to_string_lossy().to_string());
                    }
                    return None;
                }
                ancestor = parent;
            }
            _ => return None,
        }
    }
}

pub fn sanitize_shell_arg(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// Find the largest byte index <= `max_bytes` that sits on a UTF-8 char boundary.
/// Use this instead of `&s[..n]` to avoid panicking on multi-byte characters.
pub fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if max_bytes >= s.len() {
        return s;
    }
    let mut i = max_bytes;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

pub fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("ID cannot be empty".to_string());
    }
    if id.contains('/') || id.contains('\\') || id.contains("..") || id.starts_with('.') {
        return Err(format!("Invalid ID: {}", id));
    }
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(format!("ID contains invalid characters: {}", id));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn validate_id_accepts_normal_ids() {
        assert!(validate_id("my-agent").is_ok());
        assert!(validate_id("agent_01").is_ok());
        assert!(validate_id("Atlas").is_ok());
        assert!(validate_id("a").is_ok());
    }

    #[test]
    fn validate_id_rejects_empty() {
        assert!(validate_id("").is_err());
    }

    #[test]
    fn validate_id_rejects_path_traversal() {
        assert!(validate_id("../etc").is_err());
        assert!(validate_id("..").is_err());
        assert!(validate_id("foo/../bar").is_err());
    }

    #[test]
    fn validate_id_rejects_slashes() {
        assert!(validate_id("foo/bar").is_err());
        assert!(validate_id("foo\\bar").is_err());
        assert!(validate_id("/etc/passwd").is_err());
    }

    #[test]
    fn validate_id_rejects_dotfiles() {
        assert!(validate_id(".hidden").is_err());
        assert!(validate_id(".env").is_err());
    }

    #[test]
    fn validate_id_rejects_special_characters() {
        assert!(validate_id("foo bar").is_err());
        assert!(validate_id("foo;rm").is_err());
        assert!(validate_id("foo&bar").is_err());
        assert!(validate_id("$(cmd)").is_err());
    }

    #[test]
    fn sanitize_shell_arg_strips_dangerous_chars() {
        assert_eq!(sanitize_shell_arg("gateway"), "gateway");
        assert_eq!(sanitize_shell_arg("my-service_1"), "my-service_1");
        assert_eq!(sanitize_shell_arg("foo;rm -rf /"), "foorm-rf");
        assert_eq!(sanitize_shell_arg("$(whoami)"), "whoami");
        assert_eq!(sanitize_shell_arg("a b c"), "abc");
    }

    #[test]
    fn sanitize_shell_arg_strips_slashes() {
        assert_eq!(sanitize_shell_arg("../../etc/passwd"), "....etcpasswd");
        assert_eq!(sanitize_shell_arg("foo/bar"), "foobar");
    }

    #[test]
    fn sanitize_path_allows_valid_subpath() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let sub = base.join("agents").join("test");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("SOUL.md"), "test").unwrap();

        let result = sanitize_path(base.to_str().unwrap(), "agents/test/SOUL.md");
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.contains("agents/test/SOUL.md") || path.contains("agents\\test\\SOUL.md"));
    }

    #[test]
    fn sanitize_path_blocks_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("workspace");
        fs::create_dir_all(&base).unwrap();

        let result = sanitize_path(base.to_str().unwrap(), "../../../etc/passwd");
        assert!(result.is_none());
    }

    #[test]
    fn sanitize_path_allows_new_files_in_existing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let sub = base.join("agents").join("new-agent");
        fs::create_dir_all(&sub).unwrap();

        let result = sanitize_path(base.to_str().unwrap(), "agents/new-agent/SOUL.md");
        assert!(result.is_some());
    }

    #[test]
    fn sanitize_path_returns_none_for_nonexistent_base() {
        let result = sanitize_path("/nonexistent/base/path", "file.txt");
        assert!(result.is_none());
    }

    #[test]
    fn truncate_str_ascii() {
        assert_eq!(truncate_str("hello world", 5), "hello");
        assert_eq!(truncate_str("hi", 10), "hi");
        assert_eq!(truncate_str("", 5), "");
    }

    #[test]
    fn truncate_str_multibyte_does_not_panic() {
        // '€' is 3 bytes (E2 82 AC). Slicing at byte 1 or 2 would panic with &s[..n].
        let s = "€€€"; // 9 bytes
        assert_eq!(truncate_str(s, 3), "€");
        assert_eq!(truncate_str(s, 4), "€"); // backs up to byte 3
        assert_eq!(truncate_str(s, 5), "€"); // backs up to byte 3
        assert_eq!(truncate_str(s, 6), "€€");
        assert_eq!(truncate_str(s, 1), ""); // can't fit even one char
    }

    #[test]
    fn truncate_str_emoji() {
        let s = "🎉test"; // 🎉 is 4 bytes
        assert_eq!(truncate_str(s, 4), "🎉");
        assert_eq!(truncate_str(s, 3), ""); // can't split the emoji
        assert_eq!(truncate_str(s, 8), "🎉test");
    }
}
