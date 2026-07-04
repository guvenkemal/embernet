use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn ensure_dir(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p)?;
    Ok(())
}

pub fn valid_channel(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '/' || c == '-')
        && !name.is_empty()
        && !name.starts_with('/')
        && !name.ends_with('/')
}

pub fn channel_to_path(base: &Path, name: &str) -> PathBuf {
    base.join("channels").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_channel_simple() {
        assert!(valid_channel("tech"));
        assert!(valid_channel("tech-linux"));
        assert!(valid_channel("tech/linux"));
        assert!(valid_channel("a/b/c"));
    }

    #[test]
    fn valid_channel_rejects_empty() {
        assert!(!valid_channel(""));
    }

    #[test]
    fn valid_channel_rejects_leading_slash() {
        assert!(!valid_channel("/tech"));
    }

    #[test]
    fn valid_channel_rejects_trailing_slash() {
        assert!(!valid_channel("tech/"));
    }

    #[test]
    fn valid_channel_rejects_uppercase() {
        assert!(!valid_channel("Tech"));
        assert!(!valid_channel("TECH"));
    }

    #[test]
    fn valid_channel_rejects_spaces() {
        assert!(!valid_channel("tech linux"));
    }

    #[test]
    fn valid_channel_rejects_special_characters() {
        assert!(!valid_channel("tech@linux"));
        assert!(!valid_channel("tech.linux"));
        assert!(!valid_channel("tech*linux"));
    }

    #[test]
    fn channel_to_path_nesting() {
        let base = Path::new("/data");
        let p = channel_to_path(base, "tech/linux");
        assert_eq!(p, PathBuf::from("/data/channels/tech/linux"));
    }
}
