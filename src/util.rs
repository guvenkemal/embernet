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
