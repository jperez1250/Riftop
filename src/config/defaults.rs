//! Configuration defaults and file resolution paths.

use std::path::PathBuf;

/// Returns default interval in milliseconds (1000 ms = 1s).
pub fn default_interval_ms() -> u64 {
    1000
}

/// Returns default display lines count (20 lines).
pub fn default_lines() -> usize {
    20
}

/// Returns default aggregation mode ("pair").
pub fn default_aggregate() -> &'static str {
    "pair"
}

/// Returns default output mode ("tui").
pub fn default_output() -> &'static str {
    "tui"
}

/// Attempts to locate default config file (`$HOME/.config/riftop/config.toml`).
pub fn find_config_file() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".config/riftop/config.toml");
        if p.exists() {
            return Some(p);
        }
    }
    None
}
