//! Privilege handling for non-root packet capture.
//!
//! Recommended (Linux):
//! ```bash
//! cargo build --release
//! sudo setcap cap_net_raw,cap_net_admin=eip target/release/riftop
//! ./target/release/riftop -i eth0
//! ```
//!
//! Running as root works but is discouraged after open; full setuid drop
//! requires `unsafe` and is intentionally not done in-tree while
//! `unsafe_code = forbid` remains project policy.

use std::io::{self, Write};

/// True if effective UID is 0 (Unix).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // libc::geteuid would need unsafe; use /proc instead
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    let parts: Vec<_> = rest.split_whitespace().collect();
                    // effective uid is the 2nd field (uid euid suid fsuid)
                    if parts.len() >= 2 {
                        return parts[1] == "0";
                    }
                }
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Log guidance when root or when capture may fail.
pub fn warn_if_root(stderr: &mut dyn Write) -> io::Result<()> {
    if is_root() {
        writeln!(
            stderr,
            "warning: running as root. Prefer:\n  sudo setcap cap_net_raw,cap_net_admin=eip $(which riftop)\n  and run as unprivileged user."
        )?;
    }
    Ok(())
}

/// Human-readable capability advice.
pub fn setcap_hint(binary: &str) -> String {
    format!("sudo setcap cap_net_raw,cap_net_admin=eip {binary}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_setcap_hint() {
        let hint = setcap_hint("riftop");
        assert_eq!(hint, "sudo setcap cap_net_raw,cap_net_admin=eip riftop");
    }

    #[test]
    fn test_is_root_execution_does_not_panic() {
        let _root = is_root();
    }

    #[test]
    fn test_warn_if_root_outputs_or_succeeds() {
        let mut buf = Vec::new();
        warn_if_root(&mut buf).unwrap();
        if is_root() {
            let output = String::from_utf8(buf).unwrap();
            assert!(output.contains("warning: running as root"));
        } else {
            assert!(buf.is_empty());
        }
    }
}
