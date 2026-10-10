//! Application error types.

use thiserror::Error;

/// Errors that can occur while running Riftop.
#[derive(Debug, Error)]
pub enum Error {
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("no suitable network interface found")]
    NoInterface,

    #[error("invalid interface '{0}'")]
    InvalidInterface(String),

    #[error("permission denied — Riftop needs root (or CAP_NET_RAW) to capture packets")]
    PermissionDenied,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_and_conversions() {
        let err_no_iface = Error::NoInterface;
        assert_eq!(
            err_no_iface.to_string(),
            "no suitable network interface found"
        );

        let err_invalid = Error::InvalidInterface("eth99".to_string());
        assert_eq!(err_invalid.to_string(), "invalid interface 'eth99'");

        let err_perm = Error::PermissionDenied;
        assert_eq!(
            err_perm.to_string(),
            "permission denied — Riftop needs root (or CAP_NET_RAW) to capture packets"
        );

        let err_other = Error::Other("custom error".to_string());
        assert_eq!(err_other.to_string(), "custom error");

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let converted: Error = io_err.into();
        assert!(converted.to_string().contains("I/O error"));
    }
}
