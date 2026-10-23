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
    fn test_error_display_variants() {
        let err_no_if = Error::NoInterface;
        assert_eq!(err_no_if.to_string(), "no suitable network interface found");

        let err_inv_if = Error::InvalidInterface("eth99".into());
        assert_eq!(err_inv_if.to_string(), "invalid interface 'eth99'");

        let err_perm = Error::PermissionDenied;
        assert!(err_perm.to_string().contains("permission denied"));

        let err_other = Error::Other("custom issue".into());
        assert_eq!(err_other.to_string(), "custom issue");
    }

    #[test]
    fn test_error_io_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
        assert_eq!(err.to_string(), "I/O error: file missing");
    }

    #[test]
    fn test_error_pcap_conversion() {
        let pcap_err = pcap::Error::InvalidString;
        let err: Error = pcap_err.into();
        assert!(matches!(err, Error::Pcap(_)));
        assert!(err.to_string().contains("pcap error"));
    }
}
