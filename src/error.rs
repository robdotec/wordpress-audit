//! Error types for wordpress-audit

use thiserror::Error;

/// Result type alias using our Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during WordPress audit operations
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid URL provided
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Failed to create HTTP client
    #[error("failed to create HTTP client: {0}")]
    HttpClient(String),

    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpRequest(String),

    /// HTTP response error status
    #[error("HTTP error: status {0}")]
    HttpStatus(u16),

    /// Site does not appear to be WordPress
    #[error("site does not appear to be WordPress")]
    NotWordPress,

    /// Invalid output format specified
    #[error("invalid output format: '{0}' (valid: human, json, none)")]
    InvalidOutputFormat(String),

    /// Invalid output detail level specified
    #[error("invalid output detail: '{0}' (valid: all, nok)")]
    InvalidOutputDetail(String),

    /// Invalid output sort order specified
    #[error("invalid output sort: '{0}' (valid: status, name)")]
    InvalidOutputSort(String),

    /// Output operation failed
    #[error("output failed: {0}")]
    OutputFailed(#[source] std::io::Error),

    /// JSON serialization failed
    #[error("JSON serialization failed")]
    SerializationFailed(#[from] serde_json::Error),
}
