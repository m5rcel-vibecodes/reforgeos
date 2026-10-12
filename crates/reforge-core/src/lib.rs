//! Local, evidence-preserving image and executable analysis.
pub mod binary;
pub mod config;
pub mod decompiler;
pub mod image;
pub mod project;
pub mod util;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Fault {
    #[error("UNSUPPORTED_FORMAT: {0}")]
    Unsupported(String),
    #[error("CORRUPTED_INPUT: {0}")]
    Corrupt(String),
    #[error("RESOURCE_LIMIT: {0}")]
    Limit(String),
    #[error("UNSAFE_PATH: {0}")]
    UnsafePath(String),
    #[error("MISSING_DEPENDENCY: {0}")]
    Dependency(String),
    #[error("BACKEND_FAILURE: {0}")]
    Backend(String),
    #[error("ANALYSIS_TIMEOUT: {0}")]
    Timeout(String),
    #[error("INVALID_CONFIGURATION: {0}")]
    Configuration(String),
    #[error("RECONSTRUCTION_BLOCKED: {0}")]
    Blocked(String),
}
