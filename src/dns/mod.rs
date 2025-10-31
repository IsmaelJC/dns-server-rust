/// DNS protocol types and utilities
///
/// This module contains all DNS-related data structures and serialization logic.
pub mod header;

// Re-export commonly used types for convenience
pub use header::{DnsHeader, QRIndicator};
