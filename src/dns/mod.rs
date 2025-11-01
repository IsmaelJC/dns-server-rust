pub mod class;
pub mod header;
pub mod question;
pub mod record_type;

// Re-export commonly used types for convenience
pub use class::Class;
pub use header::{DnsHeader, QRIndicator, ResponseCode};
pub use question::{DnsQuestion, DomainName};
pub use record_type::RecordType;
