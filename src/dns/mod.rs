pub mod answer_record;
pub mod class;
pub mod dns_message;
pub mod domain_name;
pub mod header;
pub mod question;
pub mod record_type;

// Re-export commonly used types for convenience
pub use answer_record::{DnsAnswerRecord, RData};
pub use class::Class;
pub use dns_message::DnsMessage;
pub use domain_name::DomainName;
pub use header::{DnsHeader, QRIndicator, ResponseCode};
pub use question::DnsQuestion;
pub use record_type::RecordType;
