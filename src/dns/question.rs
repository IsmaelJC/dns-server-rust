/// DNS Record Types as defined in RFC 1035 section 3.2.2.
///
/// This enum represents the TYPE field in a DNS question or resource record, specifying
/// the kind of resource being queried or provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
}

impl RecordType {
    fn new(packet: &[u8], domain_name_len: usize) -> Result<Self, ()> {
        match (packet.get(domain_name_len), packet.get(domain_name_len + 1)) {
            (Some(first_byte), Some(second_byte)) => {
                RecordType::try_from(u16::from_be_bytes([*first_byte, *second_byte]))
            }
            _ => Err(()),
        }
    }
}

impl TryFrom<u16> for RecordType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            3 => Ok(RecordType::MD),
            4 => Ok(RecordType::MF),
            5 => Ok(RecordType::CNAME),
            6 => Ok(RecordType::SOA),
            7 => Ok(RecordType::MB),
            8 => Ok(RecordType::MG),
            9 => Ok(RecordType::MR),
            10 => Ok(RecordType::NULL),
            11 => Ok(RecordType::WKS),
            12 => Ok(RecordType::PTR),
            13 => Ok(RecordType::HINFO),
            14 => Ok(RecordType::MINFO),
            15 => Ok(RecordType::MX),
            16 => Ok(RecordType::TXT),
            _ => Err(()),
        }
    }
}

/// DNS Class types as defined in RFC 1035 section 3.2.4.
///
/// This enum represents the CLASS field in a DNS question or resource record,
/// indicating the protocol family (such as Internet, Chaos, etc.) being used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl Class {
    fn new(packet: &[u8], domain_name_len: usize) -> Result<Self, ()> {
        match (
            packet.get(domain_name_len + 2),
            packet.get(domain_name_len + 3),
        ) {
            (Some(first_byte), Some(second_byte)) => {
                Class::try_from(u16::from_be_bytes([*first_byte, *second_byte]))
            }
            _ => Err(()),
        }
    }
}

impl TryFrom<u16> for Class {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Class::IN),
            2 => Ok(Class::CS),
            3 => Ok(Class::CH),
            4 => Ok(Class::HS),
            _ => Err(()),
        }
    }
}

/// Represents a DNS domain name in both wire (binary) format and string (dot-separated label) format.
///
/// The `wire_format` field holds the domain as it appears in a DNS packet, using length-prefixed labels.
/// The `label_segments` field is a vector of label segments as strings, such as `["www", "example", "com"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainName {
    pub wire_format: Vec<u8>,
    pub label_segments: Vec<String>,
}

impl DomainName {
    fn new(packet: &[u8]) -> Result<Self, ()> {
        if packet.is_empty() {
            return Err(());
        }

        let mut wire_format: Vec<u8> = Vec::new();
        let mut label_segments: Vec<String> = Vec::new();

        let mut current_label_length: Option<usize> = None;
        let mut current_label = String::new();

        for byte in packet.iter() {
            match current_label_length {
                None => {
                    wire_format.push(*byte);

                    if *byte == 0 {
                        break;
                    }

                    current_label_length = Some(usize::from(*byte));
                }
                Some(n) => {
                    current_label.push(char::from(*byte));

                    if current_label.len() == n {
                        label_segments.push(current_label.clone());
                        current_label.clear();
                        current_label_length = None;
                    }
                }
            }
        }

        match (current_label_length, wire_format.last()) {
            (None, Some(0)) => Ok(DomainName {
                wire_format,
                label_segments,
            }),
            _ => Err(()),
        }
    }
}

/// Represents a single DNS question section entry.
///
/// A DNS question specifies the query information in a DNS packet, including the domain name to look up,
/// the type of record being requested (such as A, NS, MX, etc.), and the class of the query (typically Internet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub domain_name: DomainName,
    pub record_type: RecordType,
    pub class: Class,
}

impl DnsQuestion {
    fn new(packet: &[u8]) -> Result<Self, ()> {
        DomainName::new(packet).and_then(|domain_name| {
            let domain_name_len = domain_name.wire_format.len();
            match (
                RecordType::new(packet, domain_name_len),
                Class::new(packet, domain_name_len),
            ) {
                (Ok(record_type), Ok(class)) => Ok(DnsQuestion {
                    domain_name,
                    record_type,
                    class,
                }),
                _ => Err(()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::try_from(1), Ok(RecordType::A));
        assert_eq!(RecordType::try_from(2), Ok(RecordType::NS));
        assert_eq!(RecordType::try_from(3), Ok(RecordType::MD));
        assert_eq!(RecordType::try_from(4), Ok(RecordType::MF));
        assert_eq!(RecordType::try_from(5), Ok(RecordType::CNAME));
        assert_eq!(RecordType::try_from(6), Ok(RecordType::SOA));
        assert_eq!(RecordType::try_from(7), Ok(RecordType::MB));
        assert_eq!(RecordType::try_from(8), Ok(RecordType::MG));
        assert_eq!(RecordType::try_from(9), Ok(RecordType::MR));
        assert_eq!(RecordType::try_from(10), Ok(RecordType::NULL));
        assert_eq!(RecordType::try_from(11), Ok(RecordType::WKS));
        assert_eq!(RecordType::try_from(12), Ok(RecordType::PTR));
        assert_eq!(RecordType::try_from(13), Ok(RecordType::HINFO));
        assert_eq!(RecordType::try_from(14), Ok(RecordType::MINFO));
        assert_eq!(RecordType::try_from(15), Ok(RecordType::MX));
        assert_eq!(RecordType::try_from(16), Ok(RecordType::TXT));
        // Test error case
        assert_eq!(RecordType::try_from(0), Err(()));
        assert_eq!(RecordType::try_from(17), Err(()));
        assert_eq!(RecordType::try_from(200), Err(()));
    }

    #[test]
    fn test_record_type_new() {
        // A simple test packet that is too short and should fail.
        let bad_packet = &[0x00, 0x01];
        assert_eq!(RecordType::new(bad_packet, 1), Err(()));

        let packet = &[
            // Start of some fake domain name (not relevant for this test)
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // end of name
            0x00, 0x01, // RecordType (e.g. 0x00, 0x01 for A)
            0x00, 0x01, // Class (e.g. 0x00, 0x01 for IN)
        ];

        // domain_name_len is position after domain name (should be 17 for above)
        let domain_name_len = 16;
        assert_eq!(RecordType::new(packet, domain_name_len), Ok(RecordType::A));
    }

    #[test]
    fn test_class_conversion() {
        assert_eq!(Class::try_from(1), Ok(Class::IN));
        assert_eq!(Class::try_from(2), Ok(Class::CS));
        assert_eq!(Class::try_from(3), Ok(Class::CH));
        assert_eq!(Class::try_from(4), Ok(Class::HS));
        // Test error case
        assert_eq!(Class::try_from(0), Err(()));
        assert_eq!(Class::try_from(5), Err(()));
        assert_eq!(Class::try_from(123), Err(()));
    }

    #[test]
    fn test_class_new() {
        // A simple test packet that is too short and should fail.
        let bad_packet = &[0x00, 0x01];
        assert_eq!(Class::new(bad_packet, 1), Err(()));

        let packet = &[
            // Start of some fake domain name (not relevant for this test)
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // end of name
            0x00, 0x01, // RecordType (e.g. 0x00, 0x01 for A)
            0x00, 0x01, // Class (e.g. 0x00, 0x01 for IN)
        ];

        // domain_name_len is position after domain name (should be 17 for above)
        let domain_name_len = 16;
        assert_eq!(Class::new(packet, domain_name_len), Ok(Class::IN));
    }

    #[test]
    fn domain_name_new() {
        let google_dot_com: &[u8] = &[
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];

        let domain_name_without_terminating_null_byte = &google_dot_com[..google_dot_com.len() - 1];

        // If the domain name buffer is empty, the parsing should fail
        assert_eq!(DomainName::new(&[]), Err(()));

        // If we remove the terminating null byte, the parsing should fail
        assert_eq!(
            DomainName::new(domain_name_without_terminating_null_byte),
            Err(())
        );

        // For correctly formed domain name buffer, parsing should succeed
        assert_eq!(
            DomainName::new(google_dot_com)
                .map(|domain_name| { domain_name.label_segments.join(".") }),
            Ok(String::from("google.com"))
        );

        // If we add additional bytes after terminating null byte, the result should remain the same
        assert_eq!(
            DomainName::new(&[google_dot_com, &[0x06, 0x67, 0x6f]].concat())
                .map(|domain_name| { domain_name.label_segments.join(".") }),
            Ok(String::from("google.com"))
        );
    }
}
