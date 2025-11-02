use crate::dns::{domain_name, Class, DomainName, RecordType};

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
    pub fn new(packet: &[u8]) -> Result<Self, ()> {
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

    pub fn parse_and_return_next_slice(packet_slice: &[u8]) -> Result<(Self, &[u8]), ()> {
        let question = Self::new(packet_slice)?;
        let domain_name_len = question.domain_name.wire_format.len();

        Ok((question, &packet_slice[domain_name_len + 4..]))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let domain_name_bytes = self.domain_name.wire_format.clone();
        let record_type_bytes = (self.record_type as u16).to_be_bytes().to_vec();
        let class_bytes = (self.class as u16).to_be_bytes().to_vec();

        [domain_name_bytes, record_type_bytes, class_bytes].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_question_new() {
        // TODO: Add test cases for errors

        let packet = &[
            // Start of some fake domain name (not relevant for this test)
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // end of name
            0x00, 0x01, // RecordType (e.g. 0x00, 0x01 for A)
            0x00, 0x01, // Class (e.g. 0x00, 0x01 for IN)
        ];

        assert_eq!(
            DnsQuestion::new(packet),
            Ok(DnsQuestion {
                domain_name: DomainName {
                    wire_format: [
                        0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
                        0x63, 0x6f, 0x6d, 0x00,
                    ]
                    .to_vec(),
                    label_segments: Vec::from([
                        String::from("www"),
                        String::from("google"),
                        String::from("com")
                    ])
                },
                record_type: RecordType::A,
                class: Class::IN
            })
        );
    }

    #[test]
    fn test_dns_question_to_bytes() {
        let packet = &[
            // Start of some fake domain name (not relevant for this test)
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // end of name
            0x00, 0x01, // RecordType (e.g. 0x00, 0x01 for A)
            0x00, 0x01, // Class (e.g. 0x00, 0x01 for IN)
        ];

        assert_eq!(
            DnsQuestion::new(packet).map(|question| question.to_bytes()),
            Ok(packet.to_vec())
        );
    }
}
