use crate::dns::{Class, DomainName, RecordType};

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

    fn parse_and_return_next_slice(packet_slice: &[u8]) -> Result<(Self, &[u8]), ()> {
        let question = Self::new(packet_slice)?;
        let domain_name_len = question.domain_name.wire_format.len();

        Ok((question, &packet_slice[domain_name_len + 4..]))
    }

    pub fn parse_all_questions(
        packet_slice: &[u8],
        number_of_questions: usize,
    ) -> Result<(Vec<Self>, &[u8]), ()> {
        let mut questions: Vec<Self> = Vec::new();
        let mut current_slice = packet_slice;

        for _ in 0..number_of_questions {
            match Self::parse_and_return_next_slice(current_slice) {
                Err(_) => {
                    return Err(());
                }
                Ok((question, next_slice)) => {
                    questions.push(question);
                    current_slice = next_slice;
                }
            }
        }

        Ok((questions, current_slice))
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

    #[test]
    fn test_parse_all_questions() {
        let packet = [
            // Question 1
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // end of name
            0x00, 0x01, // RecordType::A
            0x00, 0x01, // Class::IN
            // Question 2
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x6f, 0x72, 0x67, // "org"
            0x00, // end of name
            0x00, 0x01, // RecordType::A
            0x00, 0x01, // Class::IN
            // Answer (for test purposes we include only a couple of null bytes)
            0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(
            DnsQuestion::parse_all_questions(&packet, 2),
            Ok((
                vec![
                    DnsQuestion {
                        domain_name: DomainName {
                            wire_format: vec![
                                0x03, 0x77, 0x77, 0x77, // "www"
                                0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
                                0x03, 0x63, 0x6f, 0x6d, // "com"
                                0x00, // end of name
                            ],
                            label_segments: vec!["www".into(), "google".into(), "com".into()]
                        },
                        record_type: RecordType::A,
                        class: Class::IN
                    },
                    DnsQuestion {
                        domain_name: DomainName {
                            wire_format: vec![
                                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
                                0x03, 0x6f, 0x72, 0x67, // "org"
                                0x00, // end of name
                            ],
                            label_segments: vec!["example".into(), "org".into()]
                        },
                        record_type: RecordType::A,
                        class: Class::IN
                    }
                ],
                &packet[packet.len() - 4..]
            ))
        );

        // If we trucate the second question, the parsing should fail
        assert_eq!(
            DnsQuestion::parse_all_questions(&packet[..packet.len() - 10], 2),
            Err(())
        )
    }
}
