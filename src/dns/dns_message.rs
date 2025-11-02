use crate::dns::{DnsAnswerRecord, DnsHeader, DnsQuestion};

/// Represents a complete DNS message consisting of a header, questions, and answer records.
///
/// This struct models the structure of a standard DNS message as defined in RFC 1035, comprising:
/// - `header`: The DNS message header, which contains metadata such as ID, flags, and section counts.
/// - `questions`: The list of DNS questions that the client is querying for.
/// - `answers`: The list of answer records that respond to the queries.
///
/// This struct is commonly used for parsing and constructing DNS packets in binary form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsAnswerRecord>,
}

impl DnsMessage {
    pub fn new(packet: &[u8; 512]) -> Result<Self, ()> {
        let header = DnsHeader::new(packet)?;
        let (questions, answers_slice) =
            DnsQuestion::parse_all_questions(&packet[12..], header.question_count)?;
        let (answers, _) =
            DnsAnswerRecord::parse_all_answers(answers_slice, header.answer_record_count)?;

        Ok(DnsMessage {
            header,
            questions,
            answers,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::{Class, DomainName, QRIndicator, RData, RecordType, ResponseCode};

    use super::*;

    #[test]
    fn test_dns_message_new() {
        // Successful parsing test: 1 question, 1 answer, no extra bytes
        let header_bytes = [
            0x12, 0x34,       // packet_identifier = 0x1234
            0b00000001, // QR=0, Opcode=0, AA=0, TC=0, RD=1
            0b00000000, // RA=0, Z=0, RCODE=0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];

        // Question section: qname= [3]foo[3]bar[3]com[0], QTYPE=1, QCLASS=1
        let question_bytes = [
            0x03, b'f', b'o', b'o', 0x03, b'b', b'a', b'r', 0x03, b'c', b'o', b'm',
            0x00, // end of qname
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
        ];

        // Answer section: domain=same, TYPE=1, CLASS=1, TTL=0x0000003c, RDLEN=4, RDATA=1.2.3.4
        let answer_bytes = [
            0x03, b'f', b'o', b'o', 0x03, b'b', b'a', b'r', 0x03, b'c', b'o', b'm',
            0x00, // end of name
            0x00, 0x01, // TYPE=A
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x00, 0x3c, // TTL=60
            0x00, 0x04, // RDLEN=4
            1, 2, 3, 4, // RDATA
        ];

        // Assemble the full packet
        let mut packet = [0u8; 512];
        let mut write_i = 0;
        for b in header_bytes.iter() {
            packet[write_i] = *b;
            write_i += 1;
        }
        for b in question_bytes.iter() {
            packet[write_i] = *b;
            write_i += 1;
        }
        for b in answer_bytes.iter() {
            packet[write_i] = *b;
            write_i += 1;
        }

        // Correct parse
        assert_eq!(
            DnsMessage::new(&packet),
            Ok(DnsMessage {
                header: DnsHeader {
                    packet_identifier: 0x1234,
                    query_response_indicator: QRIndicator::Question,
                    operation_code: 0,
                    authoritative_answer: false,
                    truncation: false,
                    recursion_desired: true,
                    recursion_available: false,
                    reserved: 0,
                    response_code: ResponseCode::NoError,
                    question_count: 1,
                    answer_record_count: 1,
                    authority_record_count: 0,
                    additional_record_count: 0,
                },
                questions: vec![DnsQuestion {
                    domain_name: DomainName {
                        wire_format: vec![
                            0x03, b'f', b'o', b'o', 0x03, b'b', b'a', b'r', 0x03, b'c', b'o', b'm',
                            0x00,
                        ],
                        label_segments: vec![
                            "foo".to_string(),
                            "bar".to_string(),
                            "com".to_string(),
                        ],
                    },
                    record_type: RecordType::A,
                    class: Class::IN,
                }],
                answers: vec![DnsAnswerRecord {
                    domain_name: DomainName {
                        wire_format: vec![
                            0x03, b'f', b'o', b'o', 0x03, b'b', b'a', b'r', 0x03, b'c', b'o', b'm',
                            0x00,
                        ],
                        label_segments: vec![
                            "foo".to_string(),
                            "bar".to_string(),
                            "com".to_string(),
                        ]
                    },
                    record_type: RecordType::A,
                    class: Class::IN,
                    time_to_live: 60,
                    r_data_length: 4,
                    r_data: RData(vec![1, 2, 3, 4]),
                }],
            })
        );

        // Failing test: alter answer so RDLEN claims more data than available
        let mut bad_packet = packet;
        // set RDLEN to a ridiculous value
        let bad_rdata_pos = header_bytes.len() + question_bytes.len() + 21;
        bad_packet[bad_rdata_pos] = 0x01;
        bad_packet[bad_rdata_pos + 1] = 0xFF; // RDLEN=511 but only 4 bytes present

        assert!(DnsMessage::new(&bad_packet).is_err());
    }
}
