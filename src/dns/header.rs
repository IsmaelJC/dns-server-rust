/// Query/Response indicator for DNS packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRIndicator {
    Question = 0,
    Reply = 1,
}

impl From<u8> for QRIndicator {
    fn from(byte: u8) -> Self {
        match byte {
            0 => QRIndicator::Question,
            _ => QRIndicator::Reply,
        }
    }
}

/// DNS packet header structure
///
/// Represents the fixed 12-byte header that appears at the start of every DNS message.
/// See RFC 1035 Section 4.1.1 for the full specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub packet_identifier: u16,
    pub query_response_indicator: QRIndicator,
    pub operation_code: u8,
    pub authoritative_answer: bool,
    pub truncation: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub reserved: u8,
    pub response_code: u8,
    pub question_count: u16,
    pub answer_record_count: u16,
    pub authority_record_count: u16,
    pub additional_record_count: u16,
}

impl DnsHeader {
    /// Encodes the DNS header flags into a 2-byte array
    ///
    /// The flags are packed according to RFC 1035:
    /// - Byte 1: QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1)
    /// - Byte 2: RA(1) | Z(3) | RCODE(4)
    pub fn get_flags_bytes(&self) -> [u8; 2] {
        let flags_first_byte = ((self.query_response_indicator as u8) << 7)
            | (self.operation_code << 3)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.truncation as u8) << 1)
            | (self.recursion_desired as u8);
        let flags_second_byte =
            ((self.recursion_available as u8) << 7) | (self.reserved << 4) | self.response_code;

        [flags_first_byte, flags_second_byte]
    }
}

/// Deserialize a DNS header from a 12-byte array
impl From<&[u8; 12]> for DnsHeader {
    fn from(buf: &[u8; 12]) -> Self {
        Self {
            packet_identifier: u16::from_be_bytes([buf[0], buf[1]]),
            query_response_indicator: QRIndicator::from(buf[2] & 0b10000000),
            operation_code: (buf[2] & 0b01111000) >> 3,
            authoritative_answer: (buf[2] & 0b00000100) != 0,
            truncation: (buf[2] & 0b00000010) != 0,
            recursion_desired: (buf[2] & 0b00000001) != 0,
            recursion_available: (buf[3] & 0b10000000) != 0,
            reserved: (buf[3] & 0b01110000) >> 4,
            response_code: buf[3] & 0b00001111,
            question_count: u16::from_be_bytes([buf[4], buf[5]]),
            answer_record_count: u16::from_be_bytes([buf[6], buf[7]]),
            authority_record_count: u16::from_be_bytes([buf[8], buf[9]]),
            additional_record_count: u16::from_be_bytes([buf[10], buf[11]]),
        }
    }
}

/// Serialize a DNS header to a 12-byte array (borrowed)
impl From<&DnsHeader> for [u8; 12] {
    fn from(header: &DnsHeader) -> Self {
        let packet_identifier_bytes = header.packet_identifier.to_be_bytes();
        let flags_bytes = header.get_flags_bytes();
        let question_count_bytes = header.question_count.to_be_bytes();
        let answer_record_bytes = header.answer_record_count.to_be_bytes();
        let authority_record_count = header.authority_record_count.to_be_bytes();
        let additional_record_count = header.additional_record_count.to_be_bytes();

        [
            packet_identifier_bytes[0],
            packet_identifier_bytes[1],
            flags_bytes[0],
            flags_bytes[1],
            question_count_bytes[0],
            question_count_bytes[1],
            answer_record_bytes[0],
            answer_record_bytes[1],
            authority_record_count[0],
            authority_record_count[1],
            additional_record_count[0],
            additional_record_count[1],
        ]
    }
}

/// Serialize a DNS header to a 12-byte array (owned)
impl From<DnsHeader> for [u8; 12] {
    fn from(header: DnsHeader) -> Self {
        <[u8; 12]>::from(&header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_indicator_conversion() {
        assert_eq!(QRIndicator::from(0b00000000), QRIndicator::Question);
        assert_eq!(QRIndicator::from(0b10000000), QRIndicator::Reply);
    }

    #[test]
    fn test_header_serialization_roundtrip() {
        let original = DnsHeader {
            packet_identifier: 1234,
            query_response_indicator: QRIndicator::Reply,
            operation_code: 0,
            authoritative_answer: true,
            truncation: false,
            recursion_desired: true,
            recursion_available: false,
            reserved: 0,
            response_code: 0,
            question_count: 1,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        };

        let bytes: [u8; 12] = (&original).into();
        let deserialized = DnsHeader::from(&bytes);

        assert_eq!(original, deserialized);
    }
}
