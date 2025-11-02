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

/// DNS response codes as defined in RFC 1035 section 4.1.1
///
/// These codes indicate the outcome of a DNS query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl From<u8> for ResponseCode {
    fn from(byte: u8) -> Self {
        match byte {
            0 => ResponseCode::NoError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::FormatError,
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
    pub response_code: ResponseCode,
    pub question_count: u16,
    pub answer_record_count: u16,
    pub authority_record_count: u16,
    pub additional_record_count: u16,
}

impl DnsHeader {
    pub fn new(packet_slice: &[u8]) -> Result<Self, ()> {
        packet_slice
            .get(..12)
            .and_then(|bytes| bytes.try_into().ok())
            .map(|fixed_array: &[u8; 12]| fixed_array.into())
            .ok_or(())
    }

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
        let flags_second_byte = ((self.recursion_available as u8) << 7)
            | (self.reserved << 4)
            | (self.response_code as u8);

        [flags_first_byte, flags_second_byte]
    }

    /// Serializes the DNS header into a 12-byte array as specified in RFC 1035.
    ///
    /// Returns an array containing the binary representation of the DNS header.
    pub fn to_bytes(&self) -> [u8; 12] {
        self.into()
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
            response_code: ResponseCode::from(buf[3] & 0b00001111),
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
    fn test_response_code_conversion() {
        assert_eq!(ResponseCode::from(0b0000), ResponseCode::NoError);
        assert_eq!(ResponseCode::from(0b0001), ResponseCode::FormatError);
        assert_eq!(ResponseCode::from(0b0010), ResponseCode::ServerFailure);
        assert_eq!(ResponseCode::from(0b0011), ResponseCode::NameError);
        assert_eq!(ResponseCode::from(0b0100), ResponseCode::NotImplemented);
        assert_eq!(ResponseCode::from(0b0101), ResponseCode::Refused);

        // Test case for when pattern is greater than 5
        assert_eq!(ResponseCode::from(0b1000), ResponseCode::FormatError);
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
            response_code: ResponseCode::NoError,
            question_count: 1,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        };

        let bytes: [u8; 12] = (&original).to_bytes();
        let deserialized = DnsHeader::from(&bytes);

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_dns_header_new_success_and_error() {
        // Prepare a valid 12-byte DNS header packet (all fields are minimal/deterministic)
        let header_bytes: [u8; 12] = [
            0x04, 0xD2,       // packet_identifier: 1234
            0b10000001, // QR=1 (Reply), Opcode=0, AA=0, TC=0, RD=1
            0b00000000, // RA=0, Z=0, RCODE=0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x02, // ANCOUNT = 2
            0x00, 0x03, // NSCOUNT = 3
            0x00, 0x04, // ARCOUNT = 4
        ];
        assert_eq!(
            DnsHeader::new(&header_bytes),
            Ok(DnsHeader {
                packet_identifier: 1234,
                query_response_indicator: QRIndicator::Reply,
                operation_code: 0,
                authoritative_answer: false,
                truncation: false,
                recursion_desired: true,
                recursion_available: false,
                reserved: 0,
                response_code: ResponseCode::NoError,
                question_count: 1,
                answer_record_count: 2,
                authority_record_count: 3,
                additional_record_count: 4
            })
        );

        // Provide an invalid (shorter than 12 bytes) header
        let bad_bytes: [u8; 6] = [0, 1, 2, 3, 4, 5];
        assert!(
            DnsHeader::new(&bad_bytes).is_err(),
            "Should error if input is too short"
        );
    }
}
