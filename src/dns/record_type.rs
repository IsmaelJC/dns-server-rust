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
    pub fn new(packet: &[u8], domain_name_len: usize) -> Result<Self, ()> {
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
}
