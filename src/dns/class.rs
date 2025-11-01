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
    pub fn new(packet: &[u8], domain_name_len: usize) -> Result<Self, ()> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
