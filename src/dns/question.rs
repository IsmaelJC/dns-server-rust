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
}
