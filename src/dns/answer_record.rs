use crate::dns::{Class, DomainName, RecordType};

/// Represents the raw resource data (RDATA) of a DNS resource record.
///
/// This struct encapsulates the binary wire-format of the data portion of a DNS answer,
/// which varies depending on the record type (e.g., IPv4 address for an A record, domain name for CNAME, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RData(Vec<u8>);

impl RData {
    pub fn new(packet_slice: &[u8]) -> Result<Self, ()> {
        if packet_slice.len() < 3 {
            return Err(());
        }

        let r_data_length = u16::from_be_bytes([packet_slice[0], packet_slice[1]]) as usize;
        let mut wire_format: Vec<u8> = Vec::new();

        for idx in 2..r_data_length + 2 {
            match packet_slice.get(idx) {
                Some(byte) => {
                    wire_format.push(*byte);
                }
                None => break,
            }
        }

        if wire_format.len() == r_data_length {
            Ok(RData(wire_format))
        } else {
            Err(())
        }
    }
}

/// Represents a single DNS answer record (Resource Record) in a DNS packet.
///
/// A DNS answer record provides information in response to a DNS query. It includes:
/// - `domain_name`: The domain name that this record pertains to.
/// - `record_type`: The type of the DNS record (such as A, AAAA, CNAME, etc.).
/// - `class`: The class of the record (typically IN for Internet).
/// - `time_to_live`: The number of seconds that this record can be cached.
/// - `r_data_length`: The length of the resource data (RDATA) field in bytes.
/// - `r_data`: The resource data of the answer, which contains the content specific to the record type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswerRecord {
    pub domain_name: DomainName,
    pub record_type: RecordType,
    pub class: Class,
    pub time_to_live: u32,
    pub r_data_length: usize,
    pub r_data: RData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r_data_new() {
        // If packet slice has 2 elements or less, the parsing should fail
        assert_eq!(RData::new(&[0x08, 0x08]), Err(()));

        // If the packet slice has fewer elements than what the r_data_length portion says,
        // then the parsing should also fail
        assert_eq!(RData::new(&[0x00, 0x02, 0x08]), Err(()));

        // It should succeed for an Ipv4 address
        assert_eq!(
            RData::new(&[0x00, 0x04, 0x08, 0x08, 0x08, 0x08]),
            Ok(RData([0x08, 0x08, 0x08, 0x08].to_vec()))
        );
    }
}
