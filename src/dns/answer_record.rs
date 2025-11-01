use crate::dns::{Class, DomainName, RecordType};

/// Represents the Resource Data (RDATA) portion of a DNS answer record.
///
/// The `RData` struct holds both the raw bytes of the RDATA as they appear in a DNS packet (`wire_format`),
/// and a string interpretation of the data (`data_as_string`). The interpretation as a string is
/// meaningful for certain DNS record types (such as text records), but for others it may not be human-readable
/// (such as IPv4 or IPv6 addresses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RData {
    pub wire_format: Vec<u8>,
    pub data_as_string: String,
}

impl RData {
    pub fn new(packet_slice: &[u8]) -> Result<Self, ()> {
        if packet_slice.len() < 3 {
            return Err(());
        }

        let r_data_length = u16::from_be_bytes([packet_slice[0], packet_slice[1]]) as usize;
        let mut wire_format: Vec<u8> = Vec::new();
        let mut data_as_string: String = String::new();

        for byte in packet_slice[2..r_data_length + 2].iter() {
            wire_format.push(*byte);
            data_as_string.push(char::from(*byte));
        }

        if wire_format.len() == r_data_length {
            Ok(RData {
                wire_format,
                data_as_string,
            })
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
    pub r_data_length: u16,
    pub r_data: RData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r_data_new() {
        // If packet slice has 2 elements or less, the parsing should fail
        assert_eq!(RData::new(&[0x08, 0x08]), Err(()));
    }
}
