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

impl DnsAnswerRecord {
    fn get_ttl_from_packet(packet_slice: &[u8], domain_name_len: usize) -> Result<u32, ()> {
        let ttl_start_index = domain_name_len + 4;
        let ttl_end_index = ttl_start_index + 4;
        match packet_slice.get(ttl_start_index..ttl_end_index) {
            None => Err(()),
            Some(bytes) => Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        }
    }

    fn get_r_data_from_packet(packet_slice: &[u8], domain_name_len: usize) -> Result<RData, ()> {
        let r_data_start_index = domain_name_len + 8;
        match packet_slice.get(r_data_start_index..) {
            None => Err(()),
            Some(bytes) => RData::new(bytes),
        }
    }

    pub fn new(packet_slice: &[u8]) -> Result<Self, ()> {
        let domain_name = DomainName::new(packet_slice)?;
        let domain_name_len = domain_name.wire_format.len();
        let record_type = RecordType::new(packet_slice, domain_name_len)?;
        let class = Class::new(packet_slice, domain_name_len)?;
        let time_to_live = Self::get_ttl_from_packet(packet_slice, domain_name_len)?;
        let r_data = Self::get_r_data_from_packet(packet_slice, domain_name_len)?;
        let r_data_length = r_data.0.len();

        Ok(DnsAnswerRecord {
            domain_name,
            record_type,
            class,
            time_to_live,
            r_data_length,
            r_data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let domain_name_bytes = self.domain_name.wire_format.clone();
        let record_type_bytes = (self.record_type as u16).to_be_bytes().to_vec();
        let class_bytes = (self.class as u16).to_be_bytes().to_vec();
        let time_to_live_bytes = self.time_to_live.to_be_bytes().to_vec();
        let r_data_length_bytes = (self.r_data_length as u16).to_be_bytes().to_vec();
        let r_data_bytes = self.r_data.0.clone();

        [
            domain_name_bytes,
            record_type_bytes,
            class_bytes,
            time_to_live_bytes,
            r_data_length_bytes,
            r_data_bytes,
        ]
        .concat()
    }
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

    #[test]
    fn test_dns_answer_record_new() {
        // Helper to create a full valid answer packet:
        // [domain name][record type][class][ttl][rdata len][rdata]
        // Example domain name: \x03www\x06google\x03com\x00
        let domain_bytes = [
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // end of name
        ];
        let record_type_bytes = [0x00, 0x01]; // A
        let class_bytes = [0x00, 0x01]; // IN
        let ttl_bytes = [0x00, 0x00, 0x00, 0x2a]; // TTL = 42
        let rdata_bytes = [0x00, 0x04, 192, 168, 1, 1]; // RData length = 4, IPv4 192.168.1.1

        let full_packet: Vec<u8> = domain_bytes
            .iter()
            .chain(record_type_bytes.iter())
            .chain(class_bytes.iter())
            .chain(ttl_bytes.iter())
            .chain(rdata_bytes.iter())
            .cloned()
            .collect();

        let ans = DnsAnswerRecord::new(&full_packet);
        assert_eq!(
            ans,
            Ok(DnsAnswerRecord {
                domain_name: DomainName {
                    wire_format: domain_bytes.to_vec(),
                    label_segments: vec!["www".into(), "google".into(), "com".into(),]
                },
                record_type: RecordType::A,
                class: Class::IN,
                time_to_live: 42,
                r_data_length: 4,
                r_data: RData(vec![192, 168, 1, 1])
            })
        );

        // Error: bad domain name (wrong wire format)
        let mut bad_packet = full_packet.clone();
        bad_packet[0] = 0xFF; // Not a valid label length (would cause DomainName::new to error)
        assert_eq!(DnsAnswerRecord::new(&bad_packet), Err(()));

        // Error: not enough bytes for record type
        let too_short = domain_bytes.to_vec();
        assert_eq!(DnsAnswerRecord::new(&too_short), Err(()));

        // Error: bad record type
        let mut bad_type = full_packet.clone();
        let dom_len = domain_bytes.len();
        bad_type[dom_len] = 0xFF; // Not defined in RecordType
        bad_type[dom_len + 1] = 0xFF;
        assert_eq!(DnsAnswerRecord::new(&bad_type), Err(()));

        // Error: bad class
        let mut bad_class = full_packet.clone();
        let class_offset = domain_bytes.len() + 2;
        bad_class[class_offset] = 0xFF;
        bad_class[class_offset + 1] = 0xFF; // Not defined
        assert_eq!(DnsAnswerRecord::new(&bad_class), Err(()));

        // Error: not enough bytes for TTL
        let mut bad_ttl = full_packet.clone();
        bad_ttl.truncate(domain_bytes.len() + 2 + 2 + 2); // Cut into middle of TTL
        assert_eq!(DnsAnswerRecord::new(&bad_ttl), Err(()));

        // Error: not enough bytes for RDATA
        let mut bad_rdata = full_packet.clone();
        let rdata_start = domain_bytes.len() + 2 + 2 + 4; // after header, before rdata

        // cut just after rdata len marker (so only rdata_length bytes, missing actual address)
        bad_rdata.truncate(rdata_start + 2 + 1); // less than rdata_length
        assert_eq!(DnsAnswerRecord::new(&bad_rdata), Err(()));
    }

    #[test]
    fn test_dns_answer_record_to_bytes() {
        let domain_bytes = [
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // end of name
        ];
        let record_type_bytes = [0x00, 0x01]; // A
        let class_bytes = [0x00, 0x01]; // IN
        let ttl_bytes = [0x00, 0x00, 0x00, 0x2a]; // TTL = 42
        let rdata_bytes = [0x00, 0x04, 192, 168, 1, 1]; // RData length = 4, IPv4 192.168.1.1

        let full_packet: Vec<u8> = domain_bytes
            .iter()
            .chain(record_type_bytes.iter())
            .chain(class_bytes.iter())
            .chain(ttl_bytes.iter())
            .chain(rdata_bytes.iter())
            .cloned()
            .collect();

        assert_eq!(
            DnsAnswerRecord::new(&full_packet).map(|answer| { answer.to_bytes() }),
            Ok(full_packet)
        );
    }
}
