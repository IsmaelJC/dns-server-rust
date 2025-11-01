use crate::dns::{Class, DomainName, RecordType};

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

pub struct DnsAnswerRecord {
    pub domain_name: DomainName,
    pub record_type: RecordType,
    pub class: Class,
    pub time_to_live: u32,
    pub r_data_length: u16,
    pub r_data: RData,
}
