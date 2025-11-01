/// Represents a DNS domain name in both wire (binary) format and string (dot-separated label) format.
///
/// The `wire_format` field holds the domain as it appears in a DNS packet, using length-prefixed labels.
/// The `label_segments` field is a vector of label segments as strings, such as `["www", "example", "com"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainName {
    pub wire_format: Vec<u8>,
    pub label_segments: Vec<String>,
}

impl DomainName {
    pub fn new(packet: &[u8]) -> Result<Self, ()> {
        if packet.is_empty() {
            return Err(());
        }

        let mut wire_format: Vec<u8> = Vec::new();
        let mut label_segments: Vec<String> = Vec::new();

        let mut current_label_length: Option<usize> = None;
        let mut current_label = String::new();

        for byte in packet.iter() {
            wire_format.push(*byte);

            match current_label_length {
                None => {
                    if *byte == 0 {
                        break;
                    }

                    current_label_length = Some(usize::from(*byte));
                }
                Some(n) => {
                    current_label.push(char::from(*byte));

                    if current_label.len() == n {
                        label_segments.push(current_label.clone());
                        current_label.clear();
                        current_label_length = None;
                    }
                }
            }
        }

        match (current_label_length, wire_format.last()) {
            (None, Some(0)) => Ok(DomainName {
                wire_format,
                label_segments,
            }),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_name_new() {
        let google_dot_com: &[u8] = &[
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];

        let domain_name_without_terminating_null_byte = &google_dot_com[..google_dot_com.len() - 1];

        // If the domain name buffer is empty, the parsing should fail
        assert_eq!(DomainName::new(&[]), Err(()));

        // If we remove the terminating null byte, the parsing should fail
        assert_eq!(
            DomainName::new(domain_name_without_terminating_null_byte),
            Err(())
        );

        // For correctly formed domain name buffer, parsing should succeed
        assert_eq!(
            DomainName::new(google_dot_com)
                .map(|domain_name| { domain_name.label_segments.join(".") }),
            Ok(String::from("google.com"))
        );
        assert_eq!(
            DomainName::new(google_dot_com).map(|domain_name| { domain_name.wire_format }),
            Ok(google_dot_com.to_vec())
        );

        // If we add additional bytes after terminating null byte, the result should remain the same
        assert_eq!(
            DomainName::new(&[google_dot_com, &[0x06, 0x67, 0x6f]].concat())
                .map(|domain_name| { domain_name.label_segments.join(".") }),
            Ok(String::from("google.com"))
        );
        assert_eq!(
            DomainName::new(google_dot_com).map(|domain_name| { domain_name.wire_format }),
            Ok(google_dot_com.to_vec())
        );
    }
}
