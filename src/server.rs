use std::net::UdpSocket;

use crate::dns::{
    Class, DnsAnswerRecord, DnsHeader, DnsQuestion, DomainName, QRIndicator, RData, RecordType,
    ResponseCode,
};

/// Starts and runs the DNS server
///
/// Binds to the specified address and handles incoming DNS queries in a loop.
/// For each query, it responds with a basic DNS header.
pub fn run() -> std::io::Result<()> {
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053")?;
    let mut buf = [0; 512];

    // Prepare a default response header
    let response_header = DnsHeader {
        packet_identifier: 1234,
        query_response_indicator: QRIndicator::Reply,
        operation_code: 0,
        authoritative_answer: false,
        truncation: false,
        recursion_desired: false,
        recursion_available: false,
        reserved: 0,
        response_code: ResponseCode::NoError,
        question_count: 1,
        answer_record_count: 1,
        authority_record_count: 0,
        additional_record_count: 0,
    }
    .to_bytes();

    let response_question_section = DnsQuestion {
        domain_name: DomainName {
            wire_format: [
                0x0c, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x72, 0x61, 0x66, 0x74, 0x65, 0x72, 0x73, 0x02,
                0x69, 0x6f, 0x00,
            ]
            .to_vec(),
            label_segments: Vec::from([String::from("codecrafters"), String::from("io")]),
        },
        record_type: RecordType::A,
        class: Class::IN,
    }
    .to_bytes();

    let response_answer_section = DnsAnswerRecord {
        domain_name: DomainName {
            wire_format: [
                0x0c, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x72, 0x61, 0x66, 0x74, 0x65, 0x72, 0x73, 0x02,
                0x69, 0x6f, 0x00,
            ]
            .to_vec(),
            label_segments: Vec::from([String::from("codecrafters"), String::from("io")]),
        },
        record_type: RecordType::A,
        class: Class::IN,
        time_to_live: 60,
        r_data_length: 4,
        r_data: RData(vec![8, 8, 8, 8]),
    }
    .to_bytes();

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let mut response = [0; 512];

                let header_destination_slice = &mut response[..12];
                header_destination_slice.copy_from_slice(&response_header);

                let question_destination_slice =
                    &mut response[12..12 + response_question_section.len()];
                question_destination_slice.copy_from_slice(&response_question_section);

                let answer_destination_slice = &mut response[12 + response_question_section.len()
                    ..12 + response_question_section.len() + response_answer_section.len()];
                answer_destination_slice.copy_from_slice(&response_answer_section);

                udp_socket.send_to(&response, source)?;
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                return Err(e);
            }
        }
    }
}
