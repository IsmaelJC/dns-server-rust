use std::net::UdpSocket;

use crate::dns::{DnsHeader, QRIndicator, ResponseCode};

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
        question_count: 0,
        answer_record_count: 0,
        authority_record_count: 0,
        additional_record_count: 0,
    }
    .to_bytes();

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let mut response = [0; 512];

                let destination_slice = &mut response[..12];
                destination_slice.copy_from_slice(&response_header);

                udp_socket.send_to(&response, source)?;
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                return Err(e);
            }
        }
    }
}
