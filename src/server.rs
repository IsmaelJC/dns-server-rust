use std::net::UdpSocket;

use crate::dns::DnsMessage;

/// Starts and runs the DNS server
///
/// Binds to the specified address and handles incoming DNS queries in a loop.
/// For each query, it responds with a basic DNS header.
pub fn run() -> std::io::Result<()> {
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053")?;
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let response = DnsMessage::new(&buf)
                    .map(|query| query.build_reply())
                    .unwrap_or(DnsMessage::build_error_reply())
                    .to_bytes();

                udp_socket.send_to(&response, source)?;
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                return Err(e);
            }
        }
    }
}
