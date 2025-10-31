#[allow(unused_imports)]
use std::net::UdpSocket;

#[derive(Debug)]
enum QRIndicator {
    Question,
    Reply,
}

impl From<bool> for QRIndicator {
    fn from(flag: bool) -> Self {
        match flag {
            false => QRIndicator::Question,
            true => QRIndicator::Reply,
        }
    }
}

impl From<&QRIndicator> for bool {
    fn from(indicator: &QRIndicator) -> Self {
        match indicator {
            QRIndicator::Question => false,
            QRIndicator::Reply => true,
        }
    }
}

#[derive(Debug)]
struct DnsHeader {
    packet_identifier: u16,
    query_response_indicator: QRIndicator,
    operation_code: u8,
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    reserved: u8,
    response_code: u8,
    question_count: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

impl DnsHeader {
    pub fn get_flags_bytes(&self) -> [u8; 2] {
        let flags_first_byte = ((bool::from(&self.query_response_indicator) as u8) << 7)
            | (self.operation_code << 3)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.truncation as u8) << 1)
            | (self.recursion_desired as u8);
        let flags_second_byte =
            ((self.recursion_available as u8) << 7) | (self.reserved << 4) | self.response_code;

        [flags_first_byte, flags_second_byte]
    }
}

impl From<&[u8; 12]> for DnsHeader {
    fn from(buf: &[u8; 12]) -> Self {
        Self {
            packet_identifier: u16::from_be_bytes([buf[0], buf[1]]),
            query_response_indicator: ((buf[2] & 0b10000000) != 0).into(),
            operation_code: (buf[2] & 0b01111000) >> 3,
            authoritative_answer: (buf[2] & 0b00000100) != 0,
            truncation: (buf[2] & 0b00000010) != 0,
            recursion_desired: (buf[2] & 0b00000001) != 0,
            recursion_available: (buf[3] & 0b10000000) != 0,
            reserved: (buf[3] & 0b01110000) >> 4,
            response_code: buf[3] & 0b00001111,
            question_count: u16::from_be_bytes([buf[4], buf[5]]),
            answer_record_count: u16::from_be_bytes([buf[6], buf[7]]),
            authority_record_count: u16::from_be_bytes([buf[8], buf[9]]),
            additional_record_count: u16::from_be_bytes([buf[10], buf[11]]),
        }
    }
}

impl From<&DnsHeader> for [u8; 12] {
    fn from(header: &DnsHeader) -> Self {
        let packet_identifier_bytes = header.packet_identifier.to_be_bytes();
        let flags_bytes = header.get_flags_bytes();
        let question_count_bytes = header.question_count.to_be_bytes();
        let answer_record_bytes = header.answer_record_count.to_be_bytes();
        let authority_record_count = header.authority_record_count.to_be_bytes();
        let additional_record_count = header.additional_record_count.to_be_bytes();

        [
            packet_identifier_bytes[0],
            packet_identifier_bytes[1],
            flags_bytes[0],
            flags_bytes[1],
            question_count_bytes[0],
            question_count_bytes[1],
            answer_record_bytes[0],
            answer_record_bytes[1],
            authority_record_count[0],
            authority_record_count[1],
            additional_record_count[0],
            additional_record_count[1],
        ]
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    // let header = DnsHeader {
    //     packet_identifier: 1234,
    //     query_response_indicator: true,
    //     operation_code: 0,
    //     authoritative_answer: false,
    //     truncation: false,
    //     recursion_desired: false,
    //     recursion_available: false,
    //     reserved: 0,
    //     response_code: 0,
    //     question_count: 0,
    //     answer_record_count: 0,
    //     authority_record_count: 0,
    //     additional_record_count: 0,
    // };

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let response = [];
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
