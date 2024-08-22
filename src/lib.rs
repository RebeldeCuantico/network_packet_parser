//src/lib.rs
use std::net::Ipv4Addr;

/// Represents an Ethernet frame.
#[derive(Debug, PartialEq)]
pub struct EthernetFrame {
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

/// Represents an IPv4 header.
#[derive(Debug, PartialEq)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
}

/// Represents a TCP header.
#[derive(Debug, PartialEq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dest_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

/// Enum representing the different types of packets we can parse.
#[derive(Debug, PartialEq)]
pub enum PacketType {
    Ethernet(EthernetFrame),
    Ipv4(Ipv4Header),
    Tcp(Ipv4Header, TcpHeader),
    Unknown,
}

/// Parses a byte slice into a `PacketType`.
///
/// # Arguments
///
/// * `data` - A byte slice containing the packet to be parsed.
///
/// # Returns
///
/// Returns a `PacketType` representing the parsed packet type.
pub fn parse_packet(data: &[u8]) -> PacketType {
    if data.len() < 14 {
        return PacketType::Unknown;
    }

    let ethernet_frame = EthernetFrame {
        dest_mac: data[0..6].try_into().unwrap(),
        src_mac: data[6..12].try_into().unwrap(),
        ethertype: u16::from_be_bytes(data[12..14].try_into().unwrap()),
    };

    if ethernet_frame.ethertype == 0x0800 && data.len() >= 34 {
        let ipv4_header = Ipv4Header {
            version: (data[14] >> 4) & 0xF,
            ihl: data[14] & 0xF,
            dscp: data[15] >> 2,
            ecn: data[15] & 0x3,
            total_length: u16::from_be_bytes(data[16..18].try_into().unwrap()),
            identification: u16::from_be_bytes(data[18..20].try_into().unwrap()),
            flags: (data[20] >> 5) & 0x7,
            fragment_offset: u16::from_be_bytes([data[20] & 0x1F, data[21]]),
            ttl: data[22],
            protocol: data[23],
            header_checksum: u16::from_be_bytes(data[24..26].try_into().unwrap()),
            src_ip: Ipv4Addr::new(data[26], data[27], data[28], data[29]),
            dest_ip: Ipv4Addr::new(data[30], data[31], data[32], data[33]),
        };

        if ipv4_header.protocol == 6 {
            let ip_header_length = (ipv4_header.ihl as usize) * 4;
            if data.len() >= 14 + ip_header_length + 20 {
                let tcp_data = &data[14 + ip_header_length..];
                let tcp_header = TcpHeader {
                    src_port: u16::from_be_bytes([tcp_data[0], tcp_data[1]]),
                    dest_port: u16::from_be_bytes([tcp_data[2], tcp_data[3]]),
                    sequence_number: u32::from_be_bytes([tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7]]),
                    acknowledgment_number: u32::from_be_bytes([tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11]]),
                    data_offset: (tcp_data[12] >> 4) & 0xF,
                    reserved: (tcp_data[12] & 0xF) << 2 | (tcp_data[13] >> 6) & 0x3,
                    flags: tcp_data[13] & 0x3F,
                    window_size: u16::from_be_bytes([tcp_data[14], tcp_data[15]]),
                    checksum: u16::from_be_bytes([tcp_data[16], tcp_data[17]]),
                    urgent_pointer: u16::from_be_bytes([tcp_data[18], tcp_data[19]]),
                };
                return PacketType::Tcp(ipv4_header, tcp_header);
            }
        }

        PacketType::Ipv4(ipv4_header)
    } else {
        PacketType::Ethernet(ethernet_frame)
    }
}

/// Determines the type of analyzer needed for a given packet.
///
/// # Arguments
///
/// * `packet` - A `PacketType` representing the analyzed packet.
///
/// # Returns
///
/// Returns a string slice indicating the recommended analyzer type.
pub fn determine_analyzer(packet: &PacketType) -> &str {
    match packet {
        PacketType::Ethernet(_) => "Ethernet Analyzer",
        PacketType::Ipv4(header) => {
            match header.protocol {
                6 => "TCP Analyzer",
                17 => "UDP Analyzer",
                1 => "ICMP Analyzer",
                _ => "Generic IP Analyzer",
            }
        }
        PacketType::Tcp(_, _) => "TCP Analyzer",
        PacketType::Unknown => "Unknown Packet Analyzer",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ethernet_frame() {
        let data = [
            0x00, 0x50, 0x56, 0xC0, 0x00, 0x08, 
            0x00, 0x50, 0x56, 0xC0, 0x00, 0x01, 
            0x08, 0x00
        ];
        let result = parse_packet(&data);
        assert!(matches!(result, PacketType::Ethernet(_)));
        if let PacketType::Ethernet(frame) = result {
            assert_eq!(frame.dest_mac, [0x00, 0x50, 0x56, 0xC0, 0x00, 0x08]);
            assert_eq!(frame.src_mac, [0x00, 0x50, 0x56, 0xC0, 0x00, 0x01]);
            assert_eq!(frame.ethertype, 0x0800);
        }
    }

    #[test]
    fn test_parse_ipv4_packet() {
        let data = [
            0x00, 0x50, 0x56, 0xC0, 0x00, 0x08, 0x00, 0x50, 0x56, 0xC0, 0x00, 0x01, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06, 0x61, 0x4A, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0x0A,
        ];
        let result = parse_packet(&data);
        assert!(matches!(result, PacketType::Ipv4(_)));
        if let PacketType::Ipv4(header) = result {
            assert_eq!(header.version, 4);
            assert_eq!(header.protocol, 6);
            assert_eq!(header.src_ip, Ipv4Addr::new(192, 168, 0, 1));
            assert_eq!(header.dest_ip, Ipv4Addr::new(192, 168, 0, 10));
        }
    }

    #[test]
    fn test_determine_analyzer() {
        let ethernet_frame = PacketType::Ethernet(EthernetFrame {
            dest_mac: [0; 6],
            src_mac: [0; 6],
            ethertype: 0,
        });
        assert_eq!(determine_analyzer(&ethernet_frame), "Ethernet Analyzer");

        let ipv4_header = PacketType::Ipv4(Ipv4Header {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: 0,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6,
            header_checksum: 0,
            src_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(0, 0, 0, 0),
        });
        assert_eq!(determine_analyzer(&ipv4_header), "TCP Analyzer");

        let unknown = PacketType::Unknown;
        assert_eq!(determine_analyzer(&unknown), "Unknown Packet Analyzer");
    }

    #[test]
    fn test_parse_tcp_packet() {
        let data = [
            0x00, 0x50, 0x56, 0xC0, 0x00, 0x08, 0x00, 0x50, 0x56, 0xC0, 0x00, 0x01, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06, 0x61, 0x4A, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0x0A, 0xD8, 0x65, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x91, 0x7C, 0x00, 0x00,
        ];
        let result = parse_packet(&data);
        assert!(matches!(result, PacketType::Tcp(_, _)));
        if let PacketType::Tcp(ip_header, tcp_header) = result {
            assert_eq!(ip_header.protocol, 6);
            assert_eq!(tcp_header.src_port, 55397);
            assert_eq!(tcp_header.dest_port, 80);
            assert_eq!(tcp_header.sequence_number, 1);
            assert_eq!(tcp_header.acknowledgment_number, 0);
            assert_eq!(tcp_header.data_offset, 5);
            assert_eq!(tcp_header.flags, 2);
            assert_eq!(tcp_header.window_size, 8192);
        }
    }
}