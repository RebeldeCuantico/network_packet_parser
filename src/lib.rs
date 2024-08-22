//src/lib.rs

use std::net::Ipv4Addr;

/// Represents an Ethernet frame.
#[derive(Debug, PartialEq)]
pub struct EthernetFrame {
    /// Destination MAC address.
    pub dest_mac: [u8; 6],
    /// Source MAC address.
    pub src_mac: [u8; 6],
    /// Ethernet protocol type (EtherType).
    pub ethertype: u16,
}

/// Represents an IPv4 header.
#[derive(Debug, PartialEq)]
pub struct Ipv4Header {
    /// IP version (4 for IPv4).
    pub version: u8,
    /// Internet Header Length.
    pub ihl: u8,
    /// Differentiated Services Code Point.
    pub dscp: u8,
    /// Explicit Congestion Notification.
    pub ecn: u8,
    /// Total length of the packet.
    pub total_length: u16,
    /// Packet identification.
    pub identification: u16,
    /// Fragmentation flags.
    pub flags: u8,
    /// Fragmentation offset.
    pub fragment_offset: u16,
    /// Time to Live.
    pub ttl: u8,
    /// Upper layer protocol.
    pub protocol: u8,
    /// Header checksum.
    pub header_checksum: u16,
    /// Source IP address.
    pub src_ip: Ipv4Addr,
    /// Destination IP address.
    pub dest_ip: Ipv4Addr,
}

/// Enum representing the different types of packets we can parse.
#[derive(Debug, PartialEq)]
pub enum PacketType {
    /// Ethernet frame.
    Ethernet(EthernetFrame),
    /// IPv4 packet.
    Ipv4(Ipv4Header),
    /// Unknown packet type.
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
    if data.len() >= 14 {
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
            return PacketType::Ipv4(ipv4_header);
        }

        PacketType::Ethernet(ethernet_frame)
    } else {
        PacketType::Unknown
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
}