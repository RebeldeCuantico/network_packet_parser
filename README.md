# Network Packet Parser

This project provides a Rust library for parsing and analyzing network packets, specifically Ethernet frames and IPv4 packets.

## Features

- Parsing of Ethernet frames
- Parsing of IPv4 headers
- Parsing of TCP headers
- Determination of the required analyzer type based on packet content

## Installation

To use this library in your project, add the following line to your `Cargo.toml`:

```toml
[dependencies]
network_packet_parser = { git = "https://github.com/RebeldeCuantico/network_packet_parser.git" }
```

## Usage

Here's a basic example of how to use the library:

```rust
use network_packet_parser::{parse_packet, determine_analyzer};

fn main() {
    let sample_packet = [
        0x00, 0x50, 0x56, 0xC0, 0x00, 0x08, 0x00, 0x50, 0x56, 0xC0, 0x00, 0x01, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06, 0x61, 0x4A, 0xC0, 0xA8,
        0x00, 0x01, 0xC0, 0xA8, 0x00, 0x0A,
    ];

    let parsed_packet = parse_packet(&sample_packet);
    println!("Parsed packet: {:?}", parsed_packet);

    let analyzer = determine_analyzer(&parsed_packet);
    println!("Recommended analyzer: {}", analyzer);
}
```
## Supported Packet Types
The library can parse the following types of packets:

- Ethernet frames
- IPv4 packets
- TCP segments (encapsulated in IPv4)

## API Documentation

For detailed API documentation, run `cargo doc --open` in your project directory.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the need for a simple, educational network packet parsing tool.

## Contact

If you have any questions or feedback, please open an issue on the [GitHub repository](https://github.com/RebeldeCuantico/network_packet_parser).