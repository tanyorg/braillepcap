# braillepcap

Terminal-based IPv4 traffic visualizer in Rust using Unicode Braille characters.

![Demo](./demo.gif)

## Features
- Real-time packet capture display on a 256x256 IPv4 grid
- Support for pcap files and live interfaces
- Regional Internet Registry (RIR) traffic statistics

## Usage
```bash
# Live capture
sudo cargo run --release -- -i en0

# Read pcap file
cargo run --release -- -r sample.pcap

